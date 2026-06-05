#![no_main]
//! S21 — the FULL ARC credential lifecycle, cross-crate, end to end:
//! `create_credential_request` -> `create_credential_response` ->
//! `finalize_credential` -> `PresentationState::present` -> `verify_presentation`.
//!
//! Every other ARC fuzz target attacks one decoder in isolation; this one drives
//! the whole protocol an honest deployment runs and asserts its security
//! invariants under fuzz-chosen contexts, limits, and tampering:
//!
//!   1. **No panic.** No input — context bytes, limit, tamper choice — ever
//!      crashes the pipeline; recoverable conditions surface as `Err`/`None`.
//!   2. **Completeness.** An honestly issued, honestly presented credential
//!      verifies, and its tag is fresh in a clean `TagStore`.
//!   3. **Single-use.** Re-recording the same tag is rejected (double-spend).
//!   4. **Soundness — tampering never verifies.** A presentation checked against
//!      the wrong context/limit, a credential with a corrupted MAC, or a
//!      presentation with a flipped proof byte all fail to verify.
//!   5. **Rate limit.** A credential cannot be presented more than `limit`
//!      times for a context, and a `limit < 2` admits no presentation at all.
//!
//! The RNG is a deterministic SplitMix64 seeded from the fuzz input, so the ARC
//! API's `RngCore` requirement is satisfied with **zero OS entropy** — every
//! crashing input replays bit-for-bit from its corpus file.
use libfuzzer_sys::fuzz_target;
use rand_core::RngCore;
use tessera_arc::arc::{
    create_credential_request, create_credential_response, finalize_credential,
    verify_presentation, ArcError, Credential, Presentation, PresentationState, TagStore,
};
use tessera_arc::keys::ServerPrivateKey;

/// A reproducible SplitMix64 PRNG (Steele/Lea), seeded from the fuzz input. It
/// only needs to be *uniform enough* to draw the protocol's blinding scalars;
/// it is **not** a CSPRNG and exists purely so the lifecycle is deterministic
/// per input. `random_scalar` rejection-samples on top, so a weak stream still
/// yields valid scalars.
struct SplitMix64(u64);

impl SplitMix64 {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

impl RngCore for SplitMix64 {
    fn next_u32(&mut self) -> u32 {
        self.next() as u32
    }
    fn next_u64(&mut self) -> u64 {
        self.next()
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let mut chunks = dest.chunks_exact_mut(8);
        for chunk in &mut chunks {
            chunk.copy_from_slice(&self.next().to_le_bytes());
        }
        let rem = chunks.into_remainder();
        if !rem.is_empty() {
            let bytes = self.next().to_le_bytes();
            rem.copy_from_slice(&bytes[..rem.len()]);
        }
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

/// Carve the fuzz input into protocol parameters. We take a few leading bytes as
/// structured knobs and use the remainder as both the RNG seed material and the
/// two context strings, so empty/short inputs still produce a well-formed run.
struct Inputs<'a> {
    seed: u64,
    limit: u64,
    /// Which tamper to apply on this run (mod the number of tampers).
    tamper: u8,
    /// Index of the proof byte to flip in the flip-a-byte tamper.
    flip_at: usize,
    request_context: &'a [u8],
    presentation_context: &'a [u8],
}

fn split(data: &[u8]) -> Inputs<'_> {
    // Header: 8-byte seed | 1-byte limit selector | 1-byte tamper | 2-byte flip
    // index. Missing bytes default to zero (handled by the closures below).
    let byte = |i: usize| data.get(i).copied().unwrap_or(0);
    let seed = data
        .get(0..8)
        .map(|b| u64::from_le_bytes(b.try_into().unwrap()))
        .unwrap_or(0);

    // Keep the limit in a small range so the range-proof stays cheap, while still
    // reaching the `limit < 2` refusal path and modest multi-presentation runs.
    let limit = u64::from(byte(8) % 9); // 0..=8
    let tamper = byte(9);
    let flip_at = usize::from(u16::from_le_bytes([byte(10), byte(11)]));

    // The two contexts come from disjoint slices of the tail; either may be empty
    // (a valid `&[u8]` context), and they may coincide (also valid).
    let tail = data.get(12..).unwrap_or(&[]);
    let mid = tail.len() / 2;
    let (request_context, presentation_context) = tail.split_at(mid);

    Inputs {
        seed,
        limit,
        tamper,
        flip_at,
        request_context,
        presentation_context,
    }
}

/// Run the issuance handshake and return a finalized credential. The honest path
/// must never error: the proofs are produced and checked over the same RNG-drawn
/// secrets, so request/response verification always succeeds.
fn issue<R: RngCore + ?Sized>(
    sk: &ServerPrivateKey,
    request_context: &[u8],
    rng: &mut R,
) -> Credential {
    let pk = sk.public_key();
    let (secrets, request) = create_credential_request(request_context, rng);
    let response = create_credential_response(sk, &pk, &request, rng)
        .expect("honest credential-request proof must verify");
    finalize_credential(&secrets, &pk, &request, &response)
        .expect("honest credential-response proof must verify")
}

fuzz_target!(|data: &[u8]| {
    let inp = split(data);
    let mut rng = SplitMix64(inp.seed ^ 0xA5A5_A5A5_A5A5_A5A5);

    // Fresh server key pair drawn from the (seeded) RNG — the spec's SetupServer.
    let (sk, pk) = ServerPrivateKey::setup(&mut rng);

    let credential = issue(&sk, inp.request_context, &mut rng);

    // ---- Rate-limit floor: a credential with limit < 2 admits no presentation,
    //      and the refusal is an error, not a panic.
    if inp.limit < 2 {
        let mut state = PresentationState::new(credential, inp.presentation_context, inp.limit);
        assert!(
            matches!(state.present(&mut rng), Err(ArcError::LimitExceeded)),
            "limit < 2 must refuse to present"
        );
        return;
    }

    // ---- Completeness: honest present + verify succeeds, and the tag is fresh.
    let mut state = PresentationState::new(
        credential.clone(),
        inp.presentation_context,
        inp.limit,
    );
    let presentation = match state.present(&mut rng) {
        Ok(p) => p,
        // DegenerateCredential is a ~2^-256 recoverable case; if it ever fires we
        // simply have nothing to verify. Anything else is a real bug.
        Err(ArcError::DegenerateCredential) => return,
        Err(e) => panic!("honest first presentation must succeed, got {e:?}"),
    };

    let tag = verify_presentation(
        &sk,
        &pk,
        inp.request_context,
        inp.presentation_context,
        &presentation,
        inp.limit,
    )
    .expect("honest presentation must verify");

    // ---- Single-use: the tag is fresh once, a replay of it is rejected.
    let mut store = TagStore::new();
    assert!(store.accept(tag), "first sighting of a tag must be accepted");
    assert!(
        !store.accept(tag),
        "a re-recorded tag must be rejected (double-spend)"
    );

    // ---- Soundness: none of the following tampered checks may verify.
    match inp.tamper % 4 {
        // (a) Wrong presentation context. Append a sentinel byte so the context
        //     is provably different from the one the proof was bound to.
        0 => {
            let mut wrong_ctx = inp.presentation_context.to_vec();
            wrong_ctx.push(0xFF);
            assert!(
                verify_presentation(
                    &sk,
                    &pk,
                    inp.request_context,
                    &wrong_ctx,
                    &presentation,
                    inp.limit,
                )
                .is_none(),
                "presentation must not verify against a different presentation context"
            );
        }
        // (b) Wrong request context — likewise guaranteed distinct.
        1 => {
            let mut wrong_req = inp.request_context.to_vec();
            wrong_req.push(0xFF);
            assert!(
                verify_presentation(
                    &sk,
                    &pk,
                    &wrong_req,
                    inp.presentation_context,
                    &presentation,
                    inp.limit,
                )
                .is_none(),
                "presentation must not verify against a different request context"
            );
        }
        // (c) Corrupted credential: poison the unblinded MAC `U'` before
        //     presenting. The presentation proof is internally self-consistent
        //     but no longer matches a MAC under the server key, so verification
        //     reconstructs a different `V` and rejects.
        2 => {
            let mut forged = credential.clone();
            forged.u_prime += tessera_arc::group::generator_g();
            let mut bad_state =
                PresentationState::new(forged, inp.presentation_context, inp.limit);
            match bad_state.present(&mut rng) {
                Ok(bad) => assert!(
                    verify_presentation(
                        &sk,
                        &pk,
                        inp.request_context,
                        inp.presentation_context,
                        &bad,
                        inp.limit,
                    )
                    .is_none(),
                    "a presentation from a tampered credential must not verify"
                ),
                Err(ArcError::DegenerateCredential) => {}
                Err(e) => panic!("forged-credential present must not hard-fail: {e:?}"),
            }
        }
        // (d) Flip one byte of the serialized presentation and re-decode. If it
        //     still parses as a `Presentation`, its proof can no longer satisfy
        //     the sigma check, so verification must fail.
        _ => {
            let mut bytes = presentation.to_bytes();
            if !bytes.is_empty() {
                let i = inp.flip_at % bytes.len();
                bytes[i] ^= 0x01;
                if let Ok(mutated) = Presentation::from_bytes(&bytes, inp.limit) {
                    assert!(
                        verify_presentation(
                            &sk,
                            &pk,
                            inp.request_context,
                            inp.presentation_context,
                            &mutated,
                            inp.limit,
                        )
                        .is_none(),
                        "a presentation with a flipped byte must not verify"
                    );
                }
            }
        }
    }

    // ---- Rate limit: draining the credential to its limit must refuse the next
    //      presentation. We continue from `state` (one already presented above),
    //      so this also confirms the nonce counter is shared, not reset.
    loop {
        match state.present(&mut rng) {
            Ok(_) => continue,
            Err(ArcError::LimitExceeded) => break,
            // Degenerate is a vanishingly rare recoverable case; stop here.
            Err(ArcError::DegenerateCredential) => break,
            Err(e) => panic!("present must only fail with a rate-limit error, got {e:?}"),
        }
    }
    // Once exhausted, it stays exhausted.
    assert!(
        matches!(state.present(&mut rng), Err(ArcError::LimitExceeded)),
        "an exhausted credential must keep refusing presentations"
    );
});
