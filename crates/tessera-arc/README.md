# tessera-arc

A from-scratch implementation of Anonymous Rate-Limited Credentials (IETF ARC) over NIST P-256: the arithmetic core is proven byte-for-byte against the IETF §10.2 test vectors, and the Fiat–Shamir/Σ transcript against the authoritative IETF Sigma vectors (the §10.2 *proof-blob* KATs are an upstream discrepancy and are not reconciled — see [`docs/THREAT_MODEL.md`](../../docs/THREAT_MODEL.md)). ARC is **keyed-verification**: the issuer is the verifier, so there is **no public verifiability**.

Part of [Tessera](../../README.md) — anonymous rate-limited credentials (IETF ARC) as a trust layer that admits traffic on a credential, not an IP. This crate is the cryptographic core: it implements the ARC issuance (request → response → finalize), presentation, and verification protocol from `draft-ietf-privacypass-arc-crypto-01`, on top of its own P-256 group, Sigma-protocol, and Fiat-Shamir layers. A server issues a credential to an anonymous client, which can then present it up to a fixed `limit` times, with presentations mutually unlinkable and unlinkable from issuance. Everything else (tessera-origin server guard, tessera-client, tessera-issuer PoW gate, tessera-proxy, tessera-demo) builds on the primitives exported here.

## Usage

```rust
use rand_core::OsRng;
use tessera_arc::arc::{
    create_credential_request, create_credential_response, finalize_credential,
    verify_presentation, PresentationState,
};
use tessera_arc::keys::ServerPrivateKey;

let mut rng = OsRng;
let (sk, pk) = ServerPrivateKey::setup(&mut rng);
let (request_ctx, present_ctx, limit) = (b"issue/v1".as_slice(), b"origin/v1".as_slice(), 4);

// Issuance: client requests, server responds, client finalizes.
let (secrets, request) = create_credential_request(request_ctx, &mut rng);
let response = create_credential_response(&sk, &pk, &request, &mut rng).unwrap();
let credential = finalize_credential(&secrets, &pk, &request, &response).unwrap();

// Presentation: each call yields a fresh, unlinkable token; verify returns
// the rate-limiting tag iff the proof checks out — the source IP is never an input.
let mut state = PresentationState::new(credential, present_ctx, limit);
let presentation = state.present(&mut rng).unwrap();
assert!(verify_presentation(&sk, &pk, request_ctx, present_ctx, &presentation, limit).is_some());
```

Pass each returned tag through a `TagStore` to enforce single-use of every (credential, context, nonce) slot.

## Status

Research-grade and **unaudited**; do not use to protect real users. See [SECURITY](../../SECURITY.md) and the [threat model](../../docs/THREAT_MODEL.md).
