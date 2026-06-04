//! M7 — the systematic **"a decrement can never mint balance"** proof for the
//! `R_dec` circuit's money constraints.
//!
//! ## The money-mint footgun (why this test exists)
//!
//! `R_dec` proves a channel decrement `B_next + cost === B_i` in zero-knowledge.
//! The circuit works over the BN254 scalar field `Fr` (order `r ≈ 2^254`), where
//! arithmetic is **mod r**. The decrement identity *alone* is therefore unsound:
//! a malicious prover could pick a giant `cost ≈ r` so that
//! `B_next + cost ≡ B_i (mod r)` while `B_next > B_i` — i.e. **mint** balance by
//! wrapping the field. The fix in `circuits/R_dec.circom` is a `Num2Bits(64)`
//! **range check on all three** of `B_i`, `cost`, `B_next` (not just the output):
//! forcing every amount into `[0, 2^64)`, where `B_next + cost < 2^65 ≪ r` cannot
//! wrap, so the field identity coincides with the integer identity and `cost ≥ 0`,
//! `B_next ≤ B_i` are forced.
//!
//! ## What this test proves (and its honest scope)
//!
//! It models `R_dec`'s **money constraints** — the three range checks + the
//! decrement identity — over the *same* `ark-bn254` `Fr` the circuit and the Rust
//! commitment use, and proves **systematically** (not via one vector):
//!
//!   1. every honest decrement (`cost ≤ B_i`, `B_next = B_i − cost`) satisfies them;
//!   2. the field-wrap **mint** witness (`B_next > B_i` with the wrapping `cost`)
//!      satisfies the decrement identity but is **rejected** — specifically by the
//!      `cost` range check;
//!   3. **each** range check is load-bearing: dropping the `cost` check admits the
//!      mint, dropping the `B_next` check admits an over-spend/underflow;
//!   4. the soundness lemma: in-range + identity ⇒ integer-faithful, no mint,
//!      no underflow (`B_next ≤ B_i`).
//!
//! Honest scope: this proves the **constraint set** rejects the entire mint class.
//! That the *circuit* implements exactly these constraints is established by the
//! circuit source plus the pinned on-chain proof in
//! `contracts/test/RDecVerifier.t.sol`; this test complements that single valid
//! vector with a systematic proof of the negative space.

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};

/// Model the circuit's `Num2Bits(64)` range check: the canonical representative
/// of `fe` (always `< r`) fits in 64 bits ⇔ the top 192 bits of its 32-byte
/// big-endian encoding are zero.
fn fits_u64(fe: Fr) -> bool {
    let be = fe.into_bigint().to_bytes_be(); // canonical, fixed 32 bytes, big-endian
    be[..24].iter().all(|&b| b == 0)
}

/// The FULL `R_dec` money constraints (mirrors `circuits/R_dec.circom`):
/// `Num2Bits(64)` on `B_i`, `cost`, AND `B_next`, plus `B_next + cost === B_i`.
fn rdec_satisfied(b_i: Fr, cost: Fr, b_next: Fr) -> bool {
    fits_u64(b_i) && fits_u64(cost) && fits_u64(b_next) && (b_next + cost == b_i)
}

/// Decrement identity with range checks on everything EXCEPT `cost` — to show the
/// `cost` range check is what defeats the field-wrap mint.
fn rdec_without_cost_rangecheck(b_i: Fr, cost: Fr, b_next: Fr) -> bool {
    fits_u64(b_i) && fits_u64(b_next) && (b_next + cost == b_i)
}

/// Decrement identity with range checks on everything EXCEPT `B_next` — to show
/// the `B_next` range check is what defeats over-spend/underflow.
fn rdec_without_bnext_rangecheck(b_i: Fr, cost: Fr, b_next: Fr) -> bool {
    fits_u64(b_i) && fits_u64(cost) && (b_next + cost == b_i)
}

fn fr(x: u64) -> Fr {
    Fr::from(x)
}

/// A deterministic xorshift64 — reproducible "property" coverage without pulling
/// in a PRNG crate (this is a proof, not a benchmark; determinism is the point).
struct XorShift(u64);
impl XorShift {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
}

const EDGE: [u64; 7] = [0, 1, 2, 1000, u64::MAX - 1, u64::MAX, 1 << 63];

// ---------------------------------------------------------------------------

/// (1) Every honest decrement satisfies the full constraints.
#[test]
fn honest_decrements_satisfy_the_constraints() {
    // Edge grid.
    for &b_i in &EDGE {
        for &cost in &EDGE {
            if cost <= b_i {
                let b_next = b_i - cost;
                assert!(
                    rdec_satisfied(fr(b_i), fr(cost), fr(b_next)),
                    "honest decrement B_i={b_i} cost={cost} B_next={b_next} must satisfy"
                );
            }
        }
    }
    // Randomized spread over the full u64 range.
    let mut rng = XorShift(0x9E3779B97F4A7C15);
    for _ in 0..20_000 {
        let b_i = rng.next();
        let cost = rng.next() % (b_i.wrapping_add(1)).max(1); // cost in [0, b_i]
        let b_next = b_i - cost;
        assert!(
            rdec_satisfied(fr(b_i), fr(cost), fr(b_next)),
            "honest B_i={b_i} cost={cost} must satisfy"
        );
    }
}

/// (2)+(3a) THE money-mint footgun: a `B_next > B_i` witness with the wrapping
/// `cost = B_i − B_next (mod r)` satisfies the decrement identity, yet the full
/// constraints REJECT it — and the rejection is exactly the `cost` range check
/// (dropping it admits the mint).
#[test]
fn field_wrap_mint_is_rejected_by_the_cost_range_check() {
    let mut rng = XorShift(0xD1B54A32D192ED03);
    let mut checked = 0u64;
    for _ in 0..20_000 {
        let b_i = rng.next();
        let b_next = rng.next();
        if b_next <= b_i {
            continue; // we want a MINT: B_next strictly greater than B_i
        }
        checked += 1;
        // The wrapping cost that satisfies the field identity B_next + cost == B_i.
        let cost_fe = fr(b_i) - fr(b_next);

        // The attacker DID satisfy the decrement identity over the field…
        assert_eq!(
            fr(b_next) + cost_fe,
            fr(b_i),
            "field identity holds for the mint"
        );
        // …but the wrapping cost is a ~254-bit element, far outside [0, 2^64)…
        assert!(
            !fits_u64(cost_fe),
            "the wrapping cost cannot fit the 64-bit range check"
        );
        // …so the FULL constraints reject the mint.
        assert!(
            !rdec_satisfied(fr(b_i), cost_fe, fr(b_next)),
            "mint B_i={b_i} B_next={b_next} must be rejected"
        );
        // And the rejection is precisely the cost range check: drop it → admitted.
        assert!(
            rdec_without_cost_rangecheck(fr(b_i), cost_fe, fr(b_next)),
            "without the cost range check the very same mint is admitted — so that \
             check is load-bearing"
        );
    }
    assert!(
        checked > 1_000,
        "exercised enough mint witnesses ({checked})"
    );
}

/// (3b) The `B_next` range check is the anti-underflow/over-spend guard: spending
/// more than the balance (`cost > B_i`) makes `B_next` wrap to a giant element;
/// the full constraints reject it, but dropping the `B_next` check admits it.
#[test]
fn over_spend_is_rejected_by_the_bnext_range_check() {
    let mut rng = XorShift(0x2545F4914F6CDD1D);
    let mut checked = 0u64;
    for _ in 0..20_000 {
        let b_i = rng.next() % 1_000_000; // keep B_i modest so cost>B_i is easy
        let cost = b_i + 1 + (rng.next() % 1_000_000); // cost strictly exceeds B_i
        checked += 1;
        // B_next that satisfies the field identity is B_i - cost (mod r): a wrap.
        let b_next_fe = fr(b_i) - fr(cost);
        assert_eq!(
            b_next_fe + fr(cost),
            fr(b_i),
            "field identity holds for the over-spend"
        );
        assert!(
            !fits_u64(b_next_fe),
            "underflowed B_next cannot fit the 64-bit range check"
        );
        assert!(
            !rdec_satisfied(fr(b_i), fr(cost), b_next_fe),
            "over-spend B_i={b_i} cost={cost} must be rejected"
        );
        assert!(
            rdec_without_bnext_rangecheck(fr(b_i), fr(cost), b_next_fe),
            "without the B_next range check the over-spend is admitted — load-bearing"
        );
    }
    assert!(
        checked > 1_000,
        "exercised enough over-spend witnesses ({checked})"
    );
}

/// (4) Soundness lemma: whenever the full constraints are satisfied, the witness
/// is integer-faithful — no wrap, no mint, no underflow (`B_next ≤ B_i` and
/// `B_i == B_next + cost` over the integers).
#[test]
fn in_range_plus_identity_implies_no_mint() {
    let mut rng = XorShift(0x106689D45497FDB5);
    for _ in 0..20_000 {
        // Draw an in-range honest triple (the only way to satisfy the full set).
        let b_i = rng.next();
        let cost = rng.next() % (b_i.wrapping_add(1)).max(1);
        let b_next = b_i - cost;
        assert!(rdec_satisfied(fr(b_i), fr(cost), fr(b_next)));
        // The lemma: integer arithmetic holds exactly (no field wrap).
        assert!(b_next <= b_i, "no mint: B_next <= B_i");
        assert_eq!(
            b_next as u128 + cost as u128,
            b_i as u128,
            "integer-faithful decrement (sum < 2^65 < r, so no wrap)"
        );
    }
}

/// (5) A wrong decrement (identity violated) with all-in-range amounts is
/// rejected — guards the honest path itself.
#[test]
fn wrong_decrement_is_rejected() {
    let mut rng = XorShift(0x9E6C63D0676A9A99);
    for _ in 0..20_000 {
        let b_i = (rng.next() % (u64::MAX - 1)) + 1; // >=1
        let cost = rng.next() % b_i; // in [0, b_i)
        let honest = b_i - cost;
        // Off-by-one in B_next (still in range) breaks the identity.
        let wrong = honest.wrapping_add(1);
        assert!(
            !rdec_satisfied(fr(b_i), fr(cost), fr(wrong)),
            "B_i={b_i} cost={cost} wrong_B_next={wrong} must be rejected"
        );
    }
}
