# tessera-issuer

A proof-of-work issuance gate for Tessera ARC credentials — make obtaining a credential cost something.

Part of [Tessera](../../README.md) — anonymous rate-limited credentials (IETF ARC) as a trust layer that admits traffic on a credential, not an IP. ARC's rate limit only bounds presentations *per credential*, so the real abuse lever is who gets to obtain one. This crate is the issuance gate: a hashcash-style proof of work the client must solve before the server issues, plus a `ChallengeStore` that admits exactly one issuance per solved challenge (anti-replay). It sits in front of `tessera-arc` (the crypto core); the difficulty bits are the server's policy dial.

## Usage

```rust
use rand_core::OsRng;
use tessera_issuer::{ChallengeStore, solve};

let mut store = ChallengeStore::new();

// Server issues a fresh challenge (12 leading-zero bits) and records it.
let challenge = store.issue(&mut OsRng, 12);

// Client pays the cost: brute-force the counter (~2^difficulty hashes).
let solution = solve(&challenge);

// Server redeems it: valid AND outstanding -> true, and consumed (no reuse).
assert!(store.redeem(&challenge, &solution));
assert!(!store.redeem(&challenge, &solution)); // already spent
```

## Status

Research-grade and **unaudited**; do not use to protect real users. See [SECURITY](../../SECURITY.md) and the [threat model](../../docs/THREAT_MODEL.md). The PoW gate is a cost knob, not strong Sybil resistance — an adversary with enough compute still scales, and it is unfair to low-power clients.
