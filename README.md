# Tessera

**Anonymous, rate-limited credentials for censorship-resistant network access.**

Tessera is a from-scratch, spec-faithful implementation of the IETF
**Anonymous Rate-Limited Credentials (ARC)** protocol, plus the tooling to use
it as a *trust layer for anonymous traffic*.

> A **tessera** was a small token used in ancient Rome as a ticket of
> admission — proof you were allowed in, carried in the hand, tied to no name.
> That is exactly what this is: a cryptographic token that admits a request on
> its own merit, not on who or where it came from.

## See it

![Tessera demo](docs/demo.svg)

```sh
cargo run -p tessera-demo            # real HTTP origin + client, localhost
cargo run -p tessera-demo -- --tor   # also drive it over a real Tor onion circuit
```

The demo stands up an origin guarded by `tessera-origin`, issues a credential to
a `tessera-client`, and makes **real HTTP requests**: no credential → `403`
(what every Tor user gets today); with a credential → `200` and a fresh,
unlinkable tag each time; over the limit → the client refuses; a replay → `403`
double-spend. The origin never reads the source IP. See [`DEMO.md`](./DEMO.md).

## The problem it attacks

The web decides whether to trust you by your **IP address**. Tor's exit relays
are published and deterministically blockable, so anonymous traffic is treated
as guilty by default — blocked, CAPTCHA-walled, or rate-limited into
uselessness. Throwing more crypto at *hiding that you're Tor* is a losing
arms race, and it's the wrong layer: the server sees a source IP no matter what.

Tessera changes the trust primitive instead. A client obtains an **ARC
credential** and presents it with each request. The server learns only:

- this presentation came from *some* validly-issued credential, and
- it is within that credential's fixed presentation budget,

…and **nothing else** — not the client's identity, not which credential it is,
and no two presentations are linkable to each other or to issuance. The server
can now rate-limit and trust anonymous clients **without IP reputation**, so it
has no reason to block Tor. Censorship by IP becomes obsolete rather than evaded.

This is the missing adapter between Privacy-Pass-style anonymous credentials
and anonymity networks — see [`GOAL.md`](./GOAL.md) for the full thesis and
roadmap.

## Standards

Tessera tracks three IETF drafts and is validated against their official test
vectors:

- [`draft-ietf-privacypass-arc-crypto-01`](https://datatracker.ietf.org/doc/draft-ietf-privacypass-arc-crypto/) — the ARC protocol (Yun, Wood, Faz-Hernández)
- [`draft-irtf-cfrg-sigma-protocols-01`](https://datatracker.ietf.org/doc/draft-irtf-cfrg-sigma-protocols/) — the zero-knowledge proof system
- [`draft-irtf-cfrg-fiat-shamir-01`](https://datatracker.ietf.org/doc/draft-irtf-cfrg-fiat-shamir/) — the non-interactive transform

## Status

| Layer | State |
|-------|-------|
| P-256 group / hashing / serialization | ✅ proven against IETF vectors |
| Server key generation | ✅ proven against IETF vectors |
| Issuance & presentation arithmetic | ✅ proven against IETF vectors |
| Fiat-Shamir + Sigma proofs | ✅ verifier proven against authoritative Sigma vectors; prover exercised via end-to-end round-trip † |
| Full ARC API (issue / present / verify) + range proof + double-spend store | ✅ end-to-end round-trip proven |
| `tessera-origin` guard + `tessera-client` (real HTTP demo) | ✅ admit/reject tested; IP never read |
| Tor binding (onion-service end-to-end) | ✅ implemented; live circuit needs host Tor egress |
| Hardening — CT fix, fuzzing, benches, threat model | ✅ internal audit applied ([`docs/THREAT_MODEL.md`](./docs/THREAT_MODEL.md)); **not** third-party audited |

† The ARC §10.2 *proof* blobs are not byte-reproducible from the pinned
reference (an upstream vector inconsistency — the ARC *arithmetic* vectors all
pass; see [`docs/ARC_PROOF_VECTOR_DISCREPANCY.md`](./docs/ARC_PROOF_VECTOR_DISCREPANCY.md)).
The Fiat-Shamir layer is instead proven against the authoritative IETF Sigma
Protocol test vectors, which exercise the identical transcript machinery.

The crate currently proves the entire **arithmetic core** of ARC matches the
reference byte-for-byte (`tests/test_vectors.rs`; the full crate has many more
tests — round-trip, wire, sigma-vector, proof, and robustness suites):

```
$ cargo test -p tessera-arc --test test_vectors
running 8 tests
test generator_h_is_deterministic ... ok
test server_public_key_matches_vectors ... ok
test hash_to_scalar_matches_m2 ... ok
test credential_request_encryptions_match ... ok
test credential_response_arithmetic_matches ... ok
test finalize_credential_matches ... ok
test presentation1_arithmetic_matches ... ok
test presentation2_arithmetic_matches ... ok
```

## ⚠️ Security status — read this

This is **research-grade, draft-tracking code**. It has **not** been
third-party audited; the known secret-dependent path (the range-proof bit
decomposition) is constant-time-hardened via `subtle`, but there has been **no
end-to-end constant-time audit**; and the underlying specs are IETF *drafts*
that may change. **Do not use it to protect real users yet.** The
path to that is milestone 10 in [`GOAL.md`](./GOAL.md). The cryptographic
primitives come from the audited [RustCrypto](https://github.com/RustCrypto)
project; the protocol logic on top is what still needs review.

## Build

```
cargo test --workspace
cargo clippy --all-targets -- -D warnings
```

Requires a stable Rust toolchain (1.74+).

## License

Dual-licensed under [MIT](./LICENSE-MIT) or [Apache-2.0](./LICENSE-APACHE), at
your option — the Rust ecosystem standard.
