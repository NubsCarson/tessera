# Contributing to Tessera

Thanks for your interest. Tessera is research-grade cryptographic software, so
the bar for changes is deliberately high.

## Ground rules

1. **No bespoke crypto.** Every cryptographic operation must map to a cited line
   of an IETF draft (`draft-ietf-privacypass-arc-crypto`,
   `draft-irtf-cfrg-sigma-protocols`, `draft-irtf-cfrg-fiat-shamir`) or a
   published construction. Cite it in a comment.
2. **Prove it, don't assert it.** New protocol code must be validated against
   official test vectors where they exist (see `tests/`), and have round-trip +
   negative tests. The acceptance bar is in [`GOAL.md`](./GOAL.md).
3. **No `unsafe`** (`#![forbid(unsafe_code)]`), and deserializers/verifiers must
   never panic on attacker-controlled input — add a fuzz target (`fuzz/`) and/or
   a case in `tests/robustness.rs`.
4. **Honest docs.** Don't overclaim. If something is best-effort, unaudited, or
   draft-tracking, say so (see [`docs/THREAT_MODEL.md`](./docs/THREAT_MODEL.md)).

## Before you open a PR

The same gates CI enforces — all must pass:

```sh
cargo fmt --all
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
cargo doc --workspace --no-deps        # with RUSTDOCFLAGS="-D warnings"
cargo +1.74.0 build --workspace --all-features --locked   # MSRV
cargo +nightly fuzz build              # if you touched a deserializer/verifier
```

Keep commits focused; explain the "why" in the message. End co-authored commits
per the repo convention.

## Security issues

Do **not** open a public issue for a vulnerability — see
[`SECURITY.md`](./SECURITY.md).
