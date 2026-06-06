# CLAUDE.md

Guidance for Claude Code / Claude agents working in this repo. **[AGENTS.md](AGENTS.md) is the source of truth** — read it for repo layout, build/test, architecture, and conventions. This file only surfaces the constraints that are too costly to miss.

## Posture (load-bearing)

Tessera is **research-grade and UNAUDITED**. The project's credibility is its calibrated candor — never describe it as audited, secure, production-ready, or post-quantum, and don't let edits quietly inflate the claims. Smart contracts are **TESTNET-ONLY**. The honest headline: a vector-proven ARC/P-256 (Privacy Pass ARC) **keyed-verification** implementation plus supporting network — *not* "private uncensorable clearnet access."

One-line architecture: admit a web request on an unlinkable, rate-limited ARC credential, **never on its IP**. ARC is keyed-verification (issuer is the verifier; no public verifiability), over a 2-hop split-trust loop, with an on-chain "court" that slashes only binary-provable badness.

## Do NOT (impossible-to-miss)

- **Do NOT chase upstream draft-arc §10.2 presentation-proof vectors.** There is a documented Fiat-Shamir challenge-squeeze skew (filed as `draft-arc#68`); those KATs are intentionally `#[ignore]`d. See `docs/ARC_PROOF_VECTOR_DISCREPANCY.md`. Do not re-investigate or "fix" it.
- **`contracts/src/RDecVerifier.sol` is a TEST-ONLY single-party trusted-setup ceremony — NEVER deploy it with value.** It needs a real MPC ceremony first.
- **The default `deploy/` docker-compose topology gives NO relationship anonymity when one operator runs both relay and exit** (`docs/DEPLOYMENT_TOPOLOGY.md` §6). Surface this wherever people run it.
- **Do NOT publish crates to crates.io.**
- `Cargo.lock` **is** committed (reproducible, auditable security tooling); contracts are dependency-free (vendored test `Std.sol`, pinned solc 0.8.24). Don't "clean these up."

Three gaps no code can fake, so don't pretend otherwise: a genuinely clean egress IP, a real Tor/Nym anonymity crowd, and a third-party audit.

## Gate quick-reference

Main workspace (cwd `/home/nubs/tessera`):

```sh
cargo fmt --all -- --check
cargo +1.74.0 build --workspace --all-features --locked   # MSRV (rust-version = 1.74)
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
cargo doc --workspace --no-deps --locked
cargo bench --workspace --no-run --locked
cargo deny check
```

Excluded sub-workspaces (own manifest; cwd `/home/nubs/tessera`):

```sh
cargo {fmt --all -- --check | clippy --all-targets -- -D warnings | test} --manifest-path crates/tessera-wasm/Cargo.toml
cargo {fmt --all -- --check | clippy --all-targets -- -D warnings | test} --manifest-path crates/tessera-tower-demo/Cargo.toml
```

Contracts (cwd `/home/nubs/tessera/contracts`):

```sh
forge build && forge test -vv
```

Fuzz (nightly; cwd `/home/nubs/tessera/fuzz`):

```sh
cargo +nightly fuzz build
```

Run the suite rather than trusting any stated test counts.
