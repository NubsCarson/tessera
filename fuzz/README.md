# Tessera fuzz targets

`cargo-fuzz` (libFuzzer) harnesses for every attacker-controlled parsing/verify
surface. Each target asserts the **no-panic** contract: arbitrary bytes must be
rejected with an error/`false`, never crash the process.

Targets:

| Target | Surface |
|---|---|
| `deserialize_element` | `group::deserialize_element` (SEC1 point decode) |
| `deserialize_scalar` | `group::deserialize_scalar` |
| `wire_from_bytes` | `ServerPublicKey` / `CredentialRequest` / `CredentialResponse` / `Presentation` decoders (incl. degenerate limits) |
| `presentation_verify` | full `Presentation::from_bytes` → `verify_presentation` (range-sum + `sigma::verify`); asserts random bytes never verify |
| `origin_guard_check` | end-to-end `OriginGuard::check` (hex-decode → deserialize → verify → tag store) |

## Running

Requires nightly + `cargo install cargo-fuzz`.

```sh
cargo +nightly fuzz build
cargo +nightly fuzz run wire_from_bytes -- -max_total_time=60
```

> **Sandbox/container note:** LeakSanitizer needs `ptrace`, which many
> containers disallow ("LeakSanitizer does not work under ptrace"). If you see
> an LSan fatal error at exit, disable it — it is not a finding:
>
> ```sh
> ASAN_OPTIONS=detect_leaks=0 cargo +nightly fuzz run <target> -- -detect_leaks=0
> ```

A stable-toolchain companion (`crates/tessera-arc/tests/robustness.rs`) provides
fast, reproducible no-panic coverage in normal CI without nightly.
