# syntax=docker/dockerfile:1
#
# Tessera relay + exit nodes — one image, the binary chosen by the run command.
# Built for containerized / TEE (dstack) deployment; see docs/DEPLOY.md.
#
# Multi-stage: a Rust builder produces the release binaries, then a slim runtime
# image carries just them (no toolchain, non-root). The binaries are
# std-only + #![forbid(unsafe_code)] and configured entirely via env vars.

FROM rust:1.83-slim-bookworm AS builder
WORKDIR /build
# Build deps: a C linker for any build scripts (the crypto crates are pure Rust).
RUN apt-get update && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*
COPY . .
# Only the two node binaries (the relay first hop + the credential-gated exit).
RUN cargo build --release -p tessera-proxy -p tessera-relay --bins

FROM debian:bookworm-slim AS runtime
# ca-certificates for DNS/TLS-adjacent tooling; the tunnel itself is opaque bytes
# (CONNECT, end-to-end TLS) so the node never terminates TLS.
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -u 10001 -s /usr/sbin/nologin tessera
COPY --from=builder /build/target/release/tessera-proxy /usr/local/bin/tessera-proxy
COPY --from=builder /build/target/release/tessera-relay /usr/local/bin/tessera-relay
USER tessera
# The exit by default; the relay service overrides the command (see compose).
# All config is via env: TESSERA_LISTEN / TESSERA_UPSTREAM (exit),
# TESSERA_RELAY_LISTEN / TESSERA_EXIT_ADDR (relay).
CMD ["tessera-proxy"]
