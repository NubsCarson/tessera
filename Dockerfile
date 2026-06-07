# syntax=docker/dockerfile:1
#
# Tessera network nodes — one image, the binary chosen by the run command. The
# four node roles (issuer · relay · exit · client proxy) all ship in this image;
# `command:` selects which. Built for containerized / TEE (dstack) deployment;
# see docs/DEPLOY.md.
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
# All four node binaries: tessera-issuer (authority), tessera-proxy (exit),
# tessera-relay (first hop), and tessera-client (the relay crate's --bins also
# produces the local client proxy).
RUN cargo build --release -p tessera-issuer -p tessera-proxy -p tessera-relay --bins

FROM debian:bookworm-slim AS runtime
# ca-certificates for DNS/TLS-adjacent tooling; the tunnel itself is opaque bytes
# (CONNECT, end-to-end TLS) so the node never terminates TLS. curl is only for the
# compose/k8s healthcheck against the counts-only TESSERA_HEALTH_LISTEN endpoint.
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -u 10001 -s /usr/sbin/nologin tessera
COPY --from=builder /build/target/release/tessera-issuer /usr/local/bin/tessera-issuer
COPY --from=builder /build/target/release/tessera-proxy /usr/local/bin/tessera-proxy
COPY --from=builder /build/target/release/tessera-relay /usr/local/bin/tessera-relay
COPY --from=builder /build/target/release/tessera-client /usr/local/bin/tessera-client
USER tessera
# The exit by default; each service overrides `command` (see compose). Config is
# all via env (per role): issuer TESSERA_ISSUER_LISTEN / TESSERA_KEY_FILE /
# TESSERA_POW_DIFFICULTY; exit TESSERA_LISTEN / TESSERA_UPSTREAM / TESSERA_KEY_FILE;
# relay TESSERA_RELAY_LISTEN / TESSERA_EXIT_ADDR; client TESSERA_ISSUER /
# TESSERA_RELAY / TESSERA_EXIT / TESSERA_CLIENT_LISTEN / TESSERA_ISSUER_PK.
CMD ["tessera-proxy"]
