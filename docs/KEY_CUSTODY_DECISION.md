# Multi-exit key-custody decision

> Decision record for the first real multi-exit question: what happens to the ARC
> server key once Tessera has more than one egress exit? Research-grade,
> **UNAUDITED**. This document is normative for deployment docs. It does not add
> a fleet router or issuer-discovery protocol; it fixes the custody rule the
> product must obey when those are built.

## Decision

**Use one ARC key domain per independent exit. Do not share one ARC server key
across an independent multi-exit fleet.**

In the current ARC implementation, verification is keyed: the verifier needs the
same server secret that minted the credential. For the single-exit deployment,
that means the issuer and exit share one `TESSERA_KEY_FILE`. For a multi-exit
deployment, repeat that pair per exit:

```text
issuer-a + exit-a  ->  key-domain A  ->  /keys/exit-a.arc
issuer-b + exit-b  ->  key-domain B  ->  /keys/exit-b.arc
issuer-c + exit-c  ->  key-domain C  ->  /keys/exit-c.arc
```

A client that chooses exit A obtains/presents a credential for key-domain A. A
credential from A must not verify at B; this is now covered by
`crates/tessera-origin/tests/guard.rs::presentation_for_another_key_domain_is_rejected`.

## Why not one shared fleet key?

One shared ARC server key makes every exit a member of the same keyed-verifier
authority. That is the wrong trust boundary for independent exits.

- **Blast radius:** any compromised exit can forge credentials valid at every
  other exit, because the verifier key is also the minting key.
- **Verification oracle:** every exit can validate presentations for the whole
  fleet, not just its own traffic, turning a local operator into a fleet-wide
  credential oracle if presentations, logs, or probes cross its boundary.
- **Context partitioning:** ARC anonymity is per key and per
  `presentationContext`. A shared-key fleet gives a malicious or careless
  operator a wider surface for sparse-context and cohort partitioning mistakes.
- **Audit boundary:** one key forces all exits into one cryptographic trust
  domain. That is only honest if all exits are one operator / one enclave /
  one failure domain.
- **Rotation:** one leak requires rotating the whole fleet and invalidating every
  outstanding credential under that key.

The upside of one shared key is a larger anonymity set and simpler client
routing. That is not enough to justify giving every exit the same forge-and-
verify secret.

## Why per-exit key domains?

Per-exit domains make the trust boundary match the egress boundary.

- A compromised exit burns its own key domain, not the fleet.
- Issuer public-key pins identify the exit/key domain the client intended to use.
- Rotation is local to the affected exit.
- Tag stores and presentation contexts stay scoped to the egress that enforces
  them.
- The operational story is explainable: "this credential is for this exit's key
  domain."

The cost is real: anonymity sets are partitioned by exit key, so a low-traffic
exit has a smaller set. The mitigation is not to share the secret; it is to make
exit selection explicit, keep contexts coarse, publish key-domain/traffic
statistics where safe, and grow real usage.

## What about publicly verifiable BBS?

Publicly verifiable credentials would remove the verifier-secret sharing problem:
an issuer could sign, exits could verify with public keys, and a compromised exit
would not gain the minting secret. That is architecturally cleaner for a
large, independently operated fleet.

It is not the current product. Tessera's built and vector-tested primitive is ARC
(a KVAC), and the repo already states that presentations are not publicly
verifiable. Switching to BBS or another publicly verifiable anonymous credential
would be a new cryptographic track, new test vectors, new threat model, and a
fresh audit surface. Keep it as a future migration path, not a half-built claim.

## Implementation rule

For the code that exists today:

- `TESSERA_KEY_FILE` defines exactly one key domain.
- In a single-exit deployment, set the issuer and that exit to the same
  `TESSERA_KEY_FILE`.
- In a multi-exit deployment, never mount the same `TESSERA_KEY_FILE` into
  independent exits. Give each exit its own issuer/key file/key pin.
- A client must know which issuer public key / key domain it is minting for
  before routing to an exit.
- A future fleet router must treat key domain as a routing dimension, not as an
  implementation detail.

## Target decentralized fleet shape

The censorship-resistant product shape is not a central fleet verifier. It is a
replicated directory of independent exit key domains:

- Each exit domain publishes `exit_id`, relay address, exit address, issuer
  address, issuer public-key fingerprint, egress policy, capacity envelope, and
  attestation / operator metadata.
- Directory snapshots are signed and mirrored. Clients pin the directory signer
  set or a specific exit issuer key, then verify snapshots before routing.
- Path selection chooses an exit domain before issuance, obtains a credential for
  that domain's issuer key, and refuses routes that exceed the exit's advertised
  human-volume envelope.
- Health metrics are aggregate-only. No directory, relay, issuer, or exit stores
  `(presentation tag, exit_id, key_domain, destination, timestamp)` rows.
- Censorship resistance comes from many independently operated key domains plus
  replicated directory distribution, not from one shared secret.

This target needs new product code: signed directory snapshots, client-side
selection, key-domain-aware re-issuance, and distributed spent-tag consistency if
an exit domain ever has more than one verifier replica.

## Current status

Built here:

- Single-exit shared-key convergence (`ensure_shared_key`).
- Proxy key-domain lease: one local live exit per established key-file inode
  (including symlink/hardlink aliases; copied keys or other hosts are out of
  scope for a local advisory lock).
- Optional durable single-exit spent-tag file (`TESSERA_SPENT_TAG_FILE`) that
  fails closed on malformed ledger state or append/sync failure.
- Fail-fast key-file path validation on both issuer and proxy.
- Regression coverage that a presentation from one key domain is rejected by
  another.
- This decision record and cross-linked deployment docs.

Not built here:

- Fleet discovery.
- Client-side exit/key-domain selection UX.
- Multi-key issuer service.
- Key epoch negotiation / graceful multi-key rotation.
- Publicly verifiable credential migration.
