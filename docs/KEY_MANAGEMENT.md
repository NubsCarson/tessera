# Key management

> The ARC **server key** is the one secret the trust layer is built on. ARC is
> *keyed-verification* (KVAC): the same key that mints credentials also verifies
> them, so whoever holds it can both **forge** and **verify** — there is no
> public-key asymmetry to fall back on. This document is the lifecycle for that
> key: what it is, how the issuer and exit converge on one copy, how it is stored
> (file-based default vs. dstack-KMS-sealed), what rotation costs, and exactly
> what breaks if it leaks. For more than one independent exit, the rule is
> explicit: **one ARC key domain per exit, never one shared fleet-wide key**.
> Research-grade, **UNAUDITED**; the KMS-sealed path is a deployment upgrade, not
> the shipped default.
>
> Companion docs: key distribution in [`DEPLOY.md`](./DEPLOY.md), the
> verifier-trust model in [`THREAT_MODEL.md`](./THREAT_MODEL.md) §3.4–§3.5 and
> the rotation note in §"Key rotation", and the KVAC security argument in
> [`SECURITY_ARGUMENT.md`](./SECURITY_ARGUMENT.md). The multi-exit custody
> decision record is [`KEY_CUSTODY_DECISION.md`](./KEY_CUSTODY_DECISION.md).

## 1. What the key is

The server key is an ARC key pair (`draft-ietf-privacypass-arc-crypto-01` §4.1),
defined in `crates/tessera-arc/src/keys.rs`:

- **`ServerPrivateKey`** — four secret P-256 scalars
  `(x0, x1, x2, x0_blinding)`. `x0/x1/x2` are the algebraic-MAC keys over the
  constant term and the `m1`/`m2` attributes; `x0_blinding` blinds `x0` under the
  second generator `H` and is what supplies issuance unlinkability (spec §7.2).
  Serialized by `serialize()` as exactly `4 * group::NS = 128` bytes
  (`x0 ‖ x1 ‖ x2 ‖ x0Blinding`, each a 32-byte big-endian scalar). This is the
  on-disk form.
- **`ServerPublicKey`** — three group elements `(X0, X1, X2)` derived by
  `public_key()` as `X0 = x0·G + x0Blinding·H`, `X1 = x1·H`, `X2 = x2·H`.
  Serialized as `3 * group::NE = 99` bytes. The issuer prints the first 8 bytes
  as a fingerprint (`tessera-issuer/src/main.rs:301`); the client can pin it via
  `TESSERA_ISSUER_PK`.

The private key never needs to be transmitted on the wire — it only has to exist
identically on the issuer and the exit **inside one key domain**. That is the
single-exit distribution problem, and §3 solves it without ever sending the key
over a socket. It is not permission to reuse one key across every future exit.

### Defensive handling in the type

`ServerPrivateKey` is built to keep the scalars out of incidental disclosure
(`keys.rs:33-50`):

- `Debug` is **redacted** — it prints `ServerPrivateKey(<redacted>)`, so the
  scalars can never land in a log line or panic message by accident.
- `Drop` **zeroizes** all four scalars (via the `p256`/`zeroize` integration),
  a best-effort defense against later memory/swap disclosure.

These reduce accidental in-process leakage; they do not protect the key once it
is written to disk in the file-based path (§4).

## 2. Generation

A fresh key pair comes from `ServerPrivateKey::setup(rng)` (`keys.rs:65`), the
spec's `SetupServer()` — four `random_scalar` draws from a CSPRNG. Both the
issuer and the exit seed this from `OsRng` (`crates/tessera-issuer/src/main.rs`
and `crates/tessera-proxy/src/main.rs`). There is no key-derivation-from-seed
path in the shipped code: a key is either freshly sampled or read back from
disk.
`from_scalars` is the explicit-key constructor the §10.2 test vectors require;
production generation goes through `setup`, which samples four scalars and wraps
them via `from_scalars` (`keys.rs:66`).

If `TESSERA_KEY_FILE` is **unset**, each binary samples its own ephemeral
key and there is no sharing — the exit self-issues to itself. A present-but-empty
proxy value is a config error, because silently downgrading a configured exit to
an ephemeral key is unsafe. This is the
single-node demo (`cargo run -p tessera-proxy` with no env), labeled "ephemeral
key (single-node only)" by the issuer. A multi-node deployment **must** set
`TESSERA_KEY_FILE`, or the exit's key will not match the issuer's and every
presentation fails `407` forever.

## 3. The convergent shared-key bootstrap (`ensure_shared_key`)

The issuer and exit inside one key domain must hold the **same** key. The shipped
mechanism is
`tessera_issuer::ensure_shared_key(path)` in
`crates/tessera-issuer/src/keyfile.rs`, called by both binaries against the same
`TESSERA_KEY_FILE` (`crates/tessera-issuer/src/main.rs` and
`crates/tessera-proxy/src/main.rs`).

It is **single-winner and convergence-guaranteed** by design — it does not rely
on the issuer starting before the exit, and it tolerates any startup ordering or
race. The loop (up to 600 iterations × 100 ms ≈ 60 s):

1. **Adopt an existing key (the common case).** If `path` reads back as a valid
   `ServerPrivateKey::from_bytes`, return it. If the file exists but is not yet a
   valid key (a partial write by some non-atomic external tool), the code
   **waits and re-reads** rather than clobbering it.
2. **Try to become the single creator.** With no key present, sample a fresh key,
   write it to a **process-unique temp** (`{path}.{pid}.{seq}.tmp`, opened
   `create_new(true)` = `O_EXCL`, `chmod 0600` on unix), then publish it onto
   `path` with `std::fs::hard_link`. `hard_link` **fails atomically if the target
   already exists** — so exactly one process can ever create `path`. The winner
   removes its temp and returns its key; every loser removes its temp and loops
   back to step 1 to adopt the winner's key.

There is no last-writer-wins window, so the issuer and exit can never diverge.
The per-call `TMP_SEQ` counter makes each attempt's temp unique even across
threads in one process (pid alone collides), so a writer only ever touches its
own temp. Two in-tree tests assert the guarantee:
`second_node_adopts_the_first_nodes_key` and `racing_nodes_never_diverge`
(eight simultaneous starters must all agree on one public key).

If ~60 s pass with neither a readable key nor a successful create, the path is
unusable (bad mount or permissions) and the function **panics rather than fork a
divergent key** — failing loudly is the correct behavior, since a divergent key
silently `407`s every client.

> Mechanism note: convergence depends on `hard_link`'s exclusive-create
> semantics holding on the underlying filesystem. On a standard local FS or a
> Docker named volume (the shipped `deploy/docker-compose.yaml` mounts
> `tessera-key:/keys` into both issuer and exit) this holds. On filesystems
> where hard links are unsupported or non-atomic, the single-winner property is
> not guaranteed — another reason the KMS-sealed path (§4.2) is the real
> multi-host answer.

### 3.1 One `TESSERA_KEY_FILE` is one key domain

`TESSERA_KEY_FILE` defines a single ARC key domain: one issuer authority and the
exit that verifies credentials minted by that authority. That is correct for the
single-exit topology.

For a multi-exit network, **repeat the domain per exit**. Do not mount one
fleet-wide `TESSERA_KEY_FILE` into independent exits. A shared fleet key would
make every exit a holder of the minting-and-verification secret for every other
exit: any compromised exit can forge fleet-valid credentials, every exit becomes
a verification oracle for fleet presentations that cross its boundary, and one
rotation event invalidates the whole fleet.

The accepted multi-exit shape is:

```text
issuer-a + exit-a  ->  key-domain A  ->  /keys/exit-a.arc
issuer-b + exit-b  ->  key-domain B  ->  /keys/exit-b.arc
issuer-c + exit-c  ->  key-domain C  ->  /keys/exit-c.arc
```

That partitions anonymity sets by exit key. This is a real trade-off, but it is
the safer one: blast radius and audit scope stay local to an egress domain. If a
future product needs one issuer with many independently operated public
verifiers, that is the BBS/public-verifiability track described in
[`KEY_CUSTODY_DECISION.md`](./KEY_CUSTODY_DECISION.md), not the current ARC
deployment.

For client routing, the built path is either direct pinning
(`TESSERA_ISSUER_PK`) or signed-directory mode. In directory mode the client pins
a directory signer set (`TESSERA_DIRECTORY_SIGNERS`), verifies a signature
threshold and validity window over a snapshot, optionally records a monotonic
sequence, snapshot hash, and per-exit key epoch in
`TESSERA_DIRECTORY_STATE_FILE`, selects one accepting non-exhausted exit entry,
and uses that entry's full ARC issuer public key as the issuance pin. That is a
local verification layer; running a mirrored directory publisher and real
operator governance is still deployment work.

## 4. Storage: file-based default vs. dstack-KMS-sealed

### 4.1 File-based (the shipped default)

In `deploy/docker-compose.yaml` both the issuer and exit set
`TESSERA_KEY_FILE: /keys/server.key` and mount the same `tessera-key` named
volume. The exit has `depends_on: issuer`, so the issuer typically wins the
`hard_link`, writes the 128-byte key at mode `0600` first, and the exit then
adopts it. Either node can win the race; per §3 they converge regardless of
order. This is correct and convenient **on a single trusted host / shared
volume**, and `DEPLOY.md` says so explicitly ("Key distribution is file-based
here … fine on a trusted host / shared volume").

Its honest limits:

- The key is **plaintext on disk**. `0600` and the redacted `Debug`/zeroizing
  `Drop` reduce accidental exposure, but anyone with the volume, a host-root
  shell, a backup of the volume, or filesystem access reads the key directly —
  and that is a full compromise (§5).
- It assumes both nodes can see one filesystem. A genuine **multi-host** split
  (issuer and exit on different machines, the intended split-trust topology) has
  no shared volume to converge on, so file-based distribution does not extend to
  it cleanly.

### 4.2 dstack-KMS-sealed (reserved provider — real client not wired)

The intended upgrade, documented in `DEPLOY.md` §2 and
`deploy/dstack/docker-compose.yaml`: in an Intel TDX enclave, **derive the shared
ARC key from the dstack KMS and seal it to the enclave** so it never lands on a
disk. The dstack guest-agent socket (`/var/run/dstack.sock`) is mounted into each
node for quote/attestation plumbing and future KMS key derivation. With remote
attestation a client can verify the running node is exactly the open-source
image before trusting it; combined with KMS-sealed keys, the key is bound to an
attested measurement rather than to a readable file.

This is a **trust-axis** improvement under dstack/TDX attestation assumptions
(clients can verify the expected image before trusting it), not a clean-IP
improvement — a TDX host is still a datacenter egress IP (`DEPLOY.md` "Honest
limits").

**Status — implemented, but proven only off-silicon.** All three providers
(`TESSERA_KEY_PROVIDER=ephemeral|file|dstack-kms`) are implemented. `dstack-kms`
requires `TESSERA_DSTACK_KMS_KEY_ID` and derives the ARC server key from the dstack
guest agent (`POST /GetKey` over `/var/run/dstack.sock`, expanded into the key via
a SHAKE256-seeded `SetupServer()`; `crates/tessera-issuer/src/dstack_kms.rs`),
sealed to the enclave and never on disk. It is a std-only client (no
SDK/async/protobuf) and **fails closed** off-TEE — `preflight` errors if the
guest-agent socket is unreachable. It is validated against a faithful in-process
mock and the official dstack **simulator**; it has **not** been proven against real
Intel TDX hardware + a live KMS, so treat a simulator/mock-derived key as carrying
**no** security guarantee. `deploy/dstack/docker-compose.yaml` wires the exit to
this provider but still omits the issuer; standing up a real attested deployment
needs a TDX host (see [`DEPLOY.md`](./DEPLOY.md) §2).

## 5. What breaks if the key leaks

Because ARC is keyed-verification, the server private key is **both the minting
key and the verification key**. There is no public-key separation: holding it
confers total control. A leak is unconditionally catastrophic:

- **Forgery.** With `(x0, x1, x2, x0_blinding)` an attacker runs the issuer side
  (`create_credential_response`) and mints unlimited valid credentials without
  paying the PoW or on-chain `TokenMint` gate. The issuance gate — which
  `THREAT_MODEL.md` §"The issuance gate is the real abuse-control lever" calls
  the *only* real abuse-control lever — is bypassed entirely.
- **Verification / impersonation.** The leaker can stand up a verifier that
  accepts those forged credentials, or impersonate the legitimate exit's
  verification.
- **No unforgeability for anyone.** `THREAT_MODEL.md` §"Key rotation" states it
  plainly: "Protect the private key as any MAC key — its compromise breaks
  unforgeability for everyone." Every credential under that key is suspect; the
  entire anonymity set defined by the key is poisoned at once.

What a leak does **not** do: it does not retroactively de-anonymize past honest
presentations purely from the key — issuance/presentation unlinkability is a
property of the protocol's blinding, not a secret the verifier could "decrypt"
with the key. The realistic de-anonymization vector remains operational (context
partitioning, §3.4), not key recovery. But the leak destroys the credential's
*integrity* completely, which is the property the whole trust layer rests on, so
treat any suspected leak as a mandatory immediate rotation (§6).

This asymmetry-free posture is also why the file-based default is only "fine on a
trusted host": the threat that the KMS-sealed path closes is precisely "an
operator or host-root can read the one key that forges-and-verifies everything."

## 6. Rotation

Rotation is **cheap mechanically and expensive semantically**, because the server
key *defines the anonymity set*: all credentials minted under one key are
mutually anonymous (`THREAT_MODEL.md` §7.3). The consequences
(`THREAT_MODEL.md` §"Key rotation"):

- **Rotating partitions the anonymity set** and **invalidates every outstanding
  credential** — they no longer verify under the new key. So rotation is not a
  silent operation: clients must re-obtain credentials.
- **Carry/retire the tag store in lockstep.** The spent-tag store (replay
  defense) is scoped to the key+context; on rotation, re-issue and retire the old
  store together. Rotating the key is in fact the *intended* way to bound
  spent-tag storage growth — `THREAT_MODEL.md` says to bound storage "by rotating
  keys/context, not by dropping live tags," since premature eviction is silent
  over-presentation.

Mechanics in the shipped tooling: the signed exit directory carries a per-entry
`key_epoch`, clients can persist it in `TESSERA_DIRECTORY_STATE_FILE`, and
operators can require a floor with `TESSERA_DIRECTORY_MIN_KEY_EPOCH`. That
prevents stale directory/key-domain rollback. It is **not** a dual-key wire
rotation protocol: the ARC presentation itself carries no on-the-wire epoch
identifier, so old and new keys cannot coexist gracefully. To rotate today you
replace the contents of `TESSERA_KEY_FILE` (or delete it and let
`ensure_shared_key` mint+converge a fresh one on next start), publish a signed
directory with a higher `key_epoch`, and restart the issuer and exit so both
re-bootstrap on the new key. Clients holding old credentials get `407` until
they re-issue.

## 7. Operational checklist (S14)

- **Set `TESSERA_KEY_FILE` on issuer and exit to the same path** in any
  single-exit multi-node deployment; never leave it unset there (unset ⇒
  divergent ephemeral keys ⇒ permanent `407`).
- **For multi-exit deployments, use one key file per independent exit domain.**
  Never share one fleet-wide ARC key across exits unless they are honestly one
  operator / one enclave / one failure domain.
- **Treat the key file as MAC-key-grade secret.** It is plaintext at mode
  `0600`; control volume access, backups, and host-root reach accordingly.
- **Single trusted host / shared volume only** for the file-based path. For a
  real multi-host or TEE split, the `dstack-kms` provider (§4.2) derives the key
  from the dstack guest agent instead — implemented and fail-closed off-TEE, but
  proven only against a mock/simulator, **not** real TDX hardware. Know that gap
  before deploying across a trust boundary.
- **Any suspected leak ⇒ immediate rotation** (§6): replace the key, restart both
  nodes, retire the matching spent-tag store, accept that all outstanding
  credentials are invalidated.
- **Pin the issuer pk** (`TESSERA_ISSUER_PK`, the printed fingerprint) on clients
  so issuance can't be silently wormholed to a different key/issuer. It is
  **required** in paid mode (`DEPLOY.md:62`; the client refuses to start without
  it — `tessera-client/src/net.rs:133`) and **optional** in PoW mode
  (`DEPLOY.md:52`). Pinning it in PoW mode too is advisable operator hygiene, but
  that strength is this doc's guidance, not a repo-stated requirement.
