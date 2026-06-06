# Key management

> The ARC **server key** is the one secret the trust layer is built on. ARC is
> *keyed-verification* (KVAC): the same key that mints credentials also verifies
> them, so whoever holds it can both **forge** and **verify** — there is no
> public-key asymmetry to fall back on. This document is the lifecycle for that
> key: what it is, how the issuer and exit converge on one copy, how it is stored
> (file-based default vs. dstack-KMS-sealed), what rotation costs, and exactly
> what breaks if it leaks. Research-grade, **UNAUDITED**; the KMS-sealed path is
> a deployment upgrade, not the shipped default.
>
> Companion docs: key distribution in [`DEPLOY.md`](./DEPLOY.md), the
> verifier-trust model in [`THREAT_MODEL.md`](./THREAT_MODEL.md) §3.4–§3.5 and
> the rotation note in §"Key rotation", and the KVAC security argument in
> [`SECURITY_ARGUMENT.md`](./SECURITY_ARGUMENT.md).

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
identically on the issuer and the exit. That is the entire distribution problem,
and §3 solves it without ever sending the key over a socket.

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
issuer and the exit seed this from `OsRng` (`tessera-issuer/src/main.rs:294`;
in the proxy the `OsRng` is constructed at `tessera-proxy/src/main.rs:136` and
consumed by `setup(&mut rng)` at `tessera-proxy/src/main.rs:193`). There is no key-derivation-from-seed path in the
shipped code: a key is either freshly sampled or read back from disk.
`from_scalars` is the explicit-key constructor the §10.2 test vectors require;
production generation goes through `setup`, which samples four scalars and wraps
them via `from_scalars` (`keys.rs:66`).

If `TESSERA_KEY_FILE` is **unset/empty**, each binary samples its own ephemeral
key and there is no sharing — the exit self-issues to itself. This is the
single-node demo (`cargo run -p tessera-proxy` with no env), labeled "ephemeral
key (single-node only)" by the issuer. A multi-node deployment **must** set
`TESSERA_KEY_FILE`, or the exit's key will not match the issuer's and every
presentation fails `407` forever.

## 3. The convergent shared-key bootstrap (`ensure_shared_key`)

The issuer and exit must hold the **same** key. The shipped mechanism is
`tessera_issuer::ensure_shared_key(path)` in
`crates/tessera-issuer/src/keyfile.rs`, called by both binaries against the same
`TESSERA_KEY_FILE` (`tessera-issuer/src/main.rs:290`, `tessera-proxy/src/main.rs:192`).

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

### 4.2 dstack-KMS-sealed (the deployment upgrade — not yet wired)

The intended upgrade, documented in `DEPLOY.md` §2 and
`deploy/dstack/docker-compose.yaml`: in an Intel TDX enclave, **derive the shared
ARC key from the dstack KMS and seal it to the enclave** so it never lands on a
disk. The dstack guest-agent socket (`/var/run/dstack.sock`) is mounted into each
node for exactly this — quotes and KMS key derivation. With remote attestation a
client can verify the running node is exactly the open-source image before
trusting it; combined with KMS-sealed keys, the key is bound to an attested
measurement rather than to a readable file.

This is a **trust-axis** improvement (the relay/exit physically cannot be
modified to log or to exfiltrate the key), not a clean-IP improvement — a TDX
host is still a datacenter egress IP (`DEPLOY.md` "Honest limits").

**Status — not implemented.** `deploy/dstack/docker-compose.yaml` intentionally
wires only the relay and exit and **defers the issuer + shared-key bootstrap to
the KMS-sealed flow** (its header calls the asymmetry deliberate). The actual KMS
derivation is not in this tree: `DEPLOY.md` states "Wiring that KMS derivation is
the next step." Do not read the dstack compose as a working sealed-key deployment
today; it is the scaffold for one.

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

Mechanics in the shipped tooling: there is **no automated rotation / key-epoch
mechanism** — key-epoch negotiation on the wire is not built (the server key
carries no on-the-wire epoch identifier, so old and new keys cannot coexist), and
remains future work. To rotate today you replace the contents of `TESSERA_KEY_FILE`
(or, in a clustered file-based setup, delete it and let `ensure_shared_key`
mint+converge a fresh one on next start) and restart the issuer and exit so both
re-bootstrap on the new key. Because there is no on-the-wire epoch identifier,
old and new keys cannot coexist gracefully; rotation is a hard cutover, and
clients holding old credentials get `407` until they re-issue. The client already
auto-re-issues when a credential's budget is spent (`DEPLOY.md` §1), but it does
**not** currently negotiate a key epoch, so a rotation is operator-coordinated,
not transparent.

## 7. Operational checklist (S14)

- **Set `TESSERA_KEY_FILE` on issuer and exit to the same path** in any
  multi-node deployment; never leave it unset there (unset ⇒ divergent ephemeral
  keys ⇒ permanent `407`).
- **Treat the key file as MAC-key-grade secret.** It is plaintext at mode
  `0600`; control volume access, backups, and host-root reach accordingly.
- **Single trusted host / shared volume only** for the file-based path. For a
  real multi-host or TEE split, the KMS-sealed derivation (§4.2) is the intended
  answer and is **not yet wired** — know that gap before deploying across a trust
  boundary.
- **Any suspected leak ⇒ immediate rotation** (§6): replace the key, restart both
  nodes, retire the matching spent-tag store, accept that all outstanding
  credentials are invalidated.
- **Pin the issuer pk** (`TESSERA_ISSUER_PK`, the printed fingerprint) on clients
  so issuance can't be silently wormholed to a different key/issuer. It is
  **required** in paid mode (`DEPLOY.md:62`; the client refuses to start without
  it — `tessera-client/src/net.rs:133`) and **optional** in PoW mode
  (`DEPLOY.md:52`). Pinning it in PoW mode too is advisable operator hygiene, but
  that strength is this doc's guidance, not a repo-stated requirement.
