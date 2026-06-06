# Tessera - proof-of-work difficulty analysis (honest cost knob, not a Sybil gate)

> The `tessera-issuer` PoW gate makes obtaining a credential *cost CPU time*. This
> document is the honest accounting of what that buys and - more importantly -
> what it does **not**. It is research-grade and UNAUDITED. Every claim traces to
> code; the hash-rate figures are explicitly labeled illustrative assumptions, not
> measurements (see Sec 7 - a PoW benchmark now exists, but its output has not been
> tabulated here, so Sec 4's time table stays illustrative).

The one-line summary, taken straight from the crate's own doc-comment
([`crates/tessera-issuer/src/lib.rs`](../crates/tessera-issuer/src/lib.rs)) and
the threat model ([`docs/THREAT_MODEL.md`](./THREAT_MODEL.md), Sec 4.3): a PoW gate
is a **cost knob, not strong Sybil resistance**. It throttles bulk minting and
raises the price of a flood. It is not a per-human guarantee, and an adversary with
enough compute still scales. Treat the difficulty as the server's policy dial,
nothing more.

---

## 1. Why issuance needs a gate at all

ARC's rate limit bounds *presentations per credential*. It says nothing about *how
many credentials a single actor can obtain*. `create_credential_response` issues to
**anyone** whose blinded request verifies - so without a gate in front of issuance,
one actor mints unlimited credentials and the per-credential rate limit is
meaningless ([`THREAT_MODEL.md`](./THREAT_MODEL.md), Sec 4.3 and 6.3). The
abuse-control lever is therefore *who gets to obtain a credential*, and
`tessera-issuer` provides the simplest deployable version of that lever: a
hashcash-style proof of work the client must solve before the server will issue.

---

## 2. The construction (what the code actually computes)

This is hashcash over **SHA-256** - not keccak. (The issuer crate does also pull in
`sha3`/`k256`, but those are for the *paid-mint* ABI selectors and ecrecover in
[`mint.rs`](../crates/tessera-issuer/src/mint.rs), not for the PoW.) From
[`lib.rs`](../crates/tessera-issuer/src/lib.rs):

- A challenge is a random 16-byte nonce (`CHALLENGE_LEN = 16`) plus a `difficulty`
  in **leading zero bits**.
- The candidate digest for a counter is

      SHA-256( POW_DST || nonce || counter.to_be_bytes() )

  where `POW_DST = b"tessera-pow-v1"` is a domain separator so these hashes can
  never collide with another protocol's. The counter is a `u64`.
- `solve` brute-forces the counter from `0` upward, returning the first whose digest
  has at least `difficulty` leading zero bits (`leading_zero_bits` counts them byte
  by byte). `verify` recomputes one digest and checks the same predicate.
- Difficulty is **clamped to `0..=64`** in `PowChallenge::new` (a `u64` counter
  cannot reliably exhaust a search space wider than ~`2^64` anyway).

On the wire ([`net.rs`](../crates/tessera-issuer/src/net.rs), protocol
`tessera://issue-net/v1`), the server's `HELLO` carries `pk || difficulty(4, be) ||
nonce(16)`; the client replies with `counter(8, be) || CredentialRequest`. The nonce
is **fresh per connection**, so a solved challenge cannot be replayed onto another
connection. Server-side, `ChallengeStore` records outstanding nonces and `redeem`
consumes one on success, so each solved challenge admits **exactly one** issuance
(anti-replay, mirroring the presentation tag store).

---

## 3. Expected work, and the asymmetry that makes it worth doing

A uniformly random digest has each leading bit zero with probability `1/2`
independently, so the probability a single guess clears `d` leading zero bits is
`2^-d`. The number of guesses until the first success is geometric with mean `2^d`:

- **Client solve cost:** expected `~2^difficulty` hashes. Exponential in `d`. (The
  worst case is unbounded; the *expected* and median costs are what matter, and the
  median is `~0.69 * 2^d`.)
- **Server verify cost:** **exactly one** SHA-256 hash, regardless of `d`. O(1).

That asymmetry is the whole point. The server spends a single hash to check work the
client spent `~2^d` hashes to produce. Verification cost does not grow with the
difficulty dial, so the server can crank `d` without paying for it - the cost lands
entirely on whoever wants the credential. (The networked issuer additionally caps
in-flight connections and applies socket timeouts so that *un*solved or slow-rolled
connections can't exhaust it before the PoW is even checked - see
[`docs/ABUSE_MODEL.md`](./ABUSE_MODEL.md) row 5; that is a separate DoS lever from
the PoW cost itself.)

---

## 4. What difficulty 16 (the default) costs

The default is `DEFAULT_DIFFICULTY = 16` ([`main.rs`](../crates/tessera-issuer/src/main.rs),
also the floor `MIN_DIFFICULTY = 1` and the env override below). Difficulty 16 means
`~2^16 = 65,536` expected hashes per credential.

To turn hashes into wall-clock time you need a hash rate, and **this repo does not
measure one** (see Sec 7). The table below is purely illustrative arithmetic at a
few *assumed* single-thread SHA-256 rates for this tiny ~38-byte input (`POW_DST`
14 B + nonce 16 B + counter 8 B); real numbers
depend on CPU, SIMD, and whether the client parallelizes. Read these as orders of
magnitude, not as benchmarks.

| difficulty `d` | expected hashes `2^d` | @ ~1 M h/s (assumed weak/mobile) | @ ~5 M h/s (assumed laptop, single thread) |
|---|---|---|---|
| 12 | ~4.1 K | sub-ms | sub-ms |
| **16 (default)** | ~65.5 K | ~tens of ms | ~ms |
| 20 | ~1.05 M | ~1 s | ~0.2 s |
| 24 | ~16.8 M | ~17 s | ~3 s |
| 28 | ~268 M | ~4-5 min | ~1 min |

The takeaway is structural, not numeric: difficulty 16 is a *small* per-credential
tax - fractions of a second on a normal machine. That is deliberate. It is sized to
be invisible to a human obtaining one credential while making bulk minting visibly
expensive (next section), **not** to be individually painful. Each `+1` to `d`
doubles the client's cost and leaves the server's verify cost unchanged.

---

## 5. Attacker economics: cost to mint N credentials

To mint `N` credentials an attacker pays `~N * 2^difficulty` hashes total (each
credential needs its own fresh challenge solved - challenges are single-use). The
gate is therefore *linear* in `N`: it imposes a per-unit price, it does not impose a
hard ceiling. Concretely, at difficulty 16, minting 1,000,000 credentials costs
`~10^6 * 2^16 ~= 6.6e10` hashes - seconds-to-minutes of aggregate compute on a
single modern multi-core box, and far less on a GPU/ASIC farm. That is exactly the
honest limitation: PoW raises the *slope* of the attacker's cost curve, but a
well-resourced adversary buys their way up it.

Two consequences worth stating plainly:

1. **It throttles, it does not stop.** A botnet or a GPU farm amortizes PoW cheaply.
   The defense is real against a *casual* bulk minter and useless against a
   *funded* one. If you need an actual cap, gate issuance on something with a real
   marginal cost or a real scarcity: the shipped **payment-gated mint**
   ([`mint.rs`](../crates/tessera-issuer/src/mint.rs), one credential per on-chain
   `TokenMint` purchase), an attestation, or a one-per-person credential (the latter
   two remain future work - [`GOAL.md`](../GOAL.md), "Deliberately deferred").
2. **It is regressive.** The cost is borne in CPU time, so it penalizes low-power
   and battery-constrained clients (phones, embedded, anything behind Tor on weak
   hardware) far more than it penalizes an attacker's datacenter. A difficulty that
   is "a second" on a laptop can be tens of seconds on a phone. This unfairness is
   inherent to PoW and is one of the main reasons it is not a per-human gate.

---

## 6. The honest limit (read this before you ship a difficulty)

PoW here is a **cost knob, not Sybil resistance, and not an identity check.** It
buys exactly one thing - *each credential costs CPU* - and that one thing has the
boundaries above:

- It makes bulk minting cost `~N * 2^d` hashes (good against casual floods).
- It does **not** bound how many credentials one human (or one funded adversary)
  can obtain; compute scales, ASICs/GPUs scale, the curve is linear.
- It is **not fair** across client hardware.
- It provides **no** per-person guarantee. "One PoW solved" is not "one human."

Anyone treating the PoW gate as Sybil resistance has made a deployment error
([`THREAT_MODEL.md`](./THREAT_MODEL.md), Sec 4: "Sybil control lives at issuance,
and Tessera does not provide it"). The difficulty is a policy dial for *throttling*,
and should be documented as such to operators.

---

## 7. On the (un-tabulated) measured numbers

A Criterion PoW benchmark now exists at
[`crates/tessera-issuer/benches/pow.rs`](../crates/tessera-issuer/benches/pow.rs)
(declared as `[[bench]]` in the issuer's `Cargo.toml`). It measures `solve` at
difficulties `8 / 12 / 16` (the client cost) and the single-hash `verify` (the
server cost). Run it with `cargo bench -p tessera-issuer`. The sibling
[`crates/tessera-arc/benches/arc.rs`](../crates/tessera-arc/benches/arc.rs) covers
ARC issuance/presentation/verification, not the PoW hash loop. So, to stay honest:

- The Sec 4 *time* table is **not** populated from that bench - it is still
  illustrative arithmetic at *assumed* hash rates, and bench output is in any case
  machine-specific. Every hash-rate / wall-clock figure in Sec 4 is an **assumed**
  rate plugged into `2^d`, not a measurement. The *hash-count* arithmetic (`2^d`,
  `N * 2^d`) is exact; the *time* conversions are not grounded in this codebase.
- **Recommended:** run `cargo bench -p tessera-issuer` on the target hardware and
  replace Sec 4's illustrative table with the resulting machine-tagged `solve` /
  `verify` numbers. Until that is done, the table stays labeled as illustrative.

---

## 8. Recommended difficulty range and the knobs

**Recommended range: ~16-22 leading zero bits for an interactive web client.**

- Below ~12, the work is negligible and the gate is near-cosmetic.
- ~16 (the default) is a near-invisible tax on a normal machine and a meaningful
  per-unit cost at flood scale - a reasonable starting point.
- ~20-22 starts to be noticeable (order of a second on a laptop, several on a
  phone), pushing the regressive-cost problem (Sec 5) toward unacceptable for
  low-power clients. Past ~24 you are taxing legitimate users harder than you are
  deterring a funded attacker - at which point switch abuse-control levers
  (payment/attestation) rather than turning the dial higher.

**The knobs (all in [`tessera-issuer`](../crates/tessera-issuer/)):**

| Knob | Where | Effect |
|---|---|---|
| `TESSERA_POW_DIFFICULTY` | env, read in [`main.rs`](../crates/tessera-issuer/src/main.rs) | Per-credential difficulty (leading zero bits). Default `16`. A bad parse **fails fast** rather than silently disabling the gate. |
| `MIN_DIFFICULTY = 1` | [`main.rs`](../crates/tessera-issuer/src/main.rs) | Floor enforced by the binary (`difficulty.max(MIN_DIFFICULTY)`): a configured `0` is silently raised to `1`, so the gate is never left wide open, since `0` makes every solution valid. |
| `0..=64` clamp | `PowChallenge::new` in [`lib.rs`](../crates/tessera-issuer/src/lib.rs) | Hard ceiling at mint time; a `u64` counter cannot reliably search beyond `~2^64`. |
| Fresh per-connection nonce | `handle_issuance` in [`net.rs`](../crates/tessera-issuer/src/net.rs) | A solved challenge can't be replayed onto another connection. |
| `ChallengeStore` (issue/redeem) | [`lib.rs`](../crates/tessera-issuer/src/lib.rs) | One issuance per solved challenge (anti-replay). In-memory by default - a real deployment must persist it. |

Tune the difficulty to your *throttling* goal, watch the low-power-client tax, and
when you need an actual per-actor bound reach for payment or attestation - not a
bigger exponent.

---

### See also

- [`crates/tessera-issuer/src/lib.rs`](../crates/tessera-issuer/src/lib.rs) - the PoW impl and its own doc-comments (source of truth).
- [`docs/THREAT_MODEL.md`](./THREAT_MODEL.md), Sec 4 and 6 - issuance Sybil control as a non-goal; the "cost knob, not Sybil resistance" framing.
- [`GOAL.md`](../GOAL.md) - "Deliberately deferred": PoW shipped + scoped, payment-gated mint shipped, attestation/one-per-person deferred.
- [`docs/ABUSE_MODEL.md`](./ABUSE_MODEL.md) row 5 - the issuer's connection-level DoS mitigations (distinct from PoW cost).
- [`docs/PERFORMANCE.md`](./PERFORMANCE.md) - the project's "research-grade, order-of-magnitude" numbers convention this doc follows.
