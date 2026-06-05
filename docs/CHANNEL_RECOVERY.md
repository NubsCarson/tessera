# Channel-State Durability & Recovery (optional-advanced tier)

Status: research-grade, **UNAUDITED**, ETH **testnet-only**. This is the durability/recovery
model for the **optional-advanced channel tier** — the ZK Spilman channel
(`tessera-channel`) plus its EVM court (`contracts/src/ChannelRegistry.sol`).

Per [`docs/ARCHITECTURE.md`](ARCHITECTURE.md), the channel + court + ZK settlement are
**demoted to optional-advanced (kept, documented, NOT deleted)**. The default Tessera
path is **ecash-token + Tor + traffic-shaping**, which has *no channel, no refund, no
dispute window, no watchtower, and no on-chain court*. Everything below applies **only**
to a deployer who opts into the channel tier; none of it is on the default access path.

This document closes SHOULD item **S12** ("Channel-state durability/recovery model (doc)")
in [`docs/CEILING_PROGRESS.md`](CEILING_PROGRESS.md).

## What "state" is

A channel state is exactly four fields (`state.rs`, `ChannelState`):

```text
ChannelState { chan_id: [u8;32], balance: u64, seq: u64, salt: [u8;32] }
```

The on-the-wire unit of truth is not the struct but its **commitment**
`S_i = SHA256("tessera-channel/state/v1" || chan_id || balance || seq || salt)`
(`ChannelState::commitment`). Parties do not sign the struct; they sign a digest folded
over that commitment — the *chain-facing* `keccak256` digest
`ChannelState::state_digest` (`= keccak256(len || "tessera-channel/state-sig/v1" || S_i)`),
recoverably with secp256k1 so the court can `ecrecover` the signer. A signature therefore
binds to **exactly one** state.

The "unit of truth" for settlement is a **`SignedState`** carrying *both* signatures
(`state.rs`, `SignedState`): `sig_user` (present the moment the user emits a spend) and
`sig_relayer` (present once the relayer co-signs). `SignedState::is_doubly_signed`
re-verifies both over `state_digest`. Settlement and the court only ever count
doubly-signed states.

The transition is **monotone-decrementing** by construction (`ChannelState::spend`:
`balance -= cost`, `seq += 1`, same `chan_id`/`salt`), and any wire-supplied successor is
re-checked by `ChannelState::is_successor_of` (same chan_id, same salt, `seq == prev+1`,
`balance <= prev.balance`). This monotonicity is what makes recovery tractable: an older
state always has a *higher* balance and pays the relayer *less*, so the question "is my
saved state stale?" reduces to a `seq` comparison.

## What each party must persist

The crate models the live channel as in-memory cursors. There is **no serialization, no
disk I/O, and no `serde` in `tessera-channel`** — persistence is deliberately the caller's
responsibility (the crate is the protocol state machine, not a wallet). A deployer of this
tier MUST persist the following, durably (e.g. fsync'd before acting on it):

**User side** (`channel.rs`, `UserChannel`):
- The signing key (`KeyPair`) and the channel parameters (`Channel`: `chan_id`, `b0`,
  `salt`, `user_pk`, `relayer_pk`). Parameters are also recoverable from the on-chain
  `Opened` event.
- **`latest`** — the cursor: the most recent state the user treats as authoritative. It
  starts at genesis `S_0` (`UserChannel::new`) and only advances inside
  `UserChannel::accept_cosigned`, i.e. **only after** the user has verified the relayer's
  co-signature over the same state. Critically, the *latest doubly-signed `SignedState`
  itself* (both sigs) is what must survive a crash — not merely the `(balance, seq)` tuple
  — because both signatures are needed to close, dispute, or feed the watchtower.

**Relayer side** (`channel.rs`, `RelayerChannel`):
- The signing key and parameters, as above.
- **`latest`** — the single in-memory co-signed cursor. This is the design's "single
  in-memory cursor that collapses distributed double-spend": the relayer co-signs and
  advances `latest` inside `verify_and_cosign`, and the next spend must be a successor of
  it. Two co-signers (or one co-signer that forgets `latest`) re-introduce the
  double-spend the crate exists to rule out.
- **`epoch`** and **`seen_nonces`** — the freshness/replay state. `seen_nonces` is the set
  of per-epoch nonces already consumed (replay defense, bounded at
  `MAX_NONCES_PER_EPOCH = 1024`); `advance_epoch` clears it and bumps `epoch`.

**Watchtower** (`watchtower.rs`, `Watchtower`):
- **`best`** — the highest-`seq` doubly-signed `SignedState` it has been shown
  (`Watchtower::witness`), plus the channel parameters. This is the only state the tower
  needs to challenge a stale close.

The most safety-critical single object to persist is the **latest doubly-signed
`SignedState`**: it is sufficient to cooperatively close, to start or win a unilateral
dispute, and to seed a watchtower. Losing it (but keeping an *older* one) is a recoverable
loss of revenue/refund, not a loss of safety (see Failure modes).

## Crash / restart: can a party recover its latest signed state?

The protocol is **monotone and gap-free** (`is_successor_of` enforces `seq == prev+1`),
so recovery is "reload the highest doubly-signed state you persisted and resume from it."

- **Recover the persisted cursor:** reconstruct `UserChannel`/`RelayerChannel` with the
  saved keys + params, then set the cursor to the persisted latest doubly-signed state.
  (The crate's constructors start at genesis; a deployer that persists `latest` re-seats it
  after load. The crate intentionally exposes no `from_persisted` constructor — that
  glue is the wallet's, kept out of the protocol core.)
- **The persist-then-act ordering is what makes restart safe.** The cursor only advances
  *after* the counterparty signature is in hand (`accept_cosigned` for the user,
  `verify_and_cosign` for the relayer). A deployer MUST persist the new doubly-signed
  state **before** acting on it (the user before serving; the relayer before forwarding the
  packet / issuing a `RelayAck`). Then a crash at any point leaves the persisted state
  either equal to or one step behind the true latest — never *ahead* of a state the
  counterparty can prove. Recovering "one behind" is safe: an older state is simply a
  higher-balance state, and the counterparty (or watchtower) holds the newer one.
- **In-flight spend lost on crash:** if the user emits a spend and crashes before
  persisting/receiving the co-signed reply, the user safely remains on the last persisted
  doubly-signed state (`spend` does not advance the cursor — only `accept_cosigned` does).
  No money is at risk; at worst one request is lost.
- **Freshness state on relayer restart:** if the relayer loses `seen_nonces` but keeps the
  monotone `latest`, replay within the lost epoch is *not* re-detected by the nonce set —
  but a replayed spend is still rejected because it is not a `seq`-successor of `latest`
  (the balance cursor is the backstop). The clean recovery is to call `advance_epoch` to a
  fresh epoch on restart, which is exactly the in-place epoch authority of
  [`docs/EPOCH_AUTHORITY.md`](EPOCH_AUTHORITY.md): the new epoch invalidates any old
  freshness binding and resets the budget. Persisting `epoch` lets the relayer pick a
  strictly-greater value.

## The watchtower's role

The watchtower (`watchtower.rs`) defends the **one residual offline risk: a stale
unilateral close.** The court lets either party start a unilateral close at *any*
doubly-signed state and opens a fixed challenge window in which the counterparty may
override it with a **strictly-higher-`seq`** doubly-signed state. Because the channel is
monotone-decrementing, a stale close is an attempt to under-pay the relayer (or claw back
spent funds). If the disadvantaged party is offline for the whole window, the stale state
settles.

The module is the **pure decision core**, not the plumbing:
- `Watchtower::witness(state)` adopts a state as the new `best` iff it is for this channel
  (`chan_id` + `salt`), `balance <= b0`, genuinely doubly-signed by both registered
  parties, and **strictly newer** (`seq >` current best).
- `Watchtower::on_dispute_started(disputed_seq)` returns
  `WatchtowerAction::Challenge(best)` iff `best.seq > disputed_seq`, else
  `NoAction`. This mirrors the court's `challenge` precondition
  (`state.seq > bestSeq`, `balance <= b0`, both sigs valid), so any `Challenge` the tower
  emits satisfies the court's precondition **relative to the disputed `seq` it observed**.
  (The on-chain `bestSeq` can be advanced mid-window by a *prior* `challenge`
  (`ChannelRegistry.sol` `challenge` sets `ch.bestSeq = state.seq`), so a tower emitting
  against `disputed_seq` is guaranteed acceptable against that observed seq, not
  unconditionally against a concurrently-raised `bestSeq` — a benign race the deployer's
  live wrapper, below, resolves by acting promptly and re-deciding on the current dispute
  state.)

The decision is role-agnostic — the relayer, the user, or a delegated third party can run
it (its logic is identical in all three), which is why it lives as one component. The
**live wrapper is explicitly out of scope here**: polling the chain for the
`DisputeStarted` event, signing, and broadcasting the `challenge` transaction **before
`challengeEnd`** needs an RPC endpoint and a funded key — an operational integration, not
protocol logic. The caller MUST act within the court's `CHALLENGE_WINDOW`. A watchtower
that crashes need only re-witness states up to its `best` (or be fed the persisted latest
doubly-signed state) to be functional again.

## Unilateral close + challenge windows (the on-chain court)

`ChannelRegistry.sol` is the EVM court that actually moves funds (UNAUDITED, testnet-only).
The relevant terminal paths:

- **`unilateralClose(state, userSig, relayerSig)`** — either party starts a close at a
  doubly-signed state (it requires *both* signatures, which only honest cooperation could
  produce). Sets `status = Disputing`, records `bestSeq`/`bestBalance`, and opens
  `challengeEnd = block.timestamp + CHALLENGE_WINDOW`. **`CHALLENGE_WINDOW = 1 days`.**
- **`challenge(state, …)`** — during the window (`block.timestamp <= challengeEnd`),
  override with a **strictly-higher-`seq`** doubly-signed state (`state.seq > bestSeq`).
  This is the path the watchtower drives. The latest truth wins.
- **`settleDispute(channelId)`** — after the window closes (`block.timestamp >
  challengeEnd`), settle at the highest doubly-signed state seen: relayer gets
  `B0 - bestBalance`, user gets `bestBalance`.
- **`cooperativeClose(state, …)`** — the happy path: a doubly-signed final state settles
  immediately with no window, paying relayer `B0 - balance` and refunding user `balance`.
- **`cooperativeCloseZK(…)`** — the Phase 2b-i settlement-privacy path: settle against an
  `R_dec` Groth16 proof with *no cleartext balance in calldata*. Per its own contract docs
  this is **cooperative only** (both parties co-sign the Poseidon commitment `C_next`); a
  fully unilateral ZK dispute is a documented follow-up, not built. Recovery for the ZK
  path requires persisting the Poseidon-bound signed state (`zk_state_digest`), not the
  cleartext one.
- **`refundOnTimeout(channelId)`** — the **payer-safety backstop**: after the channel's
  `timeout` with the channel still `Open` (relayer went dark), the user reclaims the full
  escrow `B0`. This is the recovery path that does **not** depend on holding any
  post-genesis state at all.

Provable equivocation is punished out-of-band of the cursor: `slashEquivocation` (two
states at the same `seq` with different commitments, both bearing the **user's** valid sig
→ escrow forfeited to the relayer) and `slashRelayerEquivocation` (the symmetric
relayer-fault path → user recovers escrow + relayer bond). These need the *two conflicting
signed states* as evidence, which is another reason to persist signed states, not just the
latest balance.

## Failure modes (lost state ⇒ ?)

| Loss | Consequence | Recovery / mitigation |
|------|-------------|------------------------|
| **User loses an in-flight (un-cosigned) spend** | None to funds. The cursor never advanced (`spend` doesn't move it). | Resume from last persisted doubly-signed state; re-issue the request. |
| **User keeps an *older* doubly-signed state, loses the newest** | User would close/refund at a *higher* balance than true — i.e. tries to under-pay the relayer. The **relayer's** copy of the newer state wins via `challenge` (latest truth wins). User does not gain; relayer is made whole. | Relayer (or its watchtower) must hold + submit the newer state within `CHALLENGE_WINDOW`. |
| **Relayer keeps an *older* state, loses the newest** | Relayer can only claim `B0 - older_balance` < what it is owed — **lost revenue**, not lost safety; the user is over-refunded. | Persist every co-signed state before forwarding. There is no court path that pays the relayer for a state it cannot exhibit. |
| **Relayer loses `seen_nonces` (keeps `latest`)** | Per-epoch replay not re-detected by the nonce set within the lost epoch. | The monotone `latest` cursor still rejects any non-successor spend; call `advance_epoch` to a fresh epoch on restart (per `EPOCH_AUTHORITY.md`) to invalidate stale freshness and reset the budget. |
| **A party loses *all* post-genesis state (total wipe)** | Cannot close cooperatively or win a dispute on its own behalf. | The **user** is still protected by `refundOnTimeout` (full `B0` back once `timeout` passes, channel still Open). The **relayer** has no equivalent backstop — a total wipe means it cannot prove what it relayed and forfeits its earned-but-unclaimable revenue (it is not slashed; going dark is not slashable). |
| **Both parties offline through the entire `CHALLENGE_WINDOW` after a stale `unilateralClose`** | The **stale** state settles (`settleDispute` at the lower-`seq` state). The disadvantaged party loses the delta. | This is the residual offline risk the watchtower exists to remove — delegate a watchtower with the latest doubly-signed state and an RPC/key that can `challenge` in time. |
| **Watchtower loses `best`** | It cannot challenge until re-seeded; a concurrent stale close could settle. | Persist `best` (the latest doubly-signed `SignedState`) or re-witness states on restart before relying on the tower. |

### Non-recoverable from state alone (documented honest limit)

A **non-forking linear rollback** — a party simply re-presenting an *older* doubly-signed
state instead of forking — produces **no conflicting object**, so it is not detectable from
the states alone (`settlement.rs` and `lib.rs` both state this). It is not an equivocation
(no two states at one `seq`), so it is **not slashable**. The *only* on-chain defense is the
dispute window: the counterparty's newer doubly-signed state overrides the rollback via
`challenge`. This is precisely why the watchtower + persisted latest state are load-bearing,
and why this risk cannot be designed away purely with better local persistence — it requires
*someone online with the newer state* during the window.

## Deployer checklist (channel tier only)

1. Persist the **latest doubly-signed `SignedState`** (both signatures), durably, **before**
   acting on it — user before serving, relayer before forwarding.
2. Persist channel params + signing key (params are also re-derivable from the `Opened` event).
3. Relayer: persist `epoch`; on restart `advance_epoch` to a strictly-greater value.
4. Run (or delegate) a **watchtower** with the latest doubly-signed state, an RPC endpoint,
   and a funded key able to broadcast `challenge` within `CHALLENGE_WINDOW = 1 days`. The
   crate provides the decision; the live broadcast loop is the deployer's to build.
5. Keep **conflicting signed states** if ever observed — they are the fraud proof for
   `slashEquivocation` / `slashRelayerEquivocation`.

See also: [`docs/ARCHITECTURE.md`](ARCHITECTURE.md) (why this is the optional-advanced tier),
[`docs/EPOCH_AUTHORITY.md`](EPOCH_AUTHORITY.md) (epoch/freshness lifecycle),
[`docs/THREAT_MODEL.md`](THREAT_MODEL.md), and `docs/DESIGN.md` §2/§6 (the channel + court design).
