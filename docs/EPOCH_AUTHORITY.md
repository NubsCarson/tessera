# Tessera — the epoch clock: who owns it, and the skew/rejection rules (S1)

> Companion to [`DESIGN.md`](./DESIGN.md) §2 and the `R_dec` circuit
> (`circuits/R_dec.circom`). Defines the **single authority** for the `epoch`
> value, why divergence would be unsafe, and the exact rejection rule — so the
> per-epoch rate nullifier (`nf_rate`) and the freshness tag (`fresh`) are sound.
> Research-grade; UNAUDITED.

## Why an epoch even exists

Two per-request anti-abuse artifacts are keyed on `epoch`:

- **Freshness tag** `fresh = Poseidon(epoch, nonce, request_hash)`
  (`tessera_channel::poseidon::freshness_tag`) — binds a spend to one request in
  one epoch, so a spend message can't be wire-replayed.
- **Rate nullifier** `nf_rate = Poseidon(K_chan, epoch, idx)`
  (`rate_nullifier`) with `idx ∈ [0, 1024)` — the per-epoch, per-channel request
  budget. Within an epoch a channel has 1024 distinct nullifiers; reusing an
  `(epoch, idx)` is a detectable double-use; a *new* epoch resets the budget
  (the same `idx` in a different epoch is a **different** nullifier).

Both appear as public signals of `R_dec` (the circuit takes `epoch` as a private
witness and feeds it into both Poseidon gadgets — `R_dec.circom` lines ~125/148),
and the relayer checks the freshness epoch off-chain
(`RelayerChannel::verify_and_cosign`). So **three views of `epoch` must agree**:
the relayer's, the circuit witness's, and the nullifier-consuming verifier's. If
they diverge, two failure modes appear:

- **Nullifier reuse across a boundary** — if one party thinks the epoch rolled
  and another doesn't, the same `idx` could be spent twice under two `epoch`
  values that *should* have been one, inflating the real budget.
- **Spurious rejection** — a client computing `fresh`/`nf_rate` under a stale
  `epoch` produces tags the relayer won't accept.

## The authority: the relayer attests the epoch

**In Tessera the relayer is the single epoch authority for its own channels.**
It is the one channel counterparty, the rate-limiter, and the only off-chain
verifier of `fresh`/`nf_rate`, so it owns the clock:

- The relayer holds a current `epoch` (`RelayGate` / `RelayerChannel`, set at
  construction and advanced on its own settlement-window schedule).
- It **advertises** that epoch in every freshness challenge it issues
  (`issue_challenge` → `RelayRequest::new(self.epoch, …)`), *before* the client
  signs. The client does not pick the epoch; it adopts the one the relayer
  handed it, and computes `fresh`/`nf_rate`/the `R_dec` witness against it.
- The relayer therefore can never disagree with itself, and the client is always
  in lockstep because it took the value from the relayer.

This is deliberately **not** a wall-clock or a block-height clock:

- The nullifier scope is already namespaced **per channel** (`K_chan`) and is
  only ever consumed by **this one relayer**, so a globally-synchronized clock
  buys nothing — there is no cross-relayer nullifier set to keep consistent.
- A wall-clock would introduce real skew between independent machines (the exact
  failure this spec exists to forbid); a block-height clock would couple every
  request to chain liveness/reorgs for no benefit at this layer.

The cost of this choice, stated honestly: epoch advancement is a **trusted
relayer action**. A malicious relayer could refuse to advance the epoch (forcing
the budget to never reset) or advance it adversarially. That is bounded by the
same accountability the rest of the relayer relies on (the bond + the user's
freedom to stop spending / refund-on-timeout), and it is **not** a fund-safety
issue — `epoch` gates rate, not money. A multi-relayer or cross-operator design
(future, see `ECONOMICS.md` §7) would need a shared clock (block height is the
natural candidate); that is out of scope for the single-relayer rail.

## The rejection rule: exact match, zero skew

`RelayerChannel::verify_and_cosign` enforces:

```
if fresh.epoch != self.epoch  →  Err(ChannelError::StaleFreshness)
```

**There is no skew tolerance — the epochs must be equal.** A spend carrying any
other epoch (stale, future, or garbage) is rejected and not co-signed; the client
recovers by requesting a fresh challenge (which carries the relayer's current
epoch) and re-spending. Because the client always sources the epoch from the
relayer's challenge, a correctly-behaving client never trips this; the rule
exists to reject replays and confused/hostile inputs, not to reconcile clocks.

At an epoch boundary the relayer advances `self.epoch`; in-flight challenges
issued under the old epoch become un-co-signable (the freshness check fails),
which is the intended behavior — a spend is valid only for the epoch it was
challenged in.

## Invariants (tested)

1. **Per-channel, per-epoch budget is exactly `idx ∈ [0, 1024)`** distinct
   nullifiers; the circuit range-checks `idx < 1024`.
2. **Same `(K_chan, epoch, idx)` ⇒ identical `nf_rate`** (a duplicate is
   detectable as a clash).
3. **Differing on `epoch` *or* `idx` *or* `K_chan` ⇒ different `nf_rate`** (the
   budget resets each epoch; channels don't collide).
4. **`fresh` binds all of `(epoch, nonce, request_hash)`** — changing any yields
   a different tag, so a spend is not replayable across requests or epochs.

These are exercised by `tessera-channel`'s `poseidon` nullifier/freshness tests
and by the cross-epoch replay integration test (S2) in `tessera-relay`.
