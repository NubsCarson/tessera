//! The **real channel-payment gate** for the 2-hop loop: how a
//! [`tessera_channel`] spend rides the relay's outer `CONNECT` and gates it.
//!
//! This module replaces the **ARC-v0 spend stand-in** (which gated at the
//! *exit*) with a **real Spilman channel spend that gates at the RELAY** — the
//! correct trust model from `DESIGN.md` §1/§2: *the relay is the single channel
//! counterparty + first hop + rate-limiter*. The relay holds a
//! [`RelayerChannel`](tessera_channel::RelayerChannel), the client a
//! [`UserChannel`](tessera_channel::UserChannel); for each request the client
//! does a channel [`spend`](tessera_channel::UserChannel::spend) and the relay
//! [`verify_and_cosign`](tessera_channel::RelayerChannel::verify_and_cosign)s it
//! **before** it forwards a single byte (*sign-then-serve*).
//!
//! # How the handshake + per-request spend coexist with the nested-CONNECT tunnel
//!
//! The existing loop is a **nested CONNECT tunnel**: the client opens an *outer*
//! `CONNECT <exit>` to the relay, and the relay — after `200` — pumps **opaque
//! bytes**, through which the client sends the *inner* `CONNECT <destination>`
//! that only the exit reads. The relay must never parse inside the tunnel (that
//! is the split-trust property), so the channel protocol cannot live in the inner
//! bytes. It lives in the **outer request headers**, which are the relay's own
//! (pre-tunnel) protocol surface:
//!
//! ```text
//! CONNECT <exit-addr> HTTP/1.1
//! Tessera-Channel-Id:    <hex chan_id>            ← which channel this is
//! Tessera-Channel-Spend: <hex spend>              ← S_{i+1} + σ_user + σ_fresh
//! Tessera-Channel-Fresh: <hex freshness>          ← the relayer challenge it answers
//! <blank line>
//! … then the opaque tunnel begins (inner CONNECT to the dest rides inside it) …
//! ```
//!
//!   * **Open** is a one-time, out-of-band handshake: the client and relay agree
//!     the [`Channel`](tessera_channel::Channel) params (`chan_id`, `B0`, salt,
//!     both pubkeys) once. The relay registers a
//!     [`RelayerChannel`](tessera_channel::RelayerChannel) under that `chan_id`
//!     (its single
//!     in-memory cursor — the design's "collapse distributed double-spend into one
//!     cursor"). In this host model the registration is an explicit API call
//!     (`RelayGate::open` in the crate root); a deployment would carry the open
//!     params in a first handshake message, but modelling it as an API call keeps
//!     the on-wire surface to *one* line per request and is enough to prove the
//!     protocol.
//!   * **Each request carries a fresh spend.** The relay parses the three outer
//!     headers (never the inner tunnel), runs `verify_and_cosign`, and **only on
//!     success** dials the exit and opens the tunnel. A bad / replayed /
//!     over-budget spend → the relay writes `402 Payment Required` and the tunnel
//!     is **never opened**, so the inner CONNECT never reaches the exit and the
//!     destination is never touched.
//!
//! Because the spend is consumed *before* the tunnel and the inner CONNECT to the
//! destination still rides *opaque* through to the exit, the **split-trust shape
//! is unchanged**: the relay still learns only `{client, exit}` (plus, now, that
//! the client paid — an in-channel link it already has by being the counterparty,
//! the accepted within-session linkability of `DESIGN.md` §9), never the
//! destination.
//!
//! # The exit's role + trust (documented, not over-engineered)
//!
//! The relay is the channel counterparty and **pays the exits downstream**
//! (`DESIGN.md` §1). The clean trust split we implement is:
//!
//!   * **The RELAY is the sole *payment* gate.** The per-request channel spend is
//!     verified+co-signed at the relay; that is the one place a request is *paid
//!     for*. There is **no second payment gate** — the exit does **not** re-verify
//!     a channel spend (that would be redundant double-gating, and the relay is
//!     the party that pays the exit, per the design).
//!   * **The EXIT stays the unchanged content-blind [`tessera_proxy`].** It keeps
//!     its own ARC `OriginGuard` admission — but here that is **not the payment**;
//!     it is the exit's orthogonal *"is this a Tessera participant, never the IP"*
//!     check (`DESIGN.md` §5: "a credential-gated CONNECT exit that verifies the
//!     presentation, never the IP"), so the exit is not an open proxy. The relay,
//!     as the exit's trusted client, is what satisfies it (the inner CONNECT
//!     carries the participant presentation, opaque to the relay).
//!
//! So the ARC presentation is **demoted from "the payment stand-in" to "the
//! exit's participant token"**, and the **real per-request payment is the channel
//! spend at the relay** — exactly the corrected trust model. We pick this over
//! "the relay re-presents a *channel* spend to the exit" because it is the cleaner
//! of the two (one payment gate, the exit stays untouched and content-blind).
//!
//! # What this is and is NOT
//!
//! This is the **Phase 2a protocol** wired into the live loop: a real,
//! user-signed, relayer-co-signed, freshness-bound, monotone-decrementing spend
//! per request. It is **not** the ZK settlement (Phase 2b-i — balance privacy
//! against an observer; the relay knows the balance by construction anyway) and
//! **not** the shielded funding pool (separate). The `cost`/`balance` are in the
//! clear here exactly as in [`tessera_channel`].

use std::io::{Error, ErrorKind, Result};

use tessera_channel::crypto::{EthSig, Hash};
use tessera_channel::relay::RelayRequest;
use tessera_channel::state::{ChanId, ChannelState, Salt, SignedState};
use tessera_channel::Spend;

/// Outer-header name carrying the hex `chan_id` (which channel a request spends).
pub const CHANNEL_ID_HEADER: &str = "Tessera-Channel-Id";
/// Outer-header name carrying the hex-encoded [`Spend`] (`S_{i+1}` + σ_user + σ_fresh).
pub const CHANNEL_SPEND_HEADER: &str = "Tessera-Channel-Spend";
/// Outer-header name carrying the hex-encoded [`RelayRequest`] freshness the spend answers.
pub const CHANNEL_FRESH_HEADER: &str = "Tessera-Channel-Fresh";

// ----- wire encoding -------------------------------------------------------
//
// Compact, fixed-layout, dependency-free hex encodings (no serde). Every field
// is fixed-width big-endian so the decoder is unambiguous; an `EthSig` is its
// canonical 65-byte `r‖s‖v`. These ride as hex in an HTTP header value, which is
// why they must be single-line and printable.

/// Serialize a freshness challenge to hex: `epoch(8) ‖ nonce(8) ‖ request_hash(32)`.
pub fn encode_fresh(fresh: &RelayRequest) -> String {
    let mut buf = Vec::with_capacity(48);
    buf.extend_from_slice(&fresh.epoch.to_be_bytes());
    buf.extend_from_slice(&fresh.nonce.to_be_bytes());
    buf.extend_from_slice(&fresh.request_hash);
    hex::encode(buf)
}

/// Parse a freshness challenge from the hex layout produced by [`encode_fresh`].
pub fn decode_fresh(s: &str) -> Result<RelayRequest> {
    let bytes = hex::decode(s.trim()).map_err(bad)?;
    if bytes.len() != 48 {
        return Err(bad("freshness must be 48 bytes"));
    }
    let epoch = u64::from_be_bytes(bytes[..8].try_into().unwrap());
    let nonce = u64::from_be_bytes(bytes[8..16].try_into().unwrap());
    let mut request_hash: Hash = [0u8; 32];
    request_hash.copy_from_slice(&bytes[16..48]);
    Ok(RelayRequest {
        epoch,
        nonce,
        request_hash,
    })
}

/// Serialize a [`Spend`] to hex. Layout (all big-endian, fixed width):
/// `chan_id(32) ‖ balance(8) ‖ seq(8) ‖ salt(32) ‖ sig_user(65) ‖ sig_fresh(65)`.
/// The relayer co-signature is intentionally absent (`sig_relayer = None` on a
/// fresh spend — the relayer adds it).
pub fn encode_spend(spend: &Spend) -> String {
    let st = &spend.signed.state;
    let mut buf = Vec::with_capacity(32 + 8 + 8 + 32 + 65 + 65);
    buf.extend_from_slice(&st.chan_id);
    buf.extend_from_slice(&st.balance.to_be_bytes());
    buf.extend_from_slice(&st.seq.to_be_bytes());
    buf.extend_from_slice(&st.salt);
    buf.extend_from_slice(&spend.signed.sig_user.to_rsv());
    buf.extend_from_slice(&spend.sig_fresh.to_rsv());
    hex::encode(buf)
}

/// Parse a [`Spend`] from the hex layout produced by [`encode_spend`].
pub fn decode_spend(s: &str) -> Result<Spend> {
    const LEN: usize = 32 + 8 + 8 + 32 + 65 + 65;
    let bytes = hex::decode(s.trim()).map_err(bad)?;
    if bytes.len() != LEN {
        return Err(bad("spend has wrong length"));
    }
    let mut chan_id: ChanId = [0u8; 32];
    chan_id.copy_from_slice(&bytes[..32]);
    let balance = u64::from_be_bytes(bytes[32..40].try_into().unwrap());
    let seq = u64::from_be_bytes(bytes[40..48].try_into().unwrap());
    let mut salt: Salt = [0u8; 32];
    salt.copy_from_slice(&bytes[48..80]);
    let sig_user =
        EthSig::from_rsv(bytes[80..145].try_into().unwrap()).ok_or_else(|| bad("bad sig_user"))?;
    let sig_fresh = EthSig::from_rsv(bytes[145..210].try_into().unwrap())
        .ok_or_else(|| bad("bad sig_fresh"))?;
    Ok(Spend {
        signed: SignedState {
            state: ChannelState {
                chan_id,
                balance,
                seq,
                salt,
            },
            sig_user,
            sig_relayer: None,
        },
        sig_fresh,
    })
}

/// Serialize a relayer-co-signed [`SignedState`] to hex (the relay's reply to the
/// client): `chan_id(32) ‖ balance(8) ‖ seq(8) ‖ salt(32) ‖ sig_user(65) ‖ sig_relayer(65)`.
/// Unlike a [`Spend`] this carries the **relayer** co-signature, not the
/// freshness signature.
pub fn encode_cosigned(co: &SignedState) -> Result<String> {
    let st = &co.state;
    let sig_relayer = co
        .sig_relayer
        .as_ref()
        .ok_or_else(|| bad("co-signed state has no relayer signature"))?;
    let mut buf = Vec::with_capacity(32 + 8 + 8 + 32 + 65 + 65);
    buf.extend_from_slice(&st.chan_id);
    buf.extend_from_slice(&st.balance.to_be_bytes());
    buf.extend_from_slice(&st.seq.to_be_bytes());
    buf.extend_from_slice(&st.salt);
    buf.extend_from_slice(&co.sig_user.to_rsv());
    buf.extend_from_slice(&sig_relayer.to_rsv());
    Ok(hex::encode(buf))
}

/// Parse a relayer-co-signed [`SignedState`] from [`encode_cosigned`]'s layout.
pub fn decode_cosigned(s: &str) -> Result<SignedState> {
    const LEN: usize = 32 + 8 + 8 + 32 + 65 + 65;
    let bytes = hex::decode(s.trim()).map_err(bad)?;
    if bytes.len() != LEN {
        return Err(bad("cosigned state has wrong length"));
    }
    let mut chan_id: ChanId = [0u8; 32];
    chan_id.copy_from_slice(&bytes[..32]);
    let balance = u64::from_be_bytes(bytes[32..40].try_into().unwrap());
    let seq = u64::from_be_bytes(bytes[40..48].try_into().unwrap());
    let mut salt: Salt = [0u8; 32];
    salt.copy_from_slice(&bytes[48..80]);
    let sig_user =
        EthSig::from_rsv(bytes[80..145].try_into().unwrap()).ok_or_else(|| bad("bad sig_user"))?;
    let sig_relayer = EthSig::from_rsv(bytes[145..210].try_into().unwrap())
        .ok_or_else(|| bad("bad sig_relayer"))?;
    Ok(SignedState {
        state: ChannelState {
            chan_id,
            balance,
            seq,
            salt,
        },
        sig_user,
        sig_relayer: Some(sig_relayer),
    })
}

/// Serialize a [`ChanId`] for the `Tessera-Channel-Id` header.
pub fn encode_chan_id(id: &ChanId) -> String {
    hex::encode(id)
}

/// Parse a [`ChanId`] from its hex form.
pub fn decode_chan_id(s: &str) -> Result<ChanId> {
    let bytes = hex::decode(s.trim()).map_err(bad)?;
    if bytes.len() != 32 {
        return Err(bad("chan_id must be 32 bytes"));
    }
    let mut id: ChanId = [0u8; 32];
    id.copy_from_slice(&bytes);
    Ok(id)
}

fn bad<E: std::fmt::Display>(e: E) -> Error {
    Error::new(ErrorKind::InvalidData, format!("channel wire: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;
    use tessera_channel::{Channel, KeyPair, RelayerChannel, UserChannel};

    fn round_trip_spend() -> (Spend, RelayRequest, SignedState) {
        let mut rng = OsRng;
        let uk = KeyPair::generate(&mut rng);
        let rk = KeyPair::generate(&mut rng);
        let chan = Channel::open(
            [5u8; 32],
            1000,
            [9u8; 32],
            uk.verifying_key(),
            rk.verifying_key(),
        );
        let user = UserChannel::new(uk, chan.clone());
        let mut relayer = RelayerChannel::new(rk, chan, 1);
        let fresh = relayer.issue_challenge(7, b"req");
        let spend = user.spend(40, &fresh).unwrap();
        let cosigned = relayer.verify_and_cosign(&spend, &fresh).unwrap();
        (spend, fresh, cosigned)
    }

    #[test]
    fn fresh_round_trips() {
        let (_, fresh, _) = round_trip_spend();
        let s = encode_fresh(&fresh);
        assert_eq!(decode_fresh(&s).unwrap(), fresh);
    }

    #[test]
    fn spend_round_trips() {
        let (spend, _, _) = round_trip_spend();
        let s = encode_spend(&spend);
        assert_eq!(decode_spend(&s).unwrap(), spend);
    }

    #[test]
    fn cosigned_round_trips() {
        let (_, _, cosigned) = round_trip_spend();
        let s = encode_cosigned(&cosigned).unwrap();
        assert_eq!(decode_cosigned(&s).unwrap(), cosigned);
    }

    #[test]
    fn chan_id_round_trips() {
        let id: ChanId = [3u8; 32];
        assert_eq!(decode_chan_id(&encode_chan_id(&id)).unwrap(), id);
    }

    #[test]
    fn decode_rejects_wrong_length() {
        assert!(decode_spend("00").is_err());
        assert!(decode_fresh("00").is_err());
        assert!(decode_chan_id("00").is_err());
        assert!(decode_cosigned("00").is_err());
    }
}
