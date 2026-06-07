//! `tessera-relay` — the **first onion hop** in Tessera's 2-hop split-trust
//! loop, and the piece that makes the privacy claim concrete and testable:
//!
//! ```text
//! CLIENT ──CONNECT exit──▶ RELAY ──opaque bytes──▶ EXIT ──CONNECT dest──▶ DESTINATION
//!                          (this crate)            (tessera-proxy: credential-gated)
//! ```
//!
//! The client opens an **outer** `CONNECT <exit-addr>` to the relay. The relay
//! tunnels that to the exit and then only pumps opaque bytes. Through that tunnel
//! the client sends a **nested / inner** `CONNECT <destination>` carrying its
//! ARC `Tessera-Presentation` header — but the relay never parses it, so:
//!
//! * the **RELAY** learns the *client's* address and the *exit's* address, but
//!   **never the final destination** (it's inside the bytes the relay just
//!   forwards) and never the credential;
//! * the **EXIT** ([`tessera_proxy`]) learns the *destination* (CONNECT host:port,
//!   i.e. SNI-level) and that *a valid credential* was presented, but **never the
//!   client's address** — it only ever sees the relay's socket;
//! * **neither** sees content: the client's TLS to the destination runs
//!   end-to-end through both hops, which only move bytes (tampering breaks TLS).
//!
//! That split — no single hop holds {who} + {where} + {what} — is the property
//! the integration test asserts by inspecting an [`Observer`] wired into each
//! hop. This proves the *protocol/loop* locally; reaching a real Tor-blocked
//! site through a real clean exit IP is a documented manual final step (the
//! egress IP is external — no code removes that). See the crate README.
//!
//! # Two payment modes
//!
//! There are **two** ways the loop gates a request. Per
//! [`docs/ARCHITECTURE.md`](../../../docs/ARCHITECTURE.md) the **recommended
//! default is the token (ARC) mode**; the channel mode is the optional-advanced
//! tier (kept + tested) for when pay-as-you-go-with-refund is genuinely needed:
//!
//!   * **Token / ARC mode (recommended default).** [`serve`] is the
//!     credential-*blind* relay: the request carries an unlinkable, rate-limited
//!     ARC token that is checked at the credential-gated **exit**
//!     ([`tessera_proxy`]) — no channel, no on-chain settlement. This is the
//!     leaner path the project recommends, proven end-to-end (`tests/loop.rs`).
//!   * **Channel mode (optional-advanced — `DESIGN.md` §1/§2).** [`serve_channel`]
//!     makes the **relay** the [`tessera_channel`] counterparty + per-request
//!     payment gate: the client opens a channel ([`RelayGate::open`]) and each
//!     request is a real channel `spend` the relay
//!     [`verify_and_cosign`](tessera_channel::RelayerChannel::verify_and_cosign)s
//!     **before** forwarding a byte (*sign-then-serve*); a bad / replayed /
//!     over-budget spend → `402` and never reaches the destination. Use it only
//!     when the heavier channel/refund/dispute machinery is actually required.
//!
//! Like [`tessera_proxy`], this is std-only (blocking sockets + one thread per
//! direction), demo/example tooling — not a hardened production relay.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod channel;

use std::io::{BufRead, BufReader, Error, ErrorKind, Read, Result, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use tessera_channel::{Channel, ChannelError, RelayerChannel, SignedState, Spend, VerifyingKey};
// The relay reuses tessera-proxy's transport scaffolding — the byte-pump
// (`pipe`), the SOCKS5 dialer, the accept-loop concurrency cap + idle timeout +
// RAII permit + reject writer — rather than re-declaring any of it.
use tessera_proxy::{
    pipe, write_status, Dialer, InflightGuard, TorSocksDialer, MAX_INFLIGHT, SOCKET_TIMEOUT,
};
// The local client proxy ([`serve_client_proxy`]) mints presentations and, on
// budget exhaustion, re-obtains a credential from the issuer.
use rand_core::OsRng;
use tessera_arc::arc::Credential;
use tessera_client::{obtain_credential, obtain_credential_paid, TesseraClient};

/// What a hop observed about a single forwarded connection. Wired into each hop
/// so a test (or an operator) can prove the **split-trust** property: assert the
/// relay never recorded the destination, and the exit never recorded the client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observation {
    /// The peer socket the hop accepted the connection *from*.
    pub peer: SocketAddr,
    /// The CONNECT target the hop parsed off the wire (`host:port`). For the
    /// relay this is the *exit's* address; for the exit this is the *destination*.
    pub connect_target: String,
}

/// A thread-safe, append-only log of [`Observation`]s for one hop.
///
/// Clone it and hand a clone to a hop (the inner [`Mutex<Vec<_>>`] is shared);
/// read the accumulated observations back with [`snapshot`](Observer::snapshot).
#[derive(Debug, Clone, Default)]
pub struct Observer {
    log: Arc<Mutex<Vec<Observation>>>,
}

impl Observer {
    /// A fresh, empty observer.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one observation (called by a hop as it forwards a connection).
    pub fn record(&self, obs: Observation) {
        // A poisoned lock can't lose us correctness here (append-only); recover.
        let mut g = self.log.lock().unwrap_or_else(|e| e.into_inner());
        g.push(obs);
    }

    /// A copy of everything recorded so far.
    pub fn snapshot(&self) -> Vec<Observation> {
        self.log.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// The set of distinct CONNECT targets this hop has seen — convenience for
    /// the split-trust assertions ("did this hop ever see `X`?").
    pub fn targets(&self) -> Vec<String> {
        self.snapshot()
            .into_iter()
            .map(|o| o.connect_target)
            .collect()
    }
}

/// Start the relay on an already-bound listener, in a background thread.
///
/// `exit_addr` is the only forwarding target the relay knows; it forwards every
/// admitted outer `CONNECT` there (and rejects a `CONNECT` to anywhere else — a
/// real relay's hop is fixed, it is not an open proxy). `observer`, if given,
/// records what the relay saw (peer + outer CONNECT target) per connection.
pub fn serve(
    listener: TcpListener,
    exit_addr: SocketAddr,
    observer: Option<Observer>,
) -> thread::JoinHandle<()> {
    let inflight = Arc::new(AtomicUsize::new(0));
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let _ = stream.set_read_timeout(Some(SOCKET_TIMEOUT));
            let _ = stream.set_write_timeout(Some(SOCKET_TIMEOUT));
            if inflight.fetch_add(1, Ordering::AcqRel) >= MAX_INFLIGHT {
                inflight.fetch_sub(1, Ordering::AcqRel);
                write_status(&mut stream, "503 Service Unavailable");
                continue;
            }
            let permit = InflightGuard::new(Arc::clone(&inflight));
            let observer = observer.clone();
            thread::spawn(move || {
                let _permit = permit;
                let _ = handle(stream, exit_addr, observer.as_ref());
            });
        }
    })
}

/// Handle one client connection: read the outer `CONNECT <exit-addr>`, open a
/// plain TCP tunnel to the exit, `200`, then pipe opaque bytes. The relay does
/// **no** credential check — it is deliberately credential-blind — and never
/// parses anything inside the tunnel, so the inner CONNECT (and the destination
/// it names) is invisible to it.
fn handle(mut stream: TcpStream, exit_addr: SocketAddr, observer: Option<&Observer>) -> Result<()> {
    let peer = stream.peer_addr()?;
    let mut reader = BufReader::new(stream.try_clone()?.take(64 * 1024));

    // Outer request line: `CONNECT host:port HTTP/1.1`.
    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let outer_target = parts.next().unwrap_or("").to_string();

    // Drain the rest of the outer header block (we forward nothing from it; in
    // particular we do NOT look for, log, or forward any credential header — the
    // credential is only inside the inner CONNECT, which the exit reads).
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            break;
        }
        if line.trim_end().is_empty() {
            break;
        }
    }

    if !method.eq_ignore_ascii_case("CONNECT") {
        write_status(&mut stream, "405 Method Not Allowed");
        return Ok(());
    }

    // The relay's single observation: who connected, and the outer target. By
    // construction this records the EXIT's address, never the destination.
    if let Some(obs) = observer {
        obs.record(Observation {
            peer,
            connect_target: outer_target.clone(),
        });
    }

    // A relay forwards only to its fixed next hop (the exit). Refuse to be an
    // open proxy to an arbitrary outer target.
    if outer_target != exit_addr.to_string() {
        write_status(
            &mut stream,
            "403 Forbidden (relay forwards only to its exit)",
        );
        return Ok(());
    }

    let upstream = match TcpStream::connect(exit_addr) {
        Ok(c) => {
            // S3: bound the upstream too, so a stalled exit can't pin this tunnel.
            let _ = c.set_read_timeout(Some(SOCKET_TIMEOUT));
            let _ = c.set_write_timeout(Some(SOCKET_TIMEOUT));
            c
        }
        Err(_) => {
            write_status(&mut stream, "502 Bad Gateway");
            return Ok(());
        }
    };

    stream.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")?;
    stream.flush()?;

    // From here the relay only moves opaque bytes between the client and the
    // exit. The inner CONNECT + credential + the client's end-to-end TLS all ride
    // inside this stream and are never inspected. Reuses tessera-proxy's pipe.
    pipe(stream, upstream);
    Ok(())
}

// ===========================================================================
// CHANNEL-PAYMENT MODE (the real, default pay-per-request gate, DESIGN §1/§2)
// ===========================================================================

/// The relay's **channel counterparty** state: the [`RelayerChannel`]s it holds,
/// one per open channel, behind a single lock.
///
/// This is the design's "**collapse distributed double-spend into a single
/// in-memory cursor**" (`DESIGN.md` §8): because the relay is the *only*
/// counterparty, one `RelayerChannel` cursor per channel is the whole
/// double-spend defense — a replayed or out-of-order spend simply fails
/// [`RelayerChannel::verify_and_cosign`] against that cursor. The lock makes the
/// cursor safe across the relay's per-connection threads (each request is a fresh
/// connection in this host model).
#[derive(Clone)]
pub struct RelayGate {
    relayer_keys: tessera_channel::KeyPair,
    epoch: u64,
    // chan_id → its RelayerChannel cursor. A Vec keyed by chan_id keeps it
    // dependency-free and the channel count is tiny in the demo/test.
    channels: Arc<Mutex<Vec<(tessera_channel::state::ChanId, RelayerChannel)>>>,
}

impl RelayGate {
    /// Create a relay gate that co-signs with `relayer_keys`, issuing freshness
    /// challenges in `epoch`. No channels are open yet.
    pub fn new(relayer_keys: tessera_channel::KeyPair, epoch: u64) -> Self {
        Self {
            relayer_keys,
            epoch,
            channels: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// The relayer's public key (the channel counterparty identity the client
    /// pins at open time, and verifies co-signatures against).
    pub fn relayer_pk(&self) -> VerifyingKey {
        self.relayer_keys.verifying_key()
    }

    /// The relayer's current freshness epoch.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// **open** — register a [`RelayerChannel`] for `params` (the one-time channel
    /// handshake). After this, requests bearing `params.chan_id` are gated against
    /// this cursor. Idempotent on `chan_id` (re-opening replaces the cursor).
    ///
    /// `params.relayer_pk` must be this gate's relayer key (the client agreed to
    /// pay *this* relay); otherwise the channel is rejected.
    pub fn open(&self, params: Channel) -> std::result::Result<(), ChannelError> {
        if params.relayer_pk != self.relayer_pk() {
            return Err(ChannelError::BadSignature);
        }
        let chan_id = params.chan_id;
        let relayer = RelayerChannel::new(self.relayer_keys.clone(), params, self.epoch);
        let mut g = self.channels.lock().unwrap_or_else(|e| e.into_inner());
        g.retain(|(id, _)| *id != chan_id);
        g.push((chan_id, relayer));
        Ok(())
    }

    /// Issue a freshness challenge for `request_payload` against the relayer's
    /// current epoch and a caller-chosen `nonce`. The client answers it in its
    /// [`spend`](tessera_channel::UserChannel::spend); the relay later checks the
    /// spend's freshness against the same challenge in [`Self::verify_spend`].
    ///
    /// (In this host model the challenge is issued via an API call rather than a
    /// wire round trip — enough to bind the spend to one epoch/nonce/request and
    /// prove the replay defense.)
    pub fn issue_challenge(
        &self,
        chan_id: &tessera_channel::state::ChanId,
        nonce: u64,
        request_payload: &[u8],
    ) -> Option<tessera_channel::RelayRequest> {
        let g = self.channels.lock().unwrap_or_else(|e| e.into_inner());
        g.iter()
            .find(|(id, _)| id == chan_id)
            .map(|(_, r)| r.issue_challenge(nonce, request_payload))
    }

    /// **verify + co-sign a spend** against the named channel's cursor (the
    /// per-request payment gate). Returns the doubly-signed state on success.
    ///
    /// This is the single place a request is *paid for*: it advances the relay's
    /// in-memory cursor (so a replay of the same `seq` / a burned nonce fails) and
    /// returns the relayer-co-signed state (`sign-then-serve`). A bad / replayed /
    /// over-budget spend errors here and the caller must refuse the tunnel.
    pub fn verify_spend(
        &self,
        chan_id: &tessera_channel::state::ChanId,
        spend: &Spend,
        fresh: &tessera_channel::RelayRequest,
    ) -> std::result::Result<SignedState, ChannelError> {
        let mut g = self.channels.lock().unwrap_or_else(|e| e.into_inner());
        let (_, relayer) = g
            .iter_mut()
            .find(|(id, _)| id == chan_id)
            .ok_or(ChannelError::BadSignature)?;
        relayer.verify_and_cosign(spend, fresh)
    }
}

/// Start the relay in **channel-payment mode** on an already-bound listener.
///
/// Identical wire shape to [`serve`] (an outer `CONNECT <exit>` then an opaque
/// tunnel), but **gated on a real channel spend**: the relay reads the three
/// `Tessera-Channel-*` outer headers, [`verify_spend`](RelayGate::verify_spend)s
/// them, and **only on success** dials the exit and opens the tunnel
/// (*sign-then-serve*). A missing / bad / replayed / over-budget spend gets
/// `402 Payment Required` and the tunnel is never opened — so the inner CONNECT
/// never reaches the exit and the destination is never touched.
///
/// `observer`, if given, records the relay's split-trust observation (peer + the
/// outer CONNECT target = the exit) — **only after** the spend is accepted, so it
/// also witnesses "this request was paid for", and still never the destination.
pub fn serve_channel(
    listener: TcpListener,
    exit_addr: SocketAddr,
    gate: RelayGate,
    observer: Option<Observer>,
) -> thread::JoinHandle<()> {
    let inflight = Arc::new(AtomicUsize::new(0));
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let _ = stream.set_read_timeout(Some(SOCKET_TIMEOUT));
            let _ = stream.set_write_timeout(Some(SOCKET_TIMEOUT));
            if inflight.fetch_add(1, Ordering::AcqRel) >= MAX_INFLIGHT {
                inflight.fetch_sub(1, Ordering::AcqRel);
                write_status(&mut stream, "503 Service Unavailable");
                continue;
            }
            let permit = InflightGuard::new(Arc::clone(&inflight));
            let gate = gate.clone();
            let observer = observer.clone();
            thread::spawn(move || {
                let _permit = permit;
                let _ = handle_channel(stream, exit_addr, &gate, observer.as_ref());
            });
        }
    })
}

fn handle_channel(
    mut stream: TcpStream,
    exit_addr: SocketAddr,
    gate: &RelayGate,
    observer: Option<&Observer>,
) -> Result<()> {
    let peer = stream.peer_addr()?;
    let mut reader = BufReader::new(stream.try_clone()?.take(64 * 1024));

    // Outer request line: `CONNECT host:port HTTP/1.1`.
    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let outer_target = parts.next().unwrap_or("").to_string();

    // Read the OUTER headers — the relay's own protocol surface. It reads ONLY
    // its three channel headers here; it still never parses anything inside the
    // tunnel, so the inner CONNECT + destination stay invisible to it.
    let (mut chan_id_hex, mut spend_hex, mut fresh_hex) = (None, None, None);
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            break;
        }
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            let value = value.trim().to_string();
            match name.trim() {
                n if n.eq_ignore_ascii_case(channel::CHANNEL_ID_HEADER) => {
                    chan_id_hex = Some(value)
                }
                n if n.eq_ignore_ascii_case(channel::CHANNEL_SPEND_HEADER) => {
                    spend_hex = Some(value)
                }
                n if n.eq_ignore_ascii_case(channel::CHANNEL_FRESH_HEADER) => {
                    fresh_hex = Some(value)
                }
                _ => {}
            }
        }
    }

    if !method.eq_ignore_ascii_case("CONNECT") {
        write_status(&mut stream, "405 Method Not Allowed");
        return Ok(());
    }

    // A relay forwards only to its fixed next hop (the exit). Refuse otherwise —
    // checked BEFORE payment so a misdirected request doesn't burn a spend.
    if outer_target != exit_addr.to_string() {
        write_status(
            &mut stream,
            "403 Forbidden (relay forwards only to its exit)",
        );
        return Ok(());
    }

    // --- THE PAYMENT GATE: verify + co-sign the spend BEFORE serving. ---
    let cosigned = match channel_gate_decision(gate, &chan_id_hex, &spend_hex, &fresh_hex) {
        Ok(co) => co,
        Err(reason) => {
            // No payment ⇒ no tunnel. The exit is never dialed; the destination
            // (inside the inner CONNECT we never read) is never touched.
            write_status(&mut stream, &format!("402 Payment Required ({reason})"));
            return Ok(());
        }
    };

    // Paid. Record the split-trust observation — peer + the EXIT's address, never
    // the destination — now that we know the request was paid for.
    if let Some(obs) = observer {
        obs.record(Observation {
            peer,
            connect_target: outer_target.clone(),
        });
    }

    // sign-then-serve: only NOW (after co-signing) do we open the byte tunnel.
    let upstream = match TcpStream::connect(exit_addr) {
        Ok(c) => {
            // S3: bound the upstream too, so a stalled exit can't pin this tunnel.
            let _ = c.set_read_timeout(Some(SOCKET_TIMEOUT));
            let _ = c.set_write_timeout(Some(SOCKET_TIMEOUT));
            c
        }
        Err(_) => {
            write_status(&mut stream, "502 Bad Gateway");
            return Ok(());
        }
    };

    // Hand the client back the relayer-co-signed state on the `200` line so the
    // user can advance its cursor (and prove sign-then-serve held). It rides in a
    // response header, before the tunnel bytes begin.
    let cosigned_hex = channel::encode_cosigned(&cosigned)
        .map_err(|e| std::io::Error::other(format!("encode cosigned: {e}")))?;
    stream.write_all(
        format!(
            "HTTP/1.1 200 Connection Established\r\n{}: {cosigned_hex}\r\n\r\n",
            channel::CHANNEL_SPEND_HEADER
        )
        .as_bytes(),
    )?;
    stream.flush()?;

    // Opaque byte tunnel — same as ARC mode. The inner CONNECT to the destination
    // rides inside it, invisible to the relay.
    pipe(stream, upstream);
    Ok(())
}

/// The pure decision half of the payment gate: decode the three headers and
/// verify+co-sign, or return a short human reason for the `402`.
fn channel_gate_decision(
    gate: &RelayGate,
    chan_id_hex: &Option<String>,
    spend_hex: &Option<String>,
    fresh_hex: &Option<String>,
) -> std::result::Result<SignedState, String> {
    let chan_id_hex = chan_id_hex.as_deref().ok_or("no channel id")?;
    let spend_hex = spend_hex.as_deref().ok_or("no spend")?;
    let fresh_hex = fresh_hex.as_deref().ok_or("no freshness")?;
    let chan_id = channel::decode_chan_id(chan_id_hex).map_err(|e| e.to_string())?;
    let spend = channel::decode_spend(spend_hex).map_err(|e| e.to_string())?;
    let fresh = channel::decode_fresh(fresh_hex).map_err(|e| e.to_string())?;
    gate.verify_spend(&chan_id, &spend, &fresh)
        .map_err(|e| e.to_string())
}

/// Drive **one paid request** through the channel-payment loop from the client
/// side. Given the client's [`UserChannel`](tessera_channel::UserChannel), the
/// relayer freshness challenge (issued by [`RelayGate::issue_challenge`]) and the
/// `cost`, this:
///
///   1. builds + signs the channel `spend` (`S_{i+1}` + σ_user + σ_fresh);
///   2. opens the outer `CONNECT <exit>` carrying the three `Tessera-Channel-*`
///      headers, and reads back the relayer-co-signed state on the `200`;
///   3. **advances the user's cursor** with that co-signed state (proving
///      sign-then-serve held — the client only adopts a co-signed state); and
///   4. sends the inner `CONNECT <destination>` (carrying any exit-side header)
///      through the now-open tunnel.
///
/// Returns the opened stream positioned right after the exit's `200`, i.e. an
/// end-to-end byte pipe to `destination`. On a refused payment the relay replies
/// `402` and this returns an error (the tunnel is never opened, the destination
/// never touched).
#[allow(clippy::too_many_arguments)]
pub fn open_through_relay_paid(
    relay_addr: SocketAddr,
    exit_addr: SocketAddr,
    user: &mut tessera_channel::UserChannel,
    chan_id: &tessera_channel::state::ChanId,
    cost: u64,
    fresh: &tessera_channel::RelayRequest,
    destination: &str,
    exit_header: &str,
) -> Result<TcpStream> {
    // (1) build + sign the spend (errors on underflow — caught before any socket).
    let spend = user
        .spend(cost, fresh)
        .map_err(|e| std::io::Error::other(format!("spend: {e}")))?;

    let mut stream = TcpStream::connect(relay_addr)?;

    // (2) OUTER hop: ask the relay to connect us to the EXIT, carrying the spend.
    // Names only the exit, never the destination.
    stream.write_all(
        format!(
            "CONNECT {exit_addr} HTTP/1.1\r\n\
             {id_hdr}: {chan_id_hex}\r\n\
             {spend_hdr}: {spend_hex}\r\n\
             {fresh_hdr}: {fresh_hex}\r\n\r\n",
            id_hdr = channel::CHANNEL_ID_HEADER,
            chan_id_hex = channel::encode_chan_id(chan_id),
            spend_hdr = channel::CHANNEL_SPEND_HEADER,
            spend_hex = channel::encode_spend(&spend),
            fresh_hdr = channel::CHANNEL_FRESH_HEADER,
            fresh_hex = channel::encode_fresh(fresh),
        )
        .as_bytes(),
    )?;
    stream.flush()?;

    // Read the relay's status block and pull the co-signed state header off it.
    let block = read_status_block(&mut stream, "relay")?;
    let status_line = block.lines().next().unwrap_or("");
    if !status_line.contains("200") {
        return Err(std::io::Error::other(format!(
            "relay refused the paid tunnel: {}",
            status_line.trim_end()
        )));
    }

    // (3) advance the user's cursor with the relayer's co-signature — this is the
    // CLIENT side of sign-then-serve: the user only adopts a co-signed state.
    let cosigned_hex = header_value(&block, channel::CHANNEL_SPEND_HEADER)
        .ok_or_else(|| std::io::Error::other("relay 200 carried no co-signed state"))?;
    let cosigned = channel::decode_cosigned(&cosigned_hex)?;
    user.accept_cosigned(&cosigned)
        .map_err(|e| std::io::Error::other(format!("co-sign: {e}")))?;
    // Serve gate: a request may only be sent on a co-signed state. This is the
    // belt-and-braces local assertion of sign-then-serve.
    user.serve(&cosigned)
        .map_err(|e| std::io::Error::other(format!("serve gate: {e}")))?;

    // (4) INNER hop: now tunneled to the EXIT, send the real CONNECT to the
    // destination. Only the exit reads this; the relay never saw it.
    stream.write_all(format!("CONNECT {destination} HTTP/1.1\r\n{exit_header}\r\n").as_bytes())?;
    stream.flush()?;
    expect_200(&mut stream, "exit")?;

    Ok(stream)
}

/// Read one HTTP head block (everything up to and including the terminating
/// `\r\n\r\n`) one byte at a time, so no tunnel payload past the blank line is
/// consumed — the load-bearing invariant for every CONNECT hop. Returns
/// `Ok(None)` if the peer closed before the blank line or `cap` bytes were
/// exceeded. The three readers below are thin parsers over this.
fn read_http_block(stream: &mut TcpStream, cap: usize) -> Result<Option<String>> {
    let mut block = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    loop {
        if stream.read(&mut byte)? == 0 {
            return Ok(None);
        }
        block.push(byte[0]);
        if block.ends_with(b"\r\n\r\n") {
            return Ok(Some(String::from_utf8_lossy(&block).into_owned()));
        }
        if block.len() > cap {
            return Ok(None);
        }
    }
}

/// Read one HTTP status block off `stream`. Shared by the paid-loop client (which
/// also needs a header off the block, unlike [`expect_200`]).
fn read_status_block(stream: &mut TcpStream, who: &str) -> Result<String> {
    read_http_block(stream, 16 * 1024)?
        .ok_or_else(|| std::io::Error::other(format!("{who} sent no status block")))
}

/// Send the inner `CONNECT <destination>` carrying the ARC presentation and wait
/// for the exit's `200`. Identical on both ARC-mode routes (the relay loop and
/// the onion lane), so they share it.
fn send_inner_connect(
    stream: &mut TcpStream,
    destination: &str,
    presentation_header: &str,
) -> Result<()> {
    stream.write_all(
        format!(
            "CONNECT {destination} HTTP/1.1\r\nTessera-Presentation: {presentation_header}\r\n\r\n"
        )
        .as_bytes(),
    )?;
    stream.flush()?;
    expect_200(stream, "exit")
}

/// Pull a header value out of a parsed status block (case-insensitive name).
fn header_value(block: &str, name: &str) -> Option<String> {
    block.lines().skip(1).find_map(|line| {
        let (n, v) = line.split_once(':')?;
        n.trim()
            .eq_ignore_ascii_case(name)
            .then(|| v.trim().to_string())
    })
}

/// Drive the 2-hop loop from the client side: open the outer tunnel to the
/// `relay`, then write the inner `CONNECT <destination>` (carrying the ARC
/// presentation header) *through* it to the exit. Returns the opened stream,
/// positioned right after the exit's `200 Connection Established` — i.e. an
/// end-to-end byte pipe straight to `destination`, ready to carry the client's
/// own TLS (or any opaque protocol).
///
/// This is the canonical client move the integration test and the binary use; it
/// makes the nesting explicit so callers don't hand-roll the two CONNECT lines.
pub fn open_through_relay(
    relay_addr: SocketAddr,
    exit_addr: SocketAddr,
    destination: &str,
    presentation_header: &str,
) -> Result<TcpStream> {
    let mut stream = TcpStream::connect(relay_addr)?;

    // OUTER hop: ask the relay to connect us to the EXIT. No credential here —
    // the relay is credential-blind, and this names only the exit, not the dest.
    stream.write_all(format!("CONNECT {exit_addr} HTTP/1.1\r\n\r\n").as_bytes())?;
    stream.flush()?;
    expect_200(&mut stream, "relay")?;

    // INNER hop: now tunneled to the EXIT, send the real CONNECT to the
    // destination, carrying the ARC presentation. Only the exit reads this.
    send_inner_connect(&mut stream, destination, presentation_header)?;

    Ok(stream)
}

/// How the local client proxy reaches the exit.
#[derive(Debug, Clone)]
pub enum ClientRoute {
    /// The 2-hop clearnet loop: TCP to the relay, which forwards a nested
    /// `CONNECT` to the exit. The relay hides the client IP from the exit.
    Relay {
        /// First hop — the credential-blind relay.
        relay_addr: SocketAddr,
        /// The exit the relay is asked to forward to.
        exit_addr: SocketAddr,
    },
    /// The single-hop onion lane: dial the exit's `.onion` through a Tor SOCKS
    /// proxy, so the exit's peer is the Tor rendezvous circuit — never the client
    /// IP — and no separate relay is needed.
    Onion {
        /// Local Tor SOCKS5 endpoint, e.g. `127.0.0.1:9050`.
        socks_addr: String,
        /// The exit's `.onion:port` (the hostname is passed to Tor unresolved).
        exit_onion: String,
    },
}

/// How many times a cold-start onion dial is retried before giving up. A freshly
/// published descriptor / building circuit can make the first dial fail
/// transiently right after boot.
const ONION_COLD_START_RETRIES: u32 = 3;

/// Delay between cold-start onion retries.
const ONION_RETRY_DELAY: Duration = Duration::from_secs(2);

/// The onion-lane analogue of [`open_through_relay`]: SOCKS5-dial the exit's
/// `.onion` through `socks_addr`, then write the **same** inner
/// `CONNECT <destination>` (carrying the ARC presentation) the relay loop sends.
/// The relay is bypassed — the Tor circuit is the outer hop, so the exit's peer
/// is the rendezvous, never the client. Returns the stream positioned right after
/// the exit's `200`, exactly like [`open_through_relay`].
///
/// Cold start: `cold_start` means the lane has not yet proven reachable this run,
/// so a transient dial failure (descriptor still publishing / circuit building)
/// is retried a bounded number of times with a "warming up" narration. Once the
/// lane is warm the caller passes `cold_start = false` and a single attempt is
/// made, so the steady-state per-request path NEVER sleeps. A *connection-refused
/// on the SOCKS port* (Tor not running) short-circuits without retry on either
/// path.
pub fn open_through_onion(
    socks_addr: &str,
    exit_onion: &str,
    destination: &str,
    presentation_header: &str,
    cold_start: bool,
) -> Result<TcpStream> {
    let (onion_host, onion_port) = split_onion_host_port(exit_onion)?;
    let mut stream = onion_dial(socks_addr, &onion_host, onion_port, cold_start)?;

    // INNER hop — the same credential-carrying CONNECT the relay loop sends. The
    // exit's OriginGuard is source-IP-blind, so admission is unchanged over Tor.
    send_inner_connect(&mut stream, destination, presentation_header)?;

    Ok(stream)
}

/// SOCKS5-dial the exit `.onion`. On `cold_start`, a transient failure is retried
/// a bounded number of times with a "warming up" narration; otherwise a single
/// attempt is made (steady state never sleeps). `ConnectionRefused` (the SOCKS
/// port is down — Tor not running) short-circuits without retry on either path.
fn onion_dial(socks_addr: &str, host: &str, port: u16, cold_start: bool) -> Result<TcpStream> {
    let dialer = TorSocksDialer::new(socks_addr.to_string());
    let attempts = if cold_start {
        ONION_COLD_START_RETRIES + 1
    } else {
        1
    };
    let mut last_err = None;
    for attempt in 0..attempts {
        match dialer.connect(host, port) {
            Ok(s) => return Ok(s),
            // The SOCKS port itself refused: Tor is not running. Don't retry.
            Err(e) if e.kind() == ErrorKind::ConnectionRefused => return Err(e),
            Err(e) => {
                if attempt + 1 < attempts {
                    eprintln!(
                        "  onion: exit {host} not reachable yet (attempt {}/{}), service may be \
                         warming up, retrying…",
                        attempt + 1,
                        ONION_COLD_START_RETRIES
                    );
                    thread::sleep(ONION_RETRY_DELAY);
                }
                last_err = Some(e);
            }
        }
    }
    Err(last_err.unwrap_or_else(|| Error::other("onion dial failed")))
}

/// Split an `.onion:port` (or any `host:port`) string into its host and port. The
/// host stays a string (a `.onion` is never resolvable to a `SocketAddr`); only
/// the port is parsed. Rejects userinfo (`@`) and a stray ':' in the host. The
/// `tessera-client` binary reuses this to validate `TESSERA_EXIT_ONION` at config
/// time with the exact rules the dial path applies.
pub fn split_onion_host_port(target: &str) -> Result<(String, u16)> {
    let (host, port) = target
        .rsplit_once(':')
        .ok_or_else(|| Error::other(format!("onion endpoint {target:?} is not host:port")))?;
    if host.is_empty() {
        return Err(Error::other(format!(
            "onion endpoint {target:?} has no host"
        )));
    }
    // Reject userinfo smuggling (`user@host`) and a stray ':' in the host — the
    // same malformed-authority guard `tessera_proxy`'s `split_host_port` applies.
    // An `.onion` is never a bracketed IPv6 literal, so ANY ':' left in the host
    // is malformed; this keeps the two authority parsers from drifting.
    if host.contains('@') || host.contains(':') {
        return Err(Error::other(format!(
            "onion endpoint {target:?} has a malformed host (stray ':' or userinfo '@')"
        )));
    }
    let port: u16 = port
        .parse()
        .map_err(|_| Error::other(format!("onion endpoint {target:?} has a bad port")))?;
    Ok((host.to_string(), port))
}

/// Read exactly one HTTP status block (status line + headers up to the blank
/// line) off `stream`, one byte at a time so we never buffer past the
/// terminating `\r\n\r\n` into the tunnel payload, and require a `200`. `who`
/// names the hop for the error message (so a `407`/`403` is attributed
/// correctly). Reading unbuffered is essential: the very next bytes after the
/// exit's `200` are the destination's reply, which the caller must not lose.
fn expect_200(stream: &mut TcpStream, who: &str) -> Result<()> {
    let block = read_status_block(stream, who)?;
    let status_line = block.lines().next().unwrap_or("");
    if status_line.contains("200") {
        Ok(())
    } else {
        Err(std::io::Error::other(format!(
            "{who} refused the tunnel: {}",
            status_line.trim_end()
        )))
    }
}

// ────────────────────────── the local client proxy ──────────────────────────
//
// The piece a *person* runs. A local HTTP `CONNECT` proxy you point a browser or
// curl at: for each request it mints a fresh, unlinkable ARC presentation and
// drives the 2-hop loop ([`open_through_relay`]) to the deployed relay+exit — so
// traffic is admitted on a credential, never the client's IP, with the relay
// blind to the destination and the exit blind to the client.

/// Cloned issuer coordinates for an off-lock re-issue: `(issuer_addr, request_ctx,
/// pk_pin, buyer_secret)`.
type ReissueCoords = (String, Vec<u8>, Option<Vec<u8>>, Option<[u8; 32]>);

/// A re-issuing credential holder for the client proxy: mints the next
/// presentation header and, once the credential's budget is spent, transparently
/// obtains a fresh one from the issuer so the proxy keeps serving.
pub struct CredentialSource {
    client: TesseraClient,
    issuer_addr: String,
    request_ctx: Vec<u8>,
    present_ctx: Vec<u8>,
    limit: u64,
    pin: Option<Vec<u8>>,
    /// `Some` => re-issue via the PAID issuer using this buyer key; `None` => PoW.
    buyer_secret: Option<[u8; 32]>,
}

impl CredentialSource {
    /// Build from an already-obtained `initial` credential plus the issuer
    /// coordinates to re-issue when the budget runs out. `pin`, if set, is the
    /// issuer-public-key prefix any re-issuance must match. `buyer_secret`, if
    /// set, re-issues against a **paid** issuer (proving control of that address);
    /// otherwise re-issuance pays the PoW.
    pub fn new(
        initial: Credential,
        issuer_addr: impl Into<String>,
        request_ctx: &[u8],
        present_ctx: &[u8],
        limit: u64,
        pin: Option<Vec<u8>>,
        buyer_secret: Option<[u8; 32]>,
    ) -> Self {
        Self {
            client: TesseraClient::new(initial, present_ctx, limit),
            issuer_addr: issuer_addr.into(),
            request_ctx: request_ctx.to_vec(),
            present_ctx: present_ctx.to_vec(),
            limit,
            pin,
            buyer_secret,
        }
    }

    /// The cheap path: mint a presentation from the current credential with **no**
    /// network I/O. `None` means the budget is spent and a re-issue is needed.
    fn try_header(&mut self) -> Option<String> {
        self.client.presentation_header(&mut OsRng).ok()
    }

    /// Issuer coordinates for a re-issue, cloned so the slow obtain call runs
    /// **without** the [`CredentialSource`] lock held (no head-of-line stall).
    fn reissue_coords(&self) -> ReissueCoords {
        (
            self.issuer_addr.clone(),
            self.request_ctx.clone(),
            self.pin.clone(),
            self.buyer_secret,
        )
    }

    /// Install a freshly obtained credential and mint the first presentation.
    fn install(&mut self, credential: Credential) -> Result<String> {
        self.client = TesseraClient::new(credential, &self.present_ctx, self.limit);
        self.client.presentation_header(&mut OsRng).map_err(|e| {
            std::io::Error::other(format!("presentation failed after re-issue: {e:?}"))
        })
    }
}

/// Mint the next presentation header for a connection, re-issuing if the budget
/// is spent. The slow re-issue (`obtain_credential`: a PoW solve + a round-trip
/// to the issuer) runs **outside** the lock — under the lock we only ever do the
/// cheap presentation mint — so one re-issue cannot stall other in-flight requests.
fn mint_header(source: &Arc<Mutex<CredentialSource>>) -> Result<String> {
    if let Some(h) = source
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .try_header()
    {
        return Ok(h);
    }
    let (issuer, req_ctx, pin, buyer) = source
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .reissue_coords();
    let credential = match buyer {
        Some(secret) => obtain_credential_paid(&issuer, &req_ctx, &secret, pin.as_deref())?,
        None => obtain_credential(&issuer, &req_ctx, pin.as_deref())?,
    };
    source
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .install(credential)
}

/// Run the **local client proxy**: a forward HTTP `CONNECT` proxy on `listener`
/// that mints a fresh presentation from `source` per request and routes the
/// tunnel through the 2-hop loop to `relay_addr` → `exit_addr`. Point a normal
/// HTTPS client at it (`curl -x http://LISTENER …`). Spawns the accept loop and
/// returns its handle.
pub fn serve_client_proxy(
    listener: TcpListener,
    relay_addr: SocketAddr,
    exit_addr: SocketAddr,
    source: CredentialSource,
) -> thread::JoinHandle<()> {
    serve_client_proxy_route(
        listener,
        ClientRoute::Relay {
            relay_addr,
            exit_addr,
        },
        source,
    )
}

/// Like [`serve_client_proxy`], but routes over an explicit [`ClientRoute`] — the
/// clearnet 2-hop relay loop *or* the single-hop onion lane (dial the exit's
/// `.onion` through Tor SOCKS). The mint, the inner `CONNECT`/presentation, the
/// `200` ACK, and the byte pump are identical on both routes; only the first hop
/// differs.
pub fn serve_client_proxy_route(
    listener: TcpListener,
    route: ClientRoute,
    source: CredentialSource,
) -> thread::JoinHandle<()> {
    let source = Arc::new(Mutex::new(source));
    let route = Arc::new(route);
    // Whether the onion lane has proven reachable this run: until the first
    // successful onion dial, requests use the cold-start retry budget; afterwards
    // they dial once (steady state never sleeps). Per-server, shared across conns.
    let onion_warm = Arc::new(AtomicBool::new(false));
    let inflight = Arc::new(AtomicUsize::new(0));
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut browser) = stream else { continue };
            let _ = browser.set_read_timeout(Some(SOCKET_TIMEOUT));
            let _ = browser.set_write_timeout(Some(SOCKET_TIMEOUT));
            if inflight.fetch_add(1, Ordering::AcqRel) >= MAX_INFLIGHT {
                inflight.fetch_sub(1, Ordering::AcqRel);
                write_status(&mut browser, "503 Service Unavailable");
                continue;
            }
            let permit = InflightGuard::new(Arc::clone(&inflight));
            let source = Arc::clone(&source);
            let route = Arc::clone(&route);
            let onion_warm = Arc::clone(&onion_warm);
            thread::spawn(move || {
                let _permit = permit;
                let _ = handle_client_proxy_conn(browser, &route, &source, &onion_warm);
            });
        }
    })
}

/// Handle one inbound `CONNECT` from the user's client: parse the target, mint a
/// presentation, open the configured route to the exit, ACK the tunnel, and pump
/// bytes.
fn handle_client_proxy_conn(
    mut browser: TcpStream,
    route: &ClientRoute,
    source: &Arc<Mutex<CredentialSource>>,
    onion_warm: &AtomicBool,
) -> Result<()> {
    let target = match read_connect_target(&mut browser)? {
        Some(t) => t,
        None => {
            write_status(&mut browser, "400 Bad Request");
            return Ok(());
        }
    };
    let header = match mint_header(source) {
        Ok(h) => h,
        Err(_) => {
            write_status(&mut browser, "502 Bad Gateway");
            return Ok(());
        }
    };
    let opened = match route {
        ClientRoute::Relay {
            relay_addr,
            exit_addr,
        } => open_through_relay(*relay_addr, *exit_addr, &target, &header),
        ClientRoute::Onion {
            socks_addr,
            exit_onion,
        } => {
            // Cold-start retry only until the lane first proves reachable.
            let cold = !onion_warm.load(Ordering::Acquire);
            let opened = open_through_onion(socks_addr, exit_onion, &target, &header, cold);
            if opened.is_ok() {
                onion_warm.store(true, Ordering::Release);
            }
            opened
        }
    };
    let upstream = match opened {
        Ok(u) => u,
        Err(_) => {
            write_status(&mut browser, "502 Bad Gateway");
            return Ok(());
        }
    };
    browser.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")?;
    browser.flush()?;
    pipe(browser, upstream);
    Ok(())
}

/// Read a `CONNECT` request block and return its `host:port` target. Reads
/// unbuffered up to the blank line so no tunnel bytes are consumed past it.
fn read_connect_target(s: &mut TcpStream) -> Result<Option<String>> {
    let Some(block) = read_http_block(s, 8 * 1024)? else {
        return Ok(None);
    };
    let first = block.lines().next().unwrap_or("");
    let mut parts = first.split_whitespace();
    match (parts.next(), parts.next()) {
        (Some(m), Some(target)) if m.eq_ignore_ascii_case("CONNECT") => {
            Ok(Some(target.to_string()))
        }
        _ => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn split_onion_host_port_parses_and_rejects_malformed() {
        assert_eq!(
            split_onion_host_port("abc.onion:443").unwrap(),
            ("abc.onion".to_string(), 443)
        );
        // Each of these must be rejected (mirrors the proxy's authority guard).
        for bad in [
            "noport",             // no ':'
            ":443",               // empty host
            "abc.onion:notnum",   // non-numeric port
            "abc.onion:99999",    // port > u16
            "user@abc.onion:443", // userinfo smuggling
            "a:b:c.onion:443",    // stray ':' in host
        ] {
            assert!(
                split_onion_host_port(bad).is_err(),
                "{bad:?} must be rejected"
            );
        }
    }

    #[test]
    fn onion_dial_connection_refused_fails_fast_without_sleeping() {
        // A closed loopback port => the SOCKS connect is refused. Even on the
        // cold-start path, onion_dial must return immediately (no retry sleeps) so
        // the lane fails fast instead of stalling 3×2s on a down Tor.
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let dead = l.local_addr().unwrap();
        drop(l);
        let t0 = Instant::now();
        let err = onion_dial(&dead.to_string(), "x.onion", 443, true).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::ConnectionRefused);
        assert!(
            t0.elapsed() < ONION_RETRY_DELAY,
            "ConnectionRefused must not sleep, took {:?}",
            t0.elapsed()
        );
    }
}
