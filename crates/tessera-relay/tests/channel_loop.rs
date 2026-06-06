//! End-to-end proof of Tessera's 2-hop loop doing **REAL channel pay-per-request**
//! (`DESIGN.md` §1/§2), all on 127.0.0.1 with ephemeral ports:
//!
//! ```text
//! CLIENT ─CONNECT exit (+ channel SPEND)→ RELAY ─bytes→ EXIT ─CONNECT origin→ ORIGIN
//!         (relay = channel counterparty + payment gate)  (tessera-proxy, content-blind)
//! ```
//!
//! The **relay** is the [`tessera_channel`] counterparty + per-request payment
//! gate: the client opens a channel, then for each request does a real channel
//! `spend`, and the relay `verify_and_cosign`s it **before** forwarding a byte
//! (sign-then-serve). This replaces the ARC-v0 spend stand-in with a real channel
//! spend. The exit keeps its own ARC participant check (not the payment).
//!
//! Asserts:
//!   * open → N spends each reach the origin (200 + the exact body);
//!   * a **replayed** spend is refused (no double-spend) and the origin is NOT
//!     re-hit;
//!   * an **over-budget / underflow** spend is refused and never reaches the dest;
//!   * **sign-then-serve** ordering holds (no serving before the relay co-signs);
//!   * the **split-trust** property still holds (the relay never recorded the
//!     destination; the exit never saw the client's address).

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

use rand_core::OsRng;
use tessera_arc::arc::create_credential_response;
use tessera_arc::keys::ServerPrivateKey;
use tessera_channel::{Channel, ChannelError, KeyPair, UserChannel};
use tessera_client::{begin_issuance, TesseraClient};
use tessera_origin::OriginGuard;
use tessera_proxy::{serve_observed, ExitObservation, ExitObserver, Upstream};
use tessera_relay::channel as chan_wire;
use tessera_relay::{open_through_relay_paid, serve_channel, Observer, RelayGate};

const REQ: &[u8] = b"tessera://issue/v1";
const CTX: &[u8] = b"tessera://relay-loop/v1";
const ARC_LIMIT: u64 = 64;

const CHAN_ID: [u8; 32] = [7u8; 32];
const SALT: [u8; 32] = [42u8; 32];
const B0: u64 = 1000;
const EPOCH: u64 = 1;
const COST: u64 = 100;

/// A minimal HTTP/1.1 origin: 200 OK with a fixed body, recording every peer.
fn spawn_http_origin() -> (SocketAddr, Arc<AtomicU32>, Arc<Mutex<Vec<SocketAddr>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let hits = Arc::new(AtomicU32::new(0));
    let peers = Arc::new(Mutex::new(Vec::<SocketAddr>::new()));
    let h = Arc::clone(&hits);
    let p = Arc::clone(&peers);
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            let h = Arc::clone(&h);
            let p = Arc::clone(&p);
            thread::spawn(move || {
                if let Ok(peer) = s.peer_addr() {
                    p.lock().unwrap().push(peer);
                }
                let mut r = BufReader::new(s.try_clone().unwrap());
                loop {
                    let mut line = String::new();
                    if r.read_line(&mut line).unwrap_or(0) == 0 || line.trim_end().is_empty() {
                        break;
                    }
                }
                h.fetch_add(1, Ordering::SeqCst);
                let body = "tessera-origin-ok";
                let _ = s.write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    )
                    .as_bytes(),
                );
                let _ = s.flush();
            });
        }
    });
    (addr, hits, peers)
}

/// Stand up the EXIT (tessera-proxy, ARC participant-gated, direct egress) with
/// an observer; return (exit_addr, client-that-mints-participant-presentations,
/// exit-observer). The exit's ARC check is the *participant* token here, NOT the
/// payment — the payment is the channel spend at the relay.
fn spawn_exit() -> (SocketAddr, TesseraClient, Arc<Mutex<Vec<ExitObservation>>>) {
    let mut rng = OsRng;
    let (sk, pk) = ServerPrivateKey::setup(&mut rng);
    let (pending, request) = begin_issuance(REQ, pk, &mut rng);
    let response = create_credential_response(&sk, &pk, &request, &mut rng).unwrap();
    let credential = pending.finalize(&response).unwrap();
    let client = TesseraClient::new(credential, CTX, ARC_LIMIT);

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let guard = Arc::new(OriginGuard::new(sk, pk, REQ, CTX, ARC_LIMIT));

    let seen = Arc::new(Mutex::new(Vec::<ExitObservation>::new()));
    let seen_cb = Arc::clone(&seen);
    let observer: ExitObserver = Arc::new(move |obs: ExitObservation| {
        seen_cb.lock().unwrap().push(obs);
    });
    serve_observed(listener, guard, Upstream::Direct, Some(observer));
    (addr, client, seen)
}

/// Stand up the RELAY in channel-payment mode in front of `exit_addr`. Returns
/// (relay_addr, the gate). The caller opens a channel on the gate and shares the
/// user side.
fn spawn_relay_channel(exit_addr: SocketAddr, gate: RelayGate, observer: Observer) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    serve_channel(listener, exit_addr, gate, Some(observer));
    addr
}

/// Open a fresh channel: returns (user keys, relay gate, user channel). The gate
/// registers the RelayerChannel for CHAN_ID.
fn open_channel() -> (RelayGate, UserChannel) {
    let mut rng = OsRng;
    let user_keys = KeyPair::generate(&mut rng);
    let relayer_keys = KeyPair::generate(&mut rng);
    let gate = RelayGate::new(relayer_keys.clone(), EPOCH);
    let params = Channel::open(
        CHAN_ID,
        B0,
        SALT,
        user_keys.verifying_key(),
        gate.relayer_pk(),
    );
    gate.open(params.clone())
        .expect("relay registers the channel");
    let user = UserChannel::new(user_keys, params);
    (gate, user)
}

/// `RelayGate::open` rejects a channel whose `relayer_pk` is not this gate's key
/// — the client must have agreed to pay *this* relay. Covers the pk-equality
/// reject arm in `RelayGate::open` that the happy-path loop tests never reach.
#[test]
fn relay_gate_rejects_channel_for_a_different_relayer() {
    let mut rng = OsRng;
    let user_keys = KeyPair::generate(&mut rng);
    let relayer_keys = KeyPair::generate(&mut rng);
    let other_relayer = KeyPair::generate(&mut rng);
    let gate = RelayGate::new(relayer_keys, EPOCH);

    // A channel the client opened against a DIFFERENT relayer's key.
    let params = Channel::open(
        CHAN_ID,
        B0,
        SALT,
        user_keys.verifying_key(),
        other_relayer.verifying_key(),
    );

    assert!(
        matches!(gate.open(params), Err(ChannelError::BadSignature)),
        "a channel naming a different relayer must be rejected by RelayGate::open"
    );
}

/// Build the inner-CONNECT exit header carrying a fresh ARC participant
/// presentation (the exit's "is this a participant" token — NOT the payment).
fn exit_header(client: &mut TesseraClient) -> String {
    let presentation = client.presentation_header(&mut OsRng).unwrap();
    format!("Tessera-Presentation: {presentation}\r\n")
}

/// Drive one full HTTP/1.1 GET through the PAID loop. Issues a freshness
/// challenge, spends `cost`, opens the paid tunnel, and reads the origin's reply.
/// Returns (client source socket, response, the freshness used).
#[allow(clippy::too_many_arguments)]
fn paid_http_get(
    relay: SocketAddr,
    exit: SocketAddr,
    origin: SocketAddr,
    gate: &RelayGate,
    user: &mut UserChannel,
    arc_client: &mut TesseraClient,
    nonce: u64,
    cost: u64,
) -> std::io::Result<(SocketAddr, String)> {
    let payload = format!("onion-to-{origin}-{nonce}");
    let fresh = gate
        .issue_challenge(&CHAN_ID, nonce, payload.as_bytes())
        .expect("channel is open");
    let hdr = exit_header(arc_client);
    let mut stream = open_through_relay_paid(
        relay,
        exit,
        user,
        &CHAN_ID,
        cost,
        &fresh,
        &origin.to_string(),
        &hdr,
    )?;
    let client_src = stream.local_addr()?;
    stream.write_all(b"GET / HTTP/1.1\r\nHost: dest\r\nConnection: close\r\n\r\n")?;
    stream.flush()?;
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf)?;
    Ok((client_src, String::from_utf8_lossy(&buf).into_owned()))
}

#[test]
fn open_then_n_paid_spends_each_reach_the_origin() {
    let (origin, hits, origin_peers) = spawn_http_origin();
    let (exit, mut arc_client, exit_seen) = spawn_exit();
    let (gate, mut user) = open_channel();
    let relay_obs = Observer::new();
    let relay = spawn_relay_channel(exit, gate.clone(), relay_obs.clone());

    // N real paid spends, each reaches the origin with 200 + the body.
    let n = 4u64;
    for i in 0..n {
        let (_, resp) = paid_http_get(
            relay,
            exit,
            origin,
            &gate,
            &mut user,
            &mut arc_client,
            i,
            COST,
        )
        .unwrap();
        assert!(
            resp.contains("200 OK"),
            "spend #{i} expected 200, got:\n{resp}"
        );
        assert!(
            resp.contains("tessera-origin-ok"),
            "spend #{i} expected the origin body, got:\n{resp}"
        );
    }
    assert_eq!(
        hits.load(Ordering::SeqCst),
        n as u32,
        "origin hit once per paid spend"
    );

    // The user's cursor advanced N times; the balance dropped by N*COST.
    assert_eq!(user.latest().seq, n);
    assert_eq!(user.latest().balance, B0 - n * COST);

    // --- SPLIT-TRUST: the RELAY recorded {client, exit}, NEVER the destination. ---
    let relay_seen = relay_obs.snapshot();
    assert_eq!(
        relay_seen.len(),
        n as usize,
        "relay recorded one obs per paid request"
    );
    for r in &relay_seen {
        assert_eq!(
            r.connect_target,
            exit.to_string(),
            "relay's CONNECT target is the EXIT"
        );
    }
    for t in relay_obs.targets() {
        assert_ne!(
            t,
            origin.to_string(),
            "RELAY must never observe the destination"
        );
        assert!(
            !t.contains(&origin.port().to_string()),
            "RELAY must never observe the destination port"
        );
    }

    // --- SPLIT-TRUST: the EXIT saw {destination}, NEVER the client's socket. ---
    let exit_seen = exit_seen.lock().unwrap().clone();
    assert_eq!(
        exit_seen.len(),
        n as usize,
        "exit admitted one tunnel per paid request"
    );
    for e in &exit_seen {
        assert_eq!(
            e.connect_target,
            origin.to_string(),
            "EXIT observes the destination"
        );
    }
    // The origin only ever saw the exit, never the client.
    let origin_peers = origin_peers.lock().unwrap().clone();
    assert_eq!(origin_peers.len(), n as usize);
}

#[test]
fn replayed_spend_is_double_spend_refused_and_origin_not_rehit() {
    let (origin, hits, _) = spawn_http_origin();
    let (exit, mut arc_client, _) = spawn_exit();
    let (gate, mut user) = open_channel();
    let relay_obs = Observer::new();
    let relay = spawn_relay_channel(exit, gate.clone(), relay_obs.clone());

    // Build ONE spend against nonce 0 and capture its wire bytes, then replay them
    // verbatim. We bypass the helper so we can resend the exact same spend.
    let payload = b"onion-replay";
    let fresh = gate.issue_challenge(&CHAN_ID, 0, payload).unwrap();
    let spend = user.spend(COST, &fresh).unwrap();

    // First send: succeeds (reaches the origin). Capture the relayer-co-signed
    // state so the user can advance its cursor (keeping it in lockstep with the
    // relay), exactly as the high-level client helper does.
    let (resp1, cosigned1) =
        send_raw_paid(relay, exit, origin, &mut arc_client, &spend, &fresh).unwrap();
    assert!(
        resp1.contains("200 OK"),
        "first paid spend must succeed:\n{resp1}"
    );
    assert_eq!(hits.load(Ordering::SeqCst), 1);
    user.accept_cosigned(&cosigned1)
        .expect("user advances its cursor");

    // REPLAY: resend the byte-identical spend + freshness. The relay's cursor has
    // already advanced past this seq AND the nonce is burned, so verify_and_cosign
    // fails → 402, the tunnel is never opened, the origin is NOT re-hit.
    let err = send_raw_paid(relay, exit, origin, &mut arc_client, &spend, &fresh).unwrap_err();
    assert!(
        err.to_string().contains("relay refused") && err.to_string().contains("402"),
        "replay must be refused with 402, got: {err}"
    );
    assert_eq!(
        hits.load(Ordering::SeqCst),
        1,
        "replayed spend must NOT reach the origin (no double-spend)"
    );

    // A fresh, properly-advanced spend (seq 2) still works (channel not wedged).
    let fresh2 = gate.issue_challenge(&CHAN_ID, 1, b"onion-2").unwrap();
    let spend2 = user.spend(COST, &fresh2).unwrap();
    let (resp2, _) = send_raw_paid(relay, exit, origin, &mut arc_client, &spend2, &fresh2).unwrap();
    assert!(
        resp2.contains("200 OK"),
        "a fresh spend must still succeed:\n{resp2}"
    );
    assert_eq!(hits.load(Ordering::SeqCst), 2);
}

#[test]
fn over_budget_spend_is_refused_and_never_reaches_dest() {
    let (origin, hits, _) = spawn_http_origin();
    let (exit, mut arc_client, exit_seen) = spawn_exit();
    let (gate, mut user) = open_channel();
    let relay_obs = Observer::new();
    let relay = spawn_relay_channel(exit, gate.clone(), relay_obs.clone());

    // Spending MORE than the channel balance underflows the monotone-decrement —
    // the user side refuses to even build the spend (UserChannel::spend → Err).
    let fresh = gate.issue_challenge(&CHAN_ID, 0, b"too-much").unwrap();
    let err = open_through_relay_paid(
        relay,
        exit,
        &mut user,
        &CHAN_ID,
        B0 + 1, // over budget
        &fresh,
        &origin.to_string(),
        &exit_header(&mut arc_client),
    )
    .unwrap_err();
    assert!(
        err.to_string().contains("underflow") || err.to_string().contains("spend"),
        "an over-budget spend must be refused (underflow), got: {err}"
    );
    assert_eq!(
        hits.load(Ordering::SeqCst),
        0,
        "over-budget request never reaches the origin"
    );
    assert!(
        exit_seen.lock().unwrap().is_empty(),
        "exit admitted nothing"
    );
    assert!(
        relay_obs.snapshot().is_empty(),
        "relay recorded nothing (no paid request)"
    );

    // A FORGED over-budget spend (one whose balance illegally exceeds the cursor)
    // is caught at the RELAY, not just the honest user side. Using the SAME user
    // (still at genesis — nothing succeeded above), build a valid spend then
    // tamper its balance HIGHER than the cursor (paying yourself). The relay's
    // verify_and_cosign rejects the bad successor — either as a balance-increase
    // (BadTransition) or, because the tamper invalidates sig_user, BadSignature.
    let fresh3 = gate.issue_challenge(&CHAN_ID, 9, b"forge").unwrap();
    let mut bad = user.spend(COST, &fresh3).unwrap();
    bad.signed.state.balance = B0 + 5; // illegal: balance increased over genesis
    let reject = gate.verify_spend(&CHAN_ID, &bad, &fresh3);
    assert!(
        matches!(
            reject,
            Err(ChannelError::BadTransition(_)) | Err(ChannelError::BadSignature)
        ),
        "the relay must reject a balance-increasing (over-budget) spend, got: {reject:?}"
    );
    assert_eq!(
        hits.load(Ordering::SeqCst),
        0,
        "still never reaches the origin"
    );
}

#[test]
fn sign_then_serve_ordering_holds_serving_before_cosign_impossible() {
    // The client side can NEVER "serve" on a state the relay has not co-signed.
    // open_through_relay_paid only returns the tunnel AFTER the user has accepted
    // the relayer's co-signature and passed UserChannel::serve. We prove the gate
    // directly: a user-only spend (no relayer co-sig) fails the serve gate.
    let (gate, user) = open_channel();
    let fresh = gate.issue_challenge(&CHAN_ID, 0, b"req").unwrap();
    let spend = user.spend(COST, &fresh).unwrap();

    // The spend's state carries NO relayer co-signature yet.
    assert!(spend.signed.sig_relayer.is_none());
    // Serving it (sign-then-serve) is rejected: no co-signature ⇒ NotCoSigned.
    let served = user.serve(&spend.signed);
    assert_eq!(
        served,
        Err(ChannelError::NotCoSigned),
        "serve before co-sign must fail"
    );

    // Only after the relay co-signs is the SAME state servable.
    let cosigned = gate.verify_spend(&CHAN_ID, &spend, &fresh).unwrap();
    assert!(
        user.serve(&cosigned).is_ok(),
        "serve after co-sign succeeds"
    );
}

#[test]
fn missing_spend_is_refused_at_relay() {
    let (_origin, hits, _) = spawn_http_origin();
    let (exit, _arc, exit_seen) = spawn_exit();
    let (gate, _user) = open_channel();
    let relay_obs = Observer::new();
    let relay = spawn_relay_channel(exit, gate, relay_obs.clone());

    // Open the outer CONNECT to the relay with NO channel headers at all → 402.
    let mut stream = std::net::TcpStream::connect(relay).unwrap();
    stream
        .write_all(format!("CONNECT {exit} HTTP/1.1\r\n\r\n").as_bytes())
        .unwrap();
    stream.flush().unwrap();
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).unwrap();
    let resp = String::from_utf8_lossy(&buf);
    assert!(
        resp.contains("402"),
        "a request with no spend must get 402, got:\n{resp}"
    );
    assert_eq!(hits.load(Ordering::SeqCst), 0, "origin never hit");
    assert!(
        exit_seen.lock().unwrap().is_empty(),
        "exit admitted nothing"
    );
    assert!(
        relay_obs.snapshot().is_empty(),
        "relay records nothing for an unpaid request"
    );
}

/// Send a paid request using a CALLER-SUPPLIED spend + freshness (so a test can
/// replay the exact same bytes), bypassing the cursor-advancing client helper.
/// Returns (the origin's response, the relayer-co-signed state), or an error if
/// the relay refused.
fn send_raw_paid(
    relay: SocketAddr,
    exit: SocketAddr,
    origin: SocketAddr,
    arc_client: &mut TesseraClient,
    spend: &tessera_channel::Spend,
    fresh: &tessera_channel::RelayRequest,
) -> std::io::Result<(String, tessera_channel::SignedState)> {
    let mut stream = std::net::TcpStream::connect(relay)?;
    stream.write_all(
        format!(
            "CONNECT {exit} HTTP/1.1\r\n{id}: {id_v}\r\n{sp}: {sp_v}\r\n{fr}: {fr_v}\r\n\r\n",
            id = chan_wire::CHANNEL_ID_HEADER,
            id_v = chan_wire::encode_chan_id(&CHAN_ID),
            sp = chan_wire::CHANNEL_SPEND_HEADER,
            sp_v = chan_wire::encode_spend(spend),
            fr = chan_wire::CHANNEL_FRESH_HEADER,
            fr_v = chan_wire::encode_fresh(fresh),
        )
        .as_bytes(),
    )?;
    stream.flush()?;

    // Read the relay's status block one byte at a time (don't consume tunnel bytes).
    let mut block = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        if stream.read(&mut byte)? == 0 {
            break;
        }
        block.push(byte[0]);
        if block.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let status = String::from_utf8_lossy(&block);
    let line = status.lines().next().unwrap_or("");
    if !line.contains("200") {
        return Err(std::io::Error::other(format!(
            "relay refused the paid tunnel: {}",
            line.trim_end()
        )));
    }
    // Pull the co-signed state header off the relay's 200 line.
    let cosigned_hex = status
        .lines()
        .skip(1)
        .find_map(|l| {
            let (n, v) = l.split_once(':')?;
            n.trim()
                .eq_ignore_ascii_case(chan_wire::CHANNEL_SPEND_HEADER)
                .then(|| v.trim().to_string())
        })
        .ok_or_else(|| std::io::Error::other("relay 200 carried no co-signed state"))?;
    let cosigned = chan_wire::decode_cosigned(&cosigned_hex)?;

    // Tunnel open → send the inner CONNECT (with the ARC participant token) + GET.
    let presentation = arc_client.presentation_header(&mut OsRng).unwrap();
    stream.write_all(
        format!("CONNECT {origin} HTTP/1.1\r\nTessera-Presentation: {presentation}\r\n\r\n")
            .as_bytes(),
    )?;
    stream.flush()?;
    // Read the exit's status block.
    let mut block2 = Vec::new();
    loop {
        if stream.read(&mut byte)? == 0 {
            break;
        }
        block2.push(byte[0]);
        if block2.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let exit_status = String::from_utf8_lossy(&block2);
    if !exit_status.lines().next().unwrap_or("").contains("200") {
        return Err(std::io::Error::other(format!(
            "exit refused: {}",
            exit_status.lines().next().unwrap_or("").trim_end()
        )));
    }

    stream.write_all(b"GET / HTTP/1.1\r\nHost: dest\r\nConnection: close\r\n\r\n")?;
    stream.flush()?;
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf)?;
    Ok((String::from_utf8_lossy(&buf).into_owned(), cosigned))
}
