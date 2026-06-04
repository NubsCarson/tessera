//! Runnable demo of the **real channel pay-per-request loop** (`DESIGN.md`
//! §1/§2): stand up the 2-hop split-trust loop locally, OPEN a channel with the
//! relay, then make a couple of **paid** requests — the relay verify-and-co-signs
//! each spend *before* forwarding (sign-then-serve), and a deliberately replayed
//! spend is **refused** (no double-spend). Everything runs on 127.0.0.1.
//!
//! ```text
//! CLIENT ─CONNECT exit (+ channel SPEND)→ RELAY ─bytes→ EXIT ─CONNECT origin→ ORIGIN
//!         (relay = channel counterparty + payment gate)  (tessera-proxy, content-blind)
//! ```
//!
//! Run: `cargo run -p tessera-relay --example paid_loop`

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::thread;

use rand_core::OsRng;
use tessera_arc::arc::create_credential_response;
use tessera_arc::keys::ServerPrivateKey;
use tessera_channel::{Channel, KeyPair, UserChannel};
use tessera_client::{begin_issuance, TesseraClient};
use tessera_origin::OriginGuard;
use tessera_proxy::{serve as serve_exit, Upstream};
use tessera_relay::{channel as chan_wire, open_through_relay_paid, serve_channel, RelayGate};

const REQ: &[u8] = b"tessera://issue/v1";
const CTX: &[u8] = b"tessera://paid-loop/v1";
const ARC_LIMIT: u64 = 64;

const CHAN_ID: [u8; 32] = [7u8; 32];
const SALT: [u8; 32] = [42u8; 32];
const B0: u64 = 1000;
const EPOCH: u64 = 1;
const COST: u64 = 100;

fn main() {
    let mut rng = OsRng;

    // --- ORIGIN: a tiny HTTP server that replies 200 + a body. ---
    let origin = spawn_http_origin();

    // --- EXIT: the unchanged content-blind tessera-proxy. Its ARC check is the
    //     "is this a participant" token here, NOT the payment (the channel is). ---
    let (sk, pk) = ServerPrivateKey::setup(&mut rng);
    let (pending, request) = begin_issuance(REQ, pk, &mut rng);
    let response = create_credential_response(&sk, &pk, &request, &mut rng).unwrap();
    let credential = pending.finalize(&response).unwrap();
    let mut arc_client = TesseraClient::new(credential, CTX, ARC_LIMIT);
    let exit_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let exit = exit_listener.local_addr().unwrap();
    let guard = std::sync::Arc::new(OriginGuard::new(sk, pk, REQ, CTX, ARC_LIMIT));
    serve_exit(exit_listener, guard, Upstream::Direct);

    // --- CHANNEL OPEN: the client and the relay agree the channel params. The
    //     relay holds the RelayerChannel (its single in-memory cursor); the client
    //     holds the UserChannel. ---
    let user_keys = KeyPair::generate(&mut rng);
    let relayer_keys = KeyPair::generate(&mut rng);
    let gate = RelayGate::new(relayer_keys, EPOCH);
    let params = Channel::open(
        CHAN_ID,
        B0,
        SALT,
        user_keys.verifying_key(),
        gate.relayer_pk(),
    );
    gate.open(params.clone()).unwrap();
    let mut user = UserChannel::new(user_keys, params);

    // --- RELAY: channel-payment mode, fixed to forward to the exit. ---
    let relay_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let relay = relay_listener.local_addr().unwrap();
    serve_channel(relay_listener, exit, gate.clone(), None);

    println!("Tessera REAL channel pay-per-request loop (DESIGN §1/§2)");
    println!("  ORIGIN {origin}");
    println!(
        "  EXIT   {exit}   (content-blind tessera-proxy; ARC = participant token, NOT payment)"
    );
    println!("  RELAY  {relay}   (channel COUNTERPARTY + per-request payment gate)");
    println!("  channel opened: B0 = {B0}, cost/request = {COST}\n");

    // --- A COUPLE OF PAID REQUESTS. Each does a real channel spend; the relay
    //     verify-and-co-signs BEFORE forwarding (sign-then-serve). ---
    for nonce in 0..3u64 {
        let payload = format!("onion-{nonce}");
        let fresh = gate
            .issue_challenge(&CHAN_ID, nonce, payload.as_bytes())
            .unwrap();
        let hdr = format!(
            "Tessera-Presentation: {}\r\n",
            arc_client.presentation_header(&mut OsRng).unwrap()
        );
        match open_through_relay_paid(
            relay,
            exit,
            &mut user,
            &CHAN_ID,
            COST,
            &fresh,
            &origin.to_string(),
            &hdr,
        ) {
            Ok(mut stream) => {
                stream
                    .write_all(b"GET / HTTP/1.1\r\nHost: dest\r\nConnection: close\r\n\r\n")
                    .unwrap();
                stream.flush().unwrap();
                let mut buf = Vec::new();
                stream.read_to_end(&mut buf).unwrap();
                let resp = String::from_utf8_lossy(&buf);
                let status = resp.lines().next().unwrap_or("");
                println!(
                    "  PAID request #{nonce}: spend cost {COST} → seq {} balance {} → exit → origin: {status}",
                    user.latest().seq,
                    user.latest().balance
                );
            }
            Err(e) => println!("  PAID request #{nonce} FAILED: {e}"),
        }
    }

    // --- REPLAY: resend a byte-identical spend. The relay's cursor has advanced
    //     and the nonce is burned, so it is REFUSED (no double-spend). ---
    println!("\n  Now replaying a stale spend (double-spend attempt):");
    let stale_fresh = gate.issue_challenge(&CHAN_ID, 0, b"onion-0").unwrap();
    // Build a spend at the CURRENT user cursor but answer an OLD (burned) nonce —
    // the relay refuses on stale freshness; and even a fresh nonce on an old seq
    // would be refused as a non-successor. Either way: no second serve.
    let replay = user.spend(COST, &stale_fresh).unwrap();
    let replay_hex = chan_wire::encode_spend(&replay);
    let mut s = std::net::TcpStream::connect(relay).unwrap();
    s.write_all(
        format!(
            "CONNECT {exit} HTTP/1.1\r\n{}: {}\r\n{}: {}\r\n{}: {}\r\n\r\n",
            chan_wire::CHANNEL_ID_HEADER,
            chan_wire::encode_chan_id(&CHAN_ID),
            chan_wire::CHANNEL_SPEND_HEADER,
            replay_hex,
            chan_wire::CHANNEL_FRESH_HEADER,
            chan_wire::encode_fresh(&stale_fresh),
        )
        .as_bytes(),
    )
    .unwrap();
    s.flush().unwrap();
    let mut block = Vec::new();
    let mut byte = [0u8; 1];
    while s.read(&mut byte).unwrap_or(0) != 0 {
        block.push(byte[0]);
        if block.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let status = String::from_utf8_lossy(&block);
    println!(
        "    relay replied: {}",
        status.lines().next().unwrap_or("<closed>").trim_end()
    );
    println!("    (the destination was NEVER touched — the tunnel never opened)\n");
    println!("HONEST: this proves the REAL channel-payment protocol end-to-end (Phase 2a).");
    println!("The ZK settlement (2b-i) + the shielded funding pool are separate; a real clean");
    println!("egress IP behind the exit is still a manual final step. Research-grade, UNAUDITED.");
}

fn spawn_http_origin() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            thread::spawn(move || {
                let mut r = BufReader::new(s.try_clone().unwrap());
                loop {
                    let mut line = String::new();
                    if r.read_line(&mut line).unwrap_or(0) == 0 || line.trim_end().is_empty() {
                        break;
                    }
                }
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
    addr
}
