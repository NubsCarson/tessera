//! `RedisTagStore` proves the multi-node double-spend fix: two stores (standing
//! in for two exit replicas) sharing one Redis backend admit a replayed
//! presentation tag **exactly once**, and an unavailable backend fails closed.
//!
//! Hermetic: a tiny in-process mock Redis (just enough RESP for `AUTH`/`PING`/
//! `SET … NX`) backs the test, so it is green in CI without a real Redis. The
//! mock's `SET NX` is atomic via a `Mutex`, exactly as real Redis serializes it —
//! so this proves Tessera's client maps `SET NX` → admit/reject correctly and
//! that two replicas sharing the backend cannot both admit the same tag.

use std::collections::HashSet;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

use tessera_origin::{RedisTagStore, SpentTagStore};

/// Read one RESP command (array of bulk strings) from a client connection.
fn read_command(reader: &mut impl BufRead) -> Option<Vec<Vec<u8>>> {
    let mut header = String::new();
    if reader.read_line(&mut header).ok()? == 0 {
        return None; // clean EOF — client hung up
    }
    let header = header.trim_end();
    let count: usize = header.strip_prefix('*')?.parse().ok()?;
    let mut args = Vec::with_capacity(count);
    for _ in 0..count {
        let mut len_line = String::new();
        reader.read_line(&mut len_line).ok()?;
        let len: usize = len_line.trim_end().strip_prefix('$')?.parse().ok()?;
        let mut body = vec![0u8; len + 2]; // value + trailing CRLF
        reader.read_exact(&mut body).ok()?;
        body.truncate(len);
        args.push(body);
    }
    Some(args)
}

/// Serve one mock-Redis connection: `AUTH`/`PING` are accepted; `SET k v NX`
/// inserts atomically (via the shared set's mutex) and replies `+OK` if the key
/// was new or `$-1` (nil) if it already existed.
fn serve(stream: TcpStream, set: Arc<Mutex<HashSet<String>>>) {
    let mut reader = BufReader::new(stream.try_clone().expect("clone"));
    let mut writer = stream;
    while let Some(args) = read_command(&mut reader) {
        if args.is_empty() {
            continue;
        }
        let cmd = String::from_utf8_lossy(&args[0]).to_ascii_uppercase();
        let reply: &[u8] = match cmd.as_str() {
            "AUTH" => b"+OK\r\n",
            "PING" => b"+PONG\r\n",
            "SET" => {
                let key = String::from_utf8_lossy(&args[1]).to_string();
                let nx = args.iter().any(|a| a.eq_ignore_ascii_case(b"NX"));
                let mut set = set.lock().expect("set mutex");
                if nx && set.contains(&key) {
                    b"$-1\r\n"
                } else {
                    set.insert(key);
                    b"+OK\r\n"
                }
            }
            _ => b"-ERR unknown command\r\n",
        };
        if writer.write_all(reply).is_err() {
            break;
        }
    }
}

/// Spin up a mock Redis on an ephemeral port; returns its `host:port`. The
/// accept loop runs detached for the test's lifetime.
fn mock_redis() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock redis");
    let addr = listener.local_addr().expect("addr").to_string();
    let set = Arc::new(Mutex::new(HashSet::new()));
    thread::spawn(move || {
        for stream in listener.incoming() {
            match stream {
                Ok(s) => {
                    let set = Arc::clone(&set);
                    thread::spawn(move || serve(s, set));
                }
                Err(_) => break,
            }
        }
    });
    addr
}

#[test]
fn shared_backend_admits_a_replay_exactly_once() {
    let addr = mock_redis();
    // Two stores = two exit replicas pointed at the same shared backend.
    let replica_a = RedisTagStore::connect(&addr, None, "tessera:tag:", None).unwrap();
    let replica_b = RedisTagStore::connect(&addr, None, "tessera:tag:", None).unwrap();

    let tag = [7u8; 33];
    // Fresh on replica A -> admit.
    assert!(replica_a.record_if_new(tag).unwrap());
    // The SAME tag replayed against the OTHER replica -> rejected (the hole this
    // store closes: a per-process set would have admitted it again).
    assert!(!replica_b.record_if_new(tag).unwrap());
    // And replayed on the original replica -> still rejected.
    assert!(!replica_a.record_if_new(tag).unwrap());
    // A different tag is still admitted (no false positives).
    assert!(replica_b.record_if_new([8u8; 33]).unwrap());
}

#[test]
fn concurrent_replicas_admit_one_winner() {
    let addr = mock_redis();
    let replicas: Vec<Arc<RedisTagStore>> = (0..2)
        .map(|_| Arc::new(RedisTagStore::connect(&addr, None, "c:", None).unwrap()))
        .collect();

    let tag = [9u8; 33];
    let admits = Arc::new(AtomicUsize::new(0));
    let mut handles = Vec::new();
    for i in 0..16 {
        let store = Arc::clone(&replicas[i % 2]);
        let admits = Arc::clone(&admits);
        handles.push(thread::spawn(move || {
            if store.record_if_new(tag).unwrap() {
                admits.fetch_add(1, Ordering::SeqCst);
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    assert_eq!(
        admits.load(Ordering::SeqCst),
        1,
        "exactly one replica may admit a given tag, even under concurrency"
    );
}

#[test]
fn unavailable_backend_fails_closed() {
    // Bind then drop to obtain an address with nothing listening.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let dead = listener.local_addr().unwrap().to_string();
    drop(listener);
    // Connect must fail at startup rather than silently admitting everything.
    assert!(
        RedisTagStore::connect(&dead, None, "x:", None).is_err(),
        "an unreachable backend must fail closed"
    );
}

#[test]
fn auth_and_ttl_paths_work() {
    let addr = mock_redis();
    // Password (AUTH) + a TTL (SET … NX EX) must both still admit a fresh tag.
    let with_auth = RedisTagStore::connect(&addr, Some("secret".into()), "a:", None).unwrap();
    assert!(with_auth.record_if_new([1u8; 33]).unwrap());
    let with_ttl = RedisTagStore::connect(&addr, None, "ttl:", Some(3600)).unwrap();
    assert!(with_ttl.record_if_new([2u8; 33]).unwrap());
}
