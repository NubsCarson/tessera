#![no_main]
//! S6 — the relay's outer-header channel decoders must reject arbitrary,
//! attacker-controlled wire input without panicking.
//!
//! `decode_fresh` / `decode_spend` / `decode_cosigned` / `decode_chan_id` parse
//! hex strings straight off untrusted request headers (the `Tessera-Fresh`,
//! `-Spend`, `-Cosigned`, `-Channel-Id` outer headers). Any panic here is a
//! remote DoS, so every one of them must return an `Err` — never abort — on
//! malformed input of any length or byte content.
use libfuzzer_sys::fuzz_target;
use tessera_relay::channel::{decode_chan_id, decode_cosigned, decode_fresh, decode_spend};

fuzz_target!(|data: &[u8]| {
    // Feed arbitrary bytes as a string (lossy so non-UTF-8 is still exercised —
    // the decoders take `&str` and parse hex, so this covers non-hex, wrong
    // length, truncated, and oversized inputs alike).
    let s = String::from_utf8_lossy(data);
    let _ = decode_fresh(&s);
    let _ = decode_spend(&s);
    let _ = decode_cosigned(&s);
    let _ = decode_chan_id(&s);
});
