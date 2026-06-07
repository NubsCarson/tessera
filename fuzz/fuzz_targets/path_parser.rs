#![no_main]
//! The onion-authority parser on the **default client→exit path**
//! (`split_onion_host_port`) decodes an untrusted `ONION:PORT` target — from a
//! signed directory entry or the `TESSERA_EXIT_ONION` env. It must reject any
//! arbitrary input without panicking (a panic here is a client-side DoS).
use libfuzzer_sys::fuzz_target;
use tessera_relay::split_onion_host_port;

fuzz_target!(|data: &[u8]| {
    // Feed it the way config does: as a (lossy) UTF-8 string, raw and trimmed.
    let s = String::from_utf8_lossy(data);
    let _ = split_onion_host_port(&s);
    let _ = split_onion_host_port(s.trim());
});
