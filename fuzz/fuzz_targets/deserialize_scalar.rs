#![no_main]
//! `deserialize_scalar` must total-function over arbitrary bytes: never panic.
use libfuzzer_sys::fuzz_target;
use tessera_arc::group::deserialize_scalar;

fuzz_target!(|data: &[u8]| {
    let _ = deserialize_scalar(data);
});
