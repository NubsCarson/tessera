#![no_main]
//! `deserialize_element` must total-function over arbitrary bytes: never panic.
use libfuzzer_sys::fuzz_target;
use tessera_arc::group::deserialize_element;

fuzz_target!(|data: &[u8]| {
    let _ = deserialize_element(data);
});
