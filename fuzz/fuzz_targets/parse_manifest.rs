#![no_main]
//! Fuzz the decrypted-manifest parser (the JSON document index, parsed after a
//! manifest blob is decrypted). Invariant: arbitrary bytes must only ever
//! produce `Ok`/`Err` — never a panic, hang, or unbounded allocation.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    pass_mgr_core::storage::fuzz::manifest(data);
});
