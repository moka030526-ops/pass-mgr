#![no_main]
//! Fuzz the decrypted document-archive parser (the hand-rolled, length-prefixed
//! binary format). This is the highest-risk surface for an out-of-bounds read or
//! an over-allocation, so the invariant is strict: arbitrary bytes must only ever
//! produce `Ok`/`Err` — never a panic, hang, or unbounded allocation.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    pass_mgr::vault::fuzz::archive(data);
});
