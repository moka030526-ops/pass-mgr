#![no_main]
//! Fuzz the hand-rolled decrypted-frame plaintext parser
//! (`[u32 id_len][id][u32 path_len][path][bytes]`). This is the highest-risk
//! surface for an out-of-bounds read or an over-allocation, so the invariant is
//! strict: arbitrary bytes must only ever produce `Ok`/`Err` — never a panic,
//! hang, or unbounded allocation.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    pass_mgr_core::storage::fuzz::frame(data);
});
