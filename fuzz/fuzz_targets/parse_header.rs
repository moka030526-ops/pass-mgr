#![no_main]
//! Fuzz the vault-file header parser: magic, version, Argon2-parameter bounds.
//! Invariant: arbitrary bytes must only ever produce `Ok`/`Err` — never a panic.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    pass_mgr::vault::fuzz::header(data);
});
