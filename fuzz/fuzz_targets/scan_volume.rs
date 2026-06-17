#![no_main]
//! Fuzz the volume scan/rebuild path (recovery for a lost/corrupt manifest):
//! arbitrary bytes are treated as a volume file and scanned frame by frame. This
//! exercises the frame length prefix, every bounds check, and the seek/advance
//! loop. Invariant: never a panic, hang, or unbounded allocation — only a
//! (possibly empty) rebuilt manifest.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    pass_mgr_core::storage::fuzz::scan_volume(data);
});
