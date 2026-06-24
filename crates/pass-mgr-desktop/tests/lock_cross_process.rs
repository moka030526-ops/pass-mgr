//! Cross-PROCESS single-writer lock test.
//!
//! The core's `single_writer_lock_blocks_second_writable_open` takes the second lock via
//! a different fd in ONE process, but `fs::File::try_lock` is per-open-file-description,
//! so genuine inter-process semantics can differ from same-process behaviour. Here a REAL
//! second process holds the writable lock (via the hidden `__holdlock` subcommand) while
//! this process asserts that a writable open fails fast with `Locked`, a read-only open
//! still succeeds, and the lock is released when that process exits. A corrupted vault
//! from a missed cross-process lock would be catastrophic, so prove the real threat model.
//!
//! Compiled only with the `fault-injection` feature (which builds `__holdlock` into the
//! spawned binary), alongside the other subprocess tests:
//!     cargo test -p pass-mgr --features pass-mgr/fault-injection --test lock_cross_process
#![cfg(feature = "fault-injection")]

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use pass_mgr::crypto::KdfParams;
use pass_mgr::vault::{OpenVault, VaultError};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_pass-mgr")
}

fn tmp_dir(tag: &str) -> PathBuf {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    let d = std::env::temp_dir().join(format!("pmlock-{tag}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn vault_pmv(dir: &Path) -> PathBuf {
    dir.join("vault.pmv")
}

#[test]
fn a_second_process_holding_the_writer_lock_blocks_a_writable_open() {
    let dir = tmp_dir("xproc");
    // Create the vault (fast KDF) with the fixed a/b passwords `__holdlock` uses, then drop
    // it so its own writer lock is released before the child takes it.
    {
        let params = KdfParams { m_cost: 256, t_cost: 1, p_cost: 1 };
        OpenVault::create(vault_pmv(&dir), b"a", b"b", params).unwrap();
    }

    // Spawn a REAL second process that opens the vault --write and holds the lock until we
    // close its stdin.
    let mut child = Command::new(bin())
        .args(["__holdlock", dir.to_str().unwrap()])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn __holdlock");

    // Wait until the child confirms it actually holds the lock.
    let mut reader = BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();
    reader.read_line(&mut line).expect("read child signal");
    assert_eq!(line.trim(), "LOCKED", "child should report it holds the writer lock");

    // While the child holds the lock, a writable open from THIS process must fail fast.
    let err = OpenVault::open(vault_pmv(&dir), b"a", b"b")
        .err()
        .expect("a writable open must fail while another process holds the lock");
    assert!(matches!(err, VaultError::Locked), "expected Locked, got {err:?}");

    // A read-only open does NOT take the lock, so it still succeeds concurrently.
    OpenVault::open_read_only(vault_pmv(&dir), b"a", b"b")
        .expect("a read-only open is allowed alongside a writer");

    // Release: close the child's stdin (EOF) so it drops the handle and exits.
    drop(child.stdin.take());
    let status = child.wait().expect("await child");
    assert!(status.success(), "child should exit cleanly after releasing the lock");

    // The lock is gone: a writable open now succeeds.
    OpenVault::open(vault_pmv(&dir), b"a", b"b")
        .expect("a writable open succeeds after the lock is freed");

    std::fs::remove_dir_all(&dir).ok();
}
