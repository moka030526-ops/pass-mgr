//! Force-kill / abrupt-shutdown crash-recovery tests against the REAL binary.
//!
//! Each test spawns `pass-mgr __crashop <scenario> <dir>` (a hidden, test-only
//! subcommand) with `PMVAULT_CRASH_AT=<label>` set, so the child performs a real
//! vault operation and is aborted (`std::process::abort` — no `Drop`, no flush,
//! like a `SIGKILL`/power cut) at the chosen commit step. The parent then reopens
//! the vault in-process and asserts it recovered: it is openable, the previously
//! committed document survives, and at most the in-flight operation was lost.
//!
//! Compiled only with the `fault-injection` feature:
//!     cargo test --features fault-injection --test crash_recovery
#![cfg(feature = "fault-injection")]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use pass_mgr::vault::OpenVault;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_pass-mgr")
}

/// A unique throwaway vault directory.
fn tmp_dir(tag: &str) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    let d = std::env::temp_dir().join(format!("pmcrash-{tag}-{nanos}-{n}"));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn vault_pmv(dir: &Path) -> PathBuf {
    dir.join("vault.pmv")
}

/// Run `__crashop <scenario> <dir>` with an optional crash label. Returns whether
/// the child exited successfully (false == aborted by the fault point / errored).
fn run_crashop(dir: &Path, scenario: &str, crash_at: Option<&str>) -> bool {
    let mut cmd = Command::new(bin());
    cmd.args(["__crashop", scenario, dir.to_str().unwrap()]);
    if let Some(label) = crash_at {
        cmd.env("PMVAULT_CRASH_AT", label);
    }
    cmd.status().expect("spawn __crashop").success()
}

/// The content `setup` stores as the referenced document (doc-one == 0xA1 x600).
fn doc_one() -> Vec<u8> {
    vec![0xA1u8; 600]
}
/// The content the clean `adddoc` stores (doc-two == 0xB2 x600).
fn doc_two() -> Vec<u8> {
    vec![0xB2u8; 600]
}

/// Bytes of every record-referenced document, sorted, for multi-doc assertions.
fn all_referenced_docs(v: &OpenVault) -> Vec<Vec<u8>> {
    let mut out: Vec<Vec<u8>> = v
        .vault
        .trust_wills
        .iter()
        .filter_map(|t| t.file.as_ref())
        .map(|id| v.read_document(id).unwrap()[..].to_vec())
        .collect();
    out.sort();
    out
}

/// The bytes of the single record-referenced document (doc-one from `setup`).
fn referenced_doc(v: &OpenVault) -> Vec<u8> {
    let tw = v.vault.trust_wills.iter().find(|t| t.file.is_some()).expect("a trust/will with a doc");
    let id = tw.file.clone().unwrap();
    v.read_document(&id).unwrap()[..].to_vec()
}

/// Create a vault (a/b) with one committed, referenced document.
fn setup(dir: &Path) {
    assert!(run_crashop(dir, "setup", None), "setup should succeed");
}

#[test]
fn force_kill_after_volume_append_recovers() {
    let dir = tmp_dir("vol");
    setup(&dir);
    // Add a 2nd doc; with the tiny cap it rolls into a NEW partition (vol.1), and we
    // abort right after its volume frame is durable but before the manifest commit.
    // On reopen vol.1 is rebuilt from its volume, recovering the frame as an
    // UNREFERENCED orphan (the record link + save never happened) — harmless; the
    // vault stays consistent and openable.
    assert!(!run_crashop(&dir, "adddoc", Some("put.after_append")), "child must abort");
    let v = OpenVault::open(vault_pmv(&dir), b"a", b"b").expect("vault recovers + lock released");
    assert_eq!(referenced_doc(&v), doc_one(), "committed doc intact");
    drop(v);
    // The store is consistent enough that a fresh add still works.
    assert!(run_crashop(&dir, "adddoc", None), "subsequent add succeeds");
    let v = OpenVault::open(vault_pmv(&dir), b"a", b"b").unwrap();
    assert_eq!(v.vault.trust_wills.iter().filter(|t| t.file.is_some()).count(), 2);
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn force_kill_after_manifest_commit_recovers() {
    let dir = tmp_dir("man");
    setup(&dir);
    // Abort after the 2nd doc's manifest committed but before the vault save: the
    // doc is a harmless orphan (unreferenced); the vault stays openable.
    assert!(!run_crashop(&dir, "adddoc", Some("put.after_commit")), "child must abort");
    let v = OpenVault::open(vault_pmv(&dir), b"a", b"b").expect("vault recovers");
    assert_eq!(referenced_doc(&v), doc_one());
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn force_kill_during_vault_save_recovers() {
    let dir = tmp_dir("save");
    setup(&dir);
    // Abort at the vault.pmv rename during the post-add save: the old vault stands.
    assert!(!run_crashop(&dir, "adddoc", Some("vault.rename")), "child must abort");
    let v = OpenVault::open(vault_pmv(&dir), b"a", b"b").expect("old vault intact");
    assert_eq!(referenced_doc(&v), doc_one());
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn force_kill_mid_rekey_rolls_forward() {
    let dir = tmp_dir("rekey");
    setup(&dir);
    // Abort mid commit_rekey (new volume swapped in, old manifest+vault still live,
    // .rekey present WITH the READY marker). Recovery must roll forward to the new
    // passwords without losing the document.
    assert!(!run_crashop(&dir, "rekey", Some("rekey.after_volume")), "child must abort");
    assert!(OpenVault::open(vault_pmv(&dir), b"a", b"b").is_err(), "old passwords no longer open it");
    let v = OpenVault::open(vault_pmv(&dir), b"c", b"d").expect("rolled forward to the new passwords");
    assert_eq!(referenced_doc(&v), doc_one(), "document survives the rekey");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn force_kill_mid_rekey_after_manifest_rolls_forward() {
    let dir = tmp_dir("rekey2");
    setup(&dir);
    // A later crash point: volume + manifest swapped, vault.pmv still old.
    assert!(!run_crashop(&dir, "rekey", Some("rekey.after_manifest")), "child must abort");
    assert!(OpenVault::open(vault_pmv(&dir), b"a", b"b").is_err());
    let v = OpenVault::open(vault_pmv(&dir), b"c", b"d").expect("rolled forward");
    assert_eq!(referenced_doc(&v), doc_one());
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn force_kill_mid_rekey_after_vault_rolls_forward() {
    let dir = tmp_dir("rekey3");
    setup(&dir);
    // The last commit step: volume + manifest + vault.pmv all swapped, but `.rekey`
    // not yet removed. The next open re-runs the (idempotent) commit and finishes.
    assert!(!run_crashop(&dir, "rekey", Some("rekey.after_vault")), "child must abort");
    let v = OpenVault::open(vault_pmv(&dir), b"c", b"d").expect("rolled forward (cleanup re-run)");
    assert_eq!(referenced_doc(&v), doc_one());
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn force_kill_during_vault_write_recovers() {
    let dir = tmp_dir("vwrite");
    setup(&dir);
    // Abort before the post-add vault temp-write even begins: the old vault stands.
    assert!(!run_crashop(&dir, "adddoc", Some("vault.write")), "child must abort");
    let v = OpenVault::open(vault_pmv(&dir), b"a", b"b").expect("old vault intact");
    assert_eq!(referenced_doc(&v), doc_one());
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn multi_partition_rekey_force_kill_rolls_forward() {
    let dir = tmp_dir("multirekey");
    setup(&dir); // doc-one in partition 0
    assert!(run_crashop(&dir, "adddoc", None), "clean add of doc-two -> partition 1");
    // Rekey re-encrypts BOTH documents across BOTH partitions; abort mid-commit.
    assert!(!run_crashop(&dir, "rekey", Some("rekey.after_manifest")), "child must abort");
    assert!(OpenVault::open(vault_pmv(&dir), b"a", b"b").is_err(), "old passwords gone");
    let v = OpenVault::open(vault_pmv(&dir), b"c", b"d").expect("rolled forward to new passwords");
    assert_eq!(all_referenced_docs(&v), vec![doc_one(), doc_two()], "both docs survive across partitions");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn force_kill_during_recovery_is_idempotent() {
    let dir = tmp_dir("recrash");
    setup(&dir);
    // 1) Abort mid-rekey -> a pending `.rekey` (with READY) is left on disk.
    assert!(!run_crashop(&dir, "rekey", Some("rekey.after_volume")), "rekey aborts");
    // 2) Re-open (which runs recover_pending_rekey) but abort DURING the
    //    roll-forward at a LATER step — a crash while recovering from a crash.
    assert!(!run_crashop(&dir, "open", Some("rekey.after_manifest")), "recovery aborts");
    // 3) A clean open completes the idempotent roll-forward; new passwords work.
    let v = OpenVault::open(vault_pmv(&dir), b"c", b"d").expect("idempotent recovery completes");
    assert_eq!(referenced_doc(&v), doc_one());
    std::fs::remove_dir_all(&dir).ok();
}
