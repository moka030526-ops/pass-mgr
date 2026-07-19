//! CLI surface regression tests.
//!
//! The arg-parser helpers are unit-tested, but nothing runs the real binary for
//! `--help` or a malformed invocation, so `main()`'s dispatch glue (mapping a
//! command + arity to a usage error) and the `ExitCode::FAILURE` path are never
//! exercised. These spawn the actual `pass-mgr` binary and pin the help output,
//! the usage strings, and the exit codes — a cheap guard against a UX/exit-code
//! regression. They need no display (every case returns before launching the UI).

use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_pass-mgr")
}

#[test]
fn help_lists_every_subcommand_and_exits_zero() {
    let out = Command::new(bin()).arg("--help").output().expect("run --help");
    assert!(out.status.success(), "--help must exit 0");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("USAGE:"), "help has a USAGE section");
    for sub in [
        "decrypt",
        "manifest",
        "extract",
        "backup",
        "export-tree",
        "import-tree",
        "update-from",
        "compact",
        "migrate-doc-paths",
        "--write",
        "--tui",
    ] {
        assert!(stdout.contains(sub), "help should mention `{sub}`");
    }
}

#[test]
fn too_many_positionals_is_a_usage_error_with_nonzero_exit() {
    let out = Command::new(bin()).args(["decrypt", "A", "B", "C"]).output().expect("run decrypt");
    assert!(!out.status.success(), "a malformed invocation exits non-zero");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("usage: pass-mgr decrypt [DIR]"), "got stderr: {stderr}");
}

#[test]
fn interactive_launch_rejects_extra_positionals() {
    // No subcommand: `pass-mgr [DIR]` takes at most one positional (the optional vault DIR).
    // A 2nd positional (here the first token isn't a known subcommand, so this is the
    // interactive path) must be rejected — returning before any UI launches — rather than
    // silently opening the first and ignoring the rest.
    let out = Command::new(bin()).args(["some-vault-dir", "stray-extra-arg"]).output().expect("run");
    assert!(!out.status.success(), "extra interactive positional exits non-zero");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("unrecognized extra arguments") || stderr.contains("Usage: pass-mgr"),
        "got stderr: {stderr}"
    );
}

#[test]
fn missing_required_output_dir_is_a_usage_error() {
    // `extract` requires an OUTPUT_DIR; with only the subcommand the arity is wrong.
    let out = Command::new(bin()).arg("extract").output().expect("run extract");
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("usage: pass-mgr extract [DIR] <OUTPUT_DIR>"),
        "got stderr: {stderr}"
    );
}

#[test]
fn part_flag_on_a_command_that_rejects_it_errors() {
    let out = Command::new(bin()).args(["--part", "2", "decrypt"]).output().expect("run");
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--part only applies to 'manifest' and 'extract'"),
        "got stderr: {stderr}"
    );
}

// --- End-to-end `compact` -----------------------------------------------------
//
// The unit tests stop at flag validation and nothing ran the real subcommand, so
// the documented DEFAULT path (back up first, then compact) was never exercised.
// It self-deadlocked: the session opens the vault writable (taking the
// single-writer lock) and then called the FREE `vault::backup`, which re-acquires
// it — flock binds to the open file description, so a second in-process acquire
// returns WouldBlock. The user saw "another writable session already has this
// vault open", naming a session that does not exist, and the documented escape
// hatch (`--no-backup`) runs an irreversible rewrite with no backup.
//
// The same shape was found and fixed for the GUI and TUI as audit R-9; this call
// site was missed.

use std::io::Write;
use std::path::{Path, PathBuf};

/// Build a real vault with one document, then delete the document so compaction
/// has dead bytes to reclaim (`compact` returns early when there is nothing to do,
/// which would make this test pass without reaching the backup).
fn vault_with_dead_bytes(tag: &str) -> PathBuf {
    use pass_mgr::crypto::KdfParams;
    use pass_mgr::vault::OpenVault;

    let dir = std::env::temp_dir().join(format!(
        "passmgr-cli-{tag}-{}",
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("vault.pmv");
    let fast = KdfParams { m_cost: 256, t_cost: 1, p_cost: 1 };
    let mut v = OpenVault::create(path.clone(), b"p1", b"p2", fast).unwrap();
    let src = dir.join("payload.bin");
    std::fs::write(&src, vec![7u8; 32 * 1024]).unwrap();
    let id = v.add_document("doc", "payload.bin", &src).unwrap();
    v.remove_document(&id).unwrap(); // tombstone it -> dead volume bytes
    drop(v); // release the single-writer lock before the CLI runs
    let _ = std::fs::remove_file(&src);
    path
}

fn run_compact(dir: &Path, extra: &[&str]) -> std::process::Output {
    let mut child = std::process::Command::new(bin())
        .arg("compact")
        .arg(dir)
        .args(extra)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn compact");
    // The two passwords, in order, on stdin.
    child.stdin.as_mut().unwrap().write_all(b"p1\np2\n").unwrap();
    child.wait_with_output().expect("compact finished")
}

#[test]
fn compact_succeeds_on_its_default_backup_first_path() {
    let path = vault_with_dead_bytes("compactdefault");
    let dir = path.parent().unwrap().to_path_buf();

    let out = run_compact(&dir, &["--volume"]);
    let stderr = String::from_utf8_lossy(&out.stderr);

    // The precise regression: the lock this session already holds must not be
    // re-acquired by the backup step.
    assert!(
        !stderr.contains("already has this vault open"),
        "compact must not self-deadlock on its own write lock; stderr: {stderr}"
    );
    assert!(out.status.success(), "compact --volume should exit 0; stderr: {stderr}");
    assert!(stderr.contains("Backed up to"), "the default path backs up first; stderr: {stderr}");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn compact_succeeds_with_an_explicit_backup_destination() {
    let path = vault_with_dead_bytes("compactexplicit");
    let dir = path.parent().unwrap().to_path_buf();
    // Must be OUTSIDE the vault directory (the CLI rejects an inside destination).
    let dest = dir.parent().unwrap().join(format!(
        "passmgr-cli-backupdest-{}",
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    ));

    let out = run_compact(&dir, &["--volume", "--backup", dest.to_str().unwrap()]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("already has this vault open"),
        "an explicit --backup must not self-deadlock either; stderr: {stderr}"
    );
    assert!(out.status.success(), "compact --backup should exit 0; stderr: {stderr}");
    assert!(dest.exists(), "the backup destination was created");

    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&dest);
}
