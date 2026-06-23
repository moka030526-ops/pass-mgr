//! End-to-end test of the `update-from` CLI subcommand: build two real vaults via the
//! core API, then drive the compiled `pass-mgr` binary (with passwords piped on stdin)
//! through a `--dry-run` preview and a real apply, and verify the result on disk.
//!
//! This complements the unit/integration tests of the merge engine in
//! `pass-mgr-core` (which cover the diff/apply/blob-copy/tombstone logic); here we
//! exercise the CLI wiring: argument dispatch, the four-password prompt ORDER
//! (target's two, then source's two), the plan printing, and that the apply persists.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use pass_mgr::crypto::KdfParams;
use pass_mgr::records;
use pass_mgr::vault::OpenVault;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_pass-mgr")
}

fn fast() -> KdfParams {
    KdfParams { m_cost: 256, t_cost: 1, p_cost: 1 }
}

fn nanos() -> u128 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
}

/// A fresh, unique vault directory (NOT the vault.pmv path — the CLI takes the dir).
fn tmp_dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("pmcli-{tag}-{}", nanos()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn account(id: &str, user: &str, pw: &str, updated_at: i64) -> records::Account {
    let mut a = records::Account::new().unwrap();
    a.id = id.into();
    a.title = format!("acct-{id}");
    a.owner = "owner".into();
    a.account_type = "Checking".into();
    a.username = user.into();
    a.password = pw.into();
    a.updated_at = updated_at;
    a.created_at = 1;
    a
}

/// Run the binary with the four passwords piped in (target pw1/pw2, then source pw1/pw2),
/// plus any extra trailing args. Returns (success, combined stderr+stdout).
fn run_update_from(other_dir: &Path, current_dir: &Path, extra: &[&str], pw: [&str; 4]) -> (bool, String) {
    let mut args = vec!["update-from".to_string(), other_dir.display().to_string(), current_dir.display().to_string()];
    for e in extra {
        args.push((*e).to_string());
    }
    let mut child = Command::new(bin())
        .args(&args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn pass-mgr");
    {
        let stdin = child.stdin.as_mut().unwrap();
        stdin.write_all(format!("{}\n{}\n{}\n{}\n", pw[0], pw[1], pw[2], pw[3]).as_bytes()).unwrap();
    }
    let out = child.wait_with_output().expect("wait");
    let mut combined = String::from_utf8_lossy(&out.stderr).into_owned();
    combined.push_str(&String::from_utf8_lossy(&out.stdout));
    (out.status.success(), combined)
}

#[test]
fn update_from_cli_dry_run_then_apply() {
    // SOURCE vault: a newer shared account + a general document with a blob.
    let s_dir = tmp_dir("src");
    let s_pmv = s_dir.join("vault.pmv");
    let blob_id;
    {
        let mut s = OpenVault::create(s_pmv.clone(), b"sp1", b"sp2", fast()).unwrap();
        s.vault.accounts.push(account("shared", "alice", "NEWPW", 2_000));
        let docfile = std::env::temp_dir().join(format!("pmcli-doc-{}.txt", nanos()));
        std::fs::write(&docfile, b"deed-bytes").unwrap();
        blob_id = s.add_document("general-documents/deed", "deed.pdf", &docfile).unwrap();
        let mut gd = records::GeneralDocument::new().unwrap();
        gd.id = "gd-1".into();
        gd.title = "Deed".into();
        gd.file = Some(blob_id.clone());
        gd.updated_at = 3_000;
        s.vault.general_documents.push(gd);
        s.save().unwrap();
        // Drop releases the single-writer lock so the binary can read it.
    }

    // CURRENT vault: an OLDER version of the shared account.
    let c_dir = tmp_dir("cur");
    let c_pmv = c_dir.join("vault.pmv");
    {
        let mut c = OpenVault::create(c_pmv.clone(), b"cp1", b"cp2", fast()).unwrap();
        c.vault.accounts.push(account("shared", "alice", "OLDPW", 1_000));
        c.save().unwrap();
    }

    // --- DRY RUN: previews the patch, writes nothing. ---
    let (ok, out) = run_update_from(&s_dir, &c_dir, &["--dry-run"], ["cp1", "cp2", "sp1", "sp2"]);
    assert!(ok, "dry-run should succeed; output:\n{out}");
    assert!(out.contains("would change"), "dry-run prints a preview; output:\n{out}");
    assert!(out.to_lowercase().contains("updated"), "shows the updated account; output:\n{out}");
    assert!(out.contains("deed"), "lists the document to copy; output:\n{out}");
    // The dry run must NOT have modified the current vault.
    {
        let c = OpenVault::open_read_only(c_pmv.clone(), b"cp1", b"cp2").unwrap();
        assert_eq!(c.vault.accounts.iter().find(|a| a.id == "shared").unwrap().password, "OLDPW");
    }

    // --- REAL APPLY. ---
    let (ok, out) = run_update_from(&s_dir, &c_dir, &[], ["cp1", "cp2", "sp1", "sp2"]);
    assert!(ok, "apply should succeed; output:\n{out}");
    assert!(out.contains("Applied:"), "prints the apply summary; output:\n{out}");

    // Verify on disk: account updated, document copied + readable under the same id.
    {
        let c = OpenVault::open_read_only(c_pmv.clone(), b"cp1", b"cp2").unwrap();
        assert_eq!(c.vault.accounts.iter().find(|a| a.id == "shared").unwrap().password, "NEWPW");
        assert!(c.vault.general_documents.iter().any(|g| g.id == "gd-1"));
        assert_eq!(&**c.read_document(&blob_id).unwrap(), b"deed-bytes");
    }

    let _ = std::fs::remove_dir_all(&s_dir);
    let _ = std::fs::remove_dir_all(&c_dir);
}

#[test]
fn update_from_cli_refuses_same_vault() {
    let d = tmp_dir("self");
    {
        OpenVault::create(d.join("vault.pmv"), b"p1", b"p2", fast()).unwrap();
    }
    // Source == target → refused before any write, regardless of passwords.
    let (ok, out) = run_update_from(&d, &d, &["--dry-run"], ["p1", "p2", "p1", "p2"]);
    assert!(!ok, "merging a vault into itself must fail; output:\n{out}");
    assert!(out.contains("same vault"), "explains the refusal; output:\n{out}");
    let _ = std::fs::remove_dir_all(&d);
}
