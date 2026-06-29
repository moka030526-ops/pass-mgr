//! THROWAWAY: end-to-end test of the `migrate-doc-paths` subcommand. Delete this file with
//! the feature. Builds a vault with OLD-scheme document paths across every tab (incl. an
//! orphan), drives the compiled binary (passwords piped on stdin) through a `--dry-run`
//! preview and a real run, and verifies the new owner-first paths, byte-identity, history
//! deletion, and idempotency.
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use pass_mgr::crypto::KdfParams;
use pass_mgr::records::{self, Change};
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
fn tmp_dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("pmmig-{tag}-{}", nanos()));
    std::fs::create_dir_all(&d).unwrap();
    d
}
fn srcfile(content: &[u8]) -> PathBuf {
    let f = std::env::temp_dir().join(format!("pmmig-src-{}.bin", nanos()));
    std::fs::write(&f, content).unwrap();
    f
}

/// Run `migrate-doc-paths DIR [extra...]` with the two passwords piped in.
fn run_migrate(dir: &Path, extra: &[&str], pw: [&str; 2]) -> (bool, String) {
    let mut args = vec!["migrate-doc-paths".to_string(), dir.display().to_string()];
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
    child.stdin.as_mut().unwrap().write_all(format!("{}\n{}\n", pw[0], pw[1]).as_bytes()).unwrap();
    let out = child.wait_with_output().expect("wait");
    let mut s = String::from_utf8_lossy(&out.stderr).into_owned();
    s.push_str(&String::from_utf8_lossy(&out.stdout));
    (out.status.success(), s)
}

#[test]
fn migrate_rewrites_owner_first_drops_history_and_is_idempotent() {
    let dir = tmp_dir("mig");
    let pmv = dir.join("vault.pmv");
    let (asset_id, tax_id, re_id, tw_id, orphan_id);
    {
        let mut v = OpenVault::create(pmv.clone(), b"p1", b"p2", fast()).unwrap();

        // Asset doc under the OLD desc-based scheme (assets/<desc>/<ts>/<file>).
        asset_id = v.add_document("assets/brokerage/20240102-030405", "stmt.pdf", &srcfile(b"ASSET")).unwrap();
        let mut a = records::AssetLiability::new().unwrap();
        a.kind = "Asset".into();
        a.owner = "Jane Doe".into();
        a.description = "Brokerage".into();
        a.statement = Some(asset_id.clone());
        a.history = vec![Change::new("created", String::new()), Change::new("updated", "owner".into())];
        v.vault.assets.push(a);

        // Tax doc (owner -> initials, year kept).
        tax_id = v.add_document("taxes/2024/20240102-030405", "w2.pdf", &srcfile(b"TAX")).unwrap();
        let mut t = records::TaxFiling::new().unwrap();
        t.owner = "Michael Kaissi".into();
        t.year = "2024".into();
        t.documents = vec![tax_id.clone()];
        v.vault.tax_filings.push(t);

        // Real-estate doc (owner -> initials, address kept).
        re_id = v.add_document("real-estate/123mainst/20240102-030405", "deed.pdf", &srcfile(b"DEED")).unwrap();
        let mut re = records::RealEstate::new().unwrap();
        re.owner = "Jane Doe".into();
        re.address = "123 Main St".into();
        re.documents = vec![re_id.clone()];
        v.vault.real_estate.push(re);

        // Trust & Will doc (no owner -> group kept, just ts moved).
        tw_id = v.add_document("trust-will/living-trust/20240102-030405", "will.pdf", &srcfile(b"WILL")).unwrap();
        let mut tw = records::TrustWill::new().unwrap();
        tw.document = "Living Trust".into();
        tw.file = Some(tw_id.clone());
        v.vault.trust_wills.push(tw);

        // Orphan doc (referenced by no record -> Plain).
        orphan_id = v.add_document("liabilities/20240102-030405", "loan.pdf", &srcfile(b"LOAN")).unwrap();

        v.save().unwrap();
    }

    // --- DRY RUN: previews old -> new, writes nothing. ---
    let (ok, out) = run_migrate(&dir, &["--dry-run"], ["p1", "p2"]);
    assert!(ok, "dry-run should succeed; output:\n{out}");
    assert!(out.contains("->"), "dry-run lists old -> new; output:\n{out}");
    assert!(out.contains("/JD/assets/20240102-030405_stmt.pdf"), "previews new asset path; output:\n{out}");
    {
        let v = OpenVault::open_read_only(pmv.clone(), b"p1", b"p2").unwrap();
        assert_eq!(
            v.doc_path(&asset_id).unwrap(),
            "/assets/brokerage/20240102-030405/stmt.pdf",
            "dry-run must not change anything"
        );
    }

    // --- REAL RUN (--no-backup keeps the temp dir clean). ---
    let (ok, out) = run_migrate(&dir, &["--no-backup"], ["p1", "p2"]);
    assert!(ok, "migrate should succeed; output:\n{out}");
    {
        let v = OpenVault::open_read_only(pmv.clone(), b"p1", b"p2").unwrap();
        assert_eq!(v.doc_path(&asset_id).unwrap(), "/JD/assets/20240102-030405_stmt.pdf");
        assert_eq!(v.doc_path(&tax_id).unwrap(), "/MK/taxes/2024/20240102-030405_w2.pdf");
        assert_eq!(v.doc_path(&re_id).unwrap(), "/JD/real-estate/123mainst/20240102-030405_deed.pdf");
        assert_eq!(v.doc_path(&tw_id).unwrap(), "/trust-will/living-trust/20240102-030405_will.pdf");
        assert_eq!(v.doc_path(&orphan_id).unwrap(), "/liabilities/20240102-030405_loan.pdf");
        // Same ids -> bytes preserved.
        assert_eq!(&**v.read_document(&asset_id).unwrap(), b"ASSET");
        assert_eq!(&**v.read_document(&tax_id).unwrap(), b"TAX");
        assert_eq!(&**v.read_document(&re_id).unwrap(), b"DEED");
        assert_eq!(&**v.read_document(&tw_id).unwrap(), b"WILL");
        assert_eq!(&**v.read_document(&orphan_id).unwrap(), b"LOAN");
        // History deleted.
        assert!(v.vault.assets.iter().all(|a| a.history.is_empty()), "record history cleared");
    }

    // --- IDEMPOTENT: a second run rewrites nothing. ---
    let (ok, out) = run_migrate(&dir, &["--no-backup"], ["p1", "p2"]);
    assert!(ok, "second migrate should succeed; output:\n{out}");
    assert!(out.contains("Migrated 0 document path(s)"), "idempotent (0 changed); output:\n{out}");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn migrate_backs_up_by_default() {
    let dir = tmp_dir("migbak");
    let pmv = dir.join("vault.pmv");
    {
        let mut v = OpenVault::create(pmv.clone(), b"p1", b"p2", fast()).unwrap();
        let id = v.add_document("assets/x/20240102-030405", "s.pdf", &srcfile(b"X")).unwrap();
        let mut a = records::AssetLiability::new().unwrap();
        a.kind = "Asset".into();
        a.owner = "Al Bert".into();
        a.statement = Some(id);
        v.vault.assets.push(a);
        v.save().unwrap();
    }
    let (ok, out) = run_migrate(&dir, &[], ["p1", "p2"]); // default: backup-first
    assert!(ok, "migrate with backup should succeed; output:\n{out}");
    assert!(out.contains("Backed up to"), "reports the backup; output:\n{out}");
    let backups = dir.parent().unwrap().join(format!("{}-backups", dir.file_name().unwrap().to_string_lossy()));
    assert!(backups.exists(), "sibling backup dir created at {}", backups.display());

    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&backups);
}
