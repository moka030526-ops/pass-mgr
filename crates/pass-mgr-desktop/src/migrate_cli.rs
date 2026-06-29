//! THROWAWAY: the `migrate-doc-paths` CLI subcommand — a one-shot conversion of an existing
//! vault to the owner-first / timestamp-in-filename document path scheme, which also deletes
//! history and compacts the volume to shrink the vault.
//!
//! To remove the feature: delete this file, the `mod migrate_cli;` line + dispatch arm in
//! `main.rs`, its HELP stanza, and (in the core crate) `src/vault/migrate.rs` + its
//! `pub mod migrate;` line. It reuses existing helpers only (no permanent surface added).
use std::path::PathBuf;

use pass_mgr::launch::{default_vault_path, vault_file};
use pass_mgr::vault::{self, OpenVault};

use crate::{default_backup_dir, dest_inside, read_password, CompactFlags};

/// `migrate-doc-paths [DIR] [--dry-run] [--no-backup]`. Rewrites every stored document path
/// to `[<owner-initials>/]<root>[/<group>]/<ts>_<file>`, deletes history (per-record + the
/// vault audit), and compacts the volume. Backs up first by default; idempotent.
pub fn run(pos: &[String], f: &CompactFlags) -> anyhow::Result<()> {
    let path = match pos.len() {
        1 => default_vault_path(),
        2 => vault_file(&pos[1]),
        _ => anyhow::bail!("usage: pass-mgr migrate-doc-paths [DIR] [--dry-run] [--no-backup]"),
    };
    eprintln!("pass-mgr: migrate-doc-paths target vault → {}", path.display());
    if !path.exists() {
        anyhow::bail!("no vault found at {}", path.display());
    }

    // --- Dry run: open READ-ONLY, list every path that would change, write nothing. ---
    if f.dry_run {
        let pw1 = read_password("Password 1: ")?;
        let pw2 = read_password("Password 2: ")?;
        let v = OpenVault::open_read_only(path.clone(), pw1.as_bytes(), pw2.as_bytes())?;
        let rows = v.migrate_v2_plan();
        let mut changed = 0;
        for r in &rows {
            if r.new_path != r.old_path {
                changed += 1;
                eprintln!("  {}  {}  ->  {}", r.id, r.old_path, r.new_path);
            }
        }
        eprintln!(
            "Would rewrite {changed} of {} document path(s), delete all history, and compact. \
             (dry-run, nothing written)",
            rows.len()
        );
        return Ok(());
    }

    // The vault DIRECTORY (parent of vault.pmv), for the default backup + inside-vault guard.
    // A bare relative vault path has an empty parent; map to "." and canonicalize so the
    // default sibling backup is not wrongly flagged as inside the vault dir.
    let dir = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    };
    let dir = std::fs::canonicalize(&dir).unwrap_or(dir);

    // --- Real run: backup-first (default), then rewrite paths + drop history + compact. ---
    let pw1 = read_password("Password 1: ")?;
    let pw2 = read_password("Password 2: ")?;

    // Back up the encrypted tree first (unless opted out). MUST precede the staged rewrite
    // (`vault::backup` refuses while a `.rekey` is staged). Default: sibling `<name>-backups/`.
    if !f.no_backup {
        let dest = default_backup_dir(&dir);
        if dest_inside(&dir, &dest) {
            anyhow::bail!("backup destination must be OUTSIDE the vault directory");
        }
        let bp = vault::backup(&path, &dest)?;
        eprintln!("Backed up to {} before migrating.", bp.display());
    }

    let mut v = OpenVault::open(path.clone(), pw1.as_bytes(), pw2.as_bytes())?;
    let report = v.migrate_v2_throwaway(true)?;
    if report.changed == 0 {
        eprintln!("Document paths already migrated.");
    }
    eprintln!(
        "Migrated {} document path(s); removed {} history entries; reclaimed {} bytes.",
        report.changed, report.history_removed, report.bytes_reclaimed
    );
    Ok(())
}
