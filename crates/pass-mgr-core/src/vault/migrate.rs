//! THROWAWAY one-shot migration to the owner-first / timestamp-in-filename document path
//! scheme, plus history deletion and volume compaction.
//!
//! This whole file is self-contained and meant to be DELETED once every vault has been
//! migrated. To remove the feature entirely: delete `src/vault/migrate.rs`, the
//! `pub mod migrate;` line in `vault.rs`, and the `migrate-doc-paths` subcommand in the
//! desktop crate. It reuses only existing primitives (`storage.read/put`, `compact`) and
//! adds NO permanent surface (no changes to `staged_rewrite`/`compact`/`change_password`).
use std::collections::HashMap;

use super::{virtual_path, CompactOptions, OpenVault, VaultError};
use crate::records::{self, Vault};
use crate::storage::MAX_PATH_LEN;

/// What a document's owning record tells us about how to re-file it.
enum DocTarget {
    Asset { kind: String, owner: String },
    Tax { owner: String, year: String },
    RealEstate { owner: String, address: String },
    /// Trust & Will, General Documents, or an orphan (no owning record): keep the existing
    /// directories, only fold the timestamp into the filename.
    Plain,
}

/// Outcome of a migration run.
pub struct MigrateReport {
    pub changed: usize,
    pub bytes_reclaimed: u64,
    pub history_removed: usize,
}

/// One planned rewrite, for `--dry-run` previews.
pub struct MigratePlanRow {
    pub id: String,
    pub old_path: String,
    pub new_path: String,
}

/// Rewrite ONE old-scheme virtual path to the new scheme. Pure & idempotent.
/// - Extracts the timestamp from a `<ts>_` filename prefix (already-migrated), else a
///   standalone `YYYYMMDD-HHMMSS` directory component, else synthesizes it from `uploaded_at`.
/// - Owner tabs are rebuilt from the record fields (`<INITIALS>/<root>[/<group>]`), dropping
///   any old auto-group/subfolder. Plain docs keep their directories minus the timestamp.
fn new_doc_path(old_path: &str, target: &DocTarget, uploaded_at: i64) -> String {
    let parts: Vec<&str> = old_path.split('/').filter(|p| !p.is_empty()).collect();
    let Some((&filename_raw, dirs)) = parts.split_last() else {
        return old_path.to_string(); // degenerate (no components) — leave unchanged
    };

    // (timestamp, bare filename): PREFER a standalone `<ts>` directory (the real upload time)
    // over a user filename that merely LOOKS like `<ts>_…`; then the migrated filename's own
    // `<ts>_` prefix (so a re-run is idempotent); then the manifest's uploaded_at.
    let ts_dir_idx = dirs.iter().position(|c| records::is_compact_utc(c));
    let (ts, bare): (String, &str) = if let Some(i) = ts_dir_idx {
        (dirs[i].to_string(), filename_raw)
    } else if filename_raw.len() >= 16
        && filename_raw.is_char_boundary(15)
        && filename_raw.as_bytes()[15] == b'_'
        && records::is_compact_utc(&filename_raw[..15])
    {
        (filename_raw[..15].to_string(), &filename_raw[16..])
    } else {
        (records::compact_utc(uploaded_at), filename_raw)
    };
    let filename = records::timestamped_filename(&ts, bare);

    match target {
        DocTarget::Asset { kind, owner } => {
            let prefix = records::owner_prefix(Some(owner), &records::asset_doc_location(kind));
            virtual_path(&prefix, &filename)
        }
        DocTarget::Tax { owner, year } => {
            let prefix = records::owner_prefix(Some(owner), &records::tax_doc_location(year));
            virtual_path(&prefix, &filename)
        }
        DocTarget::RealEstate { owner, address } => {
            let prefix = records::owner_prefix(Some(owner), &records::real_estate_doc_location(address));
            virtual_path(&prefix, &filename)
        }
        DocTarget::Plain => {
            // Keep the existing directories, removing ONLY the single component used as the
            // timestamp source (so a legitimately ts-shaped subfolder name is preserved).
            let kept: Vec<&str> =
                dirs.iter().copied().enumerate().filter(|(i, _)| Some(*i) != ts_dir_idx).map(|(_, c)| c).collect();
            virtual_path(&kept.join("/"), &filename)
        }
    }
}

impl OpenVault {
    /// Build the id -> owning-record target map. Only asset/tax/real-estate records carry an
    /// owner; Trust & Will / General Documents and any orphan id are treated as `Plain`
    /// (absent from the map -> handled by the `Plain` fallback in [`new_doc_path`]).
    fn doc_targets(vault: &Vault) -> HashMap<String, DocTarget> {
        let mut m = HashMap::new();
        for a in &vault.assets {
            if let Some(id) = &a.statement {
                m.entry(id.clone()).or_insert_with(|| DocTarget::Asset { kind: a.kind.clone(), owner: a.owner.clone() });
            }
        }
        for t in &vault.tax_filings {
            for id in &t.documents {
                m.entry(id.clone()).or_insert_with(|| DocTarget::Tax { owner: t.owner.clone(), year: t.year.clone() });
            }
        }
        for re in &vault.real_estate {
            for id in &re.documents {
                m.entry(id.clone())
                    .or_insert_with(|| DocTarget::RealEstate { owner: re.owner.clone(), address: re.address.clone() });
            }
        }
        m
    }

    /// Preview every old -> new path change without writing anything (safe on a read-only
    /// handle). Rows where `old_path == new_path` are already-migrated/unchanged.
    pub fn migrate_v2_plan(&self) -> Vec<MigratePlanRow> {
        let targets = Self::doc_targets(&self.vault);
        self.storage
            .entries()
            .map(|e| MigratePlanRow {
                id: e.id.clone(),
                old_path: e.path.clone(),
                new_path: new_doc_path(&e.path, targets.get(&e.id).unwrap_or(&DocTarget::Plain), e.uploaded_at),
            })
            .collect()
    }

    /// Rewrite every document path to the owner-first / ts-in-filename scheme; optionally
    /// delete history (per-record history + the vault audit); then compact the volume to
    /// reclaim the superseded frames. Idempotent (an already-migrated path maps to itself).
    pub fn migrate_v2_throwaway(&mut self, drop_history: bool) -> Result<MigrateReport, VaultError> {
        if self.read_only {
            return Err(VaultError::ReadOnly);
        }
        let targets = Self::doc_targets(&self.vault);

        // 1. Plan + validate up front (no writes yet): a too-long path aborts cleanly,
        //    leaving the on-disk vault untouched.
        let mut plan: Vec<(String, String, i64)> = Vec::new(); // (id, new_path, uploaded_at)
        for e in self.storage.entries() {
            let new_path = new_doc_path(&e.path, targets.get(&e.id).unwrap_or(&DocTarget::Plain), e.uploaded_at);
            if new_path.len() > MAX_PATH_LEN {
                return Err(VaultError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "migrated path for doc {} would exceed {MAX_PATH_LEN} bytes ({}): {new_path}",
                        e.id,
                        new_path.len()
                    ),
                )));
            }
            if new_path != e.path {
                plan.push((e.id.clone(), new_path, e.uploaded_at));
            }
        }
        let changed = plan.len();

        // 2. Apply the path rewrites: re-put each blob under its new path (same id +
        //    uploaded_at, so records still resolve by id). The old frame becomes garbage,
        //    reclaimed by the compaction in step 4.
        for (id, new_path, uploaded_at) in &plan {
            let bytes = self.storage.read(id, &self.key)?;
            self.storage.put(id, new_path, &bytes, *uploaded_at, &self.key)?;
        }

        // 3. Delete the vault-level audit here (compact preserves it); per-record history is
        //    cleared by the compaction's drop_all_history below.
        if drop_history {
            self.vault.audit.clear();
        }

        // 4. Compact: one atomic staged rewrite that re-packs the volume (dropping the now-
        //    superseded frames) and — when dropping history — clears every record's history.
        //    It also persists vault.pmv (with the audit already cleared in step 3).
        let report = self.compact(&CompactOptions {
            volume: true,
            json: drop_history,
            history_cutoff: None,
            drop_all_history: drop_history,
        })?;

        Ok(MigrateReport { changed, bytes_reclaimed: report.bytes_reclaimed, history_removed: report.history_removed })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn asset_doc_is_refiled_owner_first_by_kind() {
        // Old asset scheme (pre-redesign): assets/<desc>/<ts>/<file>. Re-filed under owner.
        let t = DocTarget::Asset { kind: "Asset".into(), owner: "Jane Doe".into() };
        assert_eq!(new_doc_path("/assets/brokerage/20240102-030405/stmt.pdf", &t, 0), "/JD/assets/20240102-030405_stmt.pdf");
    }

    #[test]
    fn liability_root_and_initials() {
        let t = DocTarget::Asset { kind: "Liability".into(), owner: "Bob".into() };
        assert_eq!(new_doc_path("/assets/20240102-030405/loan.pdf", &t, 0), "/B/liabilities/20240102-030405_loan.pdf");
    }

    #[test]
    fn tax_keeps_year_under_owner() {
        let t = DocTarget::Tax { owner: "Michael Kaissi".into(), year: "2024".into() };
        assert_eq!(
            new_doc_path("/taxes/2024/20240102-030405/federal/w2.pdf", &t, 0),
            "/MK/taxes/2024/20240102-030405_w2.pdf"
        );
    }

    #[test]
    fn real_estate_keeps_address_under_owner() {
        let t = DocTarget::RealEstate { owner: "Jane Doe".into(), address: "123 Main St".into() };
        assert_eq!(
            new_doc_path("/real-estate/123mainst/20240102-030405/deed.pdf", &t, 0),
            "/JD/real-estate/123mainst/20240102-030405_deed.pdf"
        );
    }

    #[test]
    fn plain_keeps_dirs_and_subfolder_drops_ts_dir() {
        let t = DocTarget::Plain;
        assert_eq!(
            new_doc_path("/trust-will/living-trust/20240102-030405/scans/will.pdf", &t, 0),
            "/trust-will/living-trust/scans/20240102-030405_will.pdf"
        );
    }

    #[test]
    fn orphan_is_plain_just_moves_ts() {
        // No owning record -> Plain: dirs preserved (minus ts), ts folded into filename.
        let t = DocTarget::Plain;
        assert_eq!(
            new_doc_path("/liabilities/20240102-030405/loan.pdf", &t, 0),
            "/liabilities/20240102-030405_loan.pdf"
        );
    }

    #[test]
    fn no_timestamp_falls_back_to_uploaded_at() {
        let t = DocTarget::Plain;
        let ts = records::compact_utc(1_704_164_645); // "20240102-030405"
        assert_eq!(
            new_doc_path("/general-documents/deed/deed.pdf", &t, 1_704_164_645),
            format!("/general-documents/deed/{ts}_deed.pdf")
        );
    }

    #[test]
    fn idempotent_on_already_migrated_paths() {
        // Feeding a migrated path back in (same target) returns it unchanged, even with
        // uploaded_at=0 — proving the embedded ts prefix is reused, never re-synthesized.
        let t = DocTarget::Asset { kind: "Asset".into(), owner: "Jane Doe".into() };
        let once = new_doc_path("/assets/brokerage/20240102-030405/stmt.pdf", &t, 0);
        assert_eq!(new_doc_path(&once, &t, 0), once);

        let p = DocTarget::Plain;
        let once_p = new_doc_path("/trust-will/living-trust/20240102-030405/will.pdf", &p, 0);
        assert_eq!(new_doc_path(&once_p, &p, 0), once_p);
    }

    #[test]
    fn blank_owner_omits_initials_level() {
        let t = DocTarget::Asset { kind: "Asset".into(), owner: "   ".into() };
        assert_eq!(new_doc_path("/assets/20240102-030405/stmt.pdf", &t, 0), "/assets/20240102-030405_stmt.pdf");
    }
}
