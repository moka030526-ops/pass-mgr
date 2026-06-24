#![no_main]
//! Fuzz the cross-vault merge ("update from another vault") end to end against an
//! attacker-shaped SOURCE vault. Each iteration builds a small CURRENT vault and a SOURCE
//! vault whose records (ids + `updated_at`, including negatives / `i64::MAX` / duplicate
//! ids) are derived from the fuzz bytes, plus one document-bearing record so the blob-copy
//! path runs, then drives the real `plan_merge_from` + `apply_merge_from`.
//!
//! The hard invariant: **a merge never corrupts the destination**. Whatever the source
//! contains, the current vault must still open afterwards (the `referenced ⊆ stored`
//! consistency check on open holds) and nothing may panic. The merge is one-way + additive,
//! so this exercises the recency diff, the duplicate-id de-duplication, the untrusted
//! blob-id/path validation, the add-only blob copy, and the atomic save — over arbitrary
//! input. (The untrusted on-disk PARSING is covered separately by parse_*/scan_volume.)
use libfuzzer_sys::fuzz_target;
use pass_mgr_core::crypto::KdfParams;
use pass_mgr_core::records;
use pass_mgr_core::vault::OpenVault;
use std::sync::atomic::{AtomicU64, Ordering};

static SEQ: AtomicU64 = AtomicU64::new(0);

// A tiny-but-valid KDF so each create/open is sub-millisecond (this target does real crypto
// + disk I/O per iteration, unlike the pure-parser targets).
fn params() -> KdfParams {
    KdfParams { m_cost: 256, t_cost: 1, p_cost: 1 }
}

fuzz_target!(|data: &[u8]| {
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    let base = std::env::temp_dir().join(format!("pmfuzz-merge-{}-{n}", std::process::id()));
    let cur_dir = base.join("cur");
    let src_dir = base.join("src");
    if std::fs::create_dir_all(&cur_dir).is_err() || std::fs::create_dir_all(&src_dir).is_err() {
        return;
    }

    // `?`-on-Option helper so a resource failure (not a bug) just bails out of this iteration.
    let run = || -> Option<()> {
        let cur_pmv = cur_dir.join("vault.pmv");
        let src_pmv = src_dir.join("vault.pmv");

        // CURRENT: a single account "shared" (updated_at = 1000) so the SOURCE drives the diff.
        let mut c = OpenVault::create(cur_pmv.clone(), b"a", b"b", params()).ok()?;
        let mut a = records::Account::new().ok()?;
        a.id = "shared".into();
        a.updated_at = 1000;
        a.owner = "o".into();
        a.password = "old".into();
        c.vault.accounts.push(a);
        c.save().ok()?;
        drop(c); // release the writer lock before the source build / reopen

        // SOURCE: accounts shaped by the fuzz bytes (arbitrary ids incl. "shared" duplicates,
        // arbitrary updated_at), plus one document-bearing record (always new ⇒ blob copied).
        let mut s = OpenVault::create(src_pmv.clone(), b"a", b"b", params()).ok()?;
        for (i, chunk) in data.chunks(9).take(16).enumerate() {
            let mut a = records::Account::new().ok()?;
            a.id = if chunk[0] & 1 == 0 { "shared".into() } else { format!("a{i}-{}", chunk[0]) };
            let mut ts = [0u8; 8];
            for (k, b) in chunk.iter().skip(1).take(8).enumerate() {
                ts[k] = *b;
            }
            a.updated_at = i64::from_le_bytes(ts); // arbitrary: negative / huge / equal
            a.owner = "o".into();
            a.password = "src".into();
            s.vault.accounts.push(a);
        }
        let docfile = base.join("doc.bin");
        std::fs::write(&docfile, data.get(..256).unwrap_or(data)).ok()?;
        let blob = s.add_document("/w", "d.txt", &docfile).ok()?;
        let mut tw = records::TrustWill::new().ok()?;
        tw.file = Some(blob);
        tw.updated_at = i64::MAX; // certainly newer/new ⇒ its blob gets copied
        s.vault.trust_wills.push(tw);
        s.save().ok()?;
        drop(s);

        // Drive the real merge. plan_merge_from is read-only; apply mutates + saves.
        let mut c = OpenVault::open(cur_pmv.clone(), b"a", b"b").ok()?;
        let src_ro = OpenVault::open_read_only(src_pmv, b"a", b"b").ok()?;
        if c.plan_merge_from(&src_ro).is_ok() {
            let _ = c.apply_merge_from(&src_ro);
        }
        drop(c);
        drop(src_ro);

        // THE invariant: the destination is never corrupted by a merge — it must reopen,
        // whether the merge fully applied, partially failed, or was rejected.
        OpenVault::open(cur_pmv, b"a", b"b").expect("current vault reopens after merge (no corruption)");
        Some(())
    };
    let _ = run();
    std::fs::remove_dir_all(&base).ok();
});
