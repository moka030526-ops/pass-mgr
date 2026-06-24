//! Metamorphic / property-based bug hunt.
//!
//! Unlike the libFuzzer targets (which assert "never panics") and the unit tests (which
//! assert fixed examples), these check **relational invariants** that must hold for *any*
//! randomized input — the kind of bug a single example never reveals:
//!
//!   * grouping a record set never loses or duplicates a record (every id appears exactly once
//!     as a tree leaf), for BOTH `account_tree` and `asset_tree`, including empty/whitespace
//!     grouping values;
//!   * a merge is idempotent (re-planning right after applying is empty) and the destination
//!     always reopens (no corruption) — over random current/source record sets with arbitrary
//!     ids / `updated_at`;
//!   * `sync_types_from_records` makes every record's type present in the category lists and is
//!     idempotent;
//!   * a `save` → reopen round-trips every record exactly.
//!
//! Each property runs over many deterministic seeds, so a failure prints the exact seed to
//! reproduce. Uses a tiny in-file xorshift PRNG — no external crates.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use pass_mgr_core::crypto::KdfParams;
use pass_mgr_core::records::{self, account_tree, asset_tree, AcctNode, Account, AssetLiability};
use pass_mgr_core::vault::OpenVault;

// --- tiny deterministic PRNG -------------------------------------------------

struct Rng(u64);
impl Rng {
    fn new(seed: u64) -> Self {
        Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(1))
    }
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next_u64() % n as u64) as usize
    }
    fn pick<'a>(&mut self, items: &'a [&'a str]) -> &'a str {
        items[self.below(items.len())]
    }
    fn i64(&mut self) -> i64 {
        self.next_u64() as i64
    }
}

// Small alphabets, INCLUDING empty + whitespace-only values (the gnarly grouping edge cases).
const OWNERS: &[&str] = &["", "Alice", "Bob", " ", "Carol", "  "];
const ATYPES: &[&str] = &["", "Bank", "Crypto", "Loan", " ", "Brokerage"];
const SUBS: &[&str] = &["", "Checking", "Savings", " "];
const KINDS: &[&str] = &["Asset", "Liability", "", " "];
const TITLES: &[&str] = &["", "X", "Beach house", "  "];

fn fast() -> KdfParams {
    KdfParams { m_cost: 256, t_cost: 1, p_cost: 1 }
}

fn rand_account(rng: &mut Rng, i: usize) -> Account {
    let mut a = Account::new().unwrap();
    a.id = format!("acc{i}"); // unique per index → clean set comparisons
    a.owner = rng.pick(OWNERS).into();
    a.account_type = rng.pick(ATYPES).into();
    a.account_subtype = rng.pick(SUBS).into();
    a.title = rng.pick(TITLES).into();
    a.updated_at = rng.i64();
    a
}

fn rand_asset(rng: &mut Rng, i: usize) -> AssetLiability {
    let mut a = AssetLiability::new().unwrap();
    a.id = format!("ast{i}");
    a.owner = rng.pick(OWNERS).into();
    a.kind = rng.pick(KINDS).into();
    a.asset_type = rng.pick(ATYPES).into();
    a.title = rng.pick(TITLES).into();
    a.updated_at = rng.i64();
    a
}

fn collect_leaf_ids(node: &AcctNode, out: &mut Vec<String>) {
    for c in &node.children {
        collect_leaf_ids(c, out);
    }
    for l in &node.leaves {
        out.push(l.id.clone());
    }
}

fn tmp_dir(tag: &str) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    let d = std::env::temp_dir().join(format!("pmmeta-{tag}-{}-{n}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

// --- Property 1: grouping never loses or duplicates a record -----------------

#[test]
fn grouping_preserves_every_account_and_asset() {
    for seed in 0..2000u64 {
        let mut rng = Rng::new(seed);
        let n = rng.below(25);

        let accts: Vec<Account> = (0..n).map(|i| rand_account(&mut rng, i)).collect();
        let mut got = Vec::new();
        collect_leaf_ids(&account_tree(&accts), &mut got);
        got.sort();
        let mut want: Vec<String> = accts.iter().map(|a| a.id.clone()).collect();
        want.sort();
        assert_eq!(got, want, "seed {seed}: account grouping lost/duplicated a record");

        let m = rng.below(25);
        let assets: Vec<AssetLiability> = (0..m).map(|i| rand_asset(&mut rng, i)).collect();
        let mut got = Vec::new();
        collect_leaf_ids(&asset_tree(&assets), &mut got);
        got.sort();
        let mut want: Vec<String> = assets.iter().map(|a| a.id.clone()).collect();
        want.sort();
        assert_eq!(got, want, "seed {seed}: asset grouping lost/duplicated a record");
    }
}

// --- Property 2: a save round-trips every record exactly ---------------------

#[test]
fn save_reopen_round_trips_records() {
    for seed in 0..80u64 {
        let mut rng = Rng::new(1000 + seed);
        let dir = tmp_dir("rt");
        let path = dir.join("vault.pmv");
        let (accts, assets);
        {
            let mut v = OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();
            accts = (0..rng.below(12)).map(|i| rand_account(&mut rng, i)).collect::<Vec<_>>();
            assets = (0..rng.below(12)).map(|i| rand_asset(&mut rng, i)).collect::<Vec<_>>();
            v.vault.accounts = accts.clone();
            v.vault.assets = assets.clone();
            v.save().unwrap();
        }
        let v = OpenVault::open(path.clone(), b"a", b"b").unwrap();
        // Records don't derive PartialEq; compare strong field-tuples.
        let acc_key = |a: &Account| {
            (a.id.clone(), a.owner.clone(), a.account_type.clone(), a.account_subtype.clone(), a.title.clone(), a.username.clone(), a.password.clone(), a.created_at, a.updated_at)
        };
        let ast_key = |a: &AssetLiability| {
            (a.id.clone(), a.owner.clone(), a.kind.clone(), a.asset_type.clone(), a.title.clone(), a.created_at, a.updated_at)
        };
        assert_eq!(
            v.vault.accounts.iter().map(acc_key).collect::<Vec<_>>(),
            accts.iter().map(acc_key).collect::<Vec<_>>(),
            "seed {seed}: accounts changed across save/reopen"
        );
        assert_eq!(
            v.vault.assets.iter().map(ast_key).collect::<Vec<_>>(),
            assets.iter().map(ast_key).collect::<Vec<_>>(),
            "seed {seed}: assets changed across save/reopen"
        );
        std::fs::remove_dir_all(&dir).ok();
    }
}

// --- Property 3: merge is idempotent + never corrupts the destination --------

#[test]
fn merge_is_idempotent_and_destination_always_reopens() {
    for seed in 0..120u64 {
        let mut rng = Rng::new(50_000 + seed);
        let cdir = tmp_dir("mc");
        let sdir = tmp_dir("ms");
        let cpath = cdir.join("vault.pmv");
        let spath = sdir.join("vault.pmv");

        // Both vaults draw account ids from a SHARED small pool so "shared id" updates and
        // disjoint inserts both occur; updated_at is arbitrary on each side.
        let id_pool: Vec<String> = (0..8).map(|i| format!("p{i}")).collect();
        let build = |path: &PathBuf, rng: &mut Rng| {
            let mut v = OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();
            for _ in 0..rng.below(10) {
                let mut a = Account::new().unwrap();
                a.id = id_pool[rng.below(id_pool.len())].clone();
                a.owner = rng.pick(OWNERS).into();
                a.account_type = rng.pick(ATYPES).into();
                a.account_subtype = rng.pick(SUBS).into();
                a.updated_at = rng.i64();
                // Direct push (not upsert) to keep the arbitrary updated_at; dedup by id so a
                // single vault never carries duplicate ids (that models a corrupt source, tested
                // elsewhere — here we want two WELL-FORMED vaults).
                if !v.vault.accounts.iter().any(|x| x.id == a.id) {
                    v.vault.accounts.push(a);
                }
            }
            v.save().unwrap();
        };
        build(&cpath, &mut rng);
        build(&spath, &mut rng);

        let mut cur = OpenVault::open(cpath.clone(), b"a", b"b").unwrap();
        let src = OpenVault::open_read_only(spath.clone(), b"a", b"b").unwrap();

        // Snapshot the expected post-merge state per id: source wins iff strictly newer or new.
        let mut expect: std::collections::HashMap<String, i64> = std::collections::HashMap::new();
        for a in &cur.vault.accounts {
            expect.insert(a.id.clone(), a.updated_at);
        }
        for s in &src.vault.accounts {
            let e = expect.entry(s.id.clone()).or_insert(i64::MIN);
            if s.updated_at > *e {
                *e = s.updated_at;
            }
        }

        cur.apply_merge_from(&src).unwrap();

        // Idempotent: re-planning against the same source yields nothing.
        assert!(cur.plan_merge_from(&src).unwrap().is_empty(), "seed {seed}: merge not idempotent");
        // Every id present with the winning updated_at; no record lost.
        for (id, ts) in &expect {
            let got = cur.vault.accounts.iter().find(|a| &a.id == id).unwrap_or_else(|| panic!("seed {seed}: id {id} vanished"));
            assert_eq!(got.updated_at, *ts, "seed {seed}: id {id} wrong winner");
        }
        assert_eq!(cur.vault.accounts.len(), expect.len(), "seed {seed}: account count != union");

        // The destination reopens cleanly (referenced ⊆ stored holds).
        drop(cur);
        drop(src);
        OpenVault::open(cpath, b"a", b"b").unwrap();
        std::fs::remove_dir_all(&cdir).ok();
        std::fs::remove_dir_all(&sdir).ok();
    }
}

// --- Property 4: sync_types backfills all types + is idempotent --------------

#[test]
fn sync_types_makes_every_record_type_present_and_is_idempotent() {
    for seed in 0..120u64 {
        let mut rng = Rng::new(900_000 + seed);
        let dir = tmp_dir("sy");
        let path = dir.join("vault.pmv");
        let mut v = OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();
        for i in 0..rng.below(12) {
            v.vault.accounts.push(rand_account(&mut rng, i));
        }
        for i in 0..rng.below(12) {
            v.vault.assets.push(rand_asset(&mut rng, i));
        }
        v.save().unwrap();

        v.sync_types_from_records().unwrap();

        // Every non-blank type/subtype used by a record is now in the lists.
        let cats = v.categories();
        for a in &v.vault.assets {
            let t = a.asset_type.trim();
            if !t.is_empty() {
                assert!(cats.asset.iter().any(|x| x.eq_ignore_ascii_case(t)), "seed {seed}: asset type {t:?} missing");
            }
        }
        for a in &v.vault.accounts {
            let t = a.account_type.trim();
            if !t.is_empty() {
                assert!(cats.account_type_names().iter().any(|x| x.eq_ignore_ascii_case(t)), "seed {seed}: account type {t:?} missing");
                let st = a.account_subtype.trim();
                if !st.is_empty() {
                    assert!(cats.subtypes_for(t).iter().any(|x| x.eq_ignore_ascii_case(st)), "seed {seed}: subtype {st:?} missing under {t:?}");
                }
            }
        }
        // Idempotent.
        assert_eq!(v.sync_types_from_records().unwrap(), 0, "seed {seed}: sync not idempotent");
        // Sanity: the vault still reopens.
        drop(v);
        OpenVault::open(path, b"a", b"b").unwrap();
        std::fs::remove_dir_all(&dir).ok();
    }
}

// --- Property 5: random OPERATION SEQUENCES never corrupt the vault ----------
//
// State-machine / model-based hunt: apply a random sequence of real operations (add record,
// attach/remove document, sync types, compact, merge from a fresh source, save+reopen) and
// assert the one global invariant that must survive ANY interleaving — the vault always
// reopens (the open-time `referenced ⊆ stored` check holds), and nothing panics.

#[test]
fn random_operation_sequences_keep_the_vault_openable() {
    for seed in 0..40u64 {
        let mut rng = Rng::new(3_000_000 + seed);
        let dir = tmp_dir("sm");
        let path = dir.join("vault.pmv");
        let srcfile = dir.join("doc.bin");
        std::fs::write(&srcfile, b"document-bytes").unwrap();
        let mut v = OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();
        let mut doc_ids: Vec<String> = Vec::new();
        let steps = 6 + rng.below(12);
        for _ in 0..steps {
            match rng.below(8) {
                0 => {
                    let mut a = Account::new().unwrap();
                    a.account_type = rng.pick(ATYPES).into();
                    a.account_subtype = rng.pick(SUBS).into();
                    a.owner = rng.pick(OWNERS).into();
                    records::upsert(&mut v.vault.accounts, a);
                    let _ = v.save();
                }
                1 => {
                    let mut a = AssetLiability::new().unwrap();
                    a.asset_type = rng.pick(ATYPES).into();
                    a.owner = rng.pick(OWNERS).into();
                    a.kind = rng.pick(KINDS).into();
                    records::upsert(&mut v.vault.assets, a);
                    let _ = v.save();
                }
                2 => {
                    if let Ok(id) = v.add_document("/w", "d.txt", &srcfile) {
                        let mut gd = records::GeneralDocument::new().unwrap();
                        gd.file = Some(id.clone());
                        records::upsert(&mut v.vault.general_documents, gd);
                        doc_ids.push(id);
                        let _ = v.save();
                    }
                }
                3 => {
                    if let Some(id) = doc_ids.pop() {
                        // Unlink the referencing record first (remove_document refuses while referenced).
                        v.vault.general_documents.retain(|g| g.file.as_deref() != Some(id.as_str()));
                        let _ = v.save();
                        let _ = v.remove_document(&id);
                    }
                }
                4 => {
                    let _ = v.sync_types_from_records();
                }
                5 => {
                    let opts = pass_mgr_core::vault::CompactOptions { volume: true, json: true, history_cutoff: None, drop_all_history: true };
                    let _ = v.compact(&opts);
                }
                6 => {
                    let _ = v.save();
                    drop(v);
                    v = OpenVault::open(path.clone(), b"a", b"b").unwrap_or_else(|e| panic!("seed {seed}: reopen mid-sequence failed: {e}"));
                }
                _ => {
                    // Merge from a freshly-built source carrying a definitely-newer account.
                    let sdir = dir.join(format!("src{}", rng.next_u64()));
                    std::fs::create_dir_all(&sdir).ok();
                    let spath = sdir.join("vault.pmv");
                    {
                        if let Ok(mut s) = OpenVault::create(spath.clone(), b"a", b"b", fast()) {
                            let mut a = Account::new().unwrap();
                            a.account_type = rng.pick(ATYPES).into();
                            a.updated_at = i64::MAX;
                            s.vault.accounts.push(a);
                            let _ = s.save();
                        }
                    }
                    if let Ok(src) = OpenVault::open_read_only(spath, b"a", b"b") {
                        let _ = v.apply_merge_from(&src);
                    }
                }
            }
        }
        // THE invariant: a final save + reopen always succeeds — no sequence corrupted the vault.
        let _ = v.save();
        drop(v);
        OpenVault::open(path.clone(), b"a", b"b").unwrap_or_else(|e| panic!("seed {seed}: vault did not reopen after the op sequence: {e}"));
        std::fs::remove_dir_all(&dir).ok();
    }
}

// --- Property 6: export_tree → import_tree round-trips records AND documents -

#[test]
fn export_import_tree_round_trips_records_and_docs() {
    for seed in 0..40u64 {
        let mut rng = Rng::new(6_000_000 + seed);
        let dir = tmp_dir("rti");
        let path = dir.join("vault.pmv");
        let srcfile = dir.join("src.bin");

        // Build a vault with random records + a few referenced documents (distinct bytes).
        let mut docs: Vec<(String, Vec<u8>)> = Vec::new();
        let acc_keys;
        let ast_keys;
        {
            let mut v = OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();
            for i in 0..rng.below(8) {
                let mut a = rand_account(&mut rng, i);
                a.account_type = rng.pick(ATYPES).into();
                v.vault.accounts.push(a);
            }
            for i in 0..rng.below(8) {
                v.vault.assets.push(rand_asset(&mut rng, i));
            }
            for d in 0..rng.below(5) {
                let body: Vec<u8> = (0..(8 + rng.below(40))).map(|k| (d as u8).wrapping_add(k as u8)).collect();
                std::fs::write(&srcfile, &body).unwrap();
                let id = v.add_document("/w", "d.txt", &srcfile).unwrap();
                let mut gd = records::GeneralDocument::new().unwrap();
                gd.file = Some(id.clone());
                v.vault.general_documents.push(gd);
                docs.push((id, body));
            }
            v.save().unwrap();
            acc_keys = v.vault.accounts.iter().map(|a| (a.id.clone(), a.account_type.clone(), a.owner.clone(), a.updated_at)).collect::<Vec<_>>();
            ast_keys = v.vault.assets.iter().map(|a| (a.id.clone(), a.kind.clone(), a.asset_type.clone(), a.updated_at)).collect::<Vec<_>>();
        }

        // Decrypt to a plaintext mirror, then re-encrypt into a brand-new vault (new passwords).
        let mirror = dir.join("mirror");
        OpenVault::export_tree(&path, b"a", b"b", &mirror).unwrap();
        let dest = dir.join("dest").join("vault.pmv");
        let v2 = OpenVault::import_tree(&mirror, &dest, b"c", b"d", fast()).unwrap();

        // Records survive identically.
        let acc2 = v2.vault.accounts.iter().map(|a| (a.id.clone(), a.account_type.clone(), a.owner.clone(), a.updated_at)).collect::<Vec<_>>();
        let ast2 = v2.vault.assets.iter().map(|a| (a.id.clone(), a.kind.clone(), a.asset_type.clone(), a.updated_at)).collect::<Vec<_>>();
        assert_eq!(acc2, acc_keys, "seed {seed}: accounts changed across export/import");
        assert_eq!(ast2, ast_keys, "seed {seed}: assets changed across export/import");
        // Every document survives byte-for-byte under the NEW key.
        for (id, body) in &docs {
            assert_eq!(&**v2.read_document(id).unwrap(), &body[..], "seed {seed}: doc {id} changed across round-trip");
        }
        std::fs::remove_dir_all(&dir).ok();
    }
}

// Keep `records` import used even if a helper is trimmed later.
#[allow(dead_code)]
fn _uses_records() -> i64 {
    records::unix_now()
}
