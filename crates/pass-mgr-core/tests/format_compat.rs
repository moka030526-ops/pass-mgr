//! Integration tests for serde / on-disk format compatibility.
//!
//! These exercise the *public* `pass_mgr_core` API (so they live in `tests/`,
//! compiled as a separate crate) and pin down three properties of the vault
//! format that are easy to break when adding fields:
//!
//!   1. End-to-end persistence of the recently-added record fields — a TaxFiling
//!      with a document and an expanded RealEstate (the four portal logins +
//!      per-portal comments, `financing_balance`, `comments`, and an attached document) survive a
//!      create -> save -> reopen cycle, and the generation counter advances.
//!   2. Backward compatibility — an *old-style* vault JSON that predates
//!      `tax_filings` and the new RealEstate fields still deserializes, with the
//!      new fields defaulting to empty (this is what the `#[serde(default)]`
//!      attributes buy us).
//!   3. serde_json round-trip of a fully-populated `Vault` preserves the new
//!      fields exactly.

use pass_mgr_core::crypto::KdfParams;
use pass_mgr_core::records::{self, RealEstate, TaxFiling, Vault};
use pass_mgr_core::vault::OpenVault;

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

// --- small local test helpers (mirroring the in-crate suite's idiom) ---------

/// Cheap KDF params so these tests are fast (the real crypto path still runs).
fn fast() -> KdfParams {
    KdfParams { m_cost: 256, t_cost: 1, p_cost: 1 }
}

fn nanos() -> u128 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
}

/// A fresh, unique vault directory; returns its `vault.pmv` path.
fn tmp_path(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("pmfmt-{tag}-{}", nanos()));
    std::fs::create_dir_all(&dir).unwrap();
    dir.join("vault.pmv")
}

/// Write a throwaway source file (the byte payload to be uploaded as a document).
fn write_src(tag: &str, body: &[u8]) -> PathBuf {
    let p = std::env::temp_dir().join(format!("pmfmt-src-{tag}-{}.bin", nanos()));
    std::fs::write(&p, body).unwrap();
    p
}

fn cleanup(path: &Path) {
    if let Some(parent) = path.parent() {
        let _ = std::fs::remove_dir_all(parent);
    }
}

// --- 1. End-to-end persistence of the new fields -----------------------------

#[test]
fn taxes_and_expanded_real_estate_survive_save_and_reopen() {
    let path = tmp_path("e2e");
    let tax_bytes = b"W-2 and 1099 for 2024";
    let deed_bytes = b"recorded deed PDF bytes";
    let tax_src = write_src("tax", tax_bytes);
    let deed_src = write_src("deed", deed_bytes);

    // Remember ids/values so we can assert against them after the reopen.
    let (tax_id, re_id, tax_doc_id, re_doc_id, gen_after_first_save);

    {
        let mut v = OpenVault::create(path.clone(), b"alpha", b"beta", fast()).unwrap();
        // The create() path performs the first save, so the generation is already 1.
        gen_after_first_save = v.vault.generation;
        assert_eq!(gen_after_first_save, 1, "create() does the first save");

        // ---- A tax filing with one uploaded document ----
        let mut tax = TaxFiling::new().unwrap();
        tax.year = "2024".into();
        tax.notes = "filed on time".into();
        tax_id = tax.id.clone();
        // Documents for a filing year live under taxes/<year>/.
        let loc = records::tax_doc_location(&tax.year);
        assert_eq!(loc, "taxes/2024");
        tax_doc_id = v.add_document(&loc, "w2.pdf", &tax_src).unwrap();
        tax.documents.push(tax_doc_id.clone());
        records::upsert(&mut v.vault.tax_filings, tax);

        // ---- An expanded real-estate record: portals + balance + comments + doc ----
        let mut re = RealEstate::new().unwrap();
        re.address = "123 Main St".into();
        re.owner = "Joint".into();
        re.financing_balance = "250000".into();
        re.comments = "tenant occupied through 2026".into();
        re.property_mgmt_url = "https://pm.example".into();
        re.property_mgmt_username = "pm_user".into();
        re.property_mgmt_password = "pm_pw".into();
        re.insurance_url = "https://ins.example".into();
        re.insurance_username = "ins_user".into();
        re.insurance_password = "ins_pw".into();
        re.hoa_url = "https://hoa.example".into();
        re.hoa_username = "hoa_user".into();
        re.hoa_password = "hoa_pw".into();
        re.tax_portal_url = "https://tax.example".into();
        re.tax_portal_username = "tax_user".into();
        re.tax_portal_password = "tax_pw".into();
        re.property_mgmt_comment = "PM notes".into();
        re.insurance_comment = "INS notes".into();
        re.hoa_comment = "HOA notes".into();
        re.tax_portal_comment = "TAX notes".into();
        re_id = re.id.clone();
        let re_loc = records::real_estate_doc_location(&re.address);
        assert_eq!(re_loc, "real-estate/123mainst");
        re_doc_id = v.add_document(&re_loc, "deed.pdf", &deed_src).unwrap();
        re.documents.push(re_doc_id.clone());
        records::upsert(&mut v.vault.real_estate, re);

        v.save().unwrap();
        // The explicit save bumps the generation past the create-time value.
        assert!(
            v.vault.generation > gen_after_first_save,
            "save() must bump generation ({} !> {})",
            v.vault.generation,
            gen_after_first_save
        );
        // dropping `v` releases the single-writer lock so we can reopen below.
    }

    // ---- Reopen with the same passwords and assert everything survived ----
    let v2 = OpenVault::open(path.clone(), b"alpha", b"beta").unwrap();

    // The reopen itself does a "refresh last-opened" save, so generation has
    // advanced again — strictly greater than the value right after create().
    assert!(
        v2.vault.generation > gen_after_first_save,
        "generation increments across save/reopen ({} !> {})",
        v2.vault.generation,
        gen_after_first_save
    );

    // Tax filing + its document.
    assert_eq!(v2.vault.tax_filings.len(), 1);
    let tax = &v2.vault.tax_filings[0];
    assert_eq!(tax.id, tax_id);
    assert_eq!(tax.year, "2024");
    assert_eq!(tax.notes, "filed on time");
    assert_eq!(tax.documents, vec![tax_doc_id.clone()]);
    assert_eq!(&*v2.read_document(&tax_doc_id).unwrap(), tax_bytes, "tax doc readable");
    assert_eq!(v2.doc_path(&tax_doc_id).unwrap(), "/taxes/2024/w2.pdf");

    // Real-estate record: all the new portal / balance / comment fields.
    assert_eq!(v2.vault.real_estate.len(), 1);
    let re = &v2.vault.real_estate[0];
    assert_eq!(re.id, re_id);
    assert_eq!(re.address, "123 Main St");
    assert_eq!(re.financing_balance, "250000");
    assert_eq!(re.comments, "tenant occupied through 2026");
    assert_eq!(re.property_mgmt_url, "https://pm.example");
    assert_eq!(re.property_mgmt_username, "pm_user");
    assert_eq!(re.property_mgmt_password, "pm_pw");
    assert_eq!(re.insurance_url, "https://ins.example");
    assert_eq!(re.insurance_username, "ins_user");
    assert_eq!(re.insurance_password, "ins_pw");
    assert_eq!(re.hoa_url, "https://hoa.example");
    assert_eq!(re.hoa_username, "hoa_user");
    assert_eq!(re.hoa_password, "hoa_pw");
    assert_eq!(re.tax_portal_url, "https://tax.example");
    assert_eq!(re.tax_portal_username, "tax_user");
    assert_eq!(re.tax_portal_password, "tax_pw");
    assert_eq!(re.property_mgmt_comment, "PM notes");
    assert_eq!(re.insurance_comment, "INS notes");
    assert_eq!(re.hoa_comment, "HOA notes");
    assert_eq!(re.tax_portal_comment, "TAX notes");
    assert_eq!(re.documents, vec![re_doc_id.clone()]);
    assert_eq!(&*v2.read_document(&re_doc_id).unwrap(), deed_bytes, "RE doc readable");
    assert_eq!(v2.doc_path(&re_doc_id).unwrap(), "/real-estate/123mainst/deed.pdf");

    drop(v2);
    cleanup(&path);
    let _ = std::fs::remove_file(&tax_src);
    let _ = std::fs::remove_file(&deed_src);
}

// --- 2. Backward compatibility: old vaults still load ------------------------

#[test]
fn old_vault_json_without_new_fields_still_deserializes() {
    // A minimal, hand-written "old-style" vault JSON: it predates `tax_filings`
    // and predates the expanded RealEstate fields. The single RealEstate entry
    // carries ONLY the original (pre-expansion) keys — no portals, no
    // financing_balance, no comments, no documents.
    let old_json = serde_json::json!({
        "version": 4,
        "generation": 7,
        "last_opened_at": 1_700_000_000,
        "instructions": [],
        "trust_wills": [],
        // An "old-style" asset: predates `title`/`url`/`beneficiary`/`review` and
        // `linked_accounts` — all of them #[serde(default)].
        "assets": [
            {
                "id": "ast-old-1",
                "kind": "Asset",
                "description": "Old brokerage",
                "owner": "Sole",
                "approx_value": "100",
                "as_of_date": "2020-01-01",
                "institution": "Bank",
                "asset_type": "Investment",
                "statement": null,
                "created_at": 1,
                "updated_at": 2,
                "history": []
            }
        ],
        "accounts": [],
        "real_estate": [
            {
                "id": "re-old-1",
                "address": "9 Old Rd",
                "ownership": "Sole",
                "taxes": "1200",
                "hoa": "0",
                "income_account": "",
                "financing_account": "",
                "payment_account": "",
                "created_at": 1,
                "updated_at": 2,
                "history": []
            }
        ],
        "id": "abc123",
        "audit": []
        // NOTE: deliberately no "tax_filings", no "settings", no "categories",
        // and the real_estate entry omits every new field.
    });

    // #[serde(default)] on the new Vault + RealEstate fields must let this load.
    let vault: Vault = serde_json::from_value(old_json).expect("old vault must still deserialize");

    // Old data preserved.
    assert_eq!(vault.version, 4);
    assert_eq!(vault.generation, 7);
    assert_eq!(vault.id, "abc123");
    assert_eq!(vault.real_estate.len(), 1);

    // New top-level collections default to empty.
    assert!(vault.tax_filings.is_empty(), "missing tax_filings defaults to empty");
    assert!(vault.general_documents.is_empty(), "missing general_documents defaults to empty");
    assert!(vault.urgent.is_empty(), "missing urgent defaults to empty");

    // Old-style asset loads with every later-added field defaulted.
    assert_eq!(vault.assets.len(), 1);
    let ast = &vault.assets[0];
    assert_eq!(ast.description, "Old brokerage", "old field preserved");
    assert_eq!(ast.title, "", "new field defaulted");
    assert!(!ast.review);
    assert!(ast.linked_accounts.is_empty(), "missing linked_accounts defaults to empty");

    // New RealEstate fields default to empty.
    let re = &vault.real_estate[0];
    assert_eq!(re.address, "9 Old Rd", "old field preserved");
    assert_eq!(re.financing_balance, "", "new field defaulted");
    assert_eq!(re.comments, "");
    assert_eq!(re.property_mgmt_url, "");
    assert_eq!(re.property_mgmt_username, "");
    assert_eq!(re.property_mgmt_password, "");
    assert_eq!(re.insurance_url, "");
    assert_eq!(re.insurance_username, "");
    assert_eq!(re.insurance_password, "");
    assert_eq!(re.hoa_url, "");
    assert_eq!(re.hoa_username, "");
    assert_eq!(re.hoa_password, "");
    assert!(re.documents.is_empty(), "new documents vec defaulted to empty");
}

#[test]
fn dropping_new_keys_from_a_current_vault_still_deserializes() {
    // Build a current, fully-populated Vault, serialize it to a JSON Value, then
    // REMOVE the keys that did not exist in older vaults — proving that a vault
    // written by an older build (which simply lacks those keys) still loads.
    let mut vault = Vault::default();
    vault.version = 4;

    let mut tax = TaxFiling::new().unwrap();
    tax.year = "2023".into();
    tax.documents.push("taxdoc".into());
    vault.tax_filings.push(tax);

    let mut re = RealEstate::new().unwrap();
    re.address = "1 New Way".into();
    re.financing_balance = "999".into();
    re.comments = "note".into();
    re.property_mgmt_url = "https://pm".into();
    re.insurance_password = "secret".into();
    re.hoa_username = "hoa".into();
    re.documents.push("redoc".into());
    vault.real_estate.push(re);

    let mut value = serde_json::to_value(&vault).unwrap();
    let obj = value.as_object_mut().unwrap();

    // Strip the vault-level field that older vaults lacked.
    obj.remove("tax_filings");

    // Strip the new RealEstate field keys from the (single) entry.
    let re_entry = obj
        .get_mut("real_estate")
        .and_then(|v| v.as_array_mut())
        .and_then(|a| a.get_mut(0))
        .and_then(|e| e.as_object_mut())
        .expect("real_estate[0] is an object");
    for k in [
        "financing_balance",
        "property_mgmt_url",
        "property_mgmt_username",
        "property_mgmt_password",
        "insurance_url",
        "insurance_username",
        "insurance_password",
        "hoa_url",
        "hoa_username",
        "hoa_password",
        "comments",
        "documents",
    ] {
        re_entry.remove(k);
    }

    let reloaded: Vault = serde_json::from_value(value).expect("vault with stripped new keys must load");

    // tax_filings defaulted away; old RE data kept, new RE fields defaulted.
    assert!(reloaded.tax_filings.is_empty());
    assert_eq!(reloaded.real_estate.len(), 1);
    let re = &reloaded.real_estate[0];
    assert_eq!(re.address, "1 New Way");
    assert_eq!(re.financing_balance, "");
    assert_eq!(re.comments, "");
    assert_eq!(re.property_mgmt_url, "");
    assert_eq!(re.insurance_password, "");
    assert_eq!(re.hoa_username, "");
    assert!(re.documents.is_empty());
}

// --- 3. serde_json round-trip preserves the new fields exactly ---------------

#[test]
fn fully_populated_vault_round_trips_through_json() {
    let mut vault = Vault::default();
    vault.version = 4;
    vault.generation = 42;
    vault.id = "vaultid".into();

    let mut tax = TaxFiling::new().unwrap();
    tax.year = "2025".into();
    tax.notes = "estimated".into();
    tax.documents = vec!["t1".into(), "t2".into()];
    vault.tax_filings.push(tax);

    let mut re = RealEstate::new().unwrap();
    re.address = "5 Round Trip Ln".into();
    re.owner = "Joint".into();
    re.financing_balance = "750000".into();
    re.comments = "multi\nline\ncomment".into();
    re.property_mgmt_url = "https://pm.example".into();
    re.property_mgmt_username = "pmu".into();
    re.property_mgmt_password = "pmp".into();
    re.insurance_url = "https://ins.example".into();
    re.insurance_username = "insu".into();
    re.insurance_password = "insp".into();
    re.hoa_url = "https://hoa.example".into();
    re.hoa_username = "hoau".into();
    re.hoa_password = "hoap".into();
    re.documents = vec!["d1".into(), "d2".into(), "d3".into()];
    vault.real_estate.push(re);

    let mut g = records::GeneralDocument::new().unwrap();
    g.title = "Passport".into();
    g.description = "scanned copy".into();
    g.file = Some("g1".into());
    vault.general_documents.push(g);

    // Serialize, then deserialize back.
    let json = serde_json::to_string(&vault).unwrap();
    let back: Vault = serde_json::from_str(&json).unwrap();

    // `Vault` does not derive PartialEq, so compare the new fields explicitly
    // (and confirm the whole thing is value-equal via serde_json::Value, which
    // catches any field that fails to round-trip).
    assert_eq!(back.tax_filings.len(), 1);
    let t = &back.tax_filings[0];
    assert_eq!(t.year, "2025");
    assert_eq!(t.notes, "estimated");
    assert_eq!(t.documents, vec!["t1".to_string(), "t2".to_string()]);

    assert_eq!(back.real_estate.len(), 1);
    let r = &back.real_estate[0];
    assert_eq!(r.address, "5 Round Trip Ln");
    assert_eq!(r.financing_balance, "750000");
    assert_eq!(r.comments, "multi\nline\ncomment");
    assert_eq!(r.property_mgmt_url, "https://pm.example");
    assert_eq!(r.property_mgmt_username, "pmu");
    assert_eq!(r.property_mgmt_password, "pmp");
    assert_eq!(r.insurance_url, "https://ins.example");
    assert_eq!(r.insurance_username, "insu");
    assert_eq!(r.insurance_password, "insp");
    assert_eq!(r.hoa_url, "https://hoa.example");
    assert_eq!(r.hoa_username, "hoau");
    assert_eq!(r.hoa_password, "hoap");
    assert_eq!(r.documents, vec!["d1".to_string(), "d2".to_string(), "d3".to_string()]);

    assert_eq!(back.general_documents.len(), 1);
    let gd = &back.general_documents[0];
    assert_eq!(gd.title, "Passport");
    assert_eq!(gd.description, "scanned copy");
    assert_eq!(gd.file.as_deref(), Some("g1"));

    // Whole-vault value equality: every field (new and old) survives the trip.
    let before = serde_json::to_value(&vault).unwrap();
    let after = serde_json::to_value(&back).unwrap();
    assert_eq!(before, after, "full Vault must round-trip byte-for-byte through JSON");
}