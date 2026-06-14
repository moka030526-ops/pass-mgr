//! Loads the external category lists used by the dropdowns. Asset/Liability
//! types are a flat list; Account types are **hierarchical** — each type has a
//! set of connected subtypes (e.g. "Financial" -> ["Bank", "IRA"]). The lists
//! live as editable JSON in the app's data dir, auto-created with defaults on
//! first run, and are not encrypted (category names only).

use std::fs;
use std::path::{Path, PathBuf};

use directories::ProjectDirs;
use serde::{Deserialize, Serialize};

const ASSET_FILE: &str = "asset_types.json";
const ACCOUNT_FILE: &str = "account_types.json";

const ASSET_DEFAULTS: &[&str] = &[
    "Cash", "Checking", "Savings", "Brokerage", "Retirement", "Real Estate",
    "Vehicle", "Business", "Insurance", "Loan", "Mortgage", "Credit Card", "Other",
];

/// An account type and its connected subtypes.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct AccountType {
    pub name: String,
    #[serde(default)]
    pub subtypes: Vec<String>,
}

fn account_defaults() -> Vec<AccountType> {
    let mk = |name: &str, subs: &[&str]| AccountType {
        name: name.to_string(),
        subtypes: subs.iter().map(|s| s.to_string()).collect(),
    };
    vec![
        mk("Financial", &["Bank", "Brokerage", "IRA", "401k", "Credit Card"]),
        mk("Utilities", &["Electric", "Gas", "Water", "Internet", "Phone"]),
        mk("Travel", &["Airline", "Hotel", "Car Rental"]),
        mk("Email", &[]),
        mk("Subscription", &[]),
        mk("Other", &[]),
    ]
}

/// The category lists used by the UI dropdowns, plus the directory they persist
/// in (so the config screen can add new types/subtypes and save them).
#[derive(Clone, Debug)]
pub struct TypeLists {
    pub asset: Vec<String>,
    pub account: Vec<AccountType>,
    dir: Option<PathBuf>,
}

impl TypeLists {
    /// In-memory lists with the built-in defaults and **no** persistence (`dir`
    /// is `None`). Used by tests that must not touch disk.
    #[cfg(test)]
    pub(crate) fn in_memory() -> Self {
        TypeLists {
            asset: ASSET_DEFAULTS.iter().map(|s| s.to_string()).collect(),
            account: account_defaults(),
            dir: None,
        }
    }

    /// Load both lists from `<data_dir>/types/`, creating defaults if missing.
    pub fn load() -> Self {
        let dir = ProjectDirs::from("dev", "passmgr", "pass-mgr")
            .map(|d| d.data_dir().join("types"));
        let asset = load_or_init(dir.as_deref(), ASSET_FILE, ASSET_DEFAULTS);
        let account = load_account_types(dir.as_deref());
        TypeLists { asset, account, dir }
    }

    // --- Asset/Liability (flat) ---------------------------------------------

    /// Add a new Asset/Liability type (trimmed, case-insensitive dedup) and
    /// persist. Returns whether it was newly added.
    pub fn add_asset_type(&mut self, name: &str) -> bool {
        if add_sorted(&mut self.asset, name) {
            self.persist_asset();
            true
        } else {
            false
        }
    }

    // --- Account (hierarchical) ---------------------------------------------

    /// The account type names, for the type dropdown/filter.
    pub fn account_type_names(&self) -> Vec<String> {
        self.account.iter().map(|t| t.name.clone()).collect()
    }

    /// The subtypes connected to `type_name` (empty if unknown). Case-insensitive.
    pub fn subtypes_for(&self, type_name: &str) -> Vec<String> {
        self.account
            .iter()
            .find(|t| t.name.eq_ignore_ascii_case(type_name))
            .map(|t| t.subtypes.clone())
            .unwrap_or_default()
    }

    /// Add a new account type (no subtypes) and persist. Returns whether added.
    pub fn add_account_type(&mut self, name: &str) -> bool {
        let name = name.trim();
        if name.is_empty() || self.account.iter().any(|t| t.name.eq_ignore_ascii_case(name)) {
            return false;
        }
        self.account.push(AccountType { name: name.to_string(), subtypes: Vec::new() });
        self.account.sort_by(|a, b| a.name.cmp(&b.name));
        self.persist_account();
        true
    }

    /// Add a subtype under an existing account type and persist. Returns whether
    /// added (false if the type is unknown or the subtype already exists/blank).
    pub fn add_account_subtype(&mut self, type_name: &str, subtype: &str) -> bool {
        let subtype = subtype.trim();
        if subtype.is_empty() {
            return false;
        }
        let Some(t) = self.account.iter_mut().find(|t| t.name.eq_ignore_ascii_case(type_name)) else {
            return false;
        };
        if t.subtypes.iter().any(|s| s.eq_ignore_ascii_case(subtype)) {
            return false;
        }
        t.subtypes.push(subtype.to_string());
        t.subtypes.sort();
        self.persist_account();
        true
    }

    // --- Persistence ---------------------------------------------------------

    fn persist_asset(&self) {
        self.write_json(ASSET_FILE, &self.asset);
    }

    fn persist_account(&self) {
        self.write_json(ACCOUNT_FILE, &self.account);
    }

    fn write_json<T: Serialize>(&self, file: &str, value: &T) {
        if let Some(dir) = &self.dir {
            let _ = fs::create_dir_all(dir);
            if let Ok(json) = serde_json::to_string_pretty(value) {
                let _ = fs::write(dir.join(file), json);
            }
        }
    }
}

/// Read a JSON string array from `dir/name`. A **missing** file is seeded with
/// defaults; an **existing** file is never overwritten — if invalid/empty we
/// fall back to defaults in memory only, so a hand-edited list is never clobbered.
fn load_or_init(dir: Option<&Path>, name: &str, defaults: &[&str]) -> Vec<String> {
    let to_vec = || defaults.iter().map(|s| s.to_string()).collect::<Vec<String>>();
    let Some(dir) = dir else { return to_vec() };
    let path = dir.join(name);

    match fs::read(&path) {
        Ok(bytes) => serde_json::from_slice::<Vec<String>>(&bytes)
            .ok()
            .filter(|list| !list.is_empty())
            .unwrap_or_else(to_vec),
        Err(_) => {
            let _ = fs::create_dir_all(dir);
            if let Ok(json) = serde_json::to_string_pretty(&to_vec()) {
                let _ = fs::write(&path, json);
            }
            to_vec()
        }
    }
}

/// Load the hierarchical account types, accepting either the new
/// `[{name, subtypes}]` form or a legacy flat `["Checking", ...]` array (each
/// legacy entry becomes a type with no subtypes). Missing file -> seed defaults.
fn load_account_types(dir: Option<&Path>) -> Vec<AccountType> {
    let Some(dir) = dir else { return account_defaults() };
    let path = dir.join(ACCOUNT_FILE);

    match fs::read(&path) {
        Ok(bytes) => {
            if let Ok(list) = serde_json::from_slice::<Vec<AccountType>>(&bytes)
                && !list.is_empty()
            {
                return list;
            }
            if let Ok(flat) = serde_json::from_slice::<Vec<String>>(&bytes)
                && !flat.is_empty()
            {
                return flat
                    .into_iter()
                    .map(|name| AccountType { name, subtypes: Vec::new() })
                    .collect();
            }
            // Present but unparsable: defaults in memory, don't clobber the file.
            account_defaults()
        }
        Err(_) => {
            let defaults = account_defaults();
            let _ = fs::create_dir_all(dir);
            if let Ok(json) = serde_json::to_string_pretty(&defaults) {
                let _ = fs::write(&path, json);
            }
            defaults
        }
    }
}

/// Insert `name` (trimmed) into `list` if not already present (case-insensitive),
/// keeping it sorted. Returns true if it was added.
fn add_sorted(list: &mut Vec<String>, name: &str) -> bool {
    let name = name.trim();
    if name.is_empty() || list.iter().any(|t| t.eq_ignore_ascii_case(name)) {
        return false;
    }
    list.push(name.to_string());
    list.sort();
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lists() -> TypeLists {
        TypeLists {
            asset: vec!["Brokerage".into()],
            account: account_defaults(),
            dir: None, // no persistence in tests
        }
    }

    #[test]
    fn add_sorted_dedups_trims_and_sorts() {
        let mut v = vec!["Brokerage".to_string()];
        assert!(add_sorted(&mut v, "  Annuity  "));
        assert!(!add_sorted(&mut v, "annuity"));
        assert!(!add_sorted(&mut v, "   "));
        assert_eq!(v, vec!["Annuity".to_string(), "Brokerage".to_string()]);
    }

    #[test]
    fn account_type_and_subtype_management() {
        let mut t = lists();
        assert!(t.account_type_names().contains(&"Financial".to_string()));
        assert!(t.subtypes_for("Financial").contains(&"IRA".to_string()));
        assert!(t.subtypes_for("financial").contains(&"IRA".to_string())); // case-insensitive

        assert!(t.add_account_type("Crypto"));
        assert!(!t.add_account_type("crypto")); // dup
        assert!(t.add_account_subtype("Crypto", "Exchange"));
        assert!(!t.add_account_subtype("Crypto", "exchange")); // dup
        assert!(!t.add_account_subtype("Nonexistent", "X")); // unknown type
        assert_eq!(t.subtypes_for("Crypto"), vec!["Exchange".to_string()]);
    }

    fn tmp_dir(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("passmgr-types-{tag}-{nanos}"))
    }

    #[test]
    fn add_persists_and_reloads_from_disk() {
        let dir = tmp_dir("persist");
        let mut t = TypeLists {
            asset: ASSET_DEFAULTS.iter().map(|s| s.to_string()).collect(),
            account: account_defaults(),
            dir: Some(dir.clone()),
        };
        assert!(t.add_asset_type("Annuity"));
        assert!(t.add_account_type("Crypto"));
        assert!(t.add_account_subtype("Crypto", "Exchange"));

        // Reload from the files on disk and confirm everything was written.
        let asset = load_or_init(Some(&dir), ASSET_FILE, ASSET_DEFAULTS);
        let account = load_account_types(Some(&dir));
        assert!(asset.contains(&"Annuity".to_string()));
        let crypto = account.iter().find(|a| a.name == "Crypto").unwrap();
        assert_eq!(crypto.subtypes, vec!["Exchange".to_string()]);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_or_init_seeds_then_honors_user_edits() {
        let dir = tmp_dir("seed");
        // Missing -> seeded with defaults.
        let first = load_or_init(Some(&dir), "asset_types.json", ASSET_DEFAULTS);
        assert_eq!(first.len(), ASSET_DEFAULTS.len());
        // A user edit is honored (not clobbered) on the next load.
        std::fs::write(dir.join("asset_types.json"), r#"["OnlyMine"]"#).unwrap();
        assert_eq!(load_or_init(Some(&dir), "asset_types.json", ASSET_DEFAULTS), vec!["OnlyMine".to_string()]);
        // An invalid file falls back to defaults in memory WITHOUT overwriting.
        std::fs::write(dir.join("asset_types.json"), "not json").unwrap();
        assert_eq!(load_or_init(Some(&dir), "asset_types.json", ASSET_DEFAULTS).len(), ASSET_DEFAULTS.len());
        assert_eq!(std::fs::read_to_string(dir.join("asset_types.json")).unwrap(), "not json");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_account_types_reads_legacy_flat_file() {
        let dir = tmp_dir("legacy");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(ACCOUNT_FILE), r#"["Checking","Savings"]"#).unwrap();
        let account = load_account_types(Some(&dir));
        assert_eq!(account.len(), 2);
        assert_eq!(account[0].name, "Checking");
        assert!(account[0].subtypes.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn in_memory_has_no_dir_and_defaults() {
        let t = TypeLists::in_memory();
        assert!(t.dir.is_none());
        assert!(!t.asset.is_empty());
        assert!(t.account_type_names().contains(&"Financial".to_string()));
    }

    #[test]
    fn legacy_flat_account_file_is_accepted() {
        let bytes = serde_json::to_vec(&vec!["Checking", "Savings"]).unwrap();
        let parsed: Vec<AccountType> = serde_json::from_slice::<Vec<AccountType>>(&bytes)
            .ok()
            .filter(|l: &Vec<AccountType>| !l.is_empty())
            .unwrap_or_else(|| {
                serde_json::from_slice::<Vec<String>>(&bytes)
                    .unwrap()
                    .into_iter()
                    .map(|name| AccountType { name, subtypes: Vec::new() })
                    .collect()
            });
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].name, "Checking");
        assert!(parsed[0].subtypes.is_empty());
    }
}
