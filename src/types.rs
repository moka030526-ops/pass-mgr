//! Loads the external category lists used by the Asset/Liability and Account
//! dropdowns. The lists live as editable JSON arrays in the app's data dir and
//! are auto-created with sensible defaults on first run. They are not encrypted
//! — they hold only category names, no secrets.

use std::fs;
use std::path::Path;

use directories::ProjectDirs;

const ASSET_DEFAULTS: &[&str] = &[
    "Cash", "Checking", "Savings", "Brokerage", "Retirement", "Real Estate",
    "Vehicle", "Business", "Insurance", "Loan", "Mortgage", "Credit Card", "Other",
];

const ACCOUNT_DEFAULTS: &[&str] = &[
    "Checking", "Savings", "Credit Card", "Brokerage", "Retirement", "Email",
    "Utility", "Subscription", "Bill Pay", "Other",
];

/// The two category lists used by the UI dropdowns.
#[derive(Clone, Debug)]
pub struct TypeLists {
    pub asset: Vec<String>,
    pub account: Vec<String>,
}

impl TypeLists {
    /// Load both lists from `<data_dir>/types/`, creating defaults if missing.
    pub fn load() -> Self {
        let dir = ProjectDirs::from("dev", "passmgr", "pass-mgr")
            .map(|d| d.data_dir().join("types"));
        TypeLists {
            asset: load_or_init(dir.as_deref(), "asset_types.json", ASSET_DEFAULTS),
            account: load_or_init(dir.as_deref(), "account_types.json", ACCOUNT_DEFAULTS),
        }
    }
}

/// Read a JSON string array from `dir/name`. A **missing** file is seeded with
/// the defaults; an **existing** file is never overwritten — if it is invalid or
/// empty we fall back to the defaults *in memory only*, so a user's hand-edited
/// list is never clobbered.
fn load_or_init(dir: Option<&Path>, name: &str, defaults: &[&str]) -> Vec<String> {
    let to_vec = || defaults.iter().map(|s| s.to_string()).collect::<Vec<String>>();
    let Some(dir) = dir else { return to_vec() };
    let path = dir.join(name);

    match fs::read(&path) {
        // File present: honor valid, non-empty content; otherwise use defaults
        // in memory but leave the file untouched.
        Ok(bytes) => serde_json::from_slice::<Vec<String>>(&bytes)
            .ok()
            .filter(|list| !list.is_empty())
            .unwrap_or_else(to_vec),
        // File missing (or unreadable): seed defaults, best-effort.
        Err(_) => {
            let _ = fs::create_dir_all(dir);
            if let Ok(json) = serde_json::to_string_pretty(&to_vec()) {
                let _ = fs::write(&path, json);
            }
            to_vec()
        }
    }
}
