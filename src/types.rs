//! Editable category lists used by the UI dropdowns. Asset/Liability types are a
//! flat list; Account types are **hierarchical** — each type has a set of
//! connected subtypes (e.g. "Financial" -> ["Bank", "IRA"]).
//!
//! These lists are stored **inside the encrypted vault** (see [`crate::records::Vault`]),
//! not in external files: a newly created vault is seeded with the built-in
//! defaults below, and the Config screen adds new types/subtypes by mutating the
//! vault and saving it. So there is nothing on disk to read at startup and no
//! unencrypted category file to leak.

use serde::{Deserialize, Serialize};

const ASSET_DEFAULTS: &[&str] = &[
    "Cash", "Checking", "Savings", "Brokerage", "Retirement", "Real Estate",
    "Vehicle", "Business", "Insurance", "Loan", "Mortgage", "Credit Card", "Other",
];

/// An account type and its connected subtypes.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
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

/// The category lists, embedded in the vault. The mutators here only update the
/// in-memory lists and report whether anything changed; **persistence happens
/// when the owning [`crate::vault::OpenVault`] is saved**, so the lists live and
/// die with the encrypted vault.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
pub struct TypeLists {
    #[serde(default)]
    pub asset: Vec<String>,
    #[serde(default)]
    pub account: Vec<AccountType>,
}

impl TypeLists {
    /// The built-in defaults, seeded into a newly created vault (and used as the
    /// serde fallback for a vault that predates this field).
    pub fn with_defaults() -> Self {
        TypeLists {
            asset: ASSET_DEFAULTS.iter().map(|s| s.to_string()).collect(),
            account: account_defaults(),
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

    // --- Mutators (in-memory only; the vault save persists them) -------------

    /// Add a new Asset/Liability type (trimmed, case-insensitive dedup). Returns
    /// whether it was newly added.
    pub fn add_asset_type(&mut self, name: &str) -> bool {
        add_sorted(&mut self.asset, name)
    }

    /// Add a new account type (no subtypes). Returns whether it was newly added.
    pub fn add_account_type(&mut self, name: &str) -> bool {
        let name = name.trim();
        if name.is_empty() || self.account.iter().any(|t| t.name.eq_ignore_ascii_case(name)) {
            return false;
        }
        self.account.push(AccountType { name: name.to_string(), subtypes: Vec::new() });
        self.account.sort_by(|a, b| a.name.cmp(&b.name));
        true
    }

    /// Add a subtype under an existing account type. Returns whether it was added
    /// (false if the type is unknown or the subtype already exists/is blank).
    pub fn add_account_subtype(&mut self, type_name: &str, subtype: &str) -> bool {
        let subtype = subtype.trim();
        if subtype.is_empty() {
            return false;
        }
        let Some(t) = self.account.iter_mut().find(|t| t.name.eq_ignore_ascii_case(type_name))
        else {
            return false;
        };
        if t.subtypes.iter().any(|s| s.eq_ignore_ascii_case(subtype)) {
            return false;
        }
        t.subtypes.push(subtype.to_string());
        t.subtypes.sort();
        true
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

    #[test]
    fn defaults_are_populated() {
        let t = TypeLists::with_defaults();
        assert!(!t.asset.is_empty());
        assert!(t.account_type_names().contains(&"Financial".to_string()));
        assert!(t.subtypes_for("Financial").contains(&"Bank".to_string()));
        assert!(t.subtypes_for("nope").is_empty());
    }

    #[test]
    fn add_asset_type_dedups_case_insensitively_and_sorts() {
        let mut t = TypeLists::default();
        assert!(t.add_asset_type("Crypto"));
        assert!(!t.add_asset_type("  crypto ")); // case-insensitive dup
        assert!(!t.add_asset_type("   ")); // blank
        assert!(t.add_asset_type("Annuity"));
        assert_eq!(t.asset, vec!["Annuity".to_string(), "Crypto".to_string()]); // sorted
    }

    #[test]
    fn add_account_type_and_subtype() {
        let mut t = TypeLists::default();
        assert!(t.add_account_type("Crypto"));
        assert!(!t.add_account_type("crypto")); // dup
        assert!(t.add_account_subtype("Crypto", "Exchange"));
        assert!(!t.add_account_subtype("Crypto", "exchange")); // dup
        assert!(!t.add_account_subtype("Unknown", "X")); // unknown type
        assert!(!t.add_account_subtype("Crypto", "  ")); // blank
        assert_eq!(t.subtypes_for("Crypto"), vec!["Exchange".to_string()]);
    }

    #[test]
    fn default_is_empty_so_serde_round_trips() {
        let t = TypeLists::default();
        assert!(t.asset.is_empty() && t.account.is_empty());
        let json = serde_json::to_string(&t).unwrap();
        let back: TypeLists = serde_json::from_str(&json).unwrap();
        assert_eq!(t, back);
    }
}
