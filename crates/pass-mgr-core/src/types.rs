//! Editable category lists used by the UI dropdowns. Asset/Liability types are a
//! flat list; Account types are **hierarchical** — each type has a set of
//! connected subtypes (e.g. "Financial" -> ["Bank", "IRA"]).
//!
//! These lists are stored **inside the encrypted vault** (see [`crate::records::Vault`]),
//! not in external files: a newly created vault is seeded with the built-in
//! defaults below, and the Config screen adds new types/subtypes by mutating the
//! vault and saving it. So there is nothing on disk to read at startup and no
//! unencrypted category file to leak.

// `use` brings names into scope (like an import). `serde` is the standard Rust
// serialization framework; `Serialize`/`Deserialize` are traits (≈ interfaces)
// that let a type be converted to/from JSON. The `{A, B}` syntax imports both
// names from the same `serde` crate in one line.
use serde::{Deserialize, Serialize};

// A module-level constant. `&[&str]` is a *slice of string slices*: a read-only
// view over a list of borrowed, fixed text strings (`&str` = an immutable text
// reference, as opposed to an owned, growable `String`). `&[...]` builds that
// slice from the literal array. These are the seed Asset/Liability type names.
const ASSET_DEFAULTS: &[&str] = &[
    "Cash", "Checking", "Savings", "Brokerage", "Retirement", "Real Estate",
    "Vehicle", "Business", "Insurance", "Loan", "Mortgage", "Credit Card", "Other",
];

/// An account type and its connected subtypes.
// `#[derive(...)]` auto-generates trait implementations for this struct so we
// don't write them by hand:
//   Serialize/Deserialize -> can become / be rebuilt from JSON
//   Clone   -> can be deep-copied via `.clone()`
//   Debug   -> can be printed for diagnostics ({:?})
//   Default -> can produce an "empty" value via `AccountType::default()`
//   PartialEq/Eq -> can be compared with `==`
// `pub` = visible outside this module. `String` is an owned, heap-allocated,
// growable UTF-8 string (it owns its bytes; contrast with the borrowed `&str`).
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
pub struct AccountType {
    pub name: String,
    // `#[serde(default)]`: if this field is missing when reading older JSON,
    // fill it with the default (an empty Vec) instead of failing to parse.
    // `Vec<String>` is a growable list (vector) of owned strings.
    #[serde(default)]
    pub subtypes: Vec<String>,
}

// `fn name(...) -> ReturnType` declares a function. This one takes no arguments
// and returns an owned `Vec<AccountType>`.
fn account_defaults() -> Vec<AccountType> {
    // `mk` is a *closure*: an inline anonymous function captured in a local
    // variable. The `|name, subs|` between the bars are its parameters; the
    // expression after them is its body. It builds one `AccountType`.
    let mk = |name: &str, subs: &[&str]| AccountType {
        // `&str` -> owned `String`: `.to_string()` allocates an owned copy.
        name: name.to_string(),
        // Iterator pipeline: `.iter()` walks the slice yielding `&&str`, `.map`
        // applies the closure `|s| s.to_string()` to copy each into an owned
        // `String`, and `.collect()` gathers the results into a `Vec<String>`
        // (the target type is inferred from the `subtypes` field).
        subtypes: subs.iter().map(|s| s.to_string()).collect(),
    };
    // `vec![...]` is a macro that builds a `Vec`. The final expression in a
    // function body (no trailing `;`) is its return value.
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
// Same auto-generated traits as AccountType (see note above). `Default` here
// yields a TypeLists with two empty Vecs.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
pub struct TypeLists {
    // `#[serde(default)]` again: tolerate old vault JSON that lacks these fields.
    #[serde(default)]
    pub asset: Vec<String>,
    #[serde(default)]
    pub account: Vec<AccountType>,
}

// `impl TypeLists { ... }` attaches methods/associated functions to the
// TypeLists type (like defining the methods of a class). Everything inside
// operates on TypeLists values.
impl TypeLists {
    /// The built-in defaults, seeded into a newly created vault (and used as the
    /// serde fallback for a vault that predates this field).
    // No `self` parameter, so this is an *associated function* (≈ a static
    // factory / constructor), called as `TypeLists::with_defaults()`. `Self` is
    // shorthand for the enclosing type, `TypeLists`.
    pub fn with_defaults() -> Self {
        TypeLists {
            asset: ASSET_DEFAULTS.iter().map(|s| s.to_string()).collect(),
            account: account_defaults(),
        }
    }

    // --- Account (hierarchical) ---------------------------------------------

    /// The account type names, for the type dropdown/filter.
    // `&self` = a *shared (read-only) borrow* of the TypeLists: the method can
    // read the value but not modify it, and the caller keeps ownership. Returns
    // a fresh owned Vec, so the caller can't mutate our internal lists.
    pub fn account_type_names(&self) -> Vec<String> {
        // Walk each AccountType by shared reference (`t` is `&AccountType`),
        // `.clone()` each name into a new owned String (we must copy because we
        // only borrowed the originals), and collect into a Vec<String>.
        self.account.iter().map(|t| t.name.clone()).collect()
    }

    /// The subtypes connected to `type_name` (empty if unknown). Case-insensitive.
    // `type_name: &str` borrows the caller's text without taking ownership.
    pub fn subtypes_for(&self, type_name: &str) -> Vec<String> {
        self.account
            .iter()
            // `.find(closure)` returns the FIRST element matching the predicate,
            // wrapped as `Option<&AccountType>`: `Some(t)` if found, else `None`.
            // The closure does a case-insensitive name compare.
            .find(|t| t.name.eq_ignore_ascii_case(type_name))
            // `.map` on an Option transforms the inner value only if it's
            // `Some`, leaving `None` as `None`. Here: clone the matched subtypes
            // into an owned Vec -> `Option<Vec<String>>`.
            .map(|t| t.subtypes.clone())
            // If the Option is `None` (type not found), substitute the type's
            // default (an empty Vec). Net effect: empty list for unknown types.
            .unwrap_or_default()
    }

    // --- Mutators (in-memory only; the vault save persists them) -------------

    /// Add a new Asset/Liability type (trimmed, case-insensitive dedup). Returns
    /// whether it was newly added.
    // `&mut self` = an *exclusive (mutable) borrow*: this method may modify the
    // TypeLists, and Rust guarantees no other reference exists meanwhile.
    pub fn add_asset_type(&mut self, name: &str) -> bool {
        // Pass an exclusive borrow of just the `asset` vector to the helper.
        add_sorted(&mut self.asset, name)
    }

    /// Add a new account type (no subtypes). Returns whether it was newly added.
    pub fn add_account_type(&mut self, name: &str) -> bool {
        // *Shadowing*: re-declare `name` to rebind it to the trimmed `&str`. The
        // original parameter is hidden from here on; this is not mutation.
        let name = name.trim();
        // Reject blank or duplicate. `.any(closure)` returns true if ANY element
        // matches; `||` short-circuits (skips the scan if already empty).
        if name.is_empty() || self.account.iter().any(|t| t.name.eq_ignore_ascii_case(name)) {
            // Early return: bail out of the function with `false`.
            return false;
        }
        // `.push` appends to the Vec. `Vec::new()` is an empty vector.
        self.account.push(AccountType { name: name.to_string(), subtypes: Vec::new() });
        // Sort in place. The closure is the comparator: `.cmp` orders the names.
        self.account.sort_by(|a, b| a.name.cmp(&b.name));
        // Bare `true` as the last expression = the return value (added).
        true
    }

    /// Add a subtype under an existing account type. Returns whether it was added
    /// (false if the type is unknown or the subtype already exists/is blank).
    pub fn add_account_subtype(&mut self, type_name: &str, subtype: &str) -> bool {
        // Shadow `subtype` with its trimmed form (see note above).
        let subtype = subtype.trim();
        if subtype.is_empty() {
            return false;
        }
        // `let ... else`: try to bind the pattern `Some(t)` from the Option that
        // `.find` returns; if it's `None` (type not found), run the `else` block,
        // which MUST diverge (here, `return false`). On success `t` is bound for
        // the rest of the function. `.iter_mut()` yields *mutable* references so
        // we can modify the matched AccountType in place.
        let Some(t) = self.account.iter_mut().find(|t| t.name.eq_ignore_ascii_case(type_name))
        else {
            return false;
        };
        // Reject if this subtype already exists (case-insensitive).
        if t.subtypes.iter().any(|s| s.eq_ignore_ascii_case(subtype)) {
            return false;
        }
        t.subtypes.push(subtype.to_string());
        t.subtypes.sort();
        true
    }

    // --- Removers (in-memory only; the vault save persists them) -------------
    // NOTE: these only edit the lists. The "is this type still used by a record?"
    // and "block deleting a type that still has subtypes" policy lives in
    // `OpenVault::remove_*` (it needs the records, which TypeLists cannot see).

    /// Remove an Asset/Liability type (case-insensitive). Returns whether removed.
    pub fn remove_asset_type(&mut self, name: &str) -> bool {
        let before = self.asset.len();
        // `retain` keeps only the elements for which the closure is true, i.e. drops
        // every case-insensitive match. The length change tells us if anything went.
        self.asset.retain(|t| !t.eq_ignore_ascii_case(name));
        self.asset.len() != before
    }

    /// Remove an account type **and its subtype list** (case-insensitive). Returns
    /// whether removed. Callers gate this on "no subtypes / not in use" themselves.
    pub fn remove_account_type(&mut self, name: &str) -> bool {
        let before = self.account.len();
        self.account.retain(|t| !t.name.eq_ignore_ascii_case(name));
        self.account.len() != before
    }

    /// Remove a subtype from an account type (case-insensitive). Returns whether
    /// removed (false if the type is unknown or the subtype was absent).
    pub fn remove_account_subtype(&mut self, type_name: &str, subtype: &str) -> bool {
        let Some(t) = self.account.iter_mut().find(|t| t.name.eq_ignore_ascii_case(type_name)) else {
            return false;
        };
        let before = t.subtypes.len();
        t.subtypes.retain(|s| !s.eq_ignore_ascii_case(subtype));
        t.subtypes.len() != before
    }
}

/// Insert `name` (trimmed) into `list` if not already present (case-insensitive),
/// keeping it sorted. Returns true if it was added.
// Free function (not in an impl). `list: &mut Vec<String>` is an exclusive
// borrow of the caller's vector, so edits here are seen by the caller; `name:
// &str` is a read-only borrow of the candidate text.
fn add_sorted(list: &mut Vec<String>, name: &str) -> bool {
    let name = name.trim();
    if name.is_empty() || list.iter().any(|t| t.eq_ignore_ascii_case(name)) {
        return false;
    }
    list.push(name.to_string());
    list.sort();
    true
}

// `#[cfg(test)]` is *conditional compilation*: this whole module is compiled
// ONLY during `cargo test` and excluded from the shipped binary. Each `#[test]`
// function below is run by the test harness; `assert!`/`assert_eq!` panic (fail
// the test) if their condition is false. `use super::*;` pulls in everything
// from the parent module so the tests can call it unqualified.
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
    fn remove_types_and_subtypes_case_insensitively() {
        let mut t = TypeLists::default();
        t.add_asset_type("Crypto");
        t.add_account_type("Bank");
        t.add_account_subtype("Bank", "Checking");
        t.add_account_subtype("Bank", "Savings");

        // Asset type: case-insensitive removal; no-op when absent.
        assert!(t.remove_asset_type("crypto")); // case-insensitive match of stored "Crypto"
        assert!(!t.remove_asset_type("Crypto"), "already gone");
        assert!(t.asset.is_empty());

        // Subtype removal is case-insensitive and scoped to the type.
        assert!(t.remove_account_subtype("bank", "CHECKING"));
        assert_eq!(t.subtypes_for("Bank"), vec!["Savings".to_string()]);
        assert!(!t.remove_account_subtype("Bank", "Checking"), "already gone");
        assert!(!t.remove_account_subtype("Unknown", "x"), "unknown type");

        // Account type removal drops the whole entry (incl. remaining subtypes).
        assert!(t.remove_account_type("BANK"));
        assert!(!t.account_type_names().contains(&"Bank".to_string()));
        assert!(t.subtypes_for("Bank").is_empty());
        assert!(!t.remove_account_type("Bank"), "already gone");
    }

    #[test]
    fn default_is_empty_so_serde_round_trips() {
        let t = TypeLists::default();
        assert!(t.asset.is_empty() && t.account.is_empty());
        // These return `Result<T, E>` (Ok value or Err). `.unwrap()` extracts
        // the Ok value and *panics* on Err — fine in a test, where a serde
        // failure should loudly fail the test rather than be handled.
        let json = serde_json::to_string(&t).unwrap();
        let back: TypeLists = serde_json::from_str(&json).unwrap();
        assert_eq!(t, back);
    }
}
