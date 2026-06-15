//! The estate-vault data model: the five record types behind the UI tabs, the
//! encrypted-volume manifest, and the [`Vault`] that owns them all.
//!
//! Every record carries an `id`, `created_at`/`updated_at` timestamps, and an
//! append-only `history` of timestamped [`Change`]s (req: trace history). The
//! shared insert/edit/diff logic lives in the [`Record`] trait + the generic
//! [`upsert`]/[`remove`] helpers, so each type only describes its own fields and
//! field-level diff. All types wipe their contents on drop (they hold secrets
//! such as passwords).
//!
//! Rust orientation for non-Rust readers (concepts used throughout this file):
//! - `//!` starts a *module*-level doc comment (this whole block describes the
//!   file); `///` documents the item right below it; `//` is an ordinary comment.
//! - `&T` is a *shared (read-only) borrow* of a value, `&mut T` an *exclusive
//!   (read/write) borrow*. Passing `&x` lends access without giving up ownership;
//!   `clone()` makes an independent copy when a value would otherwise be moved.
//! - `Result<T, E>` is "either an `Ok(T)` or an `Err(E)`"; `Option<T>` is "either
//!   `Some(T)` or `None`". The `?` operator means "if this is an error/None,
//!   return it from the current function early; otherwise unwrap the value".
//! - `Vec<T>` is a growable array; `String` is an owned text buffer; `&str` is a
//!   borrowed view of text. `derive(...)` auto-generates trait implementations.

// `use` brings names into scope (like imports).
// serde = serialization framework; Deserialize/Serialize let these structs be
// converted to/from bytes (used for encrypting the vault to disk).
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
// zeroize = securely wipe memory. `Zeroize` exposes a wipe method; `ZeroizeOnDrop`
// makes a value wipe itself automatically when it goes out of scope (req: secrets
// must not linger in RAM).
use zeroize::{Zeroize, ZeroizeOnDrop};

// `crate::crypto` is the sibling `crypto` module of this same crate (binary).
// `self` here also imports the `crypto` module name itself, so both `crypto::...`
// and `CryptoError` are usable below.
use crate::crypto::{self, CryptoError};

/// Unix-seconds "now" (0 if the clock is before the epoch).
// `pub fn` = public function; `-> i64` = returns a 64-bit signed integer.
pub fn unix_now() -> i64 {
    SystemTime::now()
        // `duration_since` returns a `Result`: Ok(duration) if now >= epoch, else Err.
        .duration_since(UNIX_EPOCH)
        // `.map(|d| ...)` transforms the Ok value with a *closure* (an inline
        // anonymous function `|d| body`). `as i64` is a numeric cast.
        .map(|d| d.as_secs() as i64)
        // `.unwrap_or(0)` yields the inner value, or 0 if it was an Err.
        .unwrap_or(0)
}

/// Case-insensitive substring match used by the UIs' free-text search (e.g.
/// searching accounts by username). An empty/whitespace-only `query` matches
/// everything (no filter). Both sides are lower-cased and the query is trimmed.
// `haystack`/`query` are borrowed `&str`; the function only reads them.
pub fn matches_search(haystack: &str, query: &str) -> bool {
    let q = query.trim().to_lowercase();
    q.is_empty() || haystack.to_lowercase().contains(&q)
}

/// A random 128-bit hex id, used for records and volume blobs.
// Returns `Ok(String)` on success or an `Err(CryptoError)` if the RNG fails.
pub fn random_id() -> Result<String, CryptoError> {
    // `::<16>` is a const generic argument: ask for exactly 16 random bytes.
    // The trailing `?` propagates an error: if `random_bytes` returns Err, this
    // function returns that Err immediately; otherwise `bytes` is the 16 bytes.
    let bytes = crypto::random_bytes::<16>()?;
    // Iterate the bytes, format each as 2 lowercase hex digits, and `.collect()`
    // the resulting chars into one `String`. `Ok(...)` wraps it as the success case.
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

/// Break a unix-seconds timestamp into civil UTC `(year, month, day, hour, min,
/// sec)` using Howard Hinnant's `civil_from_days` algorithm. Negative/zero clamps
/// to the epoch. Shared by the human and filename timestamp formatters so the
/// (fiddly) calendar math lives in exactly one place.
// `pub(crate)` = visible anywhere in this crate but not to outside users.
// The return type `(i64, i64, ...)` is a *tuple*: several values bundled together.
pub(crate) fn civil_from_unix(ts: i64) -> (i64, i64, i64, i64, i64, i64) {
    // `let ts = ...` here *shadows* the parameter `ts`: a new binding reusing the
    // name. `.max(0)` clamps negatives to 0 (so pre-epoch times become the epoch).
    let ts = ts.max(0);
    let days = ts.div_euclid(86_400);
    let sod = ts.rem_euclid(86_400);
    let (h, m, s) = (sod / 3600, (sod % 3600) / 60, sod % 60);

    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { y + 1 } else { y };
    (year, month, day, h, m, s)
}

/// A single timestamped audit record. Pushed onto a record's history on every
/// edit, or onto the vault-level audit / volume upload log.
// `#[derive(...)]` auto-implements these traits for the struct below:
//   Serialize/Deserialize -> can be encoded to/from disk bytes,
//   Clone -> can be deep-copied, Debug -> printable for debugging,
//   Default -> has a zero/empty default value,
//   Zeroize/ZeroizeOnDrop -> wipes its memory (and does so automatically on drop).
#[derive(Serialize, Deserialize, Clone, Debug, Default, Zeroize, ZeroizeOnDrop)]
pub struct Change {
    pub at: i64,        // unix-seconds timestamp of the change
    pub action: String, // e.g. "created", "updated", "deleted"
    pub detail: String, // human-readable description
}

// An `impl` block attaches methods/associated functions to a type (like adding
// methods to a class).
impl Change {
    // `&str` is a borrowed string slice (caller keeps ownership of its text);
    // `detail: String` is taken by value (an owned string moved in). `-> Self`
    // means it returns a `Change`.
    pub fn new(action: &str, detail: String) -> Self {
        // `action.to_string()` copies the borrowed text into a new owned String.
        Change { at: unix_now(), action: action.to_string(), detail }
    }
}

/// Append a field change to `out` if `old != new` (full before/after values).
// `out: &mut Vec<Change>` is an *exclusive borrow* of the caller's vector, so this
// function can push into the caller's list without copying or owning it. Plain
// `fn` (no `pub`) means this helper is private to the module.
fn track(out: &mut Vec<Change>, at: i64, name: &str, old: &str, new: &str) {
    if old != new {
        out.push(Change {
            at,
            // `.into()` converts the "updated" `&str` literal into an owned
            // `String` (the field's type) via the trait-driven `Into` conversion.
            action: "updated".into(),
            // `{old:?}`/`{new:?}` use the Debug format (quotes the strings).
            detail: format!("{name}: {old:?} -> {new:?}"),
        });
    }
}

/// Append a boolean field change to `out` if it changed.
fn track_bool(out: &mut Vec<Change>, at: i64, name: &str, old: bool, new: bool) {
    if old != new {
        out.push(Change { at, action: "updated".into(), detail: format!("{name}: {old} -> {new}") });
    }
}

/// Shared behaviour for the five record types so insert/edit/history is generic.
// A `trait` is like an interface: it lists methods a type must provide. `: Clone`
// is a *supertrait bound* — anything implementing `Record` must also be cloneable.
// These are method *signatures* only; each record type fills in the bodies later.
pub trait Record: Clone {
    // `&self` borrows the value read-only (a getter). `-> &str` returns a borrowed
    // view of the id, tied to the lifetime of `self` (no copy).
    fn id(&self) -> &str;
    fn created_at(&self) -> i64;
    // `&mut self` borrows exclusively so the method may mutate the value (a setter).
    fn set_created_at(&mut self, at: i64);
    fn set_updated_at(&mut self, at: i64);
    // Returns an exclusive borrow of the history vector so callers can push to it.
    fn history_mut(&mut self) -> &mut Vec<Change>;
    /// Field-level diff describing the change from `self` to `new`.
    // `Self` (capital S) means "the implementing type itself", so `new: &Self`
    // borrows another value of the same record type.
    fn diff(&self, new: &Self, at: i64) -> Vec<Change>;
    /// Short label for list display.
    fn label(&self) -> String;
}

/// Insert `rec` or, if a record with the same id exists, replace it — appending
/// the field-level diff to history and preserving the original creation time.
// `<R: Record>` is a *generic* parameter: this one function works for any type `R`
// that implements the `Record` trait. `list: &mut Vec<R>` borrows the caller's
// vector exclusively; `mut rec: R` takes ownership of the record (moved in) and
// `mut` lets us modify it locally.
pub fn upsert<R: Record>(list: &mut Vec<R>, mut rec: R) {
    let now = unix_now();
    rec.set_updated_at(now);
    // `match` is pattern-matching (like a powerful switch). `.position(..)` finds
    // the index of the first element matching the closure `|e| ...`, returning
    // `Some(index)` or `None`.
    match list.iter().position(|e| e.id() == rec.id()) {
        // Existing record at index `i`: this is an edit.
        Some(i) => {
            // `&rec` lends the new record to `diff` (which only needs to read it).
            let changes = list[i].diff(&rec, now);
            rec.set_created_at(list[i].created_at()); // keep original creation time
            // `.clone()` copies the old history out so we can rebuild it.
            let mut history = list[i].history_mut().clone();
            history.extend(changes); // old history + the new diffs
            // `*rec.history_mut() = history` writes through the mutable borrow,
            // replacing the record's history with the combined list.
            *rec.history_mut() = history;
            list[i] = rec; // replace the slot (the old record is dropped & wiped)
        }
        // No match: this is a fresh insert.
        None => {
            let label = rec.label();
            rec.history_mut().push(Change::new("created", label));
            list.push(rec);
        }
    }
}

/// Remove a record by id, logging a timestamped deletion in `audit`.
// Generic over any `Record` type. Returns `bool`: true if something was removed.
pub fn remove<R: Record>(list: &mut Vec<R>, id: &str, audit: &mut Vec<Change>, kind: &str) -> bool {
    match list.iter().position(|e| e.id() == id) {
        Some(i) => {
            let label = list[i].label();
            list.remove(i);
            audit.push(Change::new("deleted", format!("{kind}: {label}")));
            true
        }
        None => false,
    }
}

// --- The five record types ---------------------------------------------------
// Each struct below is one record kind. They share the same derives as `Change`
// (see that note): Serialize/Deserialize for disk, Clone/Debug/Default, and
// Zeroize/ZeroizeOnDrop so every field (including secrets) is wiped on drop.

/// Tab 1 — free-form instruction note.
#[derive(Serialize, Deserialize, Clone, Debug, Default, Zeroize, ZeroizeOnDrop)]
pub struct Instruction {
    pub id: String,
    pub title: String,
    pub description: String,
    pub created_at: i64,
    pub updated_at: i64,
    pub history: Vec<Change>, // append-only audit trail for this record
}

/// Tab 2 — a trust/will document with a usage note and an attached file.
#[derive(Serialize, Deserialize, Clone, Debug, Default, Zeroize, ZeroizeOnDrop)]
pub struct TrustWill {
    pub id: String,
    pub document: String,
    pub usage: String,
    /// Volume file id of the attached document, if any.
    // `Option<String>` = either `Some(id)` (a file is attached) or `None` (no file).
    pub file: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
    pub history: Vec<Change>,
}

/// Tab 3 — an asset or liability.
#[derive(Serialize, Deserialize, Clone, Debug, Default, Zeroize, ZeroizeOnDrop)]
pub struct AssetLiability {
    pub id: String,
    /// "Asset" or "Liability".
    pub kind: String,
    pub description: String,
    pub owner: String,
    pub approx_value: String,
    pub as_of_date: String,
    pub institution: String,
    /// Category taken from the external asset-types list.
    pub asset_type: String,
    // `#[serde(default)]` on a field: if an older saved vault lacks this field,
    // deserialization fills it with the type's default ("" for String, false for
    // bool) instead of failing. This keeps newly-added fields backward-compatible.
    #[serde(default)]
    pub url: String,
    /// Beneficiary (chiefly for liabilities, but stored for any entry).
    #[serde(default)]
    pub beneficiary: String,
    /// Flagged for review.
    #[serde(default)]
    pub review: bool,
    /// Volume file id of the attached statement, if any.
    pub statement: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
    pub history: Vec<Change>,
}

/// Tab 4 — a login/account (the original password-manager record).
#[derive(Serialize, Deserialize, Clone, Debug, Default, Zeroize, ZeroizeOnDrop)]
pub struct Account {
    pub id: String,
    /// Category taken from the external account-types list.
    pub account_type: String,
    /// Subtype connected to the account type (e.g. type "Financial" -> "IRA").
    #[serde(default)]
    pub account_subtype: String,
    pub owner: String,
    pub username: String,
    pub password: String,
    pub description: String,
    pub url: String,
    /// Flagged for review.
    #[serde(default)]
    pub review: bool,
    pub created_at: i64,
    pub updated_at: i64,
    pub history: Vec<Change>,
}

/// Tab 5 — a real-estate holding.
#[derive(Serialize, Deserialize, Clone, Debug, Default, Zeroize, ZeroizeOnDrop)]
pub struct RealEstate {
    pub id: String,
    pub address: String,
    pub ownership: String,
    pub taxes: String,
    pub hoa: String,
    pub income_account: String,
    pub financing_account: String,
    pub payment_account: String,
    pub created_at: i64,
    pub updated_at: i64,
    pub history: Vec<Change>,
}

/// Stamp a freshly-built record with an id and creation/update timestamps.
// `macro_rules!` defines a compile-time code template (a macro), expanded inline
// wherever it's invoked — used here to avoid repeating identical constructor code
// for all five types. `$ty:ident` is a parameter that captures a type name.
// Note: the macro body uses `?`, so it only compiles inside a function that
// returns a `Result` (the `new()` methods below). The double `{{ }}` makes the
// expansion a block expression whose last value `r` is the result.
macro_rules! new_record {
    ($ty:ident) => {{
        let now = unix_now();
        // `mut r` so we can assign fields; `$ty::default()` builds an all-defaults
        // value of the named type (from the derived `Default`).
        let mut r = $ty::default();
        r.id = random_id()?; // `?` bubbles up an RNG error to the caller
        r.created_at = now;
        r.updated_at = now;
        r // last expression of the block = the value the macro produces
    }};
}

// One `impl` block per type providing a `new()` constructor. Each returns
// `Result<Self, CryptoError>` because id generation can fail; `Ok(...)` wraps the
// success value.
impl Instruction {
    pub fn new() -> Result<Self, CryptoError> {
        Ok(new_record!(Instruction))
    }
}
impl TrustWill {
    pub fn new() -> Result<Self, CryptoError> {
        Ok(new_record!(TrustWill))
    }
}
impl AssetLiability {
    pub fn new() -> Result<Self, CryptoError> {
        // This type defaults to an "Asset" (vs "Liability"), so it overrides the
        // field after the macro builds the base record.
        let mut r = new_record!(AssetLiability);
        r.kind = "Asset".to_string();
        Ok(r)
    }
}
impl Account {
    pub fn new() -> Result<Self, CryptoError> {
        Ok(new_record!(Account))
    }
}
impl RealEstate {
    pub fn new() -> Result<Self, CryptoError> {
        Ok(new_record!(RealEstate))
    }
}

// --- Record trait impls (per-type fields + diff) -----------------------------

/// Generate the boilerplate `Record` impl. The id/timestamp/history accessors
/// are identical across types; the per-type `diff` and `label` are passed as
/// non-capturing closures (which coerce to `fn` pointers).
// `$ty:ty` captures a type, `$diff:expr`/`$label:expr` capture expressions (the
// two closures supplied at each call site below). The macro stamps out a full
// `impl Record for <type>` so we don't hand-write the same accessors five times.
macro_rules! impl_record {
    ($ty:ty, $diff:expr, $label:expr) => {
        // `impl Record for $ty` = "this type provides the Record interface".
        impl Record for $ty {
            fn id(&self) -> &str {
                &self.id
            }
            fn created_at(&self) -> i64 {
                self.created_at
            }
            fn set_created_at(&mut self, at: i64) {
                self.created_at = at;
            }
            fn set_updated_at(&mut self, at: i64) {
                self.updated_at = at;
            }
            fn history_mut(&mut self) -> &mut Vec<Change> {
                &mut self.history
            }
            fn diff(&self, new: &Self, at: i64) -> Vec<Change> {
                let mut out = Vec::new(); // empty, growable list to fill with diffs
                // Bind the supplied closure to a function-pointer-typed variable
                // (`fn(...)` is a plain function pointer). A closure that captures
                // nothing coerces to this. Then call it, passing `&mut out` so it
                // can append changes into our local vector.
                let f: fn(&$ty, &$ty, i64, &mut Vec<Change>) = $diff;
                f(self, new, at, &mut out);
                out // return the collected changes
            }
            fn label(&self) -> String {
                let f: fn(&$ty) -> String = $label;
                f(self)
            }
        }
    };
}

// Each call below passes: the type, a diff closure, and a label closure.
// Diff closure args: `s` = self (old), `n` = new, `at` = timestamp, `out` = the
// vector to append changes to. `&s.title` lends the field to `track` (read-only).
impl_record!(
    Instruction,
    |s: &Instruction, n: &Instruction, at: i64, out: &mut Vec<Change>| {
        track(out, at, "title", &s.title, &n.title);
        track(out, at, "description", &s.description, &n.description);
    },
    // Label closure: `l` is the record. `if/else` is an expression here (it yields
    // a value). Uses a literal placeholder when empty, else `.clone()`s the title
    // into a new owned String (the trait requires returning an owned `String`).
    |l: &Instruction| if l.title.is_empty() { "(untitled)".to_string() } else { l.title.clone() }
);

impl_record!(
    TrustWill,
    |s: &TrustWill, n: &TrustWill, at: i64, out: &mut Vec<Change>| {
        track(out, at, "document", &s.document, &n.document);
        track(out, at, "usage", &s.usage, &n.usage);
        // `file` is an `Option`, not a string, so it's compared directly (rather
        // than via `track`) and logged without exposing the file id.
        if s.file != n.file {
            out.push(Change { at, action: "updated".into(), detail: "attached file changed".into() });
        }
    },
    |l: &TrustWill| if l.document.is_empty() { "(untitled)".to_string() } else { l.document.clone() }
);

impl_record!(
    AssetLiability,
    |s: &AssetLiability, n: &AssetLiability, at: i64, out: &mut Vec<Change>| {
        track(out, at, "kind", &s.kind, &n.kind);
        track(out, at, "description", &s.description, &n.description);
        track(out, at, "owner", &s.owner, &n.owner);
        track(out, at, "approx_value", &s.approx_value, &n.approx_value);
        track(out, at, "as_of_date", &s.as_of_date, &n.as_of_date);
        track(out, at, "institution", &s.institution, &n.institution);
        track(out, at, "type", &s.asset_type, &n.asset_type);
        track(out, at, "url", &s.url, &n.url);
        track(out, at, "beneficiary", &s.beneficiary, &n.beneficiary);
        track_bool(out, at, "review", s.review, n.review);
        if s.statement != n.statement {
            out.push(Change { at, action: "updated".into(), detail: "statement document changed".into() });
        }
    },
    |l: &AssetLiability| {
        // `.as_str()` borrows the String as a `&str` so both arms have the same
        // type (the literal is already a `&str`); no allocation happens here.
        let d = if l.description.is_empty() { "(no description)" } else { l.description.as_str() };
        format!("[{}] {d}", l.kind)
    }
);

impl_record!(
    Account,
    |s: &Account, n: &Account, at: i64, out: &mut Vec<Change>| {
        track(out, at, "type", &s.account_type, &n.account_type);
        track(out, at, "subtype", &s.account_subtype, &n.account_subtype);
        track(out, at, "owner", &s.owner, &n.owner);
        track(out, at, "username", &s.username, &n.username);
        // Full before/after of the password is recorded (accepted decision).
        track(out, at, "password", &s.password, &n.password);
        track(out, at, "description", &s.description, &n.description);
        track(out, at, "url", &s.url, &n.url);
        track_bool(out, at, "review", s.review, n.review);
    },
    |l: &Account| {
        // Prefer username, fall back to owner; `.clone()` makes an owned String
        // either way so `who` owns its text.
        let who = if l.username.is_empty() { l.owner.clone() } else { l.username.clone() };
        let label =
            if l.account_type.is_empty() { who } else { format!("{}: {who}", l.account_type) };
        // `.trim()` strips surrounding whitespace just for the emptiness check.
        if label.trim().is_empty() { "(account)".to_string() } else { label }
    }
);

impl_record!(
    RealEstate,
    |s: &RealEstate, n: &RealEstate, at: i64, out: &mut Vec<Change>| {
        track(out, at, "address", &s.address, &n.address);
        track(out, at, "ownership", &s.ownership, &n.ownership);
        track(out, at, "taxes", &s.taxes, &n.taxes);
        track(out, at, "hoa", &s.hoa, &n.hoa);
        track(out, at, "income_account", &s.income_account, &n.income_account);
        track(out, at, "financing_account", &s.financing_account, &n.financing_account);
        track(out, at, "payment_account", &s.payment_account, &n.payment_account);
    },
    |l: &RealEstate| if l.address.is_empty() { "(no address)".to_string() } else { l.address.clone() }
);

// --- Vault settings ----------------------------------------------------------

/// User-configurable vault settings, stored (encrypted) inside the vault.
// Note: no `Default` in the derive list — a custom one is written by hand below
// because the default cap isn't the numeric zero.
#[derive(Serialize, Deserialize, Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct VaultSettings {
    /// Per-partition document-volume size cap (bytes). A new document that would
    /// push the active partition past this rolls into a fresh partition.
    pub volume_max_size: u64, // u64 = unsigned 64-bit integer
}

// Hand-written `Default` implementation (the `Default` trait's one method).
// Returning `Self` here means a `VaultSettings` whose cap is the project-wide
// constant rather than 0.
impl Default for VaultSettings {
    fn default() -> Self {
        VaultSettings { volume_max_size: crate::storage::DEFAULT_VOLUME_MAX_SIZE }
    }
}

/// The decrypted contents of a vault: all five record collections plus the
/// volume manifest, access time, and vault-level audit log. Wipes on drop.
// This is the top-level in-memory object; `ZeroizeOnDrop` means the entire vault
// (and every record inside it) is securely erased when it leaves scope.
// `#[serde(default)]` on each field keeps older saved vaults loadable when new
// fields are added (missing fields take their type default).
#[derive(Serialize, Deserialize, Clone, Debug, Default, Zeroize, ZeroizeOnDrop)]
pub struct Vault {
    #[serde(default)]
    pub version: u8, // u8 = unsigned 8-bit integer (0..=255)
    /// Monotonically increasing write counter, bumped on every successful save.
    /// Surfaced on unlock so a user can notice a whole-file rollback to an older
    /// snapshot (see `docs/DESIGN.md` §9.12).
    #[serde(default)]
    pub generation: u64,
    #[serde(default)]
    pub last_opened_at: i64,
    #[serde(default)]
    pub instructions: Vec<Instruction>,
    #[serde(default)]
    pub trust_wills: Vec<TrustWill>,
    #[serde(default)]
    pub assets: Vec<AssetLiability>,
    #[serde(default)]
    pub accounts: Vec<Account>,
    #[serde(default)]
    pub real_estate: Vec<RealEstate>,
    /// Stable random id binding the document volumes/manifests to this vault (so a
    /// foreign or swapped volume/manifest fails authentication). Set on create.
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub settings: VaultSettings,
    #[serde(default)]
    pub audit: Vec<Change>,
    /// The editable category lists for the dropdowns, stored in the vault itself
    /// (not in external files). A vault that predates this field falls back to
    /// the built-in defaults. Category names are not secrets, so they are skipped
    /// by the zeroize-on-drop wipe.
    // `#[serde(default = "path::to::fn")]` names a function to call for the default
    // when the field is missing (here, the built-in category lists) — used instead
    // of the plain `#[serde(default)]` because the desired default isn't "empty".
    #[serde(default = "crate::types::TypeLists::with_defaults")]
    // `#[zeroize(skip)]` excludes this one field from the secret-wiping on drop
    // (category names aren't sensitive, and `TypeLists` may not be zeroize-able).
    #[zeroize(skip)]
    pub categories: crate::types::TypeLists,
}

// `#[cfg(test)]` is *conditional compilation*: this whole module is compiled only
// when running tests, never in the shipped binary. `use super::*` pulls in
// everything from the parent module (this file). Each `#[test]` fn is run by the
// test harness; `assert!`/`assert_eq!` panic (fail the test) if their condition
// is false. `.unwrap()` extracts the value from a Result/Option and panics if it's
// Err/None — acceptable in tests, where a panic simply marks the test failed.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_search_is_case_insensitive_substring() {
        assert!(matches_search("alice@example.com", "ALICE"));
        assert!(matches_search("Bob", "b"));
        assert!(matches_search("a.user", "USER"));
        assert!(matches_search("anything", ""), "empty query matches all");
        assert!(matches_search("anything", "   "), "whitespace query matches all");
        assert!(matches_search("john", "  JOHN  "), "query is trimmed");
        assert!(!matches_search("alice", "bob"));
        assert!(!matches_search("", "x"));
    }

    #[test]
    fn unix_now_is_a_realistic_timestamp() {
        // Guards the clock source (and kills a "return a constant" mutation): the
        // value must be after 2023-11-14 and before 2100.
        let now = unix_now();
        assert!(now > 1_700_000_000, "timestamp implausibly early: {now}");
        assert!(now < 4_102_444_800, "timestamp implausibly late: {now}");
    }

    #[test]
    fn upsert_inserts_then_edits_with_history() {
        let mut list: Vec<Account> = Vec::new();
        let mut a = Account::new().unwrap();
        a.account_type = "Checking".into();
        a.username = "alice".into();
        let id = a.id.clone();
        upsert(&mut list, a);
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].history.len(), 1); // created

        let mut edit = list[0].clone();
        edit.username = "bob".into();
        edit.password = "s3cret".into();
        upsert(&mut list, edit);

        assert_eq!(list.len(), 1, "same id replaces, not appends");
        assert_eq!(list[0].id, id, "id stable");
        let h = &list[0].history;
        assert!(h.iter().any(|c| c.detail.contains("username")));
        // Password value is recorded in history (accepted decision).
        assert!(h.iter().any(|c| c.detail.contains("s3cret")));
    }

    #[test]
    fn remove_logs_audit() {
        let mut list: Vec<Instruction> = Vec::new();
        let mut i = Instruction::new().unwrap();
        i.title = "Read me".into();
        let id = i.id.clone();
        upsert(&mut list, i);
        let mut audit = Vec::new();
        assert!(remove(&mut list, &id, &mut audit, "Instruction"));
        assert!(audit.iter().any(|c| c.action == "deleted" && c.detail.contains("Read me")));
        assert!(!remove(&mut list, &id, &mut audit, "Instruction"));
    }

    #[test]
    fn account_diff_tracks_subtype_and_review() {
        let mut old = Account::new().unwrap();
        old.account_type = "Financial".into();
        let mut new = old.clone();
        new.account_subtype = "IRA".into();
        new.review = true;
        let now = unix_now();
        let changes = old.diff(&new, now);
        assert!(changes.iter().any(|c| c.detail.contains("subtype") && c.detail.contains("IRA")));
        assert!(changes.iter().any(|c| c.detail.contains("review") && c.detail.contains("true")));
        // Unchanged record yields no changes.
        assert!(old.diff(&old.clone(), now).is_empty());
    }

    #[test]
    fn asset_diff_tracks_new_fields() {
        let old = AssetLiability::new().unwrap();
        let mut new = old.clone();
        new.url = "https://x".into();
        new.beneficiary = "Spouse".into();
        new.review = true;
        new.statement = Some("blob1".into());
        let c = old.diff(&new, unix_now());
        assert!(c.iter().any(|x| x.detail.contains("url")));
        assert!(c.iter().any(|x| x.detail.contains("beneficiary")));
        assert!(c.iter().any(|x| x.detail.contains("review")));
        assert!(c.iter().any(|x| x.detail.contains("statement document changed")));
    }

    #[test]
    fn labels_are_meaningful_per_type() {
        let mut acc = Account::new().unwrap();
        acc.account_type = "Financial".into();
        acc.username = "jane".into();
        assert_eq!(acc.label(), "Financial: jane");

        let mut al = AssetLiability::new().unwrap();
        al.kind = "Liability".into();
        al.description = "Mortgage".into();
        assert_eq!(al.label(), "[Liability] Mortgage");

        let re = RealEstate::new().unwrap();
        assert_eq!(re.label(), "(no address)");
        let tw = TrustWill::new().unwrap();
        assert_eq!(tw.label(), "(untitled)");
    }

    #[test]
    fn new_records_have_distinct_ids_and_timestamps() {
        let a = Account::new().unwrap();
        let b = Account::new().unwrap();
        assert_ne!(a.id, b.id);
        assert_eq!(a.id.len(), 32); // 128-bit hex
        assert!(a.created_at > 0 && a.created_at == a.updated_at);
        assert_eq!(AssetLiability::new().unwrap().kind, "Asset"); // default kind
    }

    #[test]
    fn civil_from_unix_known_dates() {
        assert_eq!(civil_from_unix(0), (1970, 1, 1, 0, 0, 0));
        assert_eq!(civil_from_unix(1_609_459_200), (2021, 1, 1, 0, 0, 0));
        // A leap day: 2024-02-29T00:00:00Z = 1709164800.
        assert_eq!(civil_from_unix(1_709_164_800), (2024, 2, 29, 0, 0, 0));
        // The day AFTER the leap day exercises the Feb->Mar month transition.
        assert_eq!(civil_from_unix(1_709_251_200), (2024, 3, 1, 0, 0, 0));
        // Non-zero time-of-day pins the h/m/s extraction (sod/3600, %3600/60, %60).
        assert_eq!(civil_from_unix(1_609_459_200 + 3600 + 120 + 45), (2021, 1, 1, 1, 2, 45));
        // The last second of a year (year rollover boundary).
        assert_eq!(civil_from_unix(1_609_459_199), (2020, 12, 31, 23, 59, 59));
        assert_eq!(civil_from_unix(-100), (1970, 1, 1, 0, 0, 0)); // clamps to epoch
    }
}
