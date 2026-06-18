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

/// The virtual folder a tax year's documents live in: `taxes/<sanitized-year>`.
/// Non-alphanumeric characters in the year are dropped so the folder name is
/// always safe; an empty/blank year falls back to `taxes/unspecified`. Shared by
/// the GUI and TUI so both store a given year's documents in the same place.
pub fn tax_doc_location(year: &str) -> String {
    let y: String = year.chars().filter(|c| c.is_ascii_alphanumeric()).collect();
    if y.is_empty() { "taxes/unspecified".to_string() } else { format!("taxes/{y}") }
}

/// The virtual folder a property's documents live in: `real-estate/<sanitized>`,
/// derived from the address (alphanumeric only, lowercased, truncated), with a
/// `real-estate/property` fallback for a blank address. Shared by both UIs.
pub fn real_estate_doc_location(address: &str) -> String {
    let a: String =
        address.chars().filter(|c| c.is_ascii_alphanumeric()).take(40).collect::<String>().to_lowercase();
    if a.is_empty() { "real-estate/property".to_string() } else { format!("real-estate/{a}") }
}

/// Slugify one virtual-path component: lowercase, keep ASCII alphanumerics, turn
/// every other run into a single '-', trim leading/trailing '-', and cap the
/// length at 40. An empty result falls back to `fallback`. Used for the auto-group
/// level (document/description/title) and the optional user subfolder so the
/// volume path is always filesystem-safe and free of separators or traversal.
pub fn doc_slug(s: &str, fallback: &str) -> String {
    let mut out = String::new();
    let mut prev_dash = false;
    for c in s.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_lowercase());
            prev_dash = false;
        } else if !out.is_empty() && !prev_dash {
            out.push('-');
            prev_dash = true;
        }
    }
    out.truncate(40);
    while out.ends_with('-') {
        out.pop();
    }
    if out.is_empty() { fallback.to_string() } else { out }
}

/// The `<root>/<auto-group>` prefix for the Trust & Will, Assets, and General
/// Documents tabs (the multi-doc Taxes/Real-Estate tabs have their own prefix
/// helpers above). The group is slugged from the record's identifying field.
pub fn trust_will_doc_location(document: &str) -> String {
    format!("trust-will/{}", doc_slug(document, "document"))
}
pub fn asset_doc_location(description: &str) -> String {
    format!("assets/{}", doc_slug(description, "asset"))
}
pub fn general_doc_location(title: &str) -> String {
    format!("general-documents/{}", doc_slug(title, "untitled"))
}

/// A compact UTC timestamp `YYYYMMDD-HHMMSS` for the per-upload folder level, from
/// Unix seconds. Sortable, fixed-width, and filesystem-safe.
pub fn compact_utc(unix_secs: i64) -> String {
    let (y, mo, d, h, mi, s) = civil_from_unix(unix_secs);
    format!("{y:04}{mo:02}{d:02}-{h:02}{mi:02}{s:02}")
}

/// Build the virtual *directory* a freshly-uploaded document is stored under, the
/// uniform layout shared by every document tab:
///   `<root>/<auto-group>/<timestamp>[/<subfolder>]`
/// `prefix` is the `<root>/<auto-group>` from one of the `*_doc_location` helpers,
/// `timestamp` is [`compact_utc`], and `subfolder` is the optional user level
/// (slugged, omitted when blank). The caller appends the (user-controlled)
/// filename via `vault::virtual_path`.
pub fn doc_upload_dir(prefix: &str, timestamp: &str, subfolder: &str) -> String {
    let mut dir = format!("{prefix}/{timestamp}");
    let sub = subfolder.trim();
    if !sub.is_empty() {
        dir.push('/');
        dir.push_str(&doc_slug(sub, "subfolder"));
    }
    dir
}

/// Sanitize a user-supplied filename for the volume path: replace any whitespace
/// with `-` (so no path component contains a space), neutralize path separators and
/// control characters with `_` (so the user controls the name without injecting
/// extra path levels or `..` traversal), strip surrounding dots, and cap the length.
/// Falls back to `"file"` when nothing usable remains. Dots inside the name are kept
/// so extensions like `return.pdf` survive.
pub fn doc_filename(name: &str) -> String {
    let mut out: String = name
        .chars()
        .map(|c| {
            if c.is_whitespace() {
                '-' // no spaces (or tabs/newlines) anywhere in a volume path
            } else if c == '/' || c == '\\' || c.is_control() {
                '_'
            } else {
                c
            }
        })
        .collect();
    // Cap at 120 bytes, truncating on a UTF-8 char boundary. A raw `truncate(120)`
    // PANICS when byte 120 lands mid-character (multibyte name: accented Latin, CJK,
    // emoji, …), so step the cut back to the nearest boundary first.
    if out.len() > 120 {
        let mut cut = 120;
        while cut > 0 && !out.is_char_boundary(cut) {
            cut -= 1;
        }
        out.truncate(cut);
    }
    // Strip leading/trailing dots and dashes (whitespace is already mapped to `-`),
    // so a dot/space-only name collapses to the fallback rather than "--..".
    let trimmed = out.trim_matches(|c: char| c == '.' || c == '-');
    if trimmed.is_empty() { "file".to_string() } else { trimmed.to_string() }
}

/// Break a unix-seconds timestamp into civil UTC `(year, month, day, hour, min,
/// sec)` using Howard Hinnant's `civil_from_days` algorithm. Negative/zero clamps
/// to the epoch. Shared by the human and filename timestamp formatters so the
/// (fiddly) calendar math lives in exactly one place.
// `pub(crate)` = visible anywhere in this crate but not to outside users.
// The return type `(i64, i64, ...)` is a *tuple*: several values bundled together.
pub fn civil_from_unix(ts: i64) -> (i64, i64, i64, i64, i64, i64) {
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

/// Days since the Unix epoch for a civil UTC date — Howard Hinnant's
/// `days_from_civil`, the exact inverse of the `civil_from_unix` calendar math
/// above (proleptic Gregorian). `div_euclid(400)` is floored division, which is
/// what the algorithm needs for the era.
pub(crate) fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    // March-based year: shift Jan/Feb into the previous year so the leap day is
    // the last day of the year, simplifying the day-of-year formula.
    let yy = if m <= 2 { y - 1 } else { y };
    let era = yy.div_euclid(400);
    let yoe = yy - era * 400; // year of era, [0, 399]
    let mp = if m > 2 { m - 3 } else { m + 9 }; // month, March=0 .. Feb=11
    let doy = (153 * mp + 2) / 5 + d - 1; // day of year, [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // day of era, [0, 146096]
    era * 146_097 + doe - 719_468
}

/// Unix seconds for a civil UTC date-time — inverse of `civil_from_unix`.
pub(crate) fn unix_from_civil(y: i64, mo: i64, d: i64, h: i64, mi: i64, s: i64) -> i64 {
    days_from_civil(y, mo, d) * 86_400 + h * 3600 + mi * 60 + s
}

/// Parse a `YYYY-MM-DD` date as **UTC midnight**, returning Unix seconds.
/// Returns `None` for malformed input or an impossible calendar date (e.g.
/// `2026-02-31`), which the round-trip canonicalization check rejects. Used by
/// the `compact --history-before` cutoff.
pub fn parse_ymd_utc(s: &str) -> Option<i64> {
    // `split('-')` then `collect` into a Vec so we can require exactly 3 fields.
    let parts: Vec<&str> = s.trim().split('-').collect();
    if parts.len() != 3 {
        return None;
    }
    // `parse::<i64>()` returns Err on non-numeric text; `.ok()?` maps that to None.
    let y: i64 = parts[0].parse().ok()?;
    let mo: i64 = parts[1].parse().ok()?;
    let d: i64 = parts[2].parse().ok()?;
    if !(1970..=9999).contains(&y) || !(1..=12).contains(&mo) || !(1..=31).contains(&d) {
        return None;
    }
    let ts = unix_from_civil(y, mo, d, 0, 0, 0);
    // Canonicalization: re-deriving the date must reproduce the input, which
    // rejects impossible dates (Feb 31, Apr 31, ...) that days_from_civil would
    // otherwise silently normalize.
    let (cy, cmo, cd, ..) = civil_from_unix(ts);
    if (cy, cmo, cd) != (y, mo, d) {
        return None;
    }
    Some(ts)
}

/// Trim every record's per-edit `history` log in `vault`. With `drop_all`, all
/// history entries are removed; otherwise entries strictly older than `cutoff`
/// (Unix seconds) are dropped and `at >= cutoff` are kept (inclusive keep). The
/// vault-level `audit` log is deliberately **left untouched**. Returns the count
/// of history entries removed. Removed `Change`s are `ZeroizeOnDrop`, so their
/// (possibly secret-bearing) before/after detail strings are wiped from RAM.
pub fn compact_history(vault: &mut Vault, cutoff: Option<i64>, drop_all: bool) -> usize {
    // Each of the six record collections shares the generic `Record` interface,
    // so one helper trims them all.
    trim_histories(&mut vault.instructions, cutoff, drop_all)
        + trim_histories(&mut vault.trust_wills, cutoff, drop_all)
        + trim_histories(&mut vault.assets, cutoff, drop_all)
        + trim_histories(&mut vault.accounts, cutoff, drop_all)
        + trim_histories(&mut vault.real_estate, cutoff, drop_all)
        + trim_histories(&mut vault.tax_filings, cutoff, drop_all)
        + trim_histories(&mut vault.general_documents, cutoff, drop_all)
}

/// How many history entries `compact_history` would remove for the same
/// arguments — a non-mutating count for `--dry-run` and result reporting.
pub fn history_stats(vault: &Vault, cutoff: Option<i64>, drop_all: bool) -> usize {
    // Closure counting removable entries in one record's history.
    let count = |list: &[Change]| -> usize {
        if drop_all {
            list.len()
        } else if let Some(c) = cutoff {
            list.iter().filter(|ch| ch.at < c).count()
        } else {
            0
        }
    };
    let mut n = 0;
    for r in &vault.instructions {
        n += count(&r.history);
    }
    for r in &vault.trust_wills {
        n += count(&r.history);
    }
    for r in &vault.assets {
        n += count(&r.history);
    }
    for r in &vault.accounts {
        n += count(&r.history);
    }
    for r in &vault.real_estate {
        n += count(&r.history);
    }
    for r in &vault.tax_filings {
        n += count(&r.history);
    }
    for r in &vault.general_documents {
        n += count(&r.history);
    }
    n
}

/// Apply the history trim to one record collection; returns entries removed.
// Generic over any `Record` (uses its `history_mut` accessor). `&mut [R]` borrows
// the caller's Vec as a mutable slice. `retain` keeps only matching elements,
// dropping (and zeroizing) the rest in place.
fn trim_histories<R: Record>(list: &mut [R], cutoff: Option<i64>, drop_all: bool) -> usize {
    let mut removed = 0;
    for rec in list.iter_mut() {
        let h = rec.history_mut();
        let before = h.len();
        if drop_all {
            h.clear();
        } else if let Some(c) = cutoff {
            h.retain(|ch| ch.at >= c);
        }
        removed += before - h.len();
    }
    removed
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
    /// Outstanding financing/mortgage balance (free text).
    #[serde(default)]
    pub financing_balance: String,
    /// Property-management portal login.
    #[serde(default)]
    pub property_mgmt_url: String,
    #[serde(default)]
    pub property_mgmt_username: String,
    #[serde(default)]
    pub property_mgmt_password: String,
    /// Insurance portal login.
    #[serde(default)]
    pub insurance_url: String,
    #[serde(default)]
    pub insurance_username: String,
    #[serde(default)]
    pub insurance_password: String,
    /// HOA portal login.
    #[serde(default)]
    pub hoa_url: String,
    #[serde(default)]
    pub hoa_username: String,
    #[serde(default)]
    pub hoa_password: String,
    /// Free-form comments.
    #[serde(default)]
    pub comments: String,
    /// Volume file ids of documents attached to this property (deed, policy,
    /// statements), all stored under `real-estate/<address>/`.
    #[serde(default)]
    pub documents: Vec<String>,
    pub created_at: i64,
    pub updated_at: i64,
    pub history: Vec<Change>,
}

/// Tab 6 — a tax filing for a given year, holding its uploaded documents.
/// Every document attached to a filing is stored together under the
/// `taxes/<year>/` virtual folder in the encrypted volume.
#[derive(Serialize, Deserialize, Clone, Debug, Default, Zeroize, ZeroizeOnDrop)]
pub struct TaxFiling {
    pub id: String,
    /// The filing/tax year, e.g. "2024". Also names the document folder.
    pub year: String,
    pub notes: String,
    /// Volume file ids of the documents attached to this filing year (all stored
    /// under `taxes/<year>/`). An entry can hold several documents.
    pub documents: Vec<String>,
    pub created_at: i64,
    pub updated_at: i64,
    pub history: Vec<Change>,
}

/// Tab 7 — a general document: a title, a free-form description, and a single
/// uploaded file. Its file is stored under `general-documents/<title>/<timestamp>/
/// [subfolder]/<filename>` in the encrypted volume.
#[derive(Serialize, Deserialize, Clone, Debug, Default, Zeroize, ZeroizeOnDrop)]
pub struct GeneralDocument {
    pub id: String,
    pub title: String,
    pub description: String,
    /// Volume file id of the attached document, if any (single file per entry).
    pub file: Option<String>,
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
impl TaxFiling {
    pub fn new() -> Result<Self, CryptoError> {
        Ok(new_record!(TaxFiling))
    }
}
impl GeneralDocument {
    pub fn new() -> Result<Self, CryptoError> {
        Ok(new_record!(GeneralDocument))
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
        track(out, at, "financing_balance", &s.financing_balance, &n.financing_balance);
        track(out, at, "payment_account", &s.payment_account, &n.payment_account);
        track(out, at, "property_mgmt_url", &s.property_mgmt_url, &n.property_mgmt_url);
        track(out, at, "property_mgmt_username", &s.property_mgmt_username, &n.property_mgmt_username);
        track(out, at, "property_mgmt_password", &s.property_mgmt_password, &n.property_mgmt_password);
        track(out, at, "insurance_url", &s.insurance_url, &n.insurance_url);
        track(out, at, "insurance_username", &s.insurance_username, &n.insurance_username);
        track(out, at, "insurance_password", &s.insurance_password, &n.insurance_password);
        track(out, at, "hoa_url", &s.hoa_url, &n.hoa_url);
        track(out, at, "hoa_username", &s.hoa_username, &n.hoa_username);
        track(out, at, "hoa_password", &s.hoa_password, &n.hoa_password);
        track(out, at, "comments", &s.comments, &n.comments);
        if s.documents != n.documents {
            out.push(Change {
                at,
                action: "updated".into(),
                detail: format!("documents: {} -> {}", s.documents.len(), n.documents.len()),
            });
        }
    },
    |l: &RealEstate| if l.address.is_empty() { "(no address)".to_string() } else { l.address.clone() }
);

impl_record!(
    TaxFiling,
    |s: &TaxFiling, n: &TaxFiling, at: i64, out: &mut Vec<Change>| {
        track(out, at, "year", &s.year, &n.year);
        track(out, at, "notes", &s.notes, &n.notes);
        // Log document-count changes without exposing the volume file ids.
        if s.documents != n.documents {
            out.push(Change {
                at,
                action: "updated".into(),
                detail: format!("documents: {} -> {}", s.documents.len(), n.documents.len()),
            });
        }
    },
    |l: &TaxFiling| if l.year.is_empty() { "(no year)".to_string() } else { format!("Taxes {}", l.year) }
);

impl_record!(
    GeneralDocument,
    |s: &GeneralDocument, n: &GeneralDocument, at: i64, out: &mut Vec<Change>| {
        track(out, at, "title", &s.title, &n.title);
        track(out, at, "description", &s.description, &n.description);
        // `file` is an Option holding a volume id; log changes without exposing it.
        if s.file != n.file {
            out.push(Change { at, action: "updated".into(), detail: "attached file changed".into() });
        }
    },
    |l: &GeneralDocument| if l.title.is_empty() { "(untitled)".to_string() } else { l.title.clone() }
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
    /// Opt-in in-place redundancy for `vault.pmv` (see `docs/DESIGN.md` §12.8).
    /// `0` (the default) = off: just the single `vault.pmv`. `N >= 1` = also write a
    /// same-generation mirror (`vault.pmv.mirror`) AND retain the last `N` prior
    /// generations (`vault.pmv.bak1`..`bakN`), so a bit-rotted vault file can be
    /// recovered in place. This is a complement to off-device backups, NOT a
    /// replacement, and it leaves more encrypted copies of old secrets on disk.
    /// `#[serde(default)]` keeps vaults written before this field existed loadable
    /// (they decode as `0`).
    #[serde(default)]
    pub redundancy: u32,
}

// Hand-written `Default` implementation (the `Default` trait's one method).
// Returning `Self` here means a `VaultSettings` whose cap is the project-wide
// constant rather than 0.
impl Default for VaultSettings {
    fn default() -> Self {
        VaultSettings { volume_max_size: crate::storage::DEFAULT_VOLUME_MAX_SIZE, redundancy: 0 }
    }
}

/// The decrypted contents of a vault: all six record collections plus the
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
    /// Tax filings (the Taxes tab); each year's documents live under `taxes/<year>/`.
    #[serde(default)]
    pub tax_filings: Vec<TaxFiling>,
    /// General documents (the General Documents tab); each entry's single file lives
    /// under `general-documents/<title>/<timestamp>/[subfolder]/`.
    #[serde(default)]
    pub general_documents: Vec<GeneralDocument>,
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
    fn tax_filing_new_diff_label_and_folder() {
        let mut t = TaxFiling::new().unwrap();
        assert!(t.year.is_empty() && t.documents.is_empty());
        assert_eq!(t.label(), "(no year)");
        t.year = "2024".into();
        assert_eq!(t.label(), "Taxes 2024");

        let mut edited = t.clone();
        edited.notes = "filed late".into();
        edited.documents.push("blobid".into());
        let changes = t.diff(&edited, unix_now());
        assert!(changes.iter().any(|c| c.detail.contains("notes")));
        assert!(changes.iter().any(|c| c.detail.contains("documents") && c.detail.contains("0 -> 1")));
        assert!(t.diff(&t.clone(), unix_now()).is_empty(), "unchanged record yields no diff");

        // Folder convention: taxes/<sanitized-year>, with a safe fallback.
        assert_eq!(tax_doc_location("2024"), "taxes/2024");
        assert_eq!(tax_doc_location(" 2023/ "), "taxes/2023");
        assert_eq!(tax_doc_location(""), "taxes/unspecified");
    }

    #[test]
    fn compact_history_includes_tax_filings() {
        // The Taxes collection must be trimmed by compact_history and counted by
        // history_stats like the other five record types.
        let mut vault = Vault::default();
        let mut t = TaxFiling::default();
        t.history = vec![Change { at: 1, action: "u".into(), detail: String::new() }];
        vault.tax_filings.push(t);
        assert_eq!(history_stats(&vault, None, true), 1);
        assert_eq!(compact_history(&mut vault, None, true), 1);
        assert!(vault.tax_filings[0].history.is_empty());
    }

    #[test]
    fn real_estate_diff_tracks_portals_docs_and_folder() {
        let old = RealEstate::new().unwrap();
        let mut new = old.clone();
        new.financing_balance = "250000".into();
        new.property_mgmt_url = "https://pm.example".into();
        new.insurance_password = "s3cret".into();
        new.hoa_username = "owner1".into();
        new.comments = "tenant occupied".into();
        new.documents.push("blob".into());
        let c = old.diff(&new, unix_now());
        assert!(c.iter().any(|x| x.detail.contains("financing_balance")));
        assert!(c.iter().any(|x| x.detail.contains("property_mgmt_url")));
        assert!(c.iter().any(|x| x.detail.contains("insurance_password") && x.detail.contains("s3cret")));
        assert!(c.iter().any(|x| x.detail.contains("hoa_username")));
        assert!(c.iter().any(|x| x.detail.contains("comments")));
        assert!(c.iter().any(|x| x.detail.contains("documents") && x.detail.contains("0 -> 1")));

        // Folder convention: real-estate/<sanitized-address>, with a fallback.
        assert_eq!(real_estate_doc_location("123 Main St"), "real-estate/123mainst");
        assert_eq!(real_estate_doc_location(""), "real-estate/property");
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

    #[test]
    fn parse_ymd_utc_known_dates_and_roundtrip() {
        assert_eq!(parse_ymd_utc("1970-01-01"), Some(0));
        assert_eq!(parse_ymd_utc("2021-01-01"), Some(1_609_459_200));
        // Leap day.
        assert_eq!(parse_ymd_utc("2024-02-29"), Some(1_709_164_800));
        // Whitespace is trimmed; unpadded fields parse.
        assert_eq!(parse_ymd_utc("  2021-1-1  "), Some(1_609_459_200));
        // Round-trips against the civil formatter at midnight.
        for ts in [0, 1_609_459_200, 1_709_164_800, 4_102_444_800] {
            let (y, m, d, ..) = civil_from_unix(ts);
            assert_eq!(unix_from_civil(y, m, d, 0, 0, 0), ts);
        }
    }

    #[test]
    fn parse_ymd_utc_rejects_invalid() {
        for s in ["2026-02-31", "2026-13-01", "2026-01-32", "1969-12-31", "not-a-date", "2026/01/01", "20260101", "2026-01", ""] {
            assert!(parse_ymd_utc(s).is_none(), "{s:?} must be rejected");
        }
    }

    #[test]
    fn compact_history_cutoff_and_drop_all_preserve_audit() {
        let mut vault = Vault::default();
        let mut a = Account::default();
        a.history = vec![
            Change { at: 100, action: "updated".into(), detail: "a".into() },
            Change { at: 500, action: "updated".into(), detail: "b".into() },
        ];
        vault.accounts.push(a);
        vault.audit.push(Change::new("opened", String::new()));

        // Counting matches the actual trim, and the audit is never counted/touched.
        assert_eq!(history_stats(&vault, Some(300), false), 1);
        assert_eq!(history_stats(&vault, None, true), 2);

        let removed = compact_history(&mut vault, Some(300), false);
        assert_eq!(removed, 1);
        assert_eq!(vault.accounts[0].history.len(), 1);
        assert_eq!(vault.accounts[0].history[0].at, 500, "kept the at >= cutoff entry");
        assert_eq!(vault.audit.len(), 1, "audit untouched by record-history trim");

        let removed2 = compact_history(&mut vault, None, true);
        assert_eq!(removed2, 1);
        assert!(vault.accounts[0].history.is_empty());
        assert_eq!(vault.audit.len(), 1, "audit still untouched after drop-all");
    }

    #[test]
    fn parse_ymd_utc_boundaries_have_no_overflow() {
        assert_eq!(parse_ymd_utc("1970-01-01"), Some(0));
        // The far-future date stays within i64 (no multiplication overflow/panic)
        // and round-trips through the civil formatter.
        let secs = parse_ymd_utc("9999-12-31").expect("9999-12-31 is valid");
        assert!(secs > 0);
        assert_eq!(civil_from_unix(secs), (9999, 12, 31, 0, 0, 0));
    }

    #[test]
    fn days_from_civil_inverts_civil_from_unix() {
        // Round-trip midnight timestamps across centuries + leap days.
        for ts in [0i64, 86_400, 951_782_400, 1_709_164_800, 4_102_444_800, 253_370_764_800] {
            let (y, m, d, _, _, _) = civil_from_unix(ts);
            assert_eq!(unix_from_civil(y, m, d, 0, 0, 0), ts, "round-trip failed for ts={ts}");
        }
    }

    #[test]
    fn compact_history_cutoff_is_inclusive_keep() {
        let mut vault = Vault::default();
        let mut a = Account::default();
        a.history = vec![
            Change { at: 999, action: "u".into(), detail: String::new() },
            Change { at: 1000, action: "u".into(), detail: String::new() },
            Change { at: 1001, action: "u".into(), detail: String::new() },
        ];
        vault.accounts.push(a);
        // cutoff == 1000: only at=999 is older (dropped); at=1000 is kept (inclusive).
        let removed = compact_history(&mut vault, Some(1000), false);
        assert_eq!(removed, 1);
        assert_eq!(vault.accounts[0].history.iter().map(|c| c.at).collect::<Vec<_>>(), vec![1000, 1001]);
    }

    #[test]
    fn compact_history_handles_empty_and_every_record_type() {
        let mut vault = Vault::default();
        // Empty vault: nothing to do, no panic.
        assert_eq!(history_stats(&vault, Some(0), false), 0);
        assert_eq!(compact_history(&mut vault, None, true), 0);
        // One+ history entries in each of the five record types.
        let mk = |at| Change { at, action: "u".into(), detail: String::new() };
        let mut ins = Instruction::default();
        ins.history = vec![mk(1)];
        let mut tw = TrustWill::default();
        tw.history = vec![mk(1), mk(2)];
        let mut al = AssetLiability::default();
        al.history = vec![mk(1)];
        let mut ac = Account::default();
        ac.history = vec![mk(1)];
        let mut re = RealEstate::default();
        re.history = vec![mk(1)];
        vault.instructions.push(ins);
        vault.trust_wills.push(tw);
        vault.assets.push(al);
        vault.accounts.push(ac);
        vault.real_estate.push(re);
        // history_stats must agree with the actual removal count across all types.
        assert_eq!(history_stats(&vault, None, true), 6);
        assert_eq!(compact_history(&mut vault, None, true), 6, "all five record types trimmed");
        assert!(vault.trust_wills[0].history.is_empty());
    }

    // ---- Added: hardening tests for Taxes + expanded Real Estate -------------

    /// `TaxFiling::new()` produces a stamped, empty filing with a 128-bit hex id
    /// and equal created/updated timestamps (matching the macro's contract).
    #[test]
    fn tax_filing_new_is_stamped_and_empty() {
        let t = TaxFiling::new().unwrap();
        assert_eq!(t.id.len(), 32, "128-bit hex id");
        assert!(t.id.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(t.created_at > 0 && t.created_at == t.updated_at);
        assert!(t.year.is_empty() && t.notes.is_empty() && t.documents.is_empty());
        assert!(t.history.is_empty());
        let other = TaxFiling::new().unwrap();
        assert_ne!(t.id, other.id, "ids are distinct");
    }

    /// `TaxFiling::label()` shows the placeholder when blank and `Taxes <year>`
    /// otherwise — including odd, non-sanitized year strings (label is verbatim).
    #[test]
    fn tax_filing_label_variants() {
        let mut t = TaxFiling::default();
        assert_eq!(t.label(), "(no year)");
        t.year = "2024".into();
        assert_eq!(t.label(), "Taxes 2024");
        // The label does NOT sanitize; it echoes the raw year.
        t.year = "FY-2024 (amended)".into();
        assert_eq!(t.label(), "Taxes FY-2024 (amended)");
    }

    /// Every TaxFiling field that the diff tracks, exercised individually.
    #[test]
    fn tax_filing_diff_covers_each_field() {
        let base = TaxFiling::default();
        let now = unix_now();

        // year
        let mut n = base.clone();
        n.year = "2025".into();
        let c = base.diff(&n, now);
        assert!(c.iter().any(|x| x.detail.contains("year") && x.detail.contains("2025")));
        assert!(c.iter().all(|x| x.action == "updated"));

        // notes
        let mut n = base.clone();
        n.notes = "extension filed".into();
        let c = base.diff(&n, now);
        assert!(c.iter().any(|x| x.detail.contains("notes") && x.detail.contains("extension filed")));

        // documents: count goes up
        let mut n = base.clone();
        n.documents = vec!["a".into(), "b".into()];
        let c = base.diff(&n, now);
        assert!(c.iter().any(|x| x.detail.contains("documents") && x.detail.contains("0 -> 2")));

        // documents: count goes down (removal)
        let mut start = base.clone();
        start.documents = vec!["a".into(), "b".into(), "c".into()];
        let mut fewer = start.clone();
        fewer.documents = vec!["a".into()];
        let c = start.diff(&fewer, now);
        assert!(c.iter().any(|x| x.detail.contains("documents") && x.detail.contains("3 -> 1")));
    }

    /// A document set that changes contents but keeps the same length is still a
    /// diff (the diff compares the Vec, not just its length) — yet the human
    /// detail reports the (unchanged) count, which is the documented behaviour.
    #[test]
    fn tax_filing_diff_detects_swapped_doc_same_count() {
        let mut old = TaxFiling::default();
        old.documents = vec!["blob-old".into()];
        let mut new = old.clone();
        new.documents = vec!["blob-new".into()];
        let c = old.diff(&new, unix_now());
        assert_eq!(c.len(), 1, "a swapped (but equal-count) document is a change");
        assert!(c[0].detail.contains("documents") && c[0].detail.contains("1 -> 1"));
    }

    /// The diff must not leak document volume-file ids into the history detail.
    #[test]
    fn tax_filing_diff_does_not_expose_doc_ids() {
        let old = TaxFiling::default();
        let mut new = old.clone();
        new.documents = vec!["super-secret-blob-id".into()];
        let c = old.diff(&new, unix_now());
        assert!(c.iter().any(|x| x.detail.contains("documents")));
        assert!(!c.iter().any(|x| x.detail.contains("super-secret-blob-id")), "doc id must not appear in history");
    }

    /// An identical TaxFiling produces no diff at all (every field equal).
    #[test]
    fn tax_filing_unchanged_yields_no_diff() {
        let mut t = TaxFiling::default();
        t.year = "2024".into();
        t.notes = "n".into();
        t.documents = vec!["d1".into(), "d2".into()];
        assert!(t.diff(&t.clone(), unix_now()).is_empty());
    }

    /// All three TaxFiling text fields changing at once yields three changes.
    #[test]
    fn tax_filing_diff_all_fields_at_once() {
        let old = TaxFiling::default();
        let mut new = old.clone();
        new.year = "2026".into();
        new.notes = "all changed".into();
        new.documents = vec!["d".into()];
        let c = old.diff(&new, unix_now());
        assert_eq!(c.len(), 3, "year + notes + documents");
    }

    // --- Expanded RealEstate diff: one test per NEW field --------------------

    #[test]
    fn real_estate_diff_financing_balance() {
        let old = RealEstate::default();
        let mut new = old.clone();
        new.financing_balance = "199999.99".into();
        let c = old.diff(&new, unix_now());
        assert!(c.iter().any(|x| x.detail.contains("financing_balance") && x.detail.contains("199999.99")));
        assert_eq!(c.len(), 1, "only one field changed");
    }

    #[test]
    fn real_estate_diff_property_mgmt_portal() {
        let old = RealEstate::default();
        let mut new = old.clone();
        new.property_mgmt_url = "https://pm.example".into();
        new.property_mgmt_username = "pmuser".into();
        new.property_mgmt_password = "pmpass".into();
        let c = old.diff(&new, unix_now());
        assert!(c.iter().any(|x| x.detail.contains("property_mgmt_url")));
        assert!(c.iter().any(|x| x.detail.contains("property_mgmt_username") && x.detail.contains("pmuser")));
        // Full before/after of the portal password is recorded (matches Account).
        assert!(c.iter().any(|x| x.detail.contains("property_mgmt_password") && x.detail.contains("pmpass")));
        assert_eq!(c.len(), 3);
    }

    #[test]
    fn real_estate_diff_insurance_portal() {
        let old = RealEstate::default();
        let mut new = old.clone();
        new.insurance_url = "https://ins.example".into();
        new.insurance_username = "insuser".into();
        new.insurance_password = "inspass".into();
        let c = old.diff(&new, unix_now());
        assert!(c.iter().any(|x| x.detail.contains("insurance_url")));
        assert!(c.iter().any(|x| x.detail.contains("insurance_username") && x.detail.contains("insuser")));
        assert!(c.iter().any(|x| x.detail.contains("insurance_password") && x.detail.contains("inspass")));
        assert_eq!(c.len(), 3);
    }

    #[test]
    fn real_estate_diff_hoa_portal() {
        let old = RealEstate::default();
        let mut new = old.clone();
        new.hoa_url = "https://hoa.example".into();
        new.hoa_username = "hoauser".into();
        new.hoa_password = "hoapass".into();
        let c = old.diff(&new, unix_now());
        assert!(c.iter().any(|x| x.detail.contains("hoa_url")));
        assert!(c.iter().any(|x| x.detail.contains("hoa_username") && x.detail.contains("hoauser")));
        assert!(c.iter().any(|x| x.detail.contains("hoa_password") && x.detail.contains("hoapass")));
        assert_eq!(c.len(), 3);
    }

    /// The plain `hoa` (dues) field and the `hoa_url` portal field are distinct;
    /// changing one must not be reported as the other.
    #[test]
    fn real_estate_diff_distinguishes_hoa_dues_from_hoa_portal() {
        let old = RealEstate::default();
        let mut new = old.clone();
        new.hoa = "$300/mo".into();
        let c = old.diff(&new, unix_now());
        assert_eq!(c.len(), 1);
        // The detail starts with the field name "hoa:"; the portal fields are
        // "hoa_url"/"hoa_username"/"hoa_password" and must not be matched here.
        assert!(c[0].detail.starts_with("hoa:"), "got {:?}", c[0].detail);
    }

    #[test]
    fn real_estate_diff_comments() {
        let old = RealEstate::default();
        let mut new = old.clone();
        new.comments = "roof replaced 2025".into();
        let c = old.diff(&new, unix_now());
        assert!(c.iter().any(|x| x.detail.contains("comments") && x.detail.contains("roof replaced 2025")));
        assert_eq!(c.len(), 1);
    }

    /// documents count change is reported without exposing ids; both grow and
    /// shrink are covered, plus a same-count swap.
    #[test]
    fn real_estate_diff_documents_count() {
        let old = RealEstate::default();
        let mut grow = old.clone();
        grow.documents = vec!["deed".into(), "policy".into()];
        let c = old.diff(&grow, unix_now());
        assert!(c.iter().any(|x| x.detail.contains("documents") && x.detail.contains("0 -> 2")));
        assert!(!c.iter().any(|x| x.detail.contains("deed") || x.detail.contains("policy")), "doc ids not leaked");

        let mut shrink = grow.clone();
        shrink.documents = vec!["deed".into()];
        let c2 = grow.diff(&shrink, unix_now());
        assert!(c2.iter().any(|x| x.detail.contains("2 -> 1")));

        let mut swap = grow.clone();
        swap.documents = vec!["deed2".into(), "policy2".into()];
        let c3 = grow.diff(&swap, unix_now());
        assert_eq!(c3.len(), 1);
        assert!(c3[0].detail.contains("2 -> 2"), "swap with same count still diffs");
    }

    /// Every original RealEstate text field is still tracked after the expansion.
    #[test]
    fn real_estate_diff_original_fields_still_tracked() {
        let old = RealEstate::default();
        let mut new = old.clone();
        new.address = "1 A St".into();
        new.ownership = "JT".into();
        new.taxes = "5000".into();
        new.income_account = "inc".into();
        new.financing_account = "fin".into();
        new.payment_account = "pay".into();
        let c = old.diff(&new, unix_now());
        for field in ["address", "ownership", "taxes", "income_account", "financing_account", "payment_account"] {
            assert!(c.iter().any(|x| x.detail.contains(field)), "missing diff for {field}");
        }
    }

    /// Changing EVERY new+old RealEstate field at once yields exactly one change
    /// per field (no double-counting, no missing field). This pins the diff's
    /// field count so adding/removing a tracked field is caught.
    #[test]
    fn real_estate_diff_all_fields_counts_exactly() {
        let old = RealEstate::default();
        let mut n = old.clone();
        n.address = "a".into();
        n.ownership = "b".into();
        n.taxes = "c".into();
        n.hoa = "d".into();
        n.income_account = "e".into();
        n.financing_account = "f".into();
        n.financing_balance = "g".into();
        n.payment_account = "h".into();
        n.property_mgmt_url = "i".into();
        n.property_mgmt_username = "j".into();
        n.property_mgmt_password = "k".into();
        n.insurance_url = "l".into();
        n.insurance_username = "m".into();
        n.insurance_password = "n".into();
        n.hoa_url = "o".into();
        n.hoa_username = "p".into();
        n.hoa_password = "q".into();
        n.comments = "r".into();
        n.documents = vec!["doc".into()];
        let c = old.diff(&n, unix_now());
        // 18 scalar text fields + 1 documents change = 19.
        assert_eq!(c.len(), 19, "expected one change per tracked field; got {:?}", c.iter().map(|x| x.detail.clone()).collect::<Vec<_>>());
    }

    /// An identical RealEstate (with every new field populated) yields no diff.
    #[test]
    fn real_estate_unchanged_yields_no_diff() {
        let mut re = RealEstate::default();
        re.address = "x".into();
        re.financing_balance = "100".into();
        re.property_mgmt_password = "p".into();
        re.insurance_username = "u".into();
        re.hoa_url = "h".into();
        re.comments = "c".into();
        re.documents = vec!["d1".into(), "d2".into()];
        assert!(re.diff(&re.clone(), unix_now()).is_empty(), "no change -> empty diff");
    }

    /// RealEstate label: blank address -> placeholder; otherwise the address.
    #[test]
    fn real_estate_label_variants() {
        let mut re = RealEstate::default();
        assert_eq!(re.label(), "(no address)");
        re.address = "742 Evergreen Terrace".into();
        assert_eq!(re.label(), "742 Evergreen Terrace");
    }

    // --- Folder helpers: adversarial inputs (path-traversal hardening) -------

    /// Internal invariant for any tax folder: exactly `taxes/<one-segment>`,
    /// no `..`, no extra '/', and the segment is non-empty and ASCII-alnum.
    fn assert_tax_folder_safe(input: &str) {
        let f = tax_doc_location(input);
        assert!(f.starts_with("taxes/"), "{input:?} -> {f:?} lost prefix");
        let seg = &f["taxes/".len()..];
        assert!(!seg.is_empty(), "{input:?} -> empty segment");
        assert!(!seg.contains('/'), "{input:?} -> {f:?} has nested slash");
        assert!(!f.contains(".."), "{input:?} -> {f:?} contains ..");
        assert!(!seg.contains('.'), "{input:?} -> {f:?} contains a dot");
        // Either the safe fallback, or pure ASCII-alphanumeric.
        assert!(seg == "unspecified" || seg.chars().all(|c| c.is_ascii_alphanumeric()), "{input:?} -> {f:?} not alnum");
    }

    /// Internal invariant for any real-estate folder: exactly
    /// `real-estate/<one-segment>`, lowercased, <=40 chars, no traversal.
    fn assert_re_folder_safe(input: &str) {
        let f = real_estate_doc_location(input);
        assert!(f.starts_with("real-estate/"), "{input:?} -> {f:?} lost prefix");
        let seg = &f["real-estate/".len()..];
        assert!(!seg.is_empty(), "{input:?} -> empty segment");
        assert!(!seg.contains('/'), "{input:?} -> {f:?} has nested slash");
        assert!(!f.contains(".."), "{input:?} -> {f:?} contains ..");
        assert!(!seg.contains('.'), "{input:?} -> {f:?} contains a dot");
        assert!(seg.len() <= 40, "{input:?} -> {f:?} segment >40 chars");
        assert_eq!(seg, seg.to_lowercase(), "{input:?} -> {f:?} not lowercased");
        assert!(seg == "property" || seg.chars().all(|c| c.is_ascii_alphanumeric()), "{input:?} -> {f:?} not alnum");
    }

    #[test]
    fn tax_doc_location_is_always_safe() {
        let adversarial = [
            "",
            "   ",
            "\t\n  \t",
            "..",
            "../",
            "../../etc/passwd",
            "....//....//",
            "taxes/../secret",
            "/etc/shadow",
            "2024/../2025",
            "  ../2024/..  ",
            "C:\\Windows\\System32",
            "year\0null",
            "2024年",          // unicode suffix
            "二千二十四",        // all-unicode -> fallback
            "café",            // accented -> "caf"
            "\u{ff12}\u{ff10}\u{ff12}\u{ff14}", // full-width digits -> dropped -> fallback
            "FY-2024 #final!",
            "   2023/   ",
            &"9".repeat(100),  // very long
            &("a".repeat(60) + "/../../x"),
        ];
        for input in adversarial {
            assert_tax_folder_safe(input);
        }
        // Spot-check exact, documented outputs.
        assert_eq!(tax_doc_location("2024"), "taxes/2024");
        assert_eq!(tax_doc_location(" 2023/ "), "taxes/2023");
        assert_eq!(tax_doc_location("../../etc/passwd"), "taxes/etcpasswd");
        assert_eq!(tax_doc_location(""), "taxes/unspecified");
        assert_eq!(tax_doc_location("..."), "taxes/unspecified");
        // tax_doc_location preserves case (unlike real-estate).
        assert_eq!(tax_doc_location("FY2024"), "taxes/FY2024");
    }

    #[test]
    fn real_estate_doc_location_is_always_safe() {
        let adversarial = [
            "",
            "   ",
            "\t\n",
            "..",
            "../",
            "../../etc/passwd",
            "....//....//",
            "real-estate/../secret",
            "/etc/shadow",
            "123 Main St/../../root",
            "  ../1 main/..  ",
            "C:\\Users\\victim",
            "addr\0null",
            "Champs-Élysées",  // accented chars dropped
            "東京タワー",        // all-unicode -> fallback
            "\u{ff11}\u{ff12}", // full-width digits -> dropped -> fallback
            "Unit #4B, Apt. 12!",
            &"A".repeat(100),                 // long -> truncated to 40
            &("X".repeat(50) + "/../../x"),  // long + traversal
        ];
        for input in adversarial {
            assert_re_folder_safe(input);
        }
        // Spot-check exact, documented outputs.
        assert_eq!(real_estate_doc_location("123 Main St"), "real-estate/123mainst");
        assert_eq!(real_estate_doc_location(""), "real-estate/property");
        assert_eq!(real_estate_doc_location("..."), "real-estate/property");
        assert_eq!(real_estate_doc_location("../../etc/passwd"), "real-estate/etcpasswd");
        // Truncation is to 40 alnum chars, then lowercased.
        let long = real_estate_doc_location(&"A".repeat(100));
        assert_eq!(long, format!("real-estate/{}", "a".repeat(40)));
    }

    /// Long inputs are truncated to 40 chars *of the sanitized form* — and
    /// separators/junk between alnum runs don't count toward the 40.
    #[test]
    fn real_estate_doc_location_truncates_sanitized_length_not_raw() {
        // 30 'a', then lots of slashes/spaces, then 30 'b': only 40 alnum survive.
        let raw = format!("{}{}{}", "a".repeat(30), " / / / ".repeat(10), "b".repeat(30));
        let f = real_estate_doc_location(&raw);
        let seg = &f["real-estate/".len()..];
        assert_eq!(seg.len(), 40);
        assert_eq!(seg, format!("{}{}", "a".repeat(30), "b".repeat(10)));
    }

    // --- uniform document layout helpers (General Documents + new path scheme) ---

    #[test]
    fn doc_slug_is_safe_and_bounded() {
        assert_eq!(doc_slug("Federal 2024", "fb"), "federal-2024");
        assert_eq!(doc_slug("  My Docs!! ", "fb"), "my-docs");
        assert_eq!(doc_slug("a//b\\c", "fb"), "a-b-c");
        assert_eq!(doc_slug("../../etc/passwd", "fb"), "etc-passwd"); // no traversal survives
        assert_eq!(doc_slug("", "fb"), "fb"); // empty -> fallback
        assert_eq!(doc_slug("！！！", "fb"), "fb"); // all non-ascii -> fallback
        assert_eq!(doc_slug("---", "fb"), "fb"); // separators-only -> fallback
        // Length is capped at 40 with no trailing dash.
        let long = doc_slug(&"a ".repeat(60), "fb");
        assert!(long.len() <= 40 && !long.ends_with('-'));
    }

    #[test]
    fn compact_utc_is_fixed_width_sortable() {
        // 2024-01-02 03:04:05 UTC = 1704164645.
        assert_eq!(compact_utc(1_704_164_645), "20240102-030405");
        assert_eq!(compact_utc(0), "19700101-000000");
        // Always 15 chars (YYYYMMDD-HHMMSS); lexical order == chronological order.
        assert_eq!(compact_utc(1_704_164_645).len(), 15);
        assert!(compact_utc(1_000) < compact_utc(2_000_000_000));
    }

    #[test]
    fn doc_upload_dir_builds_the_uniform_layout() {
        // <root>/<auto-group>/<timestamp>[/<subfolder>] — auto-group above timestamp.
        let prefix = tax_doc_location("2024"); // "taxes/2024"
        assert_eq!(doc_upload_dir(&prefix, "20240102-030405", "federal"), "taxes/2024/20240102-030405/federal");
        // Blank subfolder is omitted entirely.
        assert_eq!(doc_upload_dir(&prefix, "20240102-030405", "   "), "taxes/2024/20240102-030405");
        // Subfolder is slugged (no separators/traversal leak into the path).
        assert_eq!(
            doc_upload_dir("general-documents/passport", "20240102-030405", "../ids"),
            "general-documents/passport/20240102-030405/ids"
        );
    }

    #[test]
    fn doc_filename_is_user_controlled_but_safe() {
        assert_eq!(doc_filename("return.pdf"), "return.pdf"); // extension preserved
        assert_eq!(doc_filename("a/b/c.pdf"), "a_b_c.pdf"); // separators neutralized
        assert_eq!(doc_filename("my report.pdf"), "my-report.pdf"); // spaces -> '-'
        assert_eq!(doc_filename("  spaced  name .pdf"), "spaced--name-.pdf"); // no spaces remain
        assert_eq!(doc_filename("tab\tname.pdf"), "tab-name.pdf"); // tabs are whitespace too
        assert!(!doc_filename("a b\tc\nd.pdf").contains(' '), "no whitespace survives");
        assert_eq!(doc_filename("  ..  "), "file"); // dot/space-only -> fallback
        assert_eq!(doc_filename(""), "file");
        assert!(doc_filename(&"x".repeat(500)).len() <= 120); // capped
        // A multibyte filename whose 120th byte lands mid-character must NOT panic
        // (a raw String::truncate(120) would). 5-byte ASCII prefix + 50 CJK chars
        // (3 bytes each) = 155 bytes; the cap falls inside a character.
        let multibyte = doc_filename(&format!("file_{}", "\u{6570}".repeat(50)));
        assert!(multibyte.len() <= 120 && !multibyte.is_empty());
        // Emoji (4-byte) near the boundary likewise truncates safely.
        let emoji = doc_filename(&"\u{1F600}".repeat(40)); // 160 bytes
        assert!(emoji.len() <= 120);
    }

    #[test]
    fn general_document_diff_and_label() {
        let mut a = GeneralDocument::new().unwrap();
        a.title = "Passport".into();
        a.description = "scan".into();
        let mut b = a.clone();
        b.description = "scan v2".into();
        b.file = Some("deadbeef".into());
        let c = a.diff(&b, 100);
        assert!(c.iter().any(|x| x.detail.contains("description")));
        // The file id itself must never appear in the history detail.
        assert!(c.iter().any(|x| x.detail.contains("attached file changed")));
        assert!(!c.iter().any(|x| x.detail.contains("deadbeef")), "doc id must not leak into history");
        assert_eq!(a.label(), "Passport");
        assert_eq!(GeneralDocument::default().label(), "(untitled)");
        // general_doc_location slugs the title.
        assert_eq!(general_doc_location("My Passport"), "general-documents/my-passport");
        assert_eq!(general_doc_location(""), "general-documents/untitled");
    }

    #[test]
    fn compact_history_includes_general_documents() {
        let mut vault = Vault::default();
        let mut g = GeneralDocument::default();
        g.history = vec![Change::new("created", String::new()), Change::new("updated", "title".into())];
        vault.general_documents.push(g);
        assert_eq!(history_stats(&vault, None, true), 2);
        assert_eq!(compact_history(&mut vault, None, true), 2);
        assert!(vault.general_documents[0].history.is_empty());
    }

    // --- compact_history / history_stats include tax_filings & real_estate ---

    /// `compact_history` and `history_stats` both account for tax_filings under a
    /// cutoff (not just drop_all), and agree with each other.
    #[test]
    fn compact_history_counts_tax_filings_under_cutoff() {
        let mut vault = Vault::default();
        let mut t = TaxFiling::default();
        t.history = vec![
            Change { at: 100, action: "u".into(), detail: String::new() },
            Change { at: 200, action: "u".into(), detail: String::new() },
            Change { at: 300, action: "u".into(), detail: String::new() },
        ];
        vault.tax_filings.push(t);
        // cutoff 250: at=100,200 are older (removed); at=300 kept.
        assert_eq!(history_stats(&vault, Some(250), false), 2);
        assert_eq!(compact_history(&mut vault, Some(250), false), 2);
        assert_eq!(vault.tax_filings[0].history.iter().map(|c| c.at).collect::<Vec<_>>(), vec![300]);
    }

    /// `compact_history`/`history_stats` count real-estate AND tax histories in
    /// the same pass as the other record types, and the two functions agree.
    #[test]
    fn compact_history_spans_all_six_record_types() {
        let mut vault = Vault::default();
        let mk = |at| Change { at, action: "u".into(), detail: String::new() };
        let mut ins = Instruction::default();
        ins.history = vec![mk(1)];
        let mut tw = TrustWill::default();
        tw.history = vec![mk(1)];
        let mut al = AssetLiability::default();
        al.history = vec![mk(1)];
        let mut ac = Account::default();
        ac.history = vec![mk(1)];
        let mut re = RealEstate::default();
        re.history = vec![mk(1), mk(2)];
        let mut tx = TaxFiling::default();
        tx.history = vec![mk(1), mk(2), mk(3)];
        vault.instructions.push(ins);
        vault.trust_wills.push(tw);
        vault.assets.push(al);
        vault.accounts.push(ac);
        vault.real_estate.push(re);
        vault.tax_filings.push(tx);
        // 1+1+1+1+2+3 = 9
        assert_eq!(history_stats(&vault, None, true), 9);
        assert_eq!(compact_history(&mut vault, None, true), 9, "all six types trimmed");
        assert!(vault.real_estate[0].history.is_empty());
        assert!(vault.tax_filings[0].history.is_empty());
        // Idempotent: nothing left to remove.
        assert_eq!(compact_history(&mut vault, None, true), 0);
    }

    // --- upsert wiring for the two new record types --------------------------

    /// `upsert` works end-to-end for TaxFiling: insert logs "created", and a
    /// subsequent edit appends the field diff while keeping id + creation time.
    #[test]
    fn upsert_taxfiling_insert_then_edit() {
        let mut list: Vec<TaxFiling> = Vec::new();
        let mut t = TaxFiling::new().unwrap();
        t.year = "2024".into();
        let id = t.id.clone();
        let created = t.created_at;
        upsert(&mut list, t);
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].history.len(), 1);
        assert_eq!(list[0].history[0].action, "created");
        assert!(list[0].history[0].detail.contains("Taxes 2024"));

        let mut edit = list[0].clone();
        edit.notes = "amended".into();
        edit.documents.push("blob".into());
        upsert(&mut list, edit);
        assert_eq!(list.len(), 1, "same id replaces");
        assert_eq!(list[0].id, id);
        assert_eq!(list[0].created_at, created, "creation time preserved");
        assert!(list[0].history.iter().any(|c| c.detail.contains("notes")));
        assert!(list[0].history.iter().any(|c| c.detail.contains("documents") && c.detail.contains("0 -> 1")));
    }

    /// `upsert` for RealEstate preserves creation time and appends a portal diff.
    #[test]
    fn upsert_real_estate_insert_then_edit() {
        let mut list: Vec<RealEstate> = Vec::new();
        let mut re = RealEstate::new().unwrap();
        re.address = "9 Pine".into();
        let id = re.id.clone();
        let created = re.created_at;
        upsert(&mut list, re);
        assert_eq!(list[0].history.len(), 1);
        assert_eq!(list[0].history[0].action, "created");

        let mut edit = list[0].clone();
        edit.hoa_password = "rotated".into();
        upsert(&mut list, edit);
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].id, id);
        assert_eq!(list[0].created_at, created);
        assert!(list[0].history.iter().any(|c| c.detail.contains("hoa_password") && c.detail.contains("rotated")));
    }

    /// `remove` logs a deletion using the RealEstate/TaxFiling labels.
    #[test]
    fn remove_logs_real_estate_and_tax_labels() {
        let mut re_list: Vec<RealEstate> = Vec::new();
        let mut re = RealEstate::new().unwrap();
        re.address = "Lot 7".into();
        let re_id = re.id.clone();
        upsert(&mut re_list, re);
        let mut audit = Vec::new();
        assert!(remove(&mut re_list, &re_id, &mut audit, "RealEstate"));
        assert!(audit.iter().any(|c| c.action == "deleted" && c.detail.contains("Lot 7")));

        let mut tx_list: Vec<TaxFiling> = Vec::new();
        let mut tx = TaxFiling::new().unwrap();
        tx.year = "2030".into();
        let tx_id = tx.id.clone();
        upsert(&mut tx_list, tx);
        assert!(remove(&mut tx_list, &tx_id, &mut audit, "TaxFiling"));
        assert!(audit.iter().any(|c| c.action == "deleted" && c.detail.contains("Taxes 2030")));
    }

    // --- ZeroizeOnDrop coverage of the new secret-bearing fields -------------

    /// The expanded RealEstate's new portal passwords / comments / documents are
    /// covered by the derived `Zeroize` (no `#[zeroize(skip)]`), so they are
    /// wiped on drop. We call `zeroize()` directly (drop calls the same impl).
    #[test]
    fn real_estate_zeroize_wipes_new_secret_fields() {
        let mut re = RealEstate::default();
        re.property_mgmt_password = "pm-secret".into();
        re.insurance_password = "ins-secret".into();
        re.hoa_password = "hoa-secret".into();
        re.property_mgmt_username = "user".into();
        re.comments = "private note".into();
        re.documents = vec!["blobA".into(), "blobB".into()];
        Zeroize::zeroize(&mut re);
        assert!(re.property_mgmt_password.is_empty());
        assert!(re.insurance_password.is_empty());
        assert!(re.hoa_password.is_empty());
        assert!(re.property_mgmt_username.is_empty());
        assert!(re.comments.is_empty());
        assert!(re.documents.is_empty(), "document id list must be wiped");
    }

    /// TaxFiling notes + document id list are wiped by the derived `Zeroize`.
    #[test]
    fn tax_filing_zeroize_wipes_fields() {
        let mut t = TaxFiling::default();
        t.year = "2024".into();
        t.notes = "sensitive".into();
        t.documents = vec!["doc1".into(), "doc2".into()];
        Zeroize::zeroize(&mut t);
        assert!(t.year.is_empty());
        assert!(t.notes.is_empty());
        assert!(t.documents.is_empty());
    }

    use proptest::prelude::*;
    proptest! {
        /// `civil_from_unix` and `unix_from_civil` are exact inverses across the whole
        /// post-epoch range the app uses — a single off-by-one in the calendar math
        /// would break this.
        #[test]
        fn prop_civil_unix_roundtrip(ts in 0i64..=253_402_300_799i64) {
            let (y, mo, d, h, mi, s) = civil_from_unix(ts);
            prop_assert_eq!(unix_from_civil(y, mo, d, h, mi, s), ts);
        }

        /// `parse_ymd_utc` never panics on arbitrary input (returns None or Some).
        #[test]
        fn prop_parse_ymd_never_panics(s in ".*") {
            let _ = parse_ymd_utc(&s);
        }

        /// For valid `YYYY-MM-DD` dates, `parse_ymd_utc` is strictly monotonic in the
        /// calendar date, and a valid date round-trips through `civil_from_unix`.
        /// (`d in 1..=28` keeps every (y,m,d) a real date, so both parses are `Some`.)
        #[test]
        fn prop_parse_ymd_monotonic_and_roundtrips(
            y1 in 1970..=9999i64, m1 in 1..=12i64, d1 in 1..=28i64,
            y2 in 1970..=9999i64, m2 in 1..=12i64, d2 in 1..=28i64,
        ) {
            let a = format!("{y1:04}-{m1:02}-{d1:02}");
            let b = format!("{y2:04}-{m2:02}-{d2:02}");
            let ta = parse_ymd_utc(&a).expect("valid date a");
            let tb = parse_ymd_utc(&b).expect("valid date b");
            prop_assert_eq!(ta.cmp(&tb), (y1, m1, d1).cmp(&(y2, m2, d2)));
            let (cy, cmo, cd, ..) = civil_from_unix(ta);
            prop_assert_eq!((cy, cmo, cd), (y1, m1, d1));
        }
    }
}
