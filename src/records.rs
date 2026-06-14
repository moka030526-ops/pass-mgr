//! The estate-vault data model: the five record types behind the UI tabs, the
//! encrypted-volume manifest, and the [`Vault`] that owns them all.
//!
//! Every record carries an `id`, `created_at`/`updated_at` timestamps, and an
//! append-only `history` of timestamped [`Change`]s (req: trace history). The
//! shared insert/edit/diff logic lives in the [`Record`] trait + the generic
//! [`upsert`]/[`remove`] helpers, so each type only describes its own fields and
//! field-level diff. All types wipe their contents on drop (they hold secrets
//! such as passwords).

use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::crypto::{self, CryptoError};

/// Unix-seconds "now" (0 if the clock is before the epoch).
pub fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// A random 128-bit hex id, used for records and volume blobs.
pub fn random_id() -> Result<String, CryptoError> {
    let bytes = crypto::random_bytes::<16>()?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

/// A single timestamped audit record. Pushed onto a record's history on every
/// edit, or onto the vault-level audit / volume upload log.
#[derive(Serialize, Deserialize, Clone, Debug, Default, Zeroize, ZeroizeOnDrop)]
pub struct Change {
    pub at: i64,
    pub action: String,
    pub detail: String,
}

impl Change {
    pub fn new(action: &str, detail: String) -> Self {
        Change { at: unix_now(), action: action.to_string(), detail }
    }
}

/// Append a field change to `out` if `old != new` (full before/after values).
fn track(out: &mut Vec<Change>, at: i64, name: &str, old: &str, new: &str) {
    if old != new {
        out.push(Change {
            at,
            action: "updated".into(),
            detail: format!("{name}: {old:?} -> {new:?}"),
        });
    }
}

/// Shared behaviour for the five record types so insert/edit/history is generic.
pub trait Record: Clone {
    fn id(&self) -> &str;
    fn created_at(&self) -> i64;
    fn set_created_at(&mut self, at: i64);
    fn set_updated_at(&mut self, at: i64);
    fn history_mut(&mut self) -> &mut Vec<Change>;
    /// Field-level diff describing the change from `self` to `new`.
    fn diff(&self, new: &Self, at: i64) -> Vec<Change>;
    /// Short label for list display.
    fn label(&self) -> String;
}

/// Insert `rec` or, if a record with the same id exists, replace it — appending
/// the field-level diff to history and preserving the original creation time.
pub fn upsert<R: Record>(list: &mut Vec<R>, mut rec: R) {
    let now = unix_now();
    rec.set_updated_at(now);
    match list.iter().position(|e| e.id() == rec.id()) {
        Some(i) => {
            let changes = list[i].diff(&rec, now);
            rec.set_created_at(list[i].created_at());
            let mut history = list[i].history_mut().clone();
            history.extend(changes);
            *rec.history_mut() = history;
            list[i] = rec;
        }
        None => {
            let label = rec.label();
            rec.history_mut().push(Change::new("created", label));
            list.push(rec);
        }
    }
}

/// Remove a record by id, logging a timestamped deletion in `audit`.
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

/// Tab 1 — free-form instruction note.
#[derive(Serialize, Deserialize, Clone, Debug, Default, Zeroize, ZeroizeOnDrop)]
pub struct Instruction {
    pub id: String,
    pub title: String,
    pub description: String,
    pub created_at: i64,
    pub updated_at: i64,
    pub history: Vec<Change>,
}

/// Tab 2 — a trust/will document with a usage note and an attached file.
#[derive(Serialize, Deserialize, Clone, Debug, Default, Zeroize, ZeroizeOnDrop)]
pub struct TrustWill {
    pub id: String,
    pub document: String,
    pub usage: String,
    /// Volume file id of the attached document, if any.
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
    pub owner: String,
    pub username: String,
    pub password: String,
    pub description: String,
    pub url: String,
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
macro_rules! new_record {
    ($ty:ident) => {{
        let now = unix_now();
        let mut r = $ty::default();
        r.id = random_id()?;
        r.created_at = now;
        r.updated_at = now;
        r
    }};
}

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
macro_rules! impl_record {
    ($ty:ty, $diff:expr, $label:expr) => {
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
                let mut out = Vec::new();
                let f: fn(&$ty, &$ty, i64, &mut Vec<Change>) = $diff;
                f(self, new, at, &mut out);
                out
            }
            fn label(&self) -> String {
                let f: fn(&$ty) -> String = $label;
                f(self)
            }
        }
    };
}

impl_record!(
    Instruction,
    |s: &Instruction, n: &Instruction, at: i64, out: &mut Vec<Change>| {
        track(out, at, "title", &s.title, &n.title);
        track(out, at, "description", &s.description, &n.description);
    },
    |l: &Instruction| if l.title.is_empty() { "(untitled)".to_string() } else { l.title.clone() }
);

impl_record!(
    TrustWill,
    |s: &TrustWill, n: &TrustWill, at: i64, out: &mut Vec<Change>| {
        track(out, at, "document", &s.document, &n.document);
        track(out, at, "usage", &s.usage, &n.usage);
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
        if s.statement != n.statement {
            out.push(Change { at, action: "updated".into(), detail: "statement document changed".into() });
        }
    },
    |l: &AssetLiability| {
        let d = if l.description.is_empty() { "(no description)" } else { l.description.as_str() };
        format!("[{}] {d}", l.kind)
    }
);

impl_record!(
    Account,
    |s: &Account, n: &Account, at: i64, out: &mut Vec<Change>| {
        track(out, at, "type", &s.account_type, &n.account_type);
        track(out, at, "owner", &s.owner, &n.owner);
        track(out, at, "username", &s.username, &n.username);
        // Full before/after of the password is recorded (accepted decision).
        track(out, at, "password", &s.password, &n.password);
        track(out, at, "description", &s.description, &n.description);
        track(out, at, "url", &s.url, &n.url);
    },
    |l: &Account| {
        let who = if l.username.is_empty() { l.owner.clone() } else { l.username.clone() };
        let label =
            if l.account_type.is_empty() { who } else { format!("{}: {who}", l.account_type) };
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

// --- Encrypted document volume manifest --------------------------------------

/// A file stored in the encrypted volume. The on-disk blob is `<id>.bin` inside
/// the volume directory; `location`/`filename` are the virtual path shown in the
/// UI's directory structure.
#[derive(Serialize, Deserialize, Clone, Debug, Default, Zeroize, ZeroizeOnDrop)]
pub struct VolumeFile {
    pub id: String,
    pub location: String,
    pub filename: String,
    pub size: u64,
    pub uploaded_at: i64,
    /// Filesystem path the file was originally uploaded from.
    pub source: String,
}

/// The manifest of the encrypted volume: the virtual directory structure, the
/// stored files, and the append-only upload history (location / date / file).
#[derive(Serialize, Deserialize, Clone, Debug, Default, Zeroize, ZeroizeOnDrop)]
pub struct Volume {
    /// Stable random id binding the encrypted archive file to this vault (so a
    /// `.vol` from another vault, or a swapped one, is rejected). Set on create.
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub directories: Vec<String>,
    #[serde(default)]
    pub files: Vec<VolumeFile>,
    #[serde(default)]
    pub uploads: Vec<Change>,
}

impl Volume {
    /// Register a virtual directory path (and its ancestors) if not present.
    pub fn register_directory(&mut self, path: &str) {
        for dir in ancestor_dirs(path) {
            if !self.directories.iter().any(|d| d == &dir) {
                self.directories.push(dir);
            }
        }
        self.directories.sort();
    }

    pub fn file(&self, id: &str) -> Option<&VolumeFile> {
        self.files.iter().find(|f| f.id == id)
    }
}

/// Normalize a virtual path and return it plus each ancestor, e.g.
/// `/a/b/c` -> ["/a", "/a/b", "/a/b/c"]. Empty/`"/"` yields nothing.
pub fn ancestor_dirs(path: &str) -> Vec<String> {
    let parts: Vec<&str> = path.split('/').filter(|p| !p.is_empty()).collect();
    let mut out = Vec::new();
    let mut acc = String::new();
    for p in parts {
        acc.push('/');
        acc.push_str(p);
        out.push(acc.clone());
    }
    out
}

/// The decrypted contents of a vault: all five record collections plus the
/// volume manifest, access time, and vault-level audit log. Wipes on drop.
#[derive(Serialize, Deserialize, Clone, Debug, Default, Zeroize, ZeroizeOnDrop)]
pub struct Vault {
    #[serde(default)]
    pub version: u8,
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
    #[serde(default)]
    pub volume: Volume,
    #[serde(default)]
    pub audit: Vec<Change>,
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn ancestor_dirs_builds_tree() {
        assert_eq!(ancestor_dirs("/statements/2026/q1"), vec!["/statements", "/statements/2026", "/statements/2026/q1"]);
        assert!(ancestor_dirs("/").is_empty());
        assert!(ancestor_dirs("").is_empty());
    }

    #[test]
    fn register_directory_dedups_and_adds_ancestors() {
        let mut v = Volume::default();
        v.register_directory("/statements/2026");
        v.register_directory("/statements/2026"); // dup
        v.register_directory("/wills");
        assert_eq!(v.directories, vec!["/statements", "/statements/2026", "/wills"]);
    }
}
