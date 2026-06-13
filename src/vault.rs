//! Vault data model and the encrypted on-disk file format.
//!
//! File layout (all integers little-endian):
//! ```text
//!   offset  len  field
//!   0       8    magic  b"PMVAULT\0"          (identifies a pass-mgr vault)
//!   8       1    format version (currently 2)
//!   9       4    Argon2 m_cost (KiB)
//!   13      4    Argon2 t_cost
//!   17      4    Argon2 p_cost
//!   21      16   salt1   (salt for the first KDF pass)
//!   37      24   nonce   (XChaCha20-Poly1305)
//!   61      ..   XChaCha20-Poly1305 ciphertext of the JSON vault
//! ```
//! The 61-byte header is passed to the AEAD as associated data, so tampering
//! with the version, KDF parameters, or salt is detected on decrypt.
//!
//! The encryption key is derived from **two** passwords via a chained Argon2id
//! derivation (see [`crate::crypto::derive_key_chained`] and `docs/DESIGN.md`).
//! Format version 2 reflects both the two-password scheme and the richer schema
//! (custom types, per-entry history, last-access time). Version 1 prototype
//! files are intentionally not auto-migrated.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::crypto::{self, CryptoError, KdfParams, Key, NONCE_LEN, SALT_LEN};

const MAGIC: &[u8; 8] = b"PMVAULT\0";
const FORMAT_VERSION: u8 = 2;
const HEADER_LEN: usize = 61;

// Sanity bounds for KDF parameters read from an untrusted file header. They are
// validated *before* the (expensive, memory-hard) key derivation runs, so a
// crafted header cannot force a huge Argon2 allocation as a denial-of-service.
// The defaults (64 MiB / 3 / 1) sit well inside these limits.
const MAX_M_COST: u32 = 1 << 20; // 1 GiB, expressed in KiB
const MAX_T_COST: u32 = 64;
const MAX_P_COST: u32 = 16;
/// Bytes of the header used as AEAD associated data: everything *except* the
/// 24-byte nonce (magic + version + KDF params + salt = the first 37 bytes).
/// The nonce is not included because it is already bound as the cipher's nonce
/// input — altering it makes decryption fail the authentication tag anyway.
const AAD_LEN: usize = HEADER_LEN - NONCE_LEN;

#[derive(Error, Debug)]
pub enum VaultError {
    #[error("vault file not found at {0}")]
    NotFound(PathBuf),
    #[error("a vault already exists at {0}")]
    AlreadyExists(PathBuf),
    #[error("not a pass-mgr vault (bad magic bytes)")]
    BadMagic,
    #[error("unsupported vault format version {0}")]
    BadVersion(u8),
    #[error("vault file is truncated or corrupt")]
    Truncated,
    #[error("vault KDF parameters are out of the allowed range")]
    BadParams,
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error("vault contents are not valid JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// A single timestamped audit record (req. 4). Pushed onto an entry's history
/// on every edit, or onto the vault-level audit log for vault-wide events.
/// History `detail` strings can contain old plaintext passwords, so this type
/// wipes its fields on drop.
#[derive(Serialize, Deserialize, Clone, Debug, Default, Zeroize, ZeroizeOnDrop)]
pub struct Change {
    /// Unix-seconds timestamp of the change.
    pub at: i64,
    /// Machine-readable action, e.g. "created", "updated", "password_changed".
    pub action: String,
    /// Human-readable summary, e.g. `username: "a" -> "b"`.
    pub detail: String,
}

impl Change {
    fn new(action: &str, detail: String) -> Self {
        Change { at: unix_now(), action: action.to_string(), detail }
    }
}

/// A single stored credential. Holds the plaintext password and history, so it
/// wipes all its fields on drop.
#[derive(Serialize, Deserialize, Clone, Debug, Default, Zeroize, ZeroizeOnDrop)]
pub struct Entry {
    pub id: String,
    pub title: String,
    /// Custom user-defined type/category, e.g. "Login", "Server" (req. 2).
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub url: String,
    pub created_at: i64,
    pub updated_at: i64,
    /// Append-only log of changes to this entry (req. 4, 5).
    #[serde(default)]
    pub history: Vec<Change>,
}

impl Entry {
    /// Build a new entry with a random id and current timestamps.
    pub fn new(title: String) -> Result<Self, CryptoError> {
        // Built field-by-field rather than with `..Default::default()` because
        // Entry implements Drop (ZeroizeOnDrop), which forbids the FRU move.
        let now = unix_now();
        let mut entry = Entry::default();
        entry.id = random_id()?;
        entry.title = title;
        entry.created_at = now;
        entry.updated_at = now;
        Ok(entry)
    }

    /// Case-insensitive match against title, type, username, url, and description.
    pub fn matches(&self, query: &str) -> bool {
        if query.is_empty() {
            return true;
        }
        let q = query.to_lowercase();
        [&self.title, &self.kind, &self.username, &self.url, &self.description]
            .iter()
            .any(|field| field.to_lowercase().contains(&q))
    }

    /// Compute the list of changes needed to turn `self` into `new`. The full
    /// before/after value of every field — including the password — is recorded
    /// so the history is a complete record (see `docs/DESIGN.md` §4.1, §9.4).
    fn diff(&self, new: &Entry, at: i64) -> Vec<Change> {
        let mut changes = Vec::new();
        let mut track = |name: &str, action: &str, old: &str, new: &str| {
            if old != new {
                changes.push(Change {
                    at,
                    action: action.into(),
                    detail: format!("{name}: {old:?} -> {new:?}"),
                });
            }
        };
        track("title", "updated", &self.title, &new.title);
        track("type", "updated", &self.kind, &new.kind);
        track("description", "updated", &self.description, &new.description);
        track("username", "updated", &self.username, &new.username);
        track("url", "updated", &self.url, &new.url);
        // The old and new password values ARE recorded in history (req. 4/5).
        track("password", "password_changed", &self.password, &new.password);
        changes
    }
}

/// The decrypted contents of a vault. Wipes all entries/history on drop so the
/// decrypted secrets do not linger in freed memory after the vault is closed.
#[derive(Serialize, Deserialize, Clone, Debug, Default, Zeroize, ZeroizeOnDrop)]
pub struct Vault {
    /// Schema version of the decrypted JSON (mirrors the file format version).
    #[serde(default)]
    pub version: u8,
    /// Unix-seconds time the vault was last successfully unlocked (req. 6).
    #[serde(default)]
    pub last_opened_at: i64,
    /// The set of custom types the user has created (req. 2).
    #[serde(default)]
    pub types: Vec<String>,
    /// Vault-level audit log: creation, password changes, deletions (req. 4).
    #[serde(default)]
    pub audit: Vec<Change>,
    #[serde(default)]
    pub entries: Vec<Entry>,
}

impl Vault {
    /// Insert or replace an entry by id. On replace, the field-level diff is
    /// appended to the entry's history and the original creation time is kept.
    /// On insert, a "created" record is added. The entry's type is registered.
    pub fn upsert(&mut self, mut entry: Entry) {
        let now = unix_now();
        entry.updated_at = now;
        // Normalize the type once so the stored value matches the registered
        // (trimmed) type string — otherwise a leading/trailing space would hide
        // the entry from its own type filter.
        if entry.kind != entry.kind.trim() {
            entry.kind = entry.kind.trim().to_string();
        }
        self.register_type(&entry.kind);

        match self.entries.iter().position(|e| e.id == entry.id) {
            Some(i) => {
                let old = &self.entries[i];
                let changes = old.diff(&entry, now);
                entry.created_at = old.created_at; // preserve original creation time
                entry.history = old.history.clone(); // preserve prior history
                entry.history.extend(changes);
                self.entries[i] = entry;
            }
            None => {
                entry.history.push(Change::new("created", entry.title.clone()));
                self.entries.push(entry);
            }
        }
    }

    /// Remove an entry by id, recording a timestamped deletion in the vault audit
    /// log (the entry itself is gone, so its own history cannot hold the record).
    pub fn remove(&mut self, id: &str) -> bool {
        match self.entries.iter().position(|e| e.id == id) {
            Some(i) => {
                let title = self.entries[i].title.clone();
                self.entries.remove(i);
                self.audit.push(Change::new("deleted", title));
                true
            }
            None => false,
        }
    }

    /// Register a custom type so it shows up in the filter bar. Case-insensitive
    /// dedup; ignores blank input.
    pub fn register_type(&mut self, kind: &str) {
        let k = kind.trim();
        if k.is_empty() || self.types.iter().any(|t| t.eq_ignore_ascii_case(k)) {
            return;
        }
        self.types.push(k.to_string());
        self.types.sort_by_key(|t| t.to_lowercase());
    }

    /// Entries matching `query` and (optionally) a custom type, sorted by title.
    /// Pass `kind = None` to search across all types.
    pub fn filter(&self, query: &str, kind: Option<&str>) -> Vec<&Entry> {
        let mut out: Vec<&Entry> = self
            .entries
            .iter()
            .filter(|e| e.matches(query))
            .filter(|e| kind.is_none_or(|k| e.kind.eq_ignore_ascii_case(k)))
            .collect();
        out.sort_by_key(|e| e.title.to_lowercase());
        out
    }
}

/// Self-describing header parsed from / written to the vault file.
#[derive(Debug, Clone)]
struct Header {
    params: KdfParams,
    salt: [u8; SALT_LEN],
    nonce: [u8; NONCE_LEN],
}

impl Header {
    fn to_bytes(&self) -> [u8; HEADER_LEN] {
        let mut b = [0u8; HEADER_LEN];
        b[0..8].copy_from_slice(MAGIC);
        b[8] = FORMAT_VERSION;
        b[9..13].copy_from_slice(&self.params.m_cost.to_le_bytes());
        b[13..17].copy_from_slice(&self.params.t_cost.to_le_bytes());
        b[17..21].copy_from_slice(&self.params.p_cost.to_le_bytes());
        b[21..37].copy_from_slice(&self.salt);
        b[37..61].copy_from_slice(&self.nonce);
        b
    }

    fn parse(buf: &[u8]) -> Result<Header, VaultError> {
        if buf.len() < HEADER_LEN {
            return Err(VaultError::Truncated);
        }
        if &buf[0..8] != MAGIC {
            return Err(VaultError::BadMagic);
        }
        if buf[8] != FORMAT_VERSION {
            return Err(VaultError::BadVersion(buf[8]));
        }
        let params = KdfParams {
            m_cost: u32::from_le_bytes(buf[9..13].try_into().unwrap()),
            t_cost: u32::from_le_bytes(buf[13..17].try_into().unwrap()),
            p_cost: u32::from_le_bytes(buf[17..21].try_into().unwrap()),
        };
        // Reject absurd parameters before they reach the memory-hard KDF.
        if params.m_cost < 8
            || params.m_cost > MAX_M_COST
            || params.t_cost < 1
            || params.t_cost > MAX_T_COST
            || params.p_cost < 1
            || params.p_cost > MAX_P_COST
        {
            return Err(VaultError::BadParams);
        }
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&buf[21..37]);
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&buf[37..61]);
        Ok(Header { params, salt, nonce })
    }
}

/// An unlocked vault: holds the decrypted entries plus the derived key and KDF
/// salt/params needed to re-encrypt on save. The key zeroizes when dropped.
pub struct OpenVault {
    pub vault: Vault,
    key: Key,
    params: KdfParams,
    salt: [u8; SALT_LEN],
    path: PathBuf,
    /// The `last_opened_at` value read from disk *before* this session updated
    /// it — i.e. the previous access time, for display on the unlock screen.
    previous_access: i64,
}

impl OpenVault {
    /// Create a brand-new vault at `path` protected by two passwords. Fails if a
    /// file is already there.
    pub fn create(
        path: PathBuf,
        pw1: &[u8],
        pw2: &[u8],
        params: KdfParams,
    ) -> Result<Self, VaultError> {
        if path.exists() {
            return Err(VaultError::AlreadyExists(path));
        }
        let salt = crypto::random_bytes::<SALT_LEN>()?;
        let key = crypto::derive_key_chained(pw1, pw2, &salt, &params)?;

        let now = unix_now();
        let mut vault = Vault::default();
        vault.version = FORMAT_VERSION;
        vault.last_opened_at = now;
        vault.audit.push(Change::new("vault_created", String::new()));

        let open = OpenVault {
            vault,
            key,
            params,
            salt,
            path,
            previous_access: 0,
        };
        open.save()?;
        Ok(open)
    }

    /// Unlock an existing vault with both passwords (entered sequentially).
    /// Updates and persists `last_opened_at` (req. 6); the prior value is kept in
    /// [`OpenVault::previous_access`] for display.
    pub fn open(path: PathBuf, pw1: &[u8], pw2: &[u8]) -> Result<Self, VaultError> {
        let (mut vault, header, key) = decrypt_file(&path, pw1, pw2)?;

        let previous_access = vault.last_opened_at;
        vault.last_opened_at = unix_now();

        let open = OpenVault {
            vault,
            key,
            params: header.params,
            salt: header.salt,
            path,
            previous_access,
        };
        // Persist the refreshed access time so it survives to the next session.
        open.save()?;
        Ok(open)
    }

    /// Decrypt the vault at `path` and return its contents **without** modifying
    /// the file (no `last_opened_at` update, no re-encrypt). Used by the
    /// command-line decrypt/export path. The derived key is dropped immediately.
    pub fn export(path: &Path, pw1: &[u8], pw2: &[u8]) -> Result<Vault, VaultError> {
        let (vault, _header, _key) = decrypt_file(path, pw1, pw2)?;
        Ok(vault)
    }

    /// Re-encrypt the current entries and write them atomically (temp + rename),
    /// with a fresh random nonce. The on-disk file is tightened to owner-only
    /// where the platform supports it (see [`harden_file`]).
    pub fn save(&self) -> Result<(), VaultError> {
        // Zeroizing so the serialized plaintext's final allocation is wiped on
        // drop (serde's transient reallocations are an accepted residual).
        let plaintext = Zeroizing::new(serde_json::to_vec(&self.vault)?);

        // The AAD covers magic/version/params/salt (the first AAD_LEN bytes) and
        // is independent of the nonce, so we can compute it before encrypt()
        // chooses the nonce. encrypt() returns the fresh nonce it used.
        let mut header = Header { params: self.params, salt: self.salt, nonce: [0u8; NONCE_LEN] };
        let aad = header.to_bytes();
        let (nonce, ciphertext) = crypto::encrypt(&self.key, &plaintext, &aad[..AAD_LEN])?;
        header.nonce = nonce;
        let header_bytes = header.to_bytes();

        if let Some(parent) = self.path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent)?;
            harden_dir(parent);
        }

        // Write to a uniquely-named, hidden temp file created with O_EXCL and
        // (on Unix) mode 0600 atomically, so there is no world-readable window
        // and a pre-planted symlink at a predictable path cannot be followed.
        let tmp = self.temp_path()?;
        if let Err(e) = write_new_file(&tmp, &header_bytes, &ciphertext) {
            let _ = fs::remove_file(&tmp);
            return Err(e);
        }
        if let Err(e) = fs::rename(&tmp, &self.path) {
            let _ = fs::remove_file(&tmp);
            return Err(e.into());
        }
        // Make the rename itself durable so a crash can't lose the whole vault.
        sync_parent_dir(&self.path);
        Ok(())
    }

    /// A unique, hidden temp path beside the vault file, e.g.
    /// `.vault.pmv.<random>.tmp`. Randomized to avoid prediction/collision.
    fn temp_path(&self) -> Result<PathBuf, VaultError> {
        let suffix = crypto::random_bytes::<8>()?
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        let name = self
            .path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("vault");
        let file = format!(".{name}.{suffix}.tmp");
        Ok(match self.path.parent() {
            Some(p) if !p.as_os_str().is_empty() => p.join(file),
            _ => PathBuf::from(file),
        })
    }

    /// Re-key the vault under two new passwords (new salt) and persist. This is
    /// transactional: the in-memory key/salt/audit are only kept if the save
    /// succeeds, so a failed write never desyncs in-memory crypto state from the
    /// on-disk file.
    pub fn change_password(&mut self, pw1: &[u8], pw2: &[u8]) -> Result<(), VaultError> {
        let salt = crypto::random_bytes::<SALT_LEN>()?;
        let key = crypto::derive_key_chained(pw1, pw2, &salt, &self.params)?;

        let old_key = std::mem::replace(&mut self.key, key);
        let old_salt = std::mem::replace(&mut self.salt, salt);
        self.vault.audit.push(Change::new("password_changed", String::new()));

        match self.save() {
            Ok(()) => Ok(()),
            Err(e) => {
                // Roll back to the previous key/salt/audit on failure.
                self.key = old_key;
                self.salt = old_salt;
                self.vault.audit.pop();
                Err(e)
            }
        }
    }

    /// The previous access time (unix seconds), or 0 if this is a new vault.
    pub fn previous_access(&self) -> i64 {
        self.previous_access
    }
}

/// Read, parse, and decrypt the vault file at `path`, returning the decoded
/// [`Vault`] together with its [`Header`] and the derived [`Key`]. Performs no
/// writes. Shared by [`OpenVault::open`] and [`OpenVault::export`].
fn decrypt_file(path: &Path, pw1: &[u8], pw2: &[u8]) -> Result<(Vault, Header, Key), VaultError> {
    let raw = match fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(VaultError::NotFound(path.to_path_buf()));
        }
        Err(e) => return Err(e.into()),
    };
    let header = Header::parse(&raw)?;
    let ciphertext = &raw[HEADER_LEN..];
    let key = crypto::derive_key_chained(pw1, pw2, &header.salt, &header.params)?;
    let aad = header.to_bytes();
    let plaintext = Zeroizing::new(crypto::decrypt(&key, &header.nonce, ciphertext, &aad[..AAD_LEN])?);
    let vault: Vault = serde_json::from_slice(&plaintext)?;
    Ok((vault, header, key))
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn random_id() -> Result<String, CryptoError> {
    let bytes = crypto::random_bytes::<16>()?;
    let mut s = String::with_capacity(32);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    Ok(s)
}

// --- Cross-platform file hardening (req: compile on Windows + Linux) ---------
//
// On Unix we set explicit owner-only permission bits. Windows has no portable
// std equivalent of mode bits; the vault directory under %APPDATA% inherits the
// per-user profile ACL, so we rely on that. See `docs/DESIGN.md` §9.9.

#[cfg(unix)]
fn harden_file(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = fs::metadata(path)?.permissions();
    perms.set_mode(0o600);
    fs::set_permissions(path, perms)
}

#[cfg(not(unix))]
fn harden_file(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn harden_dir(dir: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = fs::metadata(dir) {
        let mut perms = meta.permissions();
        perms.set_mode(0o700);
        let _ = fs::set_permissions(dir, perms);
    }
}

#[cfg(not(unix))]
fn harden_dir(_dir: &Path) {}

/// Create a brand-new file at `path`, write `header` + `ciphertext`, and fsync.
/// Uses `create_new` (O_EXCL) so an existing path — including a pre-planted
/// symlink — makes this fail instead of being followed/clobbered. On Unix the
/// 0600 mode is applied atomically at creation, so the file is never readable
/// by other users even momentarily.
fn write_new_file(path: &Path, header: &[u8], ciphertext: &[u8]) -> Result<(), VaultError> {
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    harden_file(path)?; // belt-and-suspenders (no-op on non-unix)
    f.write_all(header)?;
    f.write_all(ciphertext)?;
    f.sync_all()?;
    Ok(())
}

/// fsync the directory containing `path` so a rename into it is durable across a
/// crash/power loss. No-op on platforms without directory fsync.
#[cfg(unix)]
fn sync_parent_dir(path: &Path) {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    if let Ok(dir) = fs::File::open(parent) {
        let _ = dir.sync_all();
    }
}

#[cfg(not(unix))]
fn sync_parent_dir(_path: &Path) {}

#[cfg(test)]
mod tests {
    use super::*;

    fn fast() -> KdfParams {
        KdfParams { m_cost: 256, t_cost: 1, p_cost: 1 }
    }

    fn tmp_path(tag: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        p.push(format!("passmgr-test-{tag}-{nanos}.pmv"));
        p
    }

    #[test]
    fn create_open_round_trip() {
        let path = tmp_path("roundtrip");
        let mut v = OpenVault::create(path.clone(), b"first", b"second", fast()).unwrap();
        let mut e = Entry::new("GitHub".into()).unwrap();
        e.username = "octocat".into();
        e.password = "hunter2".into();
        e.kind = "Login".into();
        v.vault.upsert(e);
        v.save().unwrap();

        let reopened = OpenVault::open(path.clone(), b"first", b"second").unwrap();
        assert_eq!(reopened.vault.entries.len(), 1);
        assert_eq!(reopened.vault.entries[0].title, "GitHub");
        assert_eq!(reopened.vault.entries[0].password, "hunter2");
        assert_eq!(reopened.vault.version, FORMAT_VERSION);

        fs::remove_file(&path).ok();
    }

    #[test]
    fn both_passwords_required() {
        let path = tmp_path("twopw");
        OpenVault::create(path.clone(), b"right1", b"right2", fast()).unwrap();
        // Either password wrong -> decrypt fails.
        assert!(OpenVault::open(path.clone(), b"wrong1", b"right2").is_err());
        assert!(OpenVault::open(path.clone(), b"right1", b"wrong2").is_err());
        // Both right -> succeeds.
        assert!(OpenVault::open(path.clone(), b"right1", b"right2").is_ok());
        fs::remove_file(&path).ok();
    }

    #[test]
    fn password_order_matters() {
        let path = tmp_path("order");
        OpenVault::create(path.clone(), b"alpha", b"beta", fast()).unwrap();
        // Swapping the two passwords must not unlock.
        assert!(OpenVault::open(path.clone(), b"beta", b"alpha").is_err());
        fs::remove_file(&path).ok();
    }

    #[test]
    fn create_refuses_existing() {
        let path = tmp_path("exists");
        OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();
        let err = OpenVault::create(path.clone(), b"a", b"b", fast())
            .err()
            .expect("creating over an existing vault should fail");
        assert!(matches!(err, VaultError::AlreadyExists(_)));
        fs::remove_file(&path).ok();
    }

    #[test]
    fn change_password_works() {
        let path = tmp_path("changepw");
        let mut v = OpenVault::create(path.clone(), b"old1", b"old2", fast()).unwrap();
        v.vault.upsert(Entry::new("Item".into()).unwrap());
        v.change_password(b"new1", b"new2").unwrap();

        assert!(OpenVault::open(path.clone(), b"old1", b"old2").is_err());
        let reopened = OpenVault::open(path.clone(), b"new1", b"new2").unwrap();
        assert_eq!(reopened.vault.entries.len(), 1);
        fs::remove_file(&path).ok();
    }

    #[test]
    fn truncated_file_detected() {
        let path = tmp_path("trunc");
        OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();
        fs::write(&path, b"PMVAULT\0").unwrap(); // header-only, no body
        assert!(OpenVault::open(path.clone(), b"a", b"b").is_err());
        fs::remove_file(&path).ok();
    }

    #[test]
    fn last_access_is_tracked() {
        let path = tmp_path("access");
        let created = OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();
        assert_eq!(created.previous_access(), 0, "new vault has no prior access");
        let first_access = created.vault.last_opened_at;

        let reopened = OpenVault::open(path.clone(), b"a", b"b").unwrap();
        // The reopen reports the access time written by create() as the previous one.
        assert_eq!(reopened.previous_access(), first_access);
        fs::remove_file(&path).ok();
    }

    #[test]
    fn export_reads_without_mutating() {
        let path = tmp_path("export");
        let mut v = OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();
        v.vault.upsert(Entry::new("Thing".into()).unwrap());
        v.save().unwrap();
        let before = fs::read(&path).unwrap();

        let exported = OpenVault::export(&path, b"a", b"b").unwrap();
        assert_eq!(exported.entries.len(), 1);
        assert_eq!(exported.entries[0].title, "Thing");

        // export() must not rewrite the file.
        let after = fs::read(&path).unwrap();
        assert_eq!(before, after, "export must not modify the vault file");

        // Wrong passwords still rejected.
        assert!(OpenVault::export(&path, b"a", b"WRONG").is_err());
        fs::remove_file(&path).ok();
    }

    #[test]
    fn upsert_records_history() {
        let mut vault = Vault::default();
        let mut e = Entry::new("Mail".into()).unwrap();
        e.username = "alice".into();
        let id = e.id.clone();
        vault.upsert(e);
        assert_eq!(vault.entries[0].history.len(), 1); // "created"
        assert_eq!(vault.entries[0].history[0].action, "created");

        // Edit username + password.
        let mut edited = vault.entries[0].clone();
        edited.username = "bob".into();
        edited.password = "s3cret".into();
        vault.upsert(edited);

        let hist = &vault.entries[0].history;
        assert!(hist.iter().any(|c| c.action == "updated" && c.detail.contains("username")));
        // History records the full before/after password values (req. 4/5).
        let pw = hist.iter().find(|c| c.action == "password_changed").unwrap();
        assert!(pw.detail.contains("s3cret"), "history should record the new password");
        assert!(pw.detail.starts_with("password:"));

        // id is stable across edits.
        assert_eq!(vault.entries[0].id, id);
    }

    #[test]
    fn types_register_and_filter() {
        let mut vault = Vault::default();
        let mut login = Entry::new("Bank".into()).unwrap();
        login.kind = "Login".into();
        let mut server = Entry::new("Prod".into()).unwrap();
        server.kind = "Server".into();
        vault.upsert(login);
        vault.upsert(server);

        assert_eq!(vault.types, vec!["Login".to_string(), "Server".to_string()]);
        assert_eq!(vault.filter("", Some("Server")).len(), 1);
        assert_eq!(vault.filter("", Some("server")).len(), 1); // case-insensitive
        assert_eq!(vault.filter("", None).len(), 2);
    }

    #[test]
    fn deletion_logged_in_audit() {
        let mut vault = Vault::default();
        let e = Entry::new("Temp".into()).unwrap();
        let id = e.id.clone();
        vault.upsert(e);
        assert!(vault.remove(&id));
        assert!(vault.audit.iter().any(|c| c.action == "deleted" && c.detail == "Temp"));
        assert!(!vault.remove(&id)); // already gone
    }

    #[test]
    fn rejects_absurd_kdf_params() {
        let path = tmp_path("badparams");
        OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();
        // Corrupt the m_cost field (header bytes 9..13) to u32::MAX.
        let mut raw = fs::read(&path).unwrap();
        raw[9..13].copy_from_slice(&u32::MAX.to_le_bytes());
        fs::write(&path, &raw).unwrap();
        // Must be rejected at header-parse time, before the memory-hard KDF runs.
        let err = OpenVault::open(path.clone(), b"a", b"b")
            .err()
            .expect("absurd KDF params must be rejected");
        assert!(matches!(err, VaultError::BadParams));
        fs::remove_file(&path).ok();
    }

    #[test]
    fn kind_is_trimmed_on_upsert() {
        let mut vault = Vault::default();
        let mut e = Entry::new("Bank".into()).unwrap();
        e.kind = "  Login  ".into();
        vault.upsert(e);
        // Stored kind and registered type match, and the entry is filterable.
        assert_eq!(vault.entries[0].kind, "Login");
        assert_eq!(vault.types, vec!["Login".to_string()]);
        assert_eq!(vault.filter("", Some("Login")).len(), 1);
    }

    #[test]
    fn search_filters_and_sorts() {
        let mut vault = Vault::default();
        let mut a = Entry::new("Zebra".into()).unwrap();
        a.username = "z@x.com".into();
        let b = Entry::new("Apple".into()).unwrap();
        let c = Entry::new("Banana".into()).unwrap();
        vault.upsert(a);
        vault.upsert(b);
        vault.upsert(c);
        let titles: Vec<&str> = vault.filter("", None).iter().map(|e| e.title.as_str()).collect();
        assert_eq!(titles, vec!["Apple", "Banana", "Zebra"]);
        assert_eq!(vault.filter("zeb", None).len(), 1);
    }
}
