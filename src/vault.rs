//! The encrypted vault file and the orchestration over the partitioned document
//! store ([`crate::storage`]).
//!
//! The user supplies a **directory** `mypath`; inside it:
//! ```text
//!   mypath/vault.pmv          encrypted JSON vault (header + AEAD ciphertext)
//!   mypath/manifest/manifest.<N>   encrypted per-partition document index
//!   mypath/volume/vol.<N>          append-only, per-blob-encrypted documents
//! ```
//! `OpenVault` is given the vault *file* path (`mypath/vault.pmv`) and derives the
//! directory as its parent; the [`VolumeStore`] lives under that directory.
//!
//! Vault file layout (all integers little-endian):
//! ```text
//!   0   8   magic  b"PMVAULT\0"
//!   8   1   format version (currently 4)
//!   9   4   Argon2 m_cost (KiB)
//!   13  4   Argon2 t_cost
//!   17  4   Argon2 p_cost
//!   21  16  salt1
//!   37  24  nonce (XChaCha20-Poly1305)
//!   61  ..  ciphertext of the JSON vault
//! ```
//! The **entire 61-byte header** (incl. the nonce) is the AEAD associated data, so
//! tampering with the version/params/salt/nonce fails the Poly1305 tag on decrypt.
//!
//! Crash-safety: the document store commits per-operation (see [`crate::storage`]);
//! the vault file is the **final** commit point. A password change re-encrypts the
//! whole tree under a fresh key via a staged-and-rolled-forward protocol so a crash
//! mid-rotation always leaves either the old or the new tree fully working.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use thiserror::Error;
use zeroize::Zeroizing;

use crate::crypto::{self, CryptoError, KdfParams, Key, NONCE_LEN, SALT_LEN};
use crate::records::{self, Change, Vault};
use crate::storage::{self, MAX_DOC_SIZE, ManifestEntry, StorageError, VolumeStore};
use crate::types::TypeLists;

/// A decrypted document returned to the CLI: its manifest metadata plus its
/// plaintext bytes (which wipe on drop).
pub type DecryptedDoc = (ManifestEntry, Zeroizing<Vec<u8>>);

const MAGIC: &[u8; 8] = b"PMVAULT\0";
const FORMAT_VERSION: u8 = 4;
const HEADER_LEN: usize = 61;
/// Fixed vault-file name inside the user's directory.
const VAULT_FILE: &str = "vault.pmv";
/// Staging directory used during a password-change re-encryption.
const REKEY_DIR: &str = ".rekey";
const REKEY_READY: &str = "READY";
/// Single-writer advisory lock file inside the vault directory.
const LOCK_FILE: &str = "pass-mgr.lock";

// Sanity bounds for KDF parameters read from an untrusted file header, validated
// *before* the (expensive, memory-hard) key derivation runs (DoS guard).
const MAX_M_COST: u32 = 1 << 20; // 1 GiB, in KiB
const MAX_T_COST: u32 = 64;
const MAX_P_COST: u32 = 16;

#[derive(Error, Debug)]
pub enum VaultError {
    #[error("vault not found at {0}")]
    NotFound(PathBuf),
    #[error("a vault already exists at {0}")]
    AlreadyExists(PathBuf),
    #[error("not a pass-mgr vault (bad magic bytes)")]
    BadMagic,
    #[error("unsupported vault format version {0} (this build expects v{FORMAT_VERSION}; recreate the vault)")]
    BadVersion(u8),
    #[error("vault file is truncated or corrupt")]
    Truncated,
    #[error("vault KDF parameters are out of the allowed range")]
    BadParams,
    #[error("document or archive exceeds the maximum allowed size")]
    TooLarge,
    #[error("a document referenced by the vault is missing from the document store (possible tampering or rollback)")]
    ArchiveMismatch,
    #[error("an interrupted password change is pending; reopen with --write to finish recovery")]
    RekeyPending,
    #[error("vault is open read-only (relaunch with --write to make changes)")]
    ReadOnly,
    #[error("another writable session already has this vault open (close it, or open read-only)")]
    Locked,
    #[error("no such partition: {0}")]
    NoSuchPartition(u32),
    #[error(transparent)]
    Storage(#[from] StorageError),
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error("vault contents are not valid JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
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

/// An unlocked vault: the decrypted data, the derived key + KDF salt/params, and
/// the partitioned document store. The key zeroizes on drop; `vault` zeroizes via
/// its own `ZeroizeOnDrop`.
pub struct OpenVault {
    pub vault: Vault,
    key: Key,
    params: KdfParams,
    salt: [u8; SALT_LEN],
    /// The vault *file* (`<dir>/vault.pmv`).
    path: PathBuf,
    previous_access: i64,
    previous_generation: u64,
    read_only: bool,
    storage: VolumeStore,
    /// Held for a writable session: the OS advisory lock on `pass-mgr.lock`.
    /// `None` for read-only opens. Released automatically when this `OpenVault`
    /// drops (including on process crash), so the lock never goes stale.
    _write_lock: Option<WriteLock>,
}

/// An OS advisory lock on `<dir>/pass-mgr.lock`, held for the lifetime of a
/// writable [`OpenVault`]. The lock is taken on the open file handle, so the
/// kernel releases it when the handle closes — no stale lock file to clean up.
struct WriteLock {
    _file: fs::File,
}

impl WriteLock {
    /// Acquire the single-writer lock for `dir`. Errors with
    /// [`VaultError::Locked`] if another writable session already holds it.
    fn acquire(dir: &Path) -> Result<Self, VaultError> {
        let path = dir.join(LOCK_FILE);
        // The lock file carries no contents; never truncate it (avoids racing a
        // concurrent holder's handle), just ensure it exists and is lockable.
        let file = OpenOptions::new().read(true).write(true).create(true).truncate(false).open(&path)?;
        match file.try_lock() {
            Ok(()) => Ok(WriteLock { _file: file }),
            Err(fs::TryLockError::WouldBlock) => Err(VaultError::Locked),
            Err(fs::TryLockError::Error(e)) => Err(VaultError::Io(e)),
        }
    }
}

impl OpenVault {
    /// Create a brand-new vault in the directory containing `path`
    /// (`<dir>/vault.pmv`), protected by two passwords.
    pub fn create(path: PathBuf, pw1: &[u8], pw2: &[u8], params: KdfParams) -> Result<Self, VaultError> {
        if path.exists() {
            return Err(VaultError::AlreadyExists(path));
        }
        let dir = parent_dir(&path);
        fs::create_dir_all(&dir)?;
        harden_dir(&dir);
        // Take the single-writer lock before writing anything into the directory.
        let write_lock = Some(WriteLock::acquire(&dir)?);
        let salt = crypto::random_bytes::<SALT_LEN>()?;
        let key = crypto::derive_key_chained(pw1, pw2, &salt, &params)?;

        let mut vault = Vault::default();
        vault.version = FORMAT_VERSION;
        vault.last_opened_at = records::unix_now();
        vault.id = records::random_id()?; // binds the volumes/manifests to this vault
        vault.categories = TypeLists::with_defaults();
        vault.audit.push(Change::new("vault_created", String::new()));

        let storage = VolumeStore::open(&dir, &key, &vault.id, vault.settings.volume_max_size)?;

        let mut open = OpenVault {
            vault,
            key,
            params,
            salt,
            path,
            previous_access: 0,
            previous_generation: 0,
            read_only: false,
            storage,
            _write_lock: write_lock,
        };
        open.save()?;
        Ok(open)
    }

    /// Unlock an existing vault read-write.
    pub fn open(path: PathBuf, pw1: &[u8], pw2: &[u8]) -> Result<Self, VaultError> {
        Self::open_inner(path, pw1, pw2, false)
    }

    /// Unlock an existing vault **read-only**: every mutating operation is refused
    /// and nothing is written to disk on open.
    pub fn open_read_only(path: PathBuf, pw1: &[u8], pw2: &[u8]) -> Result<Self, VaultError> {
        Self::open_inner(path, pw1, pw2, true)
    }

    /// Unlock, choosing read-only explicitly.
    pub fn open_with(path: PathBuf, pw1: &[u8], pw2: &[u8], read_only: bool) -> Result<Self, VaultError> {
        Self::open_inner(path, pw1, pw2, read_only)
    }

    fn open_inner(path: PathBuf, pw1: &[u8], pw2: &[u8], read_only: bool) -> Result<Self, VaultError> {
        let dir = parent_dir(&path);
        // Single-writer: a writable open takes the advisory lock first, so a
        // second writable instance fails fast and recovery/writes below are
        // exclusive. Read-only opens never take it.
        let write_lock = if read_only { None } else { Some(WriteLock::acquire(&dir)?) };
        // Finish/abort an interrupted password change before touching the vault.
        recover_pending_rekey(&dir, read_only)?;

        let (mut vault, header, key) = decrypt_file(&path, pw1, pw2)?;
        let previous_access = vault.last_opened_at;
        let previous_generation = vault.generation;
        vault.last_opened_at = records::unix_now();

        let storage = VolumeStore::open(&dir, &key, &vault.id, vault.settings.volume_max_size)?;
        // Consistency: every document a record references must be present.
        for id in referenced_doc_ids(&vault) {
            if !storage.contains(&id) {
                return Err(VaultError::ArchiveMismatch);
            }
        }

        let mut open = OpenVault {
            vault,
            key,
            params: header.params,
            salt: header.salt,
            path,
            previous_access,
            previous_generation,
            read_only,
            storage,
            _write_lock: write_lock,
        };
        // Best-effort refresh of last-opened; skipped entirely in read-only mode.
        if !read_only {
            let _ = open.save();
        }
        Ok(open)
    }

    /// Decrypt the vault and return its contents **without** modifying any file.
    pub fn export(path: &Path, pw1: &[u8], pw2: &[u8]) -> Result<Vault, VaultError> {
        let (vault, _header, _key) = decrypt_file(path, pw1, pw2)?;
        Ok(vault)
    }

    /// Decrypt documents without modifying any file. With `part = Some(n)` only
    /// partition `n`'s volume is decrypted; with `None`, every partition.
    /// Returns each document's manifest entry + plaintext (wiped on drop).
    pub fn export_documents(
        path: &Path,
        pw1: &[u8],
        pw2: &[u8],
        part: Option<u32>,
    ) -> Result<Vec<DecryptedDoc>, VaultError> {
        let (vault, _header, key) = decrypt_file(path, pw1, pw2)?;
        let dir = parent_dir(path);
        let store = VolumeStore::open(&dir, &key, &vault.id, vault.settings.volume_max_size)?;
        // Collect entries first so the immutable borrow for reads is clean.
        let entries: Vec<ManifestEntry> = selected_entries(&store, part)?;
        let mut out = Vec::new();
        for e in entries {
            let bytes = store.read(&e.id, &key)?;
            out.push((e, bytes));
        }
        Ok(out)
    }

    /// Decrypt and return manifest entries (the document index). With
    /// `part = Some(n)` only partition `n`'s manifest; with `None`, all of them.
    pub fn export_manifests(
        path: &Path,
        pw1: &[u8],
        pw2: &[u8],
        part: Option<u32>,
    ) -> Result<Vec<ManifestEntry>, VaultError> {
        let (vault, _header, key) = decrypt_file(path, pw1, pw2)?;
        let dir = parent_dir(path);
        let store = VolumeStore::open(&dir, &key, &vault.id, vault.settings.volume_max_size)?;
        selected_entries(&store, part)
    }

    /// Re-encrypt the vault and write it atomically, bumping the write-generation.
    pub fn save(&mut self) -> Result<(), VaultError> {
        if self.read_only {
            return Err(VaultError::ReadOnly);
        }
        self.vault.generation = self.vault.generation.saturating_add(1);
        write_vault_file(&self.path, &self.vault, &self.key, &self.salt, self.params)
    }

    /// Re-key under two new passwords via a **full re-encryption** of the vault and
    /// the entire document store, staged then rolled forward so a crash leaves
    /// either the old or the new tree fully working (never a mix).
    pub fn change_password(&mut self, pw1: &[u8], pw2: &[u8]) -> Result<(), VaultError> {
        if self.read_only {
            return Err(VaultError::ReadOnly);
        }
        let dir = parent_dir(&self.path);
        let staging = dir.join(REKEY_DIR);
        let _ = fs::remove_dir_all(&staging); // clear any stale staging
        fs::create_dir_all(&staging)?;
        harden_dir(&staging);

        let new_salt = crypto::random_bytes::<SALT_LEN>()?;
        let new_key = crypto::derive_key_chained(pw1, pw2, &new_salt, &self.params)?;

        // Re-encrypt every document into a fresh store under the new key.
        let new_store = VolumeStore::open(&staging, &new_key, &self.vault.id, self.vault.settings.volume_max_size)?;
        let mut new_store = new_store;
        let ids: Vec<String> = self.storage.ids().map(|s| s.to_string()).collect();
        for id in &ids {
            let bytes = self.storage.read(id, &self.key)?;
            let (path, uploaded_at) = self
                .storage
                .entry(id)
                .map(|e| (e.path.clone(), e.uploaded_at))
                .unwrap_or_default();
            new_store.put(id, &path, &bytes, uploaded_at, &new_key)?;
        }
        drop(new_store);

        // Stage the re-encrypted vault, mark the staging complete, then commit.
        let mut staged_vault = self.vault.clone();
        staged_vault.audit.push(Change::new("password_changed", String::new()));
        write_vault_file(&staging.join(VAULT_FILE), &staged_vault, &new_key, &new_salt, self.params)?;
        write_new_bytes(&staging.join(REKEY_READY), b"ready")?;
        sync_parent_dir(&staging.join(REKEY_READY));
        commit_rekey(&dir, &staging)?;

        // Adopt the new key/salt/state and reopen the store under the new key.
        self.key = new_key;
        self.salt = new_salt;
        self.vault = staged_vault;
        self.previous_generation = self.vault.generation;
        self.storage = VolumeStore::open(&dir, &self.key, &self.vault.id, self.vault.settings.volume_max_size)?;
        Ok(())
    }

    pub fn previous_access(&self) -> i64 {
        self.previous_access
    }

    pub fn opened_generation(&self) -> u64 {
        self.previous_generation
    }

    /// The per-partition volume-size cap, in bytes.
    pub fn volume_max_size(&self) -> u64 {
        self.vault.settings.volume_max_size
    }

    /// Set the per-partition volume-size cap (bytes, clamped to >= 1). Updates the
    /// saved settings and the live store so the change governs **future**
    /// placement this session, then persists. Existing partitions are untouched.
    pub fn set_volume_max_size(&mut self, bytes: u64) -> Result<(), VaultError> {
        if self.read_only {
            return Err(VaultError::ReadOnly);
        }
        let bytes = bytes.max(1);
        self.vault.settings.volume_max_size = bytes;
        self.storage.set_max_size(bytes);
        self.vault.audit.push(Change::new("volume_size_changed", bytes.to_string()));
        self.save()
    }

    // --- Documents (delegated to the partitioned store) ----------------------

    /// Add the file at `source` under virtual directory `location` with name
    /// `filename`. Commits the blob + its manifest; the caller links the new id
    /// onto a record and saves the vault (the final commit). Returns the id.
    pub fn add_document(&mut self, location: &str, filename: &str, source: &Path) -> Result<String, VaultError> {
        if self.read_only {
            return Err(VaultError::ReadOnly);
        }
        let src_len = fs::metadata(source)?.len();
        if src_len > MAX_DOC_SIZE {
            return Err(VaultError::TooLarge);
        }
        let vpath = virtual_path(location, filename);
        if vpath.len() > storage::MAX_PATH_LEN {
            return Err(VaultError::Storage(StorageError::PathTooLong));
        }
        let data = Zeroizing::new(fs::read(source)?);
        let id = records::random_id()?;
        self.storage.put(&id, &vpath, &data, records::unix_now(), &self.key)?;
        Ok(id)
    }

    /// Permanently remove a stored document by id (drops its manifest entry; the
    /// blob lingers as garbage until a future compaction).
    pub fn remove_document(&mut self, file_id: &str) -> Result<(), VaultError> {
        if self.read_only {
            return Err(VaultError::ReadOnly);
        }
        self.storage.remove(file_id, &self.key)?;
        Ok(())
    }

    /// Decrypt and return one stored document.
    pub fn read_document(&self, file_id: &str) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        Ok(self.storage.read(file_id, &self.key)?)
    }

    /// Write a stored document out to `dest` as an **unencrypted** copy (O_EXCL +
    /// 0600; fails if `dest` exists).
    pub fn export_document(&self, file_id: &str, dest: &Path) -> Result<(), VaultError> {
        let data = self.read_document(file_id)?;
        write_new_bytes(dest, &data)
    }

    /// The virtual path ("/loc/filename") of a stored document, for UI display.
    pub fn doc_path(&self, file_id: &str) -> Option<String> {
        self.storage.entry(file_id).map(|e| e.path.clone())
    }

    /// Whether a document id is present in the store.
    pub fn has_document(&self, file_id: &str) -> bool {
        self.storage.contains(file_id)
    }

    // --- Category lists (stored in the vault) --------------------------------

    pub fn categories(&self) -> &TypeLists {
        &self.vault.categories
    }

    pub fn add_asset_type(&mut self, name: &str) -> Result<bool, VaultError> {
        self.mutate_categories(|c| c.add_asset_type(name))
    }

    pub fn add_account_type(&mut self, name: &str) -> Result<bool, VaultError> {
        self.mutate_categories(|c| c.add_account_type(name))
    }

    pub fn add_account_subtype(&mut self, type_name: &str, subtype: &str) -> Result<bool, VaultError> {
        self.mutate_categories(|c| c.add_account_subtype(type_name, subtype))
    }

    fn mutate_categories(&mut self, edit: impl FnOnce(&mut TypeLists) -> bool) -> Result<bool, VaultError> {
        if self.read_only {
            return Err(VaultError::ReadOnly);
        }
        if edit(&mut self.vault.categories) {
            self.save()?;
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

/// The directory containing the vault file (its parent, or "." if none).
fn parent_dir(vault_file: &Path) -> PathBuf {
    match vault_file.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    }
}

/// Normalize `location` and join `filename` into a virtual path "/a/b/file".
/// Exposed to the UIs so they can validate path length against
/// [`storage::MAX_PATH_LEN`] with the exact string the core will store.
pub(crate) fn virtual_path(location: &str, filename: &str) -> String {
    let loc = normalize_dir(location);
    if loc.is_empty() { format!("/{filename}") } else { format!("{loc}/{filename}") }
}

/// Manifest entries selected by an optional partition filter. `Some(n)` returns
/// only partition `n`'s entries (erroring if `n` is out of range); `None`
/// returns every partition's entries.
fn selected_entries(store: &VolumeStore, part: Option<u32>) -> Result<Vec<ManifestEntry>, VaultError> {
    match part {
        Some(p) => {
            if p as usize >= store.partition_count() {
                return Err(VaultError::NoSuchPartition(p));
            }
            Ok(store.partition_entries(p).cloned().collect())
        }
        None => Ok(store.entries().cloned().collect()),
    }
}

/// Doc ids referenced by any record (Trust&Will `file`, Asset `statement`).
fn referenced_doc_ids(vault: &Vault) -> Vec<String> {
    let mut ids = Vec::new();
    for t in &vault.trust_wills {
        if let Some(f) = &t.file {
            ids.push(f.clone());
        }
    }
    for a in &vault.assets {
        if let Some(f) = &a.statement {
            ids.push(f.clone());
        }
    }
    ids
}

/// Read, parse, and decrypt the vault file at `path`. Performs no writes.
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
    // The full header (incl. nonce) is the AEAD associated data.
    let aad = header.to_bytes();
    let plaintext = Zeroizing::new(crypto::decrypt(&key, &header.nonce, ciphertext, &aad)?);
    let vault: Vault = serde_json::from_slice(&plaintext)?;
    Ok((vault, header, key))
}

/// Encrypt `vault` under `key` and write it atomically to `path` (new nonce, full
/// header as AAD, temp → fsync → rename → dir fsync).
fn write_vault_file(
    path: &Path,
    vault: &Vault,
    key: &Key,
    salt: &[u8; SALT_LEN],
    params: KdfParams,
) -> Result<(), VaultError> {
    let plaintext = Zeroizing::new(serde_json::to_vec(vault)?);
    let nonce = crypto::random_bytes::<NONCE_LEN>()?;
    let header = Header { params, salt: *salt, nonce };
    let header_bytes = header.to_bytes();
    let ciphertext = crypto::encrypt_with_nonce(key, &nonce, &plaintext, &header_bytes)?;

    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)?;
        harden_dir(parent);
    }
    let tmp = sibling_tmp(path)?;
    if let Err(e) = write_new_file(&tmp, &header_bytes, &ciphertext) {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    if let Err(e) = fs::rename(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(e.into());
    }
    sync_parent_dir(path);
    Ok(())
}

// --- Password-change (rekey) staging recovery --------------------------------

/// Recover an interrupted password change found at `<dir>/.rekey`:
/// a `READY` marker means the new tree is complete → **roll forward** (commit);
/// no marker means staging was incomplete → **discard** it (the old tree stands).
/// In read-only mode we cannot write, so a pending rekey is reported.
fn recover_pending_rekey(dir: &Path, read_only: bool) -> Result<(), VaultError> {
    let staging = dir.join(REKEY_DIR);
    if !staging.exists() {
        return Ok(());
    }
    if read_only {
        return Err(VaultError::RekeyPending);
    }
    if staging.join(REKEY_READY).exists() {
        commit_rekey(dir, &staging)?;
    } else {
        let _ = fs::remove_dir_all(&staging);
    }
    Ok(())
}

/// Commit a staged rekey by moving the new tree into place: volumes and manifests
/// first, then the vault file **last** (the commit point). Idempotent: re-running
/// after a partial move finishes the remaining items.
fn commit_rekey(dir: &Path, staging: &Path) -> Result<(), VaultError> {
    replace_dir(&dir.join("volume"), &staging.join("volume"))?;
    replace_dir(&dir.join("manifest"), &staging.join("manifest"))?;
    replace_path(&dir.join(VAULT_FILE), &staging.join(VAULT_FILE))?;
    sync_parent_dir(&dir.join(VAULT_FILE));
    let _ = fs::remove_dir_all(staging);
    Ok(())
}

/// Replace `live` with `staged` (a directory) if `staged` still exists.
fn replace_dir(live: &Path, staged: &Path) -> Result<(), VaultError> {
    if !staged.exists() {
        return Ok(());
    }
    let old = sibling_old(live);
    let _ = fs::remove_dir_all(&old);
    if live.exists() {
        fs::rename(live, &old)?;
    }
    fs::rename(staged, live)?;
    let _ = fs::remove_dir_all(&old);
    Ok(())
}

/// Replace `live` with `staged` (a file) if `staged` still exists.
fn replace_path(live: &Path, staged: &Path) -> Result<(), VaultError> {
    if !staged.exists() {
        return Ok(());
    }
    fs::rename(staged, live)?;
    Ok(())
}

fn sibling_old(path: &Path) -> PathBuf {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("x");
    match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.join(format!(".{name}.old")),
        _ => PathBuf::from(format!(".{name}.old")),
    }
}

/// Normalize a virtual directory path to `/a/b/c` form (empty string == root).
fn normalize_dir(path: &str) -> String {
    let parts: Vec<&str> = path.split('/').filter(|p| !p.is_empty()).collect();
    if parts.is_empty() { String::new() } else { format!("/{}", parts.join("/")) }
}

fn rand_suffix() -> Result<String, CryptoError> {
    Ok(crypto::random_bytes::<8>()?.iter().map(|b| format!("{b:02x}")).collect())
}

fn sibling_tmp(path: &Path) -> Result<PathBuf, VaultError> {
    let suffix = rand_suffix()?;
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("file");
    let file = format!(".{name}.{suffix}.tmp");
    Ok(match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.join(file),
        _ => PathBuf::from(file),
    })
}

/// Copy the whole vault directory (`vault.pmv` + `manifest/` + `volume/`) into a
/// fresh timestamped subdirectory of `dest_dir`, as a consistent set. Copies the
/// encrypted files as-is — nothing is decrypted. Returns the backup vault path.
pub fn backup(vault_path: &Path, dest_dir: &Path) -> Result<PathBuf, VaultError> {
    if !vault_path.exists() {
        return Err(VaultError::NotFound(vault_path.to_path_buf()));
    }
    let src_dir = parent_dir(vault_path);
    fs::create_dir_all(dest_dir)?;
    harden_dir(dest_dir);

    let stamp = compact_timestamp(records::unix_now());
    let mut target = dest_dir.join(format!("backup-{stamp}"));
    let mut n = 1;
    while target.exists() {
        target = dest_dir.join(format!("backup-{stamp}_{n}"));
        n += 1;
    }
    fs::create_dir_all(&target)?;
    harden_dir(&target);

    fs::copy(vault_path, target.join(VAULT_FILE))?;
    harden_file(&target.join(VAULT_FILE))?;
    for sub in ["manifest", "volume"] {
        let s = src_dir.join(sub);
        if s.exists() {
            copy_dir(&s, &target.join(sub))?;
        }
    }
    Ok(target.join(VAULT_FILE))
}

/// Recursively copy a directory tree (files hardened to 0600 on Unix).
fn copy_dir(src: &Path, dst: &Path) -> Result<(), VaultError> {
    fs::create_dir_all(dst)?;
    harden_dir(dst);
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let from = entry.path();
        let to = dst.join(entry.file_name());
        if from.is_dir() {
            copy_dir(&from, &to)?;
        } else {
            fs::copy(&from, &to)?;
            harden_file(&to)?;
        }
    }
    Ok(())
}

/// Format unix seconds as a filename-safe UTC stamp `YYYYMMDD-HHMMSS`.
fn compact_timestamp(ts: i64) -> String {
    let (year, mo, d, h, m, s) = records::civil_from_unix(ts);
    format!("{year:04}{mo:02}{d:02}-{h:02}{m:02}{s:02}")
}

// --- Cross-platform file hardening (compile on Windows + Linux) --------------
// `pub` so the CLI binary (a separate crate over this library) can reuse them.

#[cfg(unix)]
pub fn harden_file(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = fs::metadata(path)?.permissions();
    perms.set_mode(0o600);
    fs::set_permissions(path, perms)
}
#[cfg(not(unix))]
pub fn harden_file(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(unix)]
pub fn harden_dir(dir: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = fs::metadata(dir) {
        let mut perms = meta.permissions();
        perms.set_mode(0o700);
        let _ = fs::set_permissions(dir, perms);
    }
}
#[cfg(not(unix))]
pub fn harden_dir(_dir: &Path) {}

/// Open a brand-new file with `create_new` (O_EXCL; no symlink-follow) + 0600.
fn create_new_0600(path: &Path) -> std::io::Result<std::fs::File> {
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)
}

fn write_new_file(path: &Path, part1: &[u8], part2: &[u8]) -> Result<(), VaultError> {
    let mut f = create_new_0600(path)?;
    harden_file(path)?;
    f.write_all(part1)?;
    f.write_all(part2)?;
    f.sync_all()?;
    Ok(())
}

/// Create a brand-new file and write a single buffer (O_EXCL + 0600); removes the
/// partial file on a write error. Shared by `export_document` and the CLI.
pub fn write_new_bytes(path: &Path, data: &[u8]) -> Result<(), VaultError> {
    let mut f = create_new_0600(path)?;
    harden_file(path)?;
    if let Err(e) = f.write_all(data).and_then(|()| f.sync_all()) {
        drop(f);
        let _ = fs::remove_file(path);
        return Err(e.into());
    }
    Ok(())
}

#[cfg(unix)]
fn sync_parent_dir(path: &Path) {
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or_else(|| Path::new("."));
    if let Ok(dir) = fs::File::open(parent) {
        let _ = dir.sync_all();
    }
}
#[cfg(not(unix))]
fn sync_parent_dir(_path: &Path) {}

/// Fuzzing entry point (hidden). The vault-file header parser; see `fuzz/`.
#[doc(hidden)]
pub mod fuzz {
    pub fn header(buf: &[u8]) {
        let _ = super::Header::parse(buf);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::records::{self, Account};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn fast() -> KdfParams {
        KdfParams { m_cost: 256, t_cost: 1, p_cost: 1 }
    }
    fn nanos() -> u128 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
    }
    /// A fresh, unique vault directory; returns its `vault.pmv` path.
    fn tmp_path(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("pmvault-{tag}-{}", nanos()));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join(VAULT_FILE)
    }
    fn cleanup(path: &Path) {
        let _ = fs::remove_dir_all(parent_dir(path));
    }
    fn write_src(tag: &str, body: &[u8]) -> PathBuf {
        let p = std::env::temp_dir().join(format!("pmsrc-{tag}-{}.txt", nanos()));
        fs::write(&p, body).unwrap();
        p
    }
    fn sample_account(user: &str, pw: &str) -> Account {
        let mut a = Account::new().unwrap();
        a.account_type = "Checking".into();
        a.username = user.into();
        a.password = pw.into();
        a
    }

    #[test]
    fn create_open_round_trip() {
        let path = tmp_path("roundtrip");
        let mut v = OpenVault::create(path.clone(), b"first", b"second", fast()).unwrap();
        records::upsert(&mut v.vault.accounts, sample_account("octocat", "hunter2"));
        v.save().unwrap();
        drop(v); // release the single-writer lock before reopening

        let reopened = OpenVault::open(path.clone(), b"first", b"second").unwrap();
        assert_eq!(reopened.vault.accounts.len(), 1);
        assert_eq!(reopened.vault.accounts[0].password, "hunter2");
        assert_eq!(reopened.vault.version, FORMAT_VERSION);
        cleanup(&path);
    }

    #[test]
    fn both_passwords_required_and_order_matters() {
        let path = tmp_path("twopw");
        OpenVault::create(path.clone(), b"right1", b"right2", fast()).unwrap();
        assert!(OpenVault::open(path.clone(), b"wrong1", b"right2").is_err());
        assert!(OpenVault::open(path.clone(), b"right1", b"wrong2").is_err());
        assert!(OpenVault::open(path.clone(), b"right2", b"right1").is_err()); // order
        assert!(OpenVault::open(path.clone(), b"right1", b"right2").is_ok());
        cleanup(&path);
    }

    #[test]
    fn create_refuses_existing() {
        let path = tmp_path("exists");
        OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();
        let err = OpenVault::create(path.clone(), b"a", b"b", fast()).err().unwrap();
        assert!(matches!(err, VaultError::AlreadyExists(_)));
        cleanup(&path);
    }

    #[test]
    fn document_round_trip_and_consistency_check() {
        let path = tmp_path("vol");
        let mut v = OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();
        let src = write_src("doc", b"statement contents");
        let id1 = v.add_document("/statements/2026", "q1.txt", &src).unwrap();
        let id2 = v.add_document("/wills", "will.txt", &src).unwrap();
        assert_eq!(&*v.read_document(&id1).unwrap(), b"statement contents");
        assert_eq!(v.doc_path(&id1).unwrap(), "/statements/2026/q1.txt");

        // Link one doc to a record so the consistency check has something to verify.
        let mut tw = crate::records::TrustWill::new().unwrap();
        tw.file = Some(id1.clone());
        records::upsert(&mut v.vault.trust_wills, tw);
        v.save().unwrap();
        drop(v); // release the single-writer lock before reopening

        let v2 = OpenVault::open(path.clone(), b"a", b"b").unwrap();
        assert_eq!(&*v2.read_document(&id1).unwrap(), b"statement contents");
        assert_eq!(&*v2.read_document(&id2).unwrap(), b"statement contents");
        cleanup(&path);
        fs::remove_file(&src).ok();
    }

    #[test]
    fn missing_referenced_document_is_rejected_on_open() {
        let path = tmp_path("mismatch");
        let mut v = OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();
        let src = write_src("d", b"doc");
        let id = v.add_document("/d", "f.txt", &src).unwrap();
        let mut tw = crate::records::TrustWill::new().unwrap();
        tw.file = Some(id);
        records::upsert(&mut v.vault.trust_wills, tw);
        v.save().unwrap();
        drop(v);

        // Wipe the volume directory: the referenced doc is now missing.
        fs::remove_dir_all(parent_dir(&path).join("volume")).unwrap();
        fs::remove_dir_all(parent_dir(&path).join("manifest")).unwrap();
        let err = OpenVault::open(path.clone(), b"a", b"b").err().unwrap();
        assert!(matches!(err, VaultError::ArchiveMismatch));
        cleanup(&path);
        fs::remove_file(&src).ok();
    }

    #[test]
    fn change_password_full_reencrypt_keeps_docs() {
        let path = tmp_path("rekey");
        let mut v = OpenVault::create(path.clone(), b"old1", b"old2", fast()).unwrap();
        records::upsert(&mut v.vault.accounts, sample_account("u", "p"));
        let src = write_src("rk", b"will body");
        let id = v.add_document("/wills", "will.txt", &src).unwrap();
        v.change_password(b"new1", b"new2").unwrap();
        drop(v); // release the single-writer lock before reopening

        // Old passwords no longer work; new ones open and the doc still reads.
        assert!(OpenVault::open(path.clone(), b"old1", b"old2").is_err());
        let reopened = OpenVault::open(path.clone(), b"new1", b"new2").unwrap();
        assert_eq!(reopened.vault.accounts.len(), 1);
        assert_eq!(&*reopened.read_document(&id).unwrap(), b"will body");
        // Staging was cleaned up.
        assert!(!parent_dir(&path).join(REKEY_DIR).exists());
        cleanup(&path);
        fs::remove_file(&src).ok();
    }

    #[test]
    fn rekey_roll_forward_on_interrupted_commit() {
        // Simulate a crash AFTER staging was marked READY but BEFORE commit: the
        // .rekey dir (with READY) is present. Reopening must roll forward.
        let path = tmp_path("rollfwd");
        {
            let mut v = OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();
            records::upsert(&mut v.vault.accounts, sample_account("u", "p"));
            v.save().unwrap();
        }
        let dir = parent_dir(&path);
        // Manually stage a new-key tree (mirror change_password's staging).
        let staging = dir.join(REKEY_DIR);
        fs::create_dir_all(&staging).unwrap();
        let new_salt = crypto::random_bytes::<SALT_LEN>().unwrap();
        let new_key = crypto::derive_key_chained(b"c", b"d", &new_salt, &fast()).unwrap();
        let (vault, _h, _k) = decrypt_file(&path, b"a", b"b").unwrap();
        // Empty store under the staging dir (no docs in this vault).
        let _ = VolumeStore::open(&staging, &new_key, &vault.id, vault.settings.volume_max_size).unwrap();
        write_vault_file(&staging.join(VAULT_FILE), &vault, &new_key, &new_salt, fast()).unwrap();
        write_new_bytes(&staging.join(REKEY_READY), b"ready").unwrap();

        // Reopen: roll-forward completes, so the NEW passwords open it.
        let reopened = OpenVault::open(path.clone(), b"c", b"d").unwrap();
        assert_eq!(reopened.vault.accounts.len(), 1);
        assert!(!dir.join(REKEY_DIR).exists());
        cleanup(&path);
    }

    #[test]
    fn rekey_discard_on_incomplete_staging() {
        // .rekey present WITHOUT READY → staging is discarded, old passwords work.
        let path = tmp_path("discard");
        OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();
        let staging = parent_dir(&path).join(REKEY_DIR);
        fs::create_dir_all(staging.join("volume")).unwrap();
        fs::write(staging.join("vault.pmv"), b"partial").unwrap();

        let reopened = OpenVault::open(path.clone(), b"a", b"b").unwrap();
        assert_eq!(reopened.vault.version, FORMAT_VERSION);
        assert!(!staging.exists(), "incomplete staging discarded");
        cleanup(&path);
    }

    #[test]
    fn read_only_with_pending_rekey_is_reported() {
        let path = tmp_path("ropending");
        OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();
        fs::create_dir_all(parent_dir(&path).join(REKEY_DIR)).unwrap();
        let err = OpenVault::open_read_only(path.clone(), b"a", b"b").err().unwrap();
        assert!(matches!(err, VaultError::RekeyPending));
        cleanup(&path);
    }

    #[test]
    fn truncated_file_detected() {
        let path = tmp_path("trunc");
        OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();
        fs::write(&path, b"PMVAULT\0").unwrap();
        assert!(OpenVault::open(path.clone(), b"a", b"b").is_err());
        cleanup(&path);
    }

    #[test]
    fn rejects_absurd_kdf_params() {
        let path = tmp_path("badparams");
        OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();
        let mut raw = fs::read(&path).unwrap();
        raw[9..13].copy_from_slice(&u32::MAX.to_le_bytes());
        fs::write(&path, &raw).unwrap();
        let err = OpenVault::open(path.clone(), b"a", b"b").err().unwrap();
        assert!(matches!(err, VaultError::BadParams));
        cleanup(&path);
    }

    #[test]
    fn header_tampering_is_detected() {
        let path = tmp_path("hdrtamper");
        OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();
        let good = fs::read(&path).unwrap();
        let flipped_fails = |offset: usize| -> bool {
            let mut bad = good.clone();
            bad[offset] ^= 0x01;
            fs::write(&path, &bad).unwrap();
            OpenVault::open(path.clone(), b"a", b"b").is_err()
        };
        assert!(flipped_fails(9), "param tampering detected");
        assert!(flipped_fails(21), "salt tampering detected");
        assert!(flipped_fails(37), "nonce tampering detected");
        fs::write(&path, &good).unwrap();
        assert!(OpenVault::open(path.clone(), b"a", b"b").is_ok());
        cleanup(&path);
    }

    #[test]
    fn export_documents_spans_all_partitions() {
        let path = tmp_path("exportall");
        let mut v = OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();
        // Tiny volume cap so the two docs land in different partitions.
        v.vault.settings.volume_max_size = 1024;
        v.save().unwrap();
        drop(v); // release the single-writer lock before reopening
        let mut v = OpenVault::open(path.clone(), b"a", b"b").unwrap();
        let src = write_src("big", &vec![3u8; 600]);
        v.add_document("/a", "a.bin", &src).unwrap();
        v.add_document("/b", "b.bin", &src).unwrap();
        drop(v);

        let docs = OpenVault::export_documents(&path, b"a", b"b", None).unwrap();
        assert_eq!(docs.len(), 2, "extract spans every partition");
        cleanup(&path);
        fs::remove_file(&src).ok();
    }

    #[test]
    fn backup_copies_consistent_tree() {
        let path = tmp_path("bkp");
        let mut v = OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();
        let src = write_src("bk", b"doc body");
        let id = v.add_document("/d", "f.txt", &src).unwrap();
        drop(v);

        let dest = std::env::temp_dir().join(format!("pmbkp-{}", nanos()));
        let backup_vault = backup(&path, &dest).unwrap();
        assert!(backup_vault.exists());

        let reopened = OpenVault::open(backup_vault.clone(), b"a", b"b").unwrap();
        assert_eq!(&*reopened.read_document(&id).unwrap(), b"doc body");
        fs::remove_dir_all(&dest).ok();
        cleanup(&path);
        fs::remove_file(&src).ok();
    }

    #[test]
    fn export_document_is_hardened_and_no_clobber() {
        let path = tmp_path("expdoc");
        let mut v = OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();
        let src = write_src("exp", b"secret doc");
        let id = v.add_document("/d", "f.txt", &src).unwrap();

        let dest = std::env::temp_dir().join(format!("pmexp-{}.txt", nanos()));
        v.export_document(&id, &dest).unwrap();
        assert_eq!(fs::read(&dest).unwrap(), b"secret doc");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&dest).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        assert!(v.export_document(&id, &dest).is_err(), "no clobber");
        fs::remove_file(&dest).ok();
        cleanup(&path);
        fs::remove_file(&src).ok();
    }

    #[test]
    fn generation_increments_and_is_surfaced() {
        let path = tmp_path("gen");
        let created = OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();
        let g = created.vault.generation;
        assert!(g >= 1);
        drop(created);
        let reopened = OpenVault::open(path.clone(), b"a", b"b").unwrap();
        assert_eq!(reopened.opened_generation(), g);
        assert!(reopened.vault.generation > g);
        cleanup(&path);
    }

    #[test]
    fn read_only_refuses_all_mutations() {
        let path = tmp_path("ro");
        {
            let mut v = OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();
            records::upsert(&mut v.vault.accounts, sample_account("u", "p"));
            v.save().unwrap();
        }
        let mut ro = OpenVault::open_read_only(path.clone(), b"a", b"b").unwrap();
        assert_eq!(ro.vault.accounts.len(), 1);
        assert!(matches!(ro.save(), Err(VaultError::ReadOnly)));
        assert!(matches!(ro.change_password(b"c", b"d"), Err(VaultError::ReadOnly)));
        assert!(matches!(ro.set_volume_max_size(1024), Err(VaultError::ReadOnly)));
        assert!(matches!(ro.remove_document("x"), Err(VaultError::ReadOnly)));
        assert!(matches!(ro.add_asset_type("X"), Err(VaultError::ReadOnly)));
        let src = write_src("ro", b"x");
        assert!(matches!(ro.add_document("/d", "f", &src), Err(VaultError::ReadOnly)));

        let g_before = OpenVault::open_read_only(path.clone(), b"a", b"b").unwrap().vault.generation;
        let _ = OpenVault::open_read_only(path.clone(), b"a", b"b").unwrap();
        let g_after = OpenVault::open_read_only(path.clone(), b"a", b"b").unwrap().vault.generation;
        assert_eq!(g_before, g_after, "read-only open writes nothing");
        cleanup(&path);
        fs::remove_file(&src).ok();
    }

    #[test]
    fn categories_persist_and_read_only_refuses_edits() {
        let path = tmp_path("cats");
        let mut v = OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();
        assert!(v.categories().account_type_names().contains(&"Financial".to_string()));
        assert!(v.add_asset_type("Annuity").unwrap());
        assert!(v.add_account_subtype("Financial", "HSA").unwrap());
        drop(v);

        let reopened = OpenVault::open(path.clone(), b"a", b"b").unwrap();
        assert!(reopened.categories().asset.contains(&"Annuity".to_string()));
        assert!(reopened.categories().subtypes_for("Financial").contains(&"HSA".to_string()));
        cleanup(&path);
    }

    #[test]
    fn compact_timestamp_is_filename_safe() {
        assert_eq!(compact_timestamp(1_609_459_200), "20210101-000000");
        assert!(!compact_timestamp(records::unix_now()).contains([':', ' ', '/']));
    }

    // ---- Phase 5: single-writer lock + partition-filtered export -----------

    #[test]
    fn single_writer_lock_blocks_second_writable_open() {
        let path = tmp_path("lock");
        let v = OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();
        // A second writable open fails fast while the first session is held.
        assert!(matches!(OpenVault::open(path.clone(), b"a", b"b"), Err(VaultError::Locked)));
        // Read-only opens never take the lock, so they are always allowed.
        assert!(OpenVault::open_read_only(path.clone(), b"a", b"b").is_ok());
        drop(v); // releasing the writer frees the lock (no stale lock file)
        assert!(OpenVault::open(path.clone(), b"a", b"b").is_ok());
        cleanup(&path);
    }

    #[test]
    fn export_filters_by_partition() {
        // seed_multi_partition lands one document in each of three partitions.
        let (path, docs) = seed_multi_partition("partfilter", b"a", b"b");
        assert_eq!(docs.len(), 3);
        // All manifests vs a single partition's manifest.
        let all = OpenVault::export_manifests(&path, b"a", b"b", None).unwrap();
        assert_eq!(all.len(), 3, "every partition's entries");
        for p in 0..3u32 {
            let one = OpenVault::export_manifests(&path, b"a", b"b", Some(p)).unwrap();
            assert_eq!(one.len(), 1, "partition {p} holds exactly one doc");
        }
        // Documents filtered by partition decrypt only that one volume.
        let d1 = OpenVault::export_documents(&path, b"a", b"b", Some(1)).unwrap();
        assert_eq!(d1.len(), 1);
        // Out-of-range partitions are rejected for both facilities.
        assert!(matches!(
            OpenVault::export_manifests(&path, b"a", b"b", Some(9)),
            Err(VaultError::NoSuchPartition(9))
        ));
        assert!(matches!(
            OpenVault::export_documents(&path, b"a", b"b", Some(9)),
            Err(VaultError::NoSuchPartition(9))
        ));
        cleanup(&path);
    }

    #[test]
    fn read_facilities_do_not_mutate_the_vault() {
        // decrypt/manifest/extract are read-only: they must not bump the
        // generation or otherwise change the on-disk vault.
        let (path, _docs) = seed_multi_partition("nomutate", b"a", b"b");
        let before = fs::read(&path).unwrap();
        let gen_before = OpenVault::export(&path, b"a", b"b").unwrap().generation;
        let _ = OpenVault::export(&path, b"a", b"b").unwrap();
        let _ = OpenVault::export_manifests(&path, b"a", b"b", None).unwrap();
        let _ = OpenVault::export_documents(&path, b"a", b"b", None).unwrap();
        let after = fs::read(&path).unwrap();
        assert_eq!(before, after, "the vault file is byte-identical after read facilities");
        let gen_after = OpenVault::export(&path, b"a", b"b").unwrap().generation;
        assert_eq!(gen_before, gen_after, "generation unchanged");
        cleanup(&path);
    }

    #[test]
    fn set_volume_max_size_governs_future_placement() {
        let path = tmp_path("volcfg");
        let mut v = OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();
        // Default cap is large: two small docs share partition 0.
        let src = write_src("vc", &vec![7u8; 600]);
        v.add_document("/a", "a.bin", &src).unwrap();
        v.add_document("/b", "b.bin", &src).unwrap();
        // Shrink the cap live; it persists and updates the running store.
        v.set_volume_max_size(1024).unwrap();
        assert_eq!(v.volume_max_size(), 1024);
        // A further doc now rolls into a fresh partition.
        v.add_document("/c", "c.bin", &src).unwrap();
        drop(v);
        // All three manifest entries survive; the third is in its own partition.
        let p1 = OpenVault::export_manifests(&path, b"a", b"b", Some(1)).unwrap();
        assert_eq!(p1.len(), 1, "the post-resize doc landed in partition 1");
        let all = OpenVault::export_manifests(&path, b"a", b"b", None).unwrap();
        assert_eq!(all.len(), 3);
        // The persisted setting is read back on reopen.
        let reopened = OpenVault::open(path.clone(), b"a", b"b").unwrap();
        assert_eq!(reopened.volume_max_size(), 1024);
        cleanup(&path);
        fs::remove_file(&src).ok();
    }

    // ---- Phase 4: exhaustive rekey crash-injection -------------------------
    //
    // Protocol: stage a complete new-key tree under `.rekey/`, mark it `READY`,
    // then commit by roll-forward — move `volume/`, then `manifest/`, then
    // `vault.pmv` **last** — and finally delete `.rekey/`. A crash at *any*
    // point must leave either the old tree (no `READY`) or the new tree
    // (`READY`) fully working, never a mix. Each test below reproduces the
    // on-disk state after a crash at one step and asserts recovery on reopen.

    /// Seed a vault whose documents span several partitions (one tiny doc each).
    /// Returns the vault path plus every stored `(id, body)` for later readback.
    fn seed_multi_partition(tag: &str, pw1: &[u8], pw2: &[u8]) -> (PathBuf, Vec<(String, Vec<u8>)>) {
        let path = tmp_path(tag);
        let mut v = OpenVault::create(path.clone(), pw1, pw2, fast()).unwrap();
        v.vault.settings.volume_max_size = 1024; // tiny cap → one doc per partition
        records::upsert(&mut v.vault.accounts, sample_account("user", "secret"));
        v.save().unwrap();
        drop(v); // release the single-writer lock before reopening
        // Reopen so the store picks up the small cap before we add documents.
        let mut v = OpenVault::open(path.clone(), pw1, pw2).unwrap();
        let mut docs = Vec::new();
        for i in 0..3u8 {
            let body = vec![i + 1; 600];
            let src = write_src(&format!("{tag}-{i}"), &body);
            let id = v.add_document(&format!("/dir{i}"), &format!("f{i}.bin"), &src).unwrap();
            fs::remove_file(&src).ok();
            docs.push((id, body));
        }
        drop(v);
        (path, docs)
    }

    /// Build a complete, `READY`-marked staging tree under `<dir>/.rekey`,
    /// re-encrypting the live vault + every blob under the new passwords —
    /// exactly like `change_password`, but stopping **before** the commit.
    fn stage_ready_rekey(path: &Path, old1: &[u8], old2: &[u8], new1: &[u8], new2: &[u8]) -> PathBuf {
        let open = OpenVault::open(path.to_path_buf(), old1, old2).unwrap();
        let dir = parent_dir(path);
        let staging = dir.join(REKEY_DIR);
        let _ = fs::remove_dir_all(&staging);
        fs::create_dir_all(&staging).unwrap();
        let new_salt = crypto::random_bytes::<SALT_LEN>().unwrap();
        let new_key = crypto::derive_key_chained(new1, new2, &new_salt, &open.params).unwrap();
        let mut new_store =
            VolumeStore::open(&staging, &new_key, &open.vault.id, open.vault.settings.volume_max_size).unwrap();
        let ids: Vec<String> = open.storage.ids().map(|s| s.to_string()).collect();
        for id in &ids {
            let bytes = open.storage.read(id, &open.key).unwrap();
            let (vpath, uploaded_at) =
                open.storage.entry(id).map(|e| (e.path.clone(), e.uploaded_at)).unwrap_or_default();
            new_store.put(id, &vpath, &bytes, uploaded_at, &new_key).unwrap();
        }
        drop(new_store);
        let mut staged_vault = open.vault.clone();
        staged_vault.audit.push(Change::new("password_changed", String::new()));
        write_vault_file(&staging.join(VAULT_FILE), &staged_vault, &new_key, &new_salt, open.params).unwrap();
        write_new_bytes(&staging.join(REKEY_READY), b"ready").unwrap();
        staging
    }

    /// After a roll-forward: only the NEW passwords open the vault, every doc
    /// reads back, the audit records the change, and no staging/`.old` debris
    /// is left behind.
    fn assert_rolled_forward(path: &Path, old: (&[u8], &[u8]), new: (&[u8], &[u8]), docs: &[(String, Vec<u8>)]) {
        assert!(OpenVault::open(path.to_path_buf(), old.0, old.1).is_err(), "old passwords must fail");
        let v = OpenVault::open(path.to_path_buf(), new.0, new.1).unwrap();
        for (id, body) in docs {
            assert_eq!(&v.read_document(id).unwrap()[..], &body[..], "doc {id} survives rekey");
        }
        assert!(v.vault.audit.iter().any(|c| c.action == "password_changed"), "audit records rekey");
        let dir = parent_dir(path);
        assert!(!dir.join(REKEY_DIR).exists(), "staging removed");
        assert!(!sibling_old(&dir.join("volume")).exists(), "no .volume.old debris");
        assert!(!sibling_old(&dir.join("manifest")).exists(), "no .manifest.old debris");
    }

    /// After a discard: only the OLD passwords open the vault, every doc reads
    /// back unchanged, and staging is gone.
    fn assert_discarded(path: &Path, old: (&[u8], &[u8]), new: (&[u8], &[u8]), docs: &[(String, Vec<u8>)]) {
        // The first open (any password) runs recovery and discards the staging.
        assert!(OpenVault::open(path.to_path_buf(), new.0, new.1).is_err(), "new passwords must fail");
        let v = OpenVault::open(path.to_path_buf(), old.0, old.1).unwrap();
        for (id, body) in docs {
            assert_eq!(&v.read_document(id).unwrap()[..], &body[..], "doc {id} intact after discard");
        }
        assert!(!parent_dir(path).join(REKEY_DIR).exists(), "staging discarded");
    }

    #[test]
    fn rekey_across_partitions_roundtrip() {
        let (path, docs) = seed_multi_partition("rkmulti", b"o1", b"o2");
        {
            let mut v = OpenVault::open(path.clone(), b"o1", b"o2").unwrap();
            v.change_password(b"n1", b"n2").unwrap();
            // The in-memory handle is already on the new key.
            for (id, body) in &docs {
                assert_eq!(&v.read_document(id).unwrap()[..], &body[..]);
            }
        }
        assert_rolled_forward(&path, (b"o1", b"o2"), (b"n1", b"n2"), &docs);
        cleanup(&path);
    }

    #[test]
    fn rekey_chained_twice_only_last_password_opens() {
        let (path, docs) = seed_multi_partition("rkchain", b"a1", b"a2");
        {
            let mut v = OpenVault::open(path.clone(), b"a1", b"a2").unwrap();
            v.change_password(b"b1", b"b2").unwrap();
            v.change_password(b"c1", b"c2").unwrap();
        }
        assert!(OpenVault::open(path.clone(), b"a1", b"a2").is_err());
        assert!(OpenVault::open(path.clone(), b"b1", b"b2").is_err());
        let v = OpenVault::open(path.clone(), b"c1", b"c2").unwrap();
        for (id, body) in &docs {
            assert_eq!(&v.read_document(id).unwrap()[..], &body[..]);
        }
        cleanup(&path);
    }

    #[test]
    fn rekey_crash_before_any_commit_rolls_forward() {
        let (path, docs) = seed_multi_partition("rkp0", b"o1", b"o2");
        // Crash right after READY, before a single item is moved.
        stage_ready_rekey(&path, b"o1", b"o2", b"n1", b"n2");
        assert_rolled_forward(&path, (b"o1", b"o2"), (b"n1", b"n2"), &docs);
        cleanup(&path);
    }

    #[test]
    fn rekey_crash_after_volume_commit_rolls_forward() {
        let (path, docs) = seed_multi_partition("rkp1", b"o1", b"o2");
        let staging = stage_ready_rekey(&path, b"o1", b"o2", b"n1", b"n2");
        let dir = parent_dir(&path);
        // Volume moved into place; manifest + vault.pmv still staged.
        replace_dir(&dir.join("volume"), &staging.join("volume")).unwrap();
        assert_rolled_forward(&path, (b"o1", b"o2"), (b"n1", b"n2"), &docs);
        cleanup(&path);
    }

    #[test]
    fn rekey_crash_after_manifest_commit_rolls_forward() {
        let (path, docs) = seed_multi_partition("rkp2", b"o1", b"o2");
        let staging = stage_ready_rekey(&path, b"o1", b"o2", b"n1", b"n2");
        let dir = parent_dir(&path);
        // Volume + manifest moved; vault.pmv still staged → old key still on disk.
        replace_dir(&dir.join("volume"), &staging.join("volume")).unwrap();
        replace_dir(&dir.join("manifest"), &staging.join("manifest")).unwrap();
        assert_rolled_forward(&path, (b"o1", b"o2"), (b"n1", b"n2"), &docs);
        cleanup(&path);
    }

    #[test]
    fn rekey_crash_after_vault_commit_before_cleanup_rolls_forward() {
        let (path, docs) = seed_multi_partition("rkp3", b"o1", b"o2");
        let staging = stage_ready_rekey(&path, b"o1", b"o2", b"n1", b"n2");
        let dir = parent_dir(&path);
        // Everything moved (new key is live), but `.rekey/` not yet removed.
        replace_dir(&dir.join("volume"), &staging.join("volume")).unwrap();
        replace_dir(&dir.join("manifest"), &staging.join("manifest")).unwrap();
        replace_path(&dir.join(VAULT_FILE), &staging.join(VAULT_FILE)).unwrap();
        assert!(staging.exists(), "staging still present at this crash point");
        assert_rolled_forward(&path, (b"o1", b"o2"), (b"n1", b"n2"), &docs);
        cleanup(&path);
    }

    #[test]
    fn rekey_crash_mid_volume_swap_rolls_forward() {
        // The dangerous window inside replace_dir: the live dir has been moved
        // aside to `.volume.old` but the staged dir is not yet renamed in.
        let (path, docs) = seed_multi_partition("rkmidv", b"o1", b"o2");
        let staging = stage_ready_rekey(&path, b"o1", b"o2", b"n1", b"n2");
        let dir = parent_dir(&path);
        let old = sibling_old(&dir.join("volume"));
        fs::rename(dir.join("volume"), &old).unwrap(); // crash here: live gone, staged intact
        assert_rolled_forward(&path, (b"o1", b"o2"), (b"n1", b"n2"), &docs);
        let _ = &staging;
        cleanup(&path);
    }

    #[test]
    fn rekey_crash_mid_manifest_swap_rolls_forward() {
        let (path, docs) = seed_multi_partition("rkmidm", b"o1", b"o2");
        let staging = stage_ready_rekey(&path, b"o1", b"o2", b"n1", b"n2");
        let dir = parent_dir(&path);
        // Volume already committed; crash mid-manifest swap.
        replace_dir(&dir.join("volume"), &staging.join("volume")).unwrap();
        let old = sibling_old(&dir.join("manifest"));
        fs::rename(dir.join("manifest"), &old).unwrap();
        assert_rolled_forward(&path, (b"o1", b"o2"), (b"n1", b"n2"), &docs);
        cleanup(&path);
    }

    #[test]
    fn rekey_commit_is_idempotent() {
        // Running the roll-forward twice (e.g. a crash during the second
        // recovery) must not panic or corrupt state.
        let (path, docs) = seed_multi_partition("rkidem", b"o1", b"o2");
        let staging = stage_ready_rekey(&path, b"o1", b"o2", b"n1", b"n2");
        let dir = parent_dir(&path);
        commit_rekey(&dir, &staging).unwrap();
        commit_rekey(&dir, &staging).unwrap(); // no-op the second time
        assert_rolled_forward(&path, (b"o1", b"o2"), (b"n1", b"n2"), &docs);
        cleanup(&path);
    }

    #[test]
    fn rekey_complete_tree_without_ready_is_discarded() {
        // A fully-staged tree missing only the READY marker is NOT trusted: it
        // is discarded and the old (intact) tree stands.
        let (path, docs) = seed_multi_partition("rknoready", b"o1", b"o2");
        let staging = stage_ready_rekey(&path, b"o1", b"o2", b"n1", b"n2");
        fs::remove_file(staging.join(REKEY_READY)).unwrap(); // the only thing missing
        assert_discarded(&path, (b"o1", b"o2"), (b"n1", b"n2"), &docs);
        cleanup(&path);
    }

    #[test]
    fn rekey_partial_staging_with_docs_discarded() {
        let (path, docs) = seed_multi_partition("rkpartial", b"o1", b"o2");
        let staging = parent_dir(&path).join(REKEY_DIR);
        fs::create_dir_all(staging.join("volume")).unwrap();
        fs::write(staging.join("vault.pmv"), b"half-written").unwrap();
        assert_discarded(&path, (b"o1", b"o2"), (b"n1", b"n2"), &docs);
        cleanup(&path);
    }

    #[test]
    fn read_only_with_ready_rekey_is_reported_then_rw_rolls_forward() {
        let (path, docs) = seed_multi_partition("rkro", b"o1", b"o2");
        stage_ready_rekey(&path, b"o1", b"o2", b"n1", b"n2");
        // Read-only cannot finish the commit, so it must refuse, untouched.
        let err = OpenVault::open_read_only(path.clone(), b"n1", b"n2").err().unwrap();
        assert!(matches!(err, VaultError::RekeyPending));
        assert!(parent_dir(&path).join(REKEY_DIR).exists(), "read-only left staging in place");
        // A read-write open then completes the roll-forward.
        assert_rolled_forward(&path, (b"o1", b"o2"), (b"n1", b"n2"), &docs);
        cleanup(&path);
    }

    #[test]
    fn stale_staging_cleared_then_rekey_succeeds() {
        // A leftover incomplete `.rekey/` from a prior aborted attempt must not
        // block a fresh password change.
        let (path, docs) = seed_multi_partition("rkstale", b"o1", b"o2");
        let staging = parent_dir(&path).join(REKEY_DIR);
        fs::create_dir_all(staging.join("volume")).unwrap(); // stale, no READY
        {
            // Open discards the stale staging, then change_password stages anew.
            let mut v = OpenVault::open(path.clone(), b"o1", b"o2").unwrap();
            v.change_password(b"n1", b"n2").unwrap();
        }
        assert_rolled_forward(&path, (b"o1", b"o2"), (b"n1", b"n2"), &docs);
        cleanup(&path);
    }

    use proptest::prelude::*;
    proptest! {
        /// Virtual paths are always rooted, and `normalize_dir` is idempotent and
        /// never yields empty ("//") segments — so the limit check and storage see
        /// a single canonical form.
        #[test]
        fn prop_virtual_path_rooted_and_normalize_idempotent(
            loc in "[ -~]{0,80}",
            name in "[ -~]{1,40}",
        ) {
            let vp = virtual_path(&loc, &name);
            prop_assert!(vp.starts_with('/'), "virtual path is rooted: {vp:?}");
            let n1 = normalize_dir(&loc);
            prop_assert_eq!(normalize_dir(&n1), n1.clone());
            prop_assert!(!n1.contains("//"), "no empty segments: {n1:?}");
            prop_assert!(n1.is_empty() || n1.starts_with('/'));
        }
    }
}
