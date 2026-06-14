//! The encrypted on-disk file format and the encrypted document volume.
//!
//! The decrypted data model itself lives in [`crate::records`]; this module owns
//! the *file* (header + AEAD ciphertext of the JSON vault) and the sidecar
//! *archive* file that stores all uploaded documents together, encrypted as a
//! single unit ("encrypted zip").
//!
//! File layout (all integers little-endian):
//! ```text
//!   offset  len  field
//!   0       8    magic  b"PMVAULT\0"          (identifies a pass-mgr vault)
//!   8       1    format version (currently 3)
//!   9       4    Argon2 m_cost (KiB)
//!   13      4    Argon2 t_cost
//!   17      4    Argon2 p_cost
//!   21      16   salt1   (salt for the first KDF pass)
//!   37      24   nonce   (XChaCha20-Poly1305)
//!   61      ..   XChaCha20-Poly1305 ciphertext of the JSON vault
//! ```
//! The first 37 header bytes (everything but the nonce) are the AEAD associated
//! data, so tampering with the version/params/salt is detected on decrypt.
//!
//! The key is derived from **two** passwords via a chained Argon2id derivation
//! (see [`crate::crypto::derive_key_chained`] and `docs/DESIGN.md`). Format
//! version 3 holds the five estate-record collections plus the document-volume
//! manifest; earlier versions are not auto-migrated.
//!
//! Document volume: uploaded files are encrypted together with the vault key and
//! stored in a single archive `<vault-filename>.vol` (`nonce ‖ ciphertext`),
//! decrypted as one unit on open. The vault JSON holds the virtual directory
//! tree, per-file metadata, and the upload history.

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use thiserror::Error;
use zeroize::Zeroizing;

use crate::crypto::{self, CryptoError, KdfParams, Key, NONCE_LEN, SALT_LEN};
use crate::records::{self, Change, Vault, VolumeFile};

/// Fixed prefix of the document-archive associated data (app/format tag). The
/// vault's `volume.id` is appended so the archive is bound to its specific vault.
const ARCHIVE_AAD_PREFIX: &[u8] = b"PMVAULT-DOC-ARCHIVE-v1\0";

/// AEAD associated data for the document archive: the fixed prefix plus the
/// vault's instance id. Binding the id means a `.vol` from a different vault (or
/// a swapped one) fails authentication on decrypt.
fn archive_aad(vault_id: &str) -> Vec<u8> {
    let mut aad = ARCHIVE_AAD_PREFIX.to_vec();
    aad.extend_from_slice(vault_id.as_bytes());
    aad
}

/// All documents, decrypted, keyed by their volume file id. The values wipe on
/// drop. This is the in-memory form of the single encrypted archive file.
type DocArchive = BTreeMap<String, Zeroizing<Vec<u8>>>;

/// A decrypted document returned to the CLI: its manifest metadata plus its
/// plaintext bytes (which wipe on drop).
pub type DecryptedDoc = (VolumeFile, Zeroizing<Vec<u8>>);

const MAGIC: &[u8; 8] = b"PMVAULT\0";
const FORMAT_VERSION: u8 = 3;
const HEADER_LEN: usize = 61;

// Sanity bounds for KDF parameters read from an untrusted file header. They are
// validated *before* the (expensive, memory-hard) key derivation runs, so a
// crafted header cannot force a huge Argon2 allocation as a denial-of-service.
const MAX_M_COST: u32 = 1 << 20; // 1 GiB, expressed in KiB
const MAX_T_COST: u32 = 64;
const MAX_P_COST: u32 = 16;
/// Bytes of the header used as AEAD associated data: everything *except* the
/// 24-byte nonce. The nonce is bound implicitly as the cipher's nonce input.
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
    #[error("document archive does not match the vault (possible tampering or rollback)")]
    ArchiveMismatch,
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

/// An unlocked vault: the decrypted data plus the derived key and KDF salt/params
/// needed to re-encrypt on save and to encrypt/decrypt the document archive. The
/// key zeroizes when dropped; the `vault` zeroizes via its own `ZeroizeOnDrop`.
pub struct OpenVault {
    pub vault: Vault,
    key: Key,
    params: KdfParams,
    salt: [u8; SALT_LEN],
    path: PathBuf,
    /// `last_opened_at` read from disk before this session updated it (the prior
    /// access time, for display on the unlock screen).
    previous_access: i64,
    /// Write-generation read from disk on open, for rollback awareness (§9.12).
    previous_generation: u64,
    /// All documents, decrypted, held together (the "encrypted zip" decrypted as
    /// a unit on open and re-encrypted as a unit on change).
    archive: DocArchive,
}

impl OpenVault {
    /// Create a brand-new vault at `path` protected by two passwords.
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

        let mut vault = Vault::default();
        vault.version = FORMAT_VERSION;
        vault.last_opened_at = records::unix_now();
        vault.volume.id = records::random_id()?; // binds the document archive to this vault
        vault.audit.push(Change::new("vault_created", String::new()));

        let mut open = OpenVault {
            vault,
            key,
            params,
            salt,
            path,
            previous_access: 0,
            previous_generation: 0,
            archive: DocArchive::new(),
        };
        open.save()?;
        Ok(open)
    }

    /// Unlock an existing vault with both passwords. Updates `last_opened_at`
    /// (persisted best-effort) and exposes the prior access time/generation.
    pub fn open(path: PathBuf, pw1: &[u8], pw2: &[u8]) -> Result<Self, VaultError> {
        let (mut vault, header, key) = decrypt_file(&path, pw1, pw2)?;

        let previous_access = vault.last_opened_at;
        let previous_generation = vault.generation;
        vault.last_opened_at = records::unix_now();

        // Decrypt the whole document archive at once (empty if none yet), bound
        // to this vault's id. Then verify it is consistent with the manifest:
        // every document referenced by the manifest must be present, so a stale
        // or swapped `.vol` (missing newer documents) is rejected.
        let archive = load_archive(&archive_path(&path), &key, &vault.volume.id)?;
        for f in &vault.volume.files {
            if !archive.contains_key(&f.id) {
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
            archive,
        };
        // Persisting the refreshed access time is best-effort: a read-only medium
        // or full disk must not stop you from viewing an otherwise-valid vault.
        let _ = open.save();
        Ok(open)
    }

    /// Decrypt the vault and return its contents **without** modifying the file.
    /// Used by the command-line decrypt/export path.
    pub fn export(path: &Path, pw1: &[u8], pw2: &[u8]) -> Result<Vault, VaultError> {
        let (vault, _header, _key) = decrypt_file(path, pw1, pw2)?;
        Ok(vault)
    }

    /// Decrypt the vault and its document archive **without** modifying any file,
    /// returning each document's metadata together with its decrypted bytes (the
    /// bytes wipe on drop). Used by the command-line `extract` command. Verifies
    /// archive↔manifest consistency, failing closed on a stale/tampered archive.
    pub fn export_documents(
        path: &Path,
        pw1: &[u8],
        pw2: &[u8],
    ) -> Result<Vec<DecryptedDoc>, VaultError> {
        let (vault, _header, key) = decrypt_file(path, pw1, pw2)?;
        let mut archive = load_archive(&archive_path(path), &key, &vault.volume.id)?;
        let mut out = Vec::with_capacity(vault.volume.files.len());
        for f in &vault.volume.files {
            match archive.remove(&f.id) {
                Some(bytes) => out.push((f.clone(), bytes)),
                None => return Err(VaultError::ArchiveMismatch),
            }
        }
        Ok(out)
    }

    /// Re-encrypt the current data and write it atomically (unique temp file +
    /// fsync + rename + dir fsync), with a fresh random nonce and owner-only mode.
    /// Bumps the write-generation counter so a later rollback is detectable.
    pub fn save(&mut self) -> Result<(), VaultError> {
        self.vault.generation = self.vault.generation.saturating_add(1);
        let plaintext = Zeroizing::new(serde_json::to_vec(&self.vault)?);

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

        let tmp = self.temp_path()?;
        if let Err(e) = write_new_file(&tmp, &header_bytes, &ciphertext) {
            let _ = fs::remove_file(&tmp);
            return Err(e);
        }
        if let Err(e) = fs::rename(&tmp, &self.path) {
            let _ = fs::remove_file(&tmp);
            return Err(e.into());
        }
        sync_parent_dir(&self.path);
        Ok(())
    }

    /// A unique, hidden temp path beside the vault file.
    fn temp_path(&self) -> Result<PathBuf, VaultError> {
        sibling_tmp(&self.path)
    }

    /// Re-key under two new passwords (new salt) and persist. Transactional: the
    /// in-memory key/salt/audit are only kept if the save succeeds.
    pub fn change_password(&mut self, pw1: &[u8], pw2: &[u8]) -> Result<(), VaultError> {
        let salt = crypto::random_bytes::<SALT_LEN>()?;
        let key = crypto::derive_key_chained(pw1, pw2, &salt, &self.params)?;

        let old_key = std::mem::replace(&mut self.key, key);
        let old_salt = std::mem::replace(&mut self.salt, salt);
        self.vault.audit.push(Change::new("password_changed", String::new()));

        // Re-encrypt the document archive under the new key FIRST (atomic write).
        // If it fails the archive file is untouched, so we can fully revert.
        if let Err(e) = self.save_archive() {
            self.key = old_key;
            self.salt = old_salt;
            self.vault.audit.pop();
            return Err(e);
        }
        // Then write the vault under the new key.
        if let Err(e) = self.save() {
            // The vault file is still under the OLD key. Restore the archive to
            // the old key too, then revert, so vault + archive stay consistent.
            self.key = old_key;
            self.salt = old_salt;
            self.vault.audit.pop();
            // Surface a failure to restore the archive (don't silently ignore):
            // if this errors, the on-disk archive may be under the new key while
            // the vault is under the old — the caller must know to retry.
            self.save_archive()?;
            return Err(e);
        }
        Ok(())
    }

    /// The previous access time (unix seconds), or 0 for a new vault.
    pub fn previous_access(&self) -> i64 {
        self.previous_access
    }

    /// The write-generation read from disk on open (before this session bumped
    /// it). Lets the UI surface "generation N" so a rollback to an older
    /// whole-file snapshot is noticeable (§9.12).
    pub fn opened_generation(&self) -> u64 {
        self.previous_generation
    }

    // --- Encrypted document volume (single archive) -------------------------
    //
    // All documents live together in one encrypted container, `<vault>.vol`,
    // decrypted as a unit on open and re-encrypted as a unit on change. The
    // vault JSON holds only the lightweight metadata (id/location/filename/...).

    /// Add the file at `source` to the document archive under virtual directory
    /// `location` with name `filename`; record its metadata + upload history and
    /// persist both the archive and the vault. Returns the new file id.
    pub fn add_document(
        &mut self,
        location: &str,
        filename: &str,
        source: &Path,
    ) -> Result<String, VaultError> {
        let data = Zeroizing::new(fs::read(source)?);
        let size = data.len() as u64;
        let id = records::random_id()?;

        self.archive.insert(id.clone(), data);
        if let Err(e) = self.save_archive() {
            self.archive.remove(&id);
            return Err(e);
        }

        let location = normalize_dir(location);
        let display_loc = if location.is_empty() { "/".to_string() } else { location.clone() };
        // Snapshot the directory list so the rollback can restore it exactly.
        let dirs_before = self.vault.volume.directories.clone();
        self.vault.volume.register_directory(&location);
        self.vault.volume.files.push(VolumeFile {
            id: id.clone(),
            location: location.clone(),
            filename: filename.to_string(),
            size,
            uploaded_at: records::unix_now(),
            source: source.display().to_string(),
        });
        self.vault
            .volume
            .uploads
            .push(Change::new("uploaded", format!("{display_loc}/{filename}")));

        if let Err(e) = self.save() {
            // Roll back the manifest (files, uploads, directories) and the archive.
            self.vault.volume.files.pop();
            self.vault.volume.uploads.pop();
            self.vault.volume.directories = dirs_before;
            self.archive.remove(&id);
            let _ = self.save_archive();
            return Err(e);
        }
        Ok(id)
    }

    /// Permanently remove a stored document by id: drop it from the archive and
    /// the manifest, log the removal, and persist. Called when a record holding
    /// the document is deleted or its attachment is detached, so "deleted"
    /// documents do not linger in the encrypted archive.
    pub fn remove_document(&mut self, file_id: &str) -> Result<(), VaultError> {
        // Snapshot what we remove so a failed persist can be fully rolled back.
        let removed_blob = self.archive.remove(file_id);
        let removed_idx = self.vault.volume.files.iter().position(|f| f.id == file_id);
        let removed_file = removed_idx.map(|i| self.vault.volume.files.remove(i));
        let pushed_upload = removed_file.is_some();
        if let Some(f) = &removed_file {
            let loc = if f.location.is_empty() { "/".to_string() } else { f.location.clone() };
            self.vault.volume.uploads.push(Change::new("removed", format!("{loc}/{}", f.filename)));
        }

        // Write the vault (manifest WITHOUT this entry) FIRST, then rewrite the
        // archive WITHOUT the blob. If the vault save fails, restore the in-memory
        // state so the operation is a true no-op (in-memory stays == on-disk).
        if let Err(e) = self.save() {
            if let (Some(idx), Some(f)) = (removed_idx, removed_file) {
                self.vault.volume.files.insert(idx.min(self.vault.volume.files.len()), f);
            }
            if let Some(blob) = removed_blob {
                self.archive.insert(file_id.to_string(), blob);
            }
            if pushed_upload {
                self.vault.volume.uploads.pop();
            }
            return Err(e);
        }
        // A failure here leaves a harmless orphan blob (manifest ⊆ archive still
        // holds, so the vault still opens) — never a dangling manifest reference.
        self.save_archive()
    }

    /// Return a stored document by id (already decrypted in memory).
    pub fn read_document(&self, file_id: &str) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        match self.archive.get(file_id) {
            Some(data) => Ok(Zeroizing::new(data.to_vec())),
            None => Err(VaultError::NotFound(archive_path(&self.path))),
        }
    }

    /// Write a stored document out to `dest` (to view/open it). This produces an
    /// **unencrypted** copy, created with `create_new` (O_EXCL, so a pre-planted
    /// symlink can't be followed) and mode 0600 on Unix. Fails if `dest` exists.
    pub fn export_document(&self, file_id: &str, dest: &Path) -> Result<(), VaultError> {
        let data = self.read_document(file_id)?;
        write_new_bytes(dest, &data)
    }

    /// Encrypt the whole document archive and write it atomically to `<vault>.vol`.
    fn save_archive(&self) -> Result<(), VaultError> {
        let archive_file = archive_path(&self.path);
        if self.archive.is_empty() {
            // Nothing to store; remove any stale archive file.
            let _ = fs::remove_file(&archive_file);
            return Ok(());
        }
        let plaintext = Zeroizing::new(serialize_archive(&self.archive));
        let aad = archive_aad(&self.vault.volume.id);
        let (nonce, ciphertext) = crypto::encrypt(&self.key, &plaintext, &aad)?;

        if let Some(parent) = archive_file.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent)?;
            harden_dir(parent);
        }
        // Unique temp file + rename, like the vault save, so a crash can't corrupt
        // the existing archive.
        let tmp = sibling_tmp(&archive_file)?;
        if let Err(e) = write_new_file(&tmp, &nonce, &ciphertext) {
            let _ = fs::remove_file(&tmp);
            return Err(e);
        }
        if let Err(e) = fs::rename(&tmp, &archive_file) {
            let _ = fs::remove_file(&tmp);
            return Err(e.into());
        }
        sync_parent_dir(&archive_file);
        Ok(())
    }
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
    let aad = header.to_bytes();
    let plaintext = Zeroizing::new(crypto::decrypt(&key, &header.nonce, ciphertext, &aad[..AAD_LEN])?);
    let vault: Vault = serde_json::from_slice(&plaintext)?;
    Ok((vault, header, key))
}

/// Normalize a virtual directory path to `/a/b/c` form (empty string == root).
fn normalize_dir(path: &str) -> String {
    let parts: Vec<&str> = path.split('/').filter(|p| !p.is_empty()).collect();
    if parts.is_empty() {
        String::new()
    } else {
        format!("/{}", parts.join("/"))
    }
}

/// A short random hex suffix for temp filenames.
fn rand_suffix() -> Result<String, CryptoError> {
    Ok(crypto::random_bytes::<8>()?.iter().map(|b| format!("{b:02x}")).collect())
}

/// A unique, hidden temp path beside `path` (same directory).
fn sibling_tmp(path: &Path) -> Result<PathBuf, VaultError> {
    let suffix = rand_suffix()?;
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("file");
    let file = format!(".{name}.{suffix}.tmp");
    Ok(match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.join(file),
        _ => PathBuf::from(file),
    })
}

/// Copy the vault file **and** its document archive into `dest_dir` as a
/// self-consistent, timestamped pair (e.g. `vault-20260614-013055.pmv` and
/// `vault-20260614-013055.pmv.vol`). Copies the encrypted files as-is — no
/// passwords needed and nothing is decrypted. Returns the backup vault path.
pub fn backup(vault_path: &Path, dest_dir: &Path) -> Result<PathBuf, VaultError> {
    if !vault_path.exists() {
        return Err(VaultError::NotFound(vault_path.to_path_buf()));
    }
    fs::create_dir_all(dest_dir)?;
    harden_dir(dest_dir);

    let stem = vault_path.file_stem().and_then(|s| s.to_str()).unwrap_or("vault");
    let ext = vault_path.extension().and_then(|s| s.to_str()).unwrap_or("pmv");
    let stamp = compact_timestamp(records::unix_now());
    let src_archive = archive_path(vault_path);

    // Choose a base name that collides with neither the vault nor its `.vol`
    // companion, so two backups in the same second don't silently overwrite one
    // another (the timestamp has 1-second resolution).
    let mut backup_vault = dest_dir.join(format!("{stem}-{stamp}.{ext}"));
    let mut n = 1;
    while backup_vault.exists() || archive_path(&backup_vault).exists() {
        backup_vault = dest_dir.join(format!("{stem}-{stamp}_{n}.{ext}"));
        n += 1;
    }

    fs::copy(vault_path, &backup_vault)?;
    harden_file(&backup_vault)?;
    // Keep the archive named `<backup-vault>.vol` so the pair opens together.
    if src_archive.exists() {
        let backup_archive = archive_path(&backup_vault);
        fs::copy(&src_archive, &backup_archive)?;
        harden_file(&backup_archive)?;
    }
    Ok(backup_vault)
}

/// Format unix seconds as a filename-safe UTC stamp `YYYYMMDD-HHMMSS`.
fn compact_timestamp(ts: i64) -> String {
    let (year, mo, d, h, m, s) = records::civil_from_unix(ts);
    format!("{year:04}{mo:02}{d:02}-{h:02}{m:02}{s:02}")
}

/// The single encrypted document-archive path for a vault: `<vault-name>.vol`.
fn archive_path(vault: &Path) -> PathBuf {
    let name = vault.file_name().and_then(|n| n.to_str()).unwrap_or("vault");
    let file = format!("{name}.vol");
    match vault.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.join(file),
        _ => PathBuf::from(file),
    }
}

/// Read and decrypt the whole document archive (empty map if the file is absent),
/// authenticated against `vault_id` so a foreign/swapped archive is rejected.
fn load_archive(path: &Path, key: &Key, vault_id: &str) -> Result<DocArchive, VaultError> {
    let raw = match fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(DocArchive::new()),
        Err(e) => return Err(e.into()),
    };
    if raw.len() < NONCE_LEN {
        return Err(VaultError::Truncated);
    }
    let (nonce, ciphertext) = raw.split_at(NONCE_LEN);
    let aad = archive_aad(vault_id);
    let plaintext = Zeroizing::new(crypto::decrypt(key, nonce, ciphertext, &aad)?);
    parse_archive(&plaintext)
}

/// Serialize the archive map to a length-prefixed binary buffer:
/// `[u32 count]` then per entry `[u32 id_len][id][u64 data_len][data]`.
fn serialize_archive(map: &DocArchive) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&(map.len() as u32).to_le_bytes());
    for (id, data) in map {
        let idb = id.as_bytes();
        buf.extend_from_slice(&(idb.len() as u32).to_le_bytes());
        buf.extend_from_slice(idb);
        buf.extend_from_slice(&(data.len() as u64).to_le_bytes());
        buf.extend_from_slice(data);
    }
    buf
}

/// Parse the archive buffer with bounds-checked reads (the archive is attacker-
/// controllable, so a malformed buffer must fail closed, never panic). Every
/// read is bounded by the actual buffer length, so a huge length field cannot
/// trigger an over-read or over-allocation.
fn parse_archive(buf: &[u8]) -> Result<DocArchive, VaultError> {
    fn take<'a>(buf: &'a [u8], cur: &mut usize, n: usize) -> Result<&'a [u8], VaultError> {
        let end = cur.checked_add(n).ok_or(VaultError::Truncated)?;
        let slice = buf.get(*cur..end).ok_or(VaultError::Truncated)?;
        *cur = end;
        Ok(slice)
    }
    let mut map = DocArchive::new();
    let mut cur = 0usize;
    let count = u32::from_le_bytes(take(buf, &mut cur, 4)?.try_into().unwrap());
    for _ in 0..count {
        let id_len = u32::from_le_bytes(take(buf, &mut cur, 4)?.try_into().unwrap()) as usize;
        let id = String::from_utf8(take(buf, &mut cur, id_len)?.to_vec())
            .map_err(|_| VaultError::Truncated)?;
        let data_len = u64::from_le_bytes(take(buf, &mut cur, 8)?.try_into().unwrap()) as usize;
        let data = take(buf, &mut cur, data_len)?.to_vec();
        map.insert(id, Zeroizing::new(data));
    }
    Ok(map)
}

// --- Cross-platform file hardening (req: compile on Windows + Linux) ---------
// `pub(crate)` so the CLI (`main.rs`) can reuse these instead of re-implementing
// the same security-sensitive primitives.

#[cfg(unix)]
pub(crate) fn harden_file(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = fs::metadata(path)?.permissions();
    perms.set_mode(0o600);
    fs::set_permissions(path, perms)
}

#[cfg(not(unix))]
pub(crate) fn harden_file(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(unix)]
pub(crate) fn harden_dir(dir: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = fs::metadata(dir) {
        let mut perms = meta.permissions();
        perms.set_mode(0o700);
        let _ = fs::set_permissions(dir, perms);
    }
}

#[cfg(not(unix))]
pub(crate) fn harden_dir(_dir: &Path) {}

/// Open a brand-new file at `path` with `create_new` (O_EXCL, so an existing
/// path — including a pre-planted symlink — fails instead of being followed) and
/// mode 0600 on Unix applied atomically at creation.
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

/// Create a brand-new file at `path`, write `part1` + `part2`, and fsync.
/// Used for the vault file (header+ciphertext) and the document archive
/// (nonce+ciphertext). See [`create_new_0600`] for the symlink/permission notes.
fn write_new_file(path: &Path, part1: &[u8], part2: &[u8]) -> Result<(), VaultError> {
    let mut f = create_new_0600(path)?;
    harden_file(path)?; // belt-and-suspenders (no-op on non-unix)
    f.write_all(part1)?;
    f.write_all(part2)?;
    f.sync_all()?;
    Ok(())
}

/// Create a brand-new file and write a single buffer to it (O_EXCL + 0600); on a
/// write error the partial file is removed so no fragment is left behind. Shared
/// by `export_document` and the CLI `extract` command.
pub(crate) fn write_new_bytes(path: &Path, data: &[u8]) -> Result<(), VaultError> {
    let mut f = create_new_0600(path)?;
    harden_file(path)?;
    if let Err(e) = f.write_all(data).and_then(|()| f.sync_all()) {
        drop(f);
        let _ = fs::remove_file(path);
        return Err(e.into());
    }
    Ok(())
}

/// fsync the directory containing `path` so a rename into it is durable.
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
    use crate::records::{self, Account};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn fast() -> KdfParams {
        KdfParams { m_cost: 256, t_cost: 1, p_cost: 1 }
    }

    fn nanos() -> u128 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
    }

    fn tmp_path(tag: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("passmgr-test-{tag}-{}.pmv", nanos()));
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

        let reopened = OpenVault::open(path.clone(), b"first", b"second").unwrap();
        assert_eq!(reopened.vault.accounts.len(), 1);
        assert_eq!(reopened.vault.accounts[0].password, "hunter2");
        assert_eq!(reopened.vault.version, FORMAT_VERSION);
        fs::remove_file(&path).ok();
    }

    #[test]
    fn both_passwords_required() {
        let path = tmp_path("twopw");
        OpenVault::create(path.clone(), b"right1", b"right2", fast()).unwrap();
        assert!(OpenVault::open(path.clone(), b"wrong1", b"right2").is_err());
        assert!(OpenVault::open(path.clone(), b"right1", b"wrong2").is_err());
        assert!(OpenVault::open(path.clone(), b"right1", b"right2").is_ok());
        fs::remove_file(&path).ok();
    }

    #[test]
    fn password_order_matters() {
        let path = tmp_path("order");
        OpenVault::create(path.clone(), b"alpha", b"beta", fast()).unwrap();
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
        records::upsert(&mut v.vault.accounts, sample_account("u", "p"));
        v.change_password(b"new1", b"new2").unwrap();

        assert!(OpenVault::open(path.clone(), b"old1", b"old2").is_err());
        let reopened = OpenVault::open(path.clone(), b"new1", b"new2").unwrap();
        assert_eq!(reopened.vault.accounts.len(), 1);
        fs::remove_file(&path).ok();
    }

    #[test]
    fn change_password_keeps_documents_readable() {
        let path = tmp_path("rekeydoc");
        let mut v = OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();
        let mut src = std::env::temp_dir();
        src.push(format!("passmgr-src-{}.txt", nanos()));
        fs::write(&src, b"will body").unwrap();
        let id = v.add_document("/wills", "will.txt", &src).unwrap();
        v.change_password(b"c", b"d").unwrap();

        let reopened = OpenVault::open(path.clone(), b"c", b"d").unwrap();
        assert_eq!(&reopened.read_document(&id).unwrap()[..], b"will body");
        fs::remove_file(&src).ok();
        fs::remove_file(archive_path(&path)).ok();
        fs::remove_file(&path).ok();
    }

    #[test]
    fn truncated_file_detected() {
        let path = tmp_path("trunc");
        OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();
        fs::write(&path, b"PMVAULT\0").unwrap();
        assert!(OpenVault::open(path.clone(), b"a", b"b").is_err());
        fs::remove_file(&path).ok();
    }

    #[test]
    fn last_access_is_tracked() {
        let path = tmp_path("access");
        let created = OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();
        assert_eq!(created.previous_access(), 0);
        let first_access = created.vault.last_opened_at;
        let reopened = OpenVault::open(path.clone(), b"a", b"b").unwrap();
        assert_eq!(reopened.previous_access(), first_access);
        fs::remove_file(&path).ok();
    }

    #[test]
    fn rejects_absurd_kdf_params() {
        let path = tmp_path("badparams");
        OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();
        let mut raw = fs::read(&path).unwrap();
        raw[9..13].copy_from_slice(&u32::MAX.to_le_bytes());
        fs::write(&path, &raw).unwrap();
        let err = OpenVault::open(path.clone(), b"a", b"b")
            .err()
            .expect("absurd KDF params must be rejected");
        assert!(matches!(err, VaultError::BadParams));
        fs::remove_file(&path).ok();
    }

    #[test]
    fn export_reads_without_mutating() {
        let path = tmp_path("export");
        let mut v = OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();
        records::upsert(&mut v.vault.accounts, sample_account("octocat", "pw"));
        v.save().unwrap();
        let before = fs::read(&path).unwrap();

        let exported = OpenVault::export(&path, b"a", b"b").unwrap();
        assert_eq!(exported.accounts.len(), 1);

        let after = fs::read(&path).unwrap();
        assert_eq!(before, after, "export must not modify the vault file");
        assert!(OpenVault::export(&path, b"a", b"WRONG").is_err());
        fs::remove_file(&path).ok();
    }

    #[test]
    fn document_volume_round_trip() {
        let path = tmp_path("vol");
        let mut v = OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();

        let mut src = std::env::temp_dir();
        src.push(format!("passmgr-src-{}.txt", nanos()));
        fs::write(&src, b"statement contents").unwrap();

        let id1 = v.add_document("/statements/2026", "q1.txt", &src).unwrap();
        let id2 = v.add_document("/wills", "will.txt", &src).unwrap();
        assert_eq!(v.vault.volume.files.len(), 2);
        assert!(v.vault.volume.directories.contains(&"/statements".to_string()));
        assert!(v.vault.volume.uploads.iter().any(|c| c.action == "uploaded"));

        // Both documents live in ONE archive file decrypted as a unit.
        let arc = archive_path(&path);
        assert!(arc.exists(), "single archive file should exist");
        let raw = fs::read(&arc).unwrap();
        assert!(
            raw.windows(b"statement contents".len()).all(|w| w != b"statement contents"),
            "archive must be encrypted"
        );

        assert_eq!(&v.read_document(&id1).unwrap()[..], b"statement contents");

        let v2 = OpenVault::open(path.clone(), b"a", b"b").unwrap();
        assert_eq!(&v2.read_document(&id1).unwrap()[..], b"statement contents");
        assert_eq!(&v2.read_document(&id2).unwrap()[..], b"statement contents");
        assert!(v2.read_document("deadbeef").is_err());

        fs::remove_file(&src).ok();
        fs::remove_file(&arc).ok();
        fs::remove_file(&path).ok();
    }

    #[test]
    fn archive_mismatch_detected_when_stale() {
        let path = tmp_path("mismatch");
        let mut v = OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();
        let mut src = std::env::temp_dir();
        src.push(format!("passmgr-src-{}.txt", nanos()));
        fs::write(&src, b"doc").unwrap();
        v.add_document("/d", "f.txt", &src).unwrap();

        // Drop the archive: the manifest still references the document id, so the
        // on-open consistency check must reject it (a stale/missing/rolled-back .vol).
        fs::remove_file(archive_path(&path)).unwrap();
        let err = OpenVault::open(path.clone(), b"a", b"b")
            .err()
            .expect("a manifest id with no archive entry must be rejected");
        assert!(matches!(err, VaultError::ArchiveMismatch));
        fs::remove_file(&src).ok();
        fs::remove_file(&path).ok();
    }

    #[test]
    fn remove_document_reclaims_blob() {
        let path = tmp_path("rmdoc");
        let mut v = OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();
        let mut src = std::env::temp_dir();
        src.push(format!("passmgr-src-{}.txt", nanos()));
        fs::write(&src, b"doc").unwrap();
        let id = v.add_document("/d", "f.txt", &src).unwrap();
        assert!(v.read_document(&id).is_ok());

        v.remove_document(&id).unwrap();
        assert!(v.read_document(&id).is_err(), "blob is gone from the archive");
        assert!(v.vault.volume.files.iter().all(|f| f.id != id), "manifest entry removed");

        // Reopen: archive is now empty and consistent with the empty manifest.
        let v2 = OpenVault::open(path.clone(), b"a", b"b").unwrap();
        assert!(v2.vault.volume.files.is_empty());
        fs::remove_file(&src).ok();
        let _ = fs::remove_file(archive_path(&path));
        fs::remove_file(&path).ok();
    }

    #[test]
    fn compact_timestamp_is_filename_safe() {
        assert_eq!(compact_timestamp(1_609_459_200), "20210101-000000");
        assert_eq!(compact_timestamp(1_609_459_201), "20210101-000001");
        assert!(!compact_timestamp(records::unix_now()).contains([':', ' ', '/']));
    }

    #[test]
    fn backup_copies_consistent_pair() {
        let path = tmp_path("bkp");
        let mut v = OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();
        let mut src = std::env::temp_dir();
        src.push(format!("passmgr-bkpsrc-{}.txt", nanos()));
        fs::write(&src, b"doc body").unwrap();
        let id = v.add_document("/d", "f.txt", &src).unwrap();

        let dest = std::env::temp_dir().join(format!("passmgr-bkp-{}", nanos()));
        let backup_vault = backup(&path, &dest).unwrap();
        assert!(backup_vault.exists());
        assert!(archive_path(&backup_vault).exists(), "archive backed up alongside the vault");

        // The backup is a self-consistent pair: it opens and its document reads.
        let reopened = OpenVault::open(backup_vault.clone(), b"a", b"b").unwrap();
        assert_eq!(&reopened.read_document(&id).unwrap()[..], b"doc body");

        fs::remove_file(&src).ok();
        fs::remove_dir_all(&dest).ok();
        let _ = fs::remove_file(archive_path(&path));
        fs::remove_file(&path).ok();
    }

    #[test]
    fn backup_same_second_does_not_overwrite() {
        let path = tmp_path("bkdup");
        OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();
        let dest = std::env::temp_dir().join(format!("passmgr-bkdup-{}", nanos()));

        // Two backups "in the same second" must produce two distinct files.
        let b1 = backup(&path, &dest).unwrap();
        let b2 = backup(&path, &dest).unwrap();
        assert_ne!(b1, b2, "second backup must not reuse the first name");
        assert!(b1.exists() && b2.exists(), "both backups survive");

        fs::remove_dir_all(&dest).ok();
        fs::remove_file(&path).ok();
    }

    #[test]
    fn export_document_is_hardened_and_no_clobber() {
        let path = tmp_path("expdoc");
        let mut v = OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();
        let mut src = std::env::temp_dir();
        src.push(format!("passmgr-expsrc-{}.txt", nanos()));
        fs::write(&src, b"secret doc").unwrap();
        let id = v.add_document("/d", "f.txt", &src).unwrap();

        let dest = std::env::temp_dir().join(format!("passmgr-exp-{}.txt", nanos()));
        v.export_document(&id, &dest).unwrap();
        assert_eq!(fs::read(&dest).unwrap(), b"secret doc");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&dest).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "exported plaintext is owner-only");
        }
        // create_new semantics: a second export to the same path fails (no clobber).
        assert!(v.export_document(&id, &dest).is_err());

        fs::remove_file(&src).ok();
        fs::remove_file(&dest).ok();
        let _ = fs::remove_file(archive_path(&path));
        fs::remove_file(&path).ok();
    }

    #[test]
    fn generation_increments_and_is_surfaced() {
        let path = tmp_path("gen");
        let created = OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();
        let g_after_create = created.vault.generation;
        assert!(g_after_create >= 1);
        drop(created);

        let reopened = OpenVault::open(path.clone(), b"a", b"b").unwrap();
        // The generation read from disk (before this open bumped it) is surfaced.
        assert_eq!(reopened.opened_generation(), g_after_create);
        // Opening also bumps and persists a new generation.
        assert!(reopened.vault.generation > g_after_create);
        fs::remove_file(&path).ok();
    }

    #[test]
    fn malformed_archive_fails_closed() {
        let mut bad = Vec::new();
        bad.extend_from_slice(&5u32.to_le_bytes()); // claims 5 entries
        bad.extend_from_slice(&9999u32.to_le_bytes()); // absurd id_len, no data
        assert!(parse_archive(&bad).is_err());
        assert!(parse_archive(&[]).is_err());
        assert!(parse_archive(&0u32.to_le_bytes()).unwrap().is_empty());
    }
}
