//! Partitioned, lazily-loaded, crash-safe document store (format v4).
//!
//! Replaces the single `<vault>.vol` archive. Documents live under a user-chosen
//! directory in **append-only, per-blob-encrypted volumes** (`volume/vol.<N>`),
//! each indexed by an **encrypted manifest** (`manifest/manifest.<N>`). See
//! `docs/PLAN.md` and `DESIGN.md` §11 for the full design.
//!
//! Crash-safety backbone (per add/update/delete): (1) append the encrypted frame
//! to `vol.N` and **fsync**; then (2) atomically swap `manifest.N` (temp → fsync →
//! rename → fsync dir) — the storage-layer **commit point**.
//! The manifest's `end_offset` is authoritative for where valid data ends, so a
//! torn trailing frame from a crash is ignored and overwritten. A lost/corrupt
//! manifest is **rebuilt by scanning** its self-describing volume. The caller
//! (the vault) commits last, so anything here not referenced by the vault is
//! harmless garbage. Net: any crash recovers to the last fully-committed state.
//!
//! On-disk volume frame: `[u32 frame_len][nonce(24)][ciphertext]`, where
//! `ciphertext = AEAD(key, nonce, plaintext, aad = PREFIX|vault_id|partition)` and
//! `plaintext = [u32 id_len][id][u32 path_len][path][doc_bytes]`. The id/path live
//! inside the (authenticated) plaintext — not the AAD — so a rebuild can decrypt a
//! frame without first knowing them.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::crypto::{self, CryptoError, Key, NONCE_LEN};

/// AAD prefixes — separate domains for manifests and volume frames.
const MANIFEST_AAD_PREFIX: &[u8] = b"PMVAULT-MANIFEST-v1\0";
const VOLUME_AAD_PREFIX: &[u8] = b"PMVAULT-VOLUME-v1\0";

/// Max bytes for one stored document (bounds allocation on read/rebuild).
pub const MAX_DOC_SIZE: u64 = 64 * 1024 * 1024; // 64 MiB
/// Max length (bytes) of a document's virtual path (`location` + `/` + filename).
pub const MAX_PATH_LEN: usize = 256;
/// Default partition size cap; new documents roll to a fresh partition past this.
pub const DEFAULT_VOLUME_MAX_SIZE: u64 = 256 * 1024 * 1024; // 256 MiB
/// Hard ceiling on a single decrypted manifest (DoS guard).
const MAX_MANIFEST_SIZE: u64 = 256 * 1024 * 1024;

const FRAME_PREFIX_LEN: u64 = 4; // the `[u32 frame_len]`

#[derive(Error, Debug)]
pub enum StorageError {
    #[error("document not found: {0}")]
    NotFound(String),
    #[error("virtual path exceeds {MAX_PATH_LEN} bytes")]
    PathTooLong,
    #[error("document or manifest exceeds the maximum allowed size")]
    TooLarge,
    #[error("document store is corrupt: {0}")]
    Corrupt(String),
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("manifest is not valid JSON: {0}")]
    Json(#[from] serde_json::Error),
}

/// One document's entry in a partition manifest.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ManifestEntry {
    pub id: String,
    /// Virtual path: normalized `location` + `/` + filename (<= MAX_PATH_LEN).
    pub path: String,
    /// Plaintext document size in bytes.
    pub size: u64,
    /// Byte offset of the frame (its `[u32 frame_len]`) within the volume.
    pub offset: u64,
    /// Total on-disk frame length (`4 + frame_len`).
    pub length: u64,
    pub uploaded_at: i64,
}

/// A partition manifest (encrypted on disk as `nonce ‖ ciphertext`).
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
pub struct Manifest {
    /// Monotonic per-partition write counter.
    pub seq: u64,
    /// Committed valid length of the volume — the append point. Authoritative;
    /// bytes beyond it are a torn/garbage tail to ignore.
    pub end_offset: u64,
    pub entries: Vec<ManifestEntry>,
}

/// Where a document currently lives (in-memory lookup).
#[derive(Clone, Copy, Debug)]
struct Located {
    partition: u32,
    offset: u64,
    length: u64,
}

/// The partitioned document store for one vault directory.
pub struct VolumeStore {
    manifest_dir: PathBuf,
    volume_dir: PathBuf,
    vault_id: String,
    max_size: u64,
    /// `manifests[p]` is the manifest for partition `p` (partitions are 0..N).
    manifests: Vec<Manifest>,
    /// id -> location, rebuilt from `manifests` after each change.
    index: BTreeMap<String, Located>,
}

impl VolumeStore {
    /// Open (or lazily initialise) the store under `dir`, decrypting every
    /// manifest. A manifest that fails to decrypt/parse is **rebuilt** by scanning
    /// its volume. No volume bytes are read for documents (lazy). Creates nothing
    /// on disk — directories are made on the first write.
    pub fn open(dir: &Path, key: &Key, vault_id: &str, max_size: u64) -> Result<Self, StorageError> {
        let manifest_dir = dir.join("manifest");
        let volume_dir = dir.join("volume");
        let mut store = VolumeStore {
            manifest_dir,
            volume_dir,
            vault_id: vault_id.to_string(),
            max_size: max_size.max(1),
            manifests: Vec::new(),
            index: BTreeMap::new(),
        };

        // Load contiguous partitions 0,1,2,... stopping at the first absent one.
        let mut part: u32 = 0;
        loop {
            let mpath = store.manifest_path(part);
            let vpath = store.volume_path(part);
            if !mpath.exists() && !vpath.exists() {
                break;
            }
            let manifest = match store.load_manifest(part, key) {
                Ok(m) => m,
                // A missing/corrupt manifest with a present volume is rebuilt.
                Err(_) if vpath.exists() => store.rebuild_manifest(part, key)?,
                Err(e) => return Err(e),
            };
            store.manifests.push(manifest);
            part += 1;
        }
        store.reindex();
        Ok(store)
    }

    fn manifest_path(&self, part: u32) -> PathBuf {
        self.manifest_dir.join(format!("manifest.{part}"))
    }
    fn volume_path(&self, part: u32) -> PathBuf {
        self.volume_dir.join(format!("vol.{part}"))
    }

    /// Rebuild the in-memory id → location index from the loaded manifests.
    fn reindex(&mut self) {
        self.index.clear();
        for (p, m) in self.manifests.iter().enumerate() {
            for e in &m.entries {
                self.index.insert(
                    e.id.clone(),
                    Located { partition: p as u32, offset: e.offset, length: e.length },
                );
            }
        }
    }

    /// The document ids currently stored (live entries).
    pub fn ids(&self) -> impl Iterator<Item = &str> {
        self.index.keys().map(|s| s.as_str())
    }

    pub fn contains(&self, id: &str) -> bool {
        self.index.contains_key(id)
    }

    /// Metadata for a stored document (path/size), if present.
    pub fn entry(&self, id: &str) -> Option<&ManifestEntry> {
        let loc = self.index.get(id)?;
        self.manifests
            .get(loc.partition as usize)
            .and_then(|m| m.entries.iter().find(|e| e.id == id))
    }

    /// Iterate every stored document's metadata.
    pub fn entries(&self) -> impl Iterator<Item = &ManifestEntry> {
        self.manifests.iter().flat_map(|m| m.entries.iter())
    }

    /// Iterate the metadata of documents in a single partition (empty if that
    /// partition does not exist).
    pub fn partition_entries(&self, part: u32) -> impl Iterator<Item = &ManifestEntry> {
        self.manifests.get(part as usize).into_iter().flat_map(|m| m.entries.iter())
    }

    pub fn partition_count(&self) -> usize {
        self.manifests.len()
    }

    // --- Reads (lazy: open the one volume, read one frame) -------------------

    /// Decrypt and return one stored document.
    pub fn read(&self, id: &str, key: &Key) -> Result<Zeroizing<Vec<u8>>, StorageError> {
        let loc = *self.index.get(id).ok_or_else(|| StorageError::NotFound(id.to_string()))?;
        let mut f = File::open(self.volume_path(loc.partition))?;
        let (_id, _path, bytes) = read_frame_at(&mut f, loc.offset, loc.length, key, &self.aad(loc.partition))?;
        Ok(bytes)
    }

    // --- Mutations (append + atomic manifest commit) -------------------------

    /// Add or replace a document. A new id goes to the active partition (rolling
    /// to a fresh one if it would exceed `max_size`); an existing id is appended
    /// to **its own** partition (old frame becomes garbage). The append is fsync'd
    /// before the manifest is atomically committed.
    pub fn put(&mut self, id: &str, path: &str, bytes: &[u8], uploaded_at: i64, key: &Key) -> Result<(), StorageError> {
        if path.len() > MAX_PATH_LEN {
            return Err(StorageError::PathTooLong);
        }
        if bytes.len() as u64 > MAX_DOC_SIZE {
            return Err(StorageError::TooLarge);
        }

        let part = self.target_partition(id, bytes.len() as u64);
        let frame = encode_frame(key, &self.vault_id, part, id, path, bytes)?;
        self.ensure_dirs()?;

        // (1) Append the frame at the committed end_offset; fsync the volume.
        let start = self.manifests.get(part as usize).map(|m| m.end_offset).unwrap_or(0);
        append_frame(&self.volume_path(part), start, &frame)?;

        // (2) Build and atomically commit the new manifest for that partition.
        let mut manifest = self.manifests.get(part as usize).cloned().unwrap_or_default();
        manifest.entries.retain(|e| e.id != id); // replace any previous entry
        manifest.entries.push(ManifestEntry {
            id: id.to_string(),
            path: path.to_string(),
            size: bytes.len() as u64,
            offset: start,
            length: frame.len() as u64,
            uploaded_at,
        });
        manifest.end_offset = start + frame.len() as u64;
        manifest.seq += 1;
        self.commit_manifest(part, &manifest, key)?;

        // Reflect in memory only after the on-disk commit succeeds.
        if part as usize == self.manifests.len() {
            self.manifests.push(manifest);
        } else {
            self.manifests[part as usize] = manifest;
        }
        self.reindex();
        Ok(())
    }

    /// Remove a document: drop its entry from the partition manifest and commit.
    /// The blob stays in the volume as garbage (no compaction in v1).
    pub fn remove(&mut self, id: &str, key: &Key) -> Result<(), StorageError> {
        let Some(loc) = self.index.get(id).copied() else {
            return Ok(());
        };
        let mut manifest = self.manifests[loc.partition as usize].clone();
        manifest.entries.retain(|e| e.id != id);
        manifest.seq += 1;
        self.commit_manifest(loc.partition, &manifest, key)?;
        self.manifests[loc.partition as usize] = manifest;
        self.reindex();
        Ok(())
    }

    /// Choose the partition for a `put`: the document's own partition if it exists
    /// (update locality), else the active (last) partition, rolling to a new one
    /// if the frame would push it past `max_size`.
    fn target_partition(&self, id: &str, doc_size: u64) -> u32 {
        if let Some(loc) = self.index.get(id) {
            return loc.partition;
        }
        match self.manifests.last() {
            // Rough frame size estimate (doc + framing/crypto overhead) for the cap.
            Some(m) if m.end_offset + doc_size + 256 <= self.max_size => (self.manifests.len() - 1) as u32,
            Some(_) => self.manifests.len() as u32, // full → new partition
            None => 0,
        }
    }

    fn aad(&self, part: u32) -> Vec<u8> {
        volume_aad(&self.vault_id, part)
    }

    fn ensure_dirs(&self) -> Result<(), StorageError> {
        fs::create_dir_all(&self.manifest_dir)?;
        fs::create_dir_all(&self.volume_dir)?;
        harden_dir(&self.manifest_dir);
        harden_dir(&self.volume_dir);
        Ok(())
    }

    // --- Manifest I/O --------------------------------------------------------

    fn load_manifest(&self, part: u32, key: &Key) -> Result<Manifest, StorageError> {
        let path = self.manifest_path(part);
        let meta = fs::metadata(&path)?;
        if meta.len() > MAX_MANIFEST_SIZE {
            return Err(StorageError::TooLarge);
        }
        let raw = fs::read(&path)?;
        if raw.len() < NONCE_LEN {
            return Err(StorageError::Corrupt(format!("manifest.{part} truncated")));
        }
        let (nonce, ct) = raw.split_at(NONCE_LEN);
        let plain = Zeroizing::new(crypto::decrypt(key, nonce, ct, &manifest_aad(&self.vault_id, part))?);
        let manifest: Manifest = serde_json::from_slice(&plain)?;
        Ok(manifest)
    }

    /// Write `manifest.<part>` atomically: temp → fsync → rename → fsync dir.
    fn commit_manifest(&self, part: u32, manifest: &Manifest, key: &Key) -> Result<(), StorageError> {
        self.ensure_dirs()?;
        let plain = Zeroizing::new(serde_json::to_vec(manifest)?);
        let nonce = crypto::random_bytes::<NONCE_LEN>()?;
        let ct = crypto::encrypt_with_nonce(key, &nonce, &plain, &manifest_aad(&self.vault_id, part))?;
        let mut blob = Vec::with_capacity(NONCE_LEN + ct.len());
        blob.extend_from_slice(&nonce);
        blob.extend_from_slice(&ct);
        write_atomic(&self.manifest_path(part), &blob)
    }

    /// Reconstruct a partition manifest by scanning its self-describing volume up
    /// to the last decryptable frame (recovery for a lost/corrupt manifest).
    fn rebuild_manifest(&self, part: u32, key: &Key) -> Result<Manifest, StorageError> {
        let mut f = File::open(self.volume_path(part))?;
        let file_len = f.metadata()?.len();
        let aad = volume_aad(&self.vault_id, part);
        let mut offset = 0u64;
        // Last write wins for a repeated id (updates append a newer frame).
        let mut latest: BTreeMap<String, ManifestEntry> = BTreeMap::new();
        let mut order: Vec<String> = Vec::new();
        while offset + FRAME_PREFIX_LEN <= file_len {
            match read_frame_at(&mut f, offset, 0, key, &aad) {
                Ok((id, path, bytes)) => {
                    // read_frame_at(length=0) parsed the prefix to learn the size;
                    // recover the on-disk frame length to advance.
                    let frame_len = frame_total_len(&mut f, offset)?;
                    let entry = ManifestEntry {
                        id: id.clone(),
                        path,
                        size: bytes.len() as u64,
                        offset,
                        length: frame_len,
                        uploaded_at: 0,
                    };
                    if latest.insert(id.clone(), entry).is_none() {
                        order.push(id);
                    }
                    offset += frame_len;
                }
                // Torn/garbage/foreign frame → end of valid data.
                Err(_) => break,
            }
        }
        let entries: Vec<ManifestEntry> = order.into_iter().filter_map(|id| latest.remove(&id)).collect();
        Ok(Manifest { seq: 1, end_offset: offset, entries })
    }
}

// --- Frame & AAD helpers -----------------------------------------------------

fn manifest_aad(vault_id: &str, part: u32) -> Vec<u8> {
    let mut a = MANIFEST_AAD_PREFIX.to_vec();
    a.extend_from_slice(vault_id.as_bytes());
    a.extend_from_slice(&part.to_le_bytes());
    a
}

fn volume_aad(vault_id: &str, part: u32) -> Vec<u8> {
    let mut a = VOLUME_AAD_PREFIX.to_vec();
    a.extend_from_slice(vault_id.as_bytes());
    a.extend_from_slice(&part.to_le_bytes());
    a
}

/// Build a complete on-disk frame: `[u32 frame_len][nonce][ciphertext]`.
fn encode_frame(key: &Key, vault_id: &str, part: u32, id: &str, path: &str, bytes: &[u8]) -> Result<Vec<u8>, StorageError> {
    let mut plain = Vec::with_capacity(8 + id.len() + path.len() + bytes.len());
    plain.extend_from_slice(&(id.len() as u32).to_le_bytes());
    plain.extend_from_slice(id.as_bytes());
    plain.extend_from_slice(&(path.len() as u32).to_le_bytes());
    plain.extend_from_slice(path.as_bytes());
    plain.extend_from_slice(bytes);
    let plain = Zeroizing::new(plain);

    let nonce = crypto::random_bytes::<NONCE_LEN>()?;
    let ct = crypto::encrypt_with_nonce(key, &nonce, &plain, &volume_aad(vault_id, part))?;
    let frame_len = (NONCE_LEN + ct.len()) as u32;
    let mut frame = Vec::with_capacity(FRAME_PREFIX_LEN as usize + frame_len as usize);
    frame.extend_from_slice(&frame_len.to_le_bytes());
    frame.extend_from_slice(&nonce);
    frame.extend_from_slice(&ct);
    Ok(frame)
}

/// Read the `[u32 frame_len]` at `offset` and return the total frame length
/// (`4 + frame_len`), bounds-checked against the file.
fn frame_total_len(f: &mut File, offset: u64) -> Result<u64, StorageError> {
    f.seek(SeekFrom::Start(offset))?;
    let mut lb = [0u8; 4];
    f.read_exact(&mut lb)?;
    Ok(FRAME_PREFIX_LEN + u32::from_le_bytes(lb) as u64)
}

/// Read and decrypt the frame at `offset`. If `expected_len` is non-zero it is a
/// sanity check against the manifest. Returns `(id, path, doc_bytes)`. Every read
/// is bounds-checked so a corrupt length can't over-read or over-allocate.
fn read_frame_at(
    f: &mut File,
    offset: u64,
    expected_len: u64,
    key: &Key,
    aad: &[u8],
) -> Result<(String, String, Zeroizing<Vec<u8>>), StorageError> {
    let file_len = f.metadata()?.len();
    if offset + FRAME_PREFIX_LEN > file_len {
        return Err(StorageError::Corrupt("frame offset past EOF".into()));
    }
    f.seek(SeekFrom::Start(offset))?;
    let mut lb = [0u8; 4];
    f.read_exact(&mut lb)?;
    let frame_len = u32::from_le_bytes(lb) as u64;
    if frame_len < NONCE_LEN as u64 || frame_len > MAX_DOC_SIZE + 4096 {
        return Err(StorageError::Corrupt("implausible frame length".into()));
    }
    if offset + FRAME_PREFIX_LEN + frame_len > file_len {
        return Err(StorageError::Corrupt("frame overruns EOF".into()));
    }
    if expected_len != 0 && expected_len != FRAME_PREFIX_LEN + frame_len {
        return Err(StorageError::Corrupt("frame length disagrees with manifest".into()));
    }
    let mut buf = vec![0u8; frame_len as usize];
    f.read_exact(&mut buf)?;
    let (nonce, ct) = buf.split_at(NONCE_LEN);
    let plain = Zeroizing::new(crypto::decrypt(key, nonce, ct, aad)?);
    parse_plaintext(&plain)
}

/// Parse `[u32 id_len][id][u32 path_len][path][bytes]` with bounds checks.
fn parse_plaintext(plain: &[u8]) -> Result<(String, String, Zeroizing<Vec<u8>>), StorageError> {
    let mut cur = 0usize;
    let take = |cur: &mut usize, n: usize| -> Result<&[u8], StorageError> {
        let end = cur.checked_add(n).ok_or_else(|| StorageError::Corrupt("length overflow".into()))?;
        let s = plain.get(*cur..end).ok_or_else(|| StorageError::Corrupt("short frame".into()))?;
        *cur = end;
        Ok(s)
    };
    let id_len = u32::from_le_bytes(take(&mut cur, 4)?.try_into().unwrap()) as usize;
    let id = String::from_utf8(take(&mut cur, id_len)?.to_vec()).map_err(|_| StorageError::Corrupt("bad id utf8".into()))?;
    let path_len = u32::from_le_bytes(take(&mut cur, 4)?.try_into().unwrap()) as usize;
    let path = String::from_utf8(take(&mut cur, path_len)?.to_vec()).map_err(|_| StorageError::Corrupt("bad path utf8".into()))?;
    let bytes = Zeroizing::new(plain[cur..].to_vec());
    Ok((id, path, bytes))
}

// --- Crash-safe filesystem helpers ------------------------------------------

/// Append `frame` to the volume at `start`, truncating any torn tail beyond it,
/// then fsync. Opens read/write (create if absent).
fn append_frame(path: &Path, start: u64, frame: &[u8]) -> Result<(), StorageError> {
    let mut opts = OpenOptions::new();
    opts.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    harden_file(path);
    f.seek(SeekFrom::Start(start))?;
    f.write_all(frame)?;
    // Drop any pre-existing garbage tail beyond the new committed end.
    f.set_len(start + frame.len() as u64)?;
    f.sync_all()?;
    Ok(())
}

/// Atomic write: unique hidden temp in the same dir → fsync → rename → fsync dir.
fn write_atomic(path: &Path, data: &[u8]) -> Result<(), StorageError> {
    let dir = path.parent().filter(|p| !p.as_os_str().is_empty());
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("f");
    let suffix: String = crypto::random_bytes::<8>()?.iter().map(|b| format!("{b:02x}")).collect();
    let tmp = match dir {
        Some(d) => d.join(format!(".{name}.{suffix}.tmp")),
        None => PathBuf::from(format!(".{name}.{suffix}.tmp")),
    };
    {
        let mut opts = OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp)?;
        if let Err(e) = f.write_all(data).and_then(|()| f.sync_all()) {
            drop(f);
            let _ = fs::remove_file(&tmp);
            return Err(e.into());
        }
    }
    if let Err(e) = fs::rename(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(e.into());
    }
    if let Some(d) = dir {
        sync_dir(d);
    }
    Ok(())
}

#[cfg(unix)]
fn sync_dir(dir: &Path) {
    if let Ok(f) = File::open(dir) {
        let _ = f.sync_all();
    }
}
#[cfg(not(unix))]
fn sync_dir(_dir: &Path) {}

#[cfg(unix)]
fn harden_file(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = fs::metadata(path) {
        let mut perms = meta.permissions();
        perms.set_mode(0o600);
        let _ = fs::set_permissions(path, perms);
    }
}
#[cfg(not(unix))]
fn harden_file(_path: &Path) {}

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{derive_key, KdfParams};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn fast_key() -> Key {
        derive_key(b"pw", b"sixteen-byte-slt", &KdfParams { m_cost: 256, t_cost: 1, p_cost: 1 }).unwrap()
    }
    fn nanos() -> u128 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
    }
    fn tmp_dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("pmstore-{tag}-{}", nanos()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn put_read_round_trip() {
        let dir = tmp_dir("rt");
        let key = fast_key();
        let mut s = VolumeStore::open(&dir, &key, "vault-1", DEFAULT_VOLUME_MAX_SIZE).unwrap();
        s.put("id1", "/wills/will.pdf", b"last will and testament", 100, &key).unwrap();
        assert_eq!(&*s.read("id1", &key).unwrap(), b"last will and testament");
        // Reopen: lazily load manifests, read again.
        let s2 = VolumeStore::open(&dir, &key, "vault-1", DEFAULT_VOLUME_MAX_SIZE).unwrap();
        assert!(s2.contains("id1"));
        assert_eq!(&*s2.read("id1", &key).unwrap(), b"last will and testament");
        assert_eq!(s2.entry("id1").unwrap().path, "/wills/will.pdf");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn update_stays_in_same_partition_and_new_value_wins() {
        let dir = tmp_dir("upd");
        let key = fast_key();
        let mut s = VolumeStore::open(&dir, &key, "v", DEFAULT_VOLUME_MAX_SIZE).unwrap();
        s.put("a", "/p", b"v1", 1, &key).unwrap();
        s.put("a", "/p", b"version two", 2, &key).unwrap();
        assert_eq!(s.partition_count(), 1, "update reuses the same partition");
        assert_eq!(&*s.read("a", &key).unwrap(), b"version two");
        let s2 = VolumeStore::open(&dir, &key, "v", DEFAULT_VOLUME_MAX_SIZE).unwrap();
        assert_eq!(&*s2.read("a", &key).unwrap(), b"version two");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn partition_rolls_over_at_cap() {
        let dir = tmp_dir("roll");
        let key = fast_key();
        // Tiny cap so each ~1 KiB doc lands in its own partition.
        let mut s = VolumeStore::open(&dir, &key, "v", 1024).unwrap();
        let big = vec![7u8; 600];
        s.put("a", "/a", &big, 1, &key).unwrap();
        s.put("b", "/b", &big, 2, &key).unwrap();
        s.put("c", "/c", &big, 3, &key).unwrap();
        assert!(s.partition_count() >= 2, "documents rolled into new partitions");
        let s2 = VolumeStore::open(&dir, &key, "v", 1024).unwrap();
        for id in ["a", "b", "c"] {
            assert!(s2.contains(id));
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn remove_drops_entry() {
        let dir = tmp_dir("rm");
        let key = fast_key();
        let mut s = VolumeStore::open(&dir, &key, "v", DEFAULT_VOLUME_MAX_SIZE).unwrap();
        s.put("a", "/a", b"data", 1, &key).unwrap();
        s.remove("a", &key).unwrap();
        assert!(!s.contains("a"));
        assert!(matches!(s.read("a", &key), Err(StorageError::NotFound(_))));
        let s2 = VolumeStore::open(&dir, &key, "v", DEFAULT_VOLUME_MAX_SIZE).unwrap();
        assert!(!s2.contains("a"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn path_too_long_rejected() {
        let dir = tmp_dir("path");
        let key = fast_key();
        let mut s = VolumeStore::open(&dir, &key, "v", DEFAULT_VOLUME_MAX_SIZE).unwrap();
        let long = "x".repeat(MAX_PATH_LEN + 1);
        assert!(matches!(s.put("a", &long, b"d", 1, &key), Err(StorageError::PathTooLong)));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn crash_after_append_before_manifest_commit_is_ignored() {
        // Simulate a crash between the volume fsync and the manifest commit by
        // appending a raw frame to vol.0 WITHOUT updating manifest.0. On reopen,
        // the manifest's end_offset is authoritative, so the orphan is invisible.
        let dir = tmp_dir("crash1");
        let key = fast_key();
        let mut s = VolumeStore::open(&dir, &key, "v", DEFAULT_VOLUME_MAX_SIZE).unwrap();
        s.put("a", "/a", b"committed", 1, &key).unwrap();
        let committed_end = s.manifests[0].end_offset;

        // Append an extra (uncommitted) frame directly to the volume.
        let orphan = encode_frame(&key, "v", 0, "ghost", "/g", b"never committed").unwrap();
        append_frame(&dir.join("volume/vol.0"), committed_end, &orphan).unwrap();

        let s2 = VolumeStore::open(&dir, &key, "v", DEFAULT_VOLUME_MAX_SIZE).unwrap();
        assert!(s2.contains("a"), "committed doc survives");
        assert!(!s2.contains("ghost"), "uncommitted orphan is ignored");
        assert_eq!(s2.manifests[0].end_offset, committed_end);

        // A subsequent put overwrites the orphan region; data stays consistent.
        let mut s3 = VolumeStore::open(&dir, &key, "v", DEFAULT_VOLUME_MAX_SIZE).unwrap();
        s3.put("b", "/b", b"next", 2, &key).unwrap();
        assert_eq!(&*s3.read("a", &key).unwrap(), b"committed");
        assert_eq!(&*s3.read("b", &key).unwrap(), b"next");
        assert!(!s3.contains("ghost"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn corrupt_manifest_is_rebuilt_from_volume() {
        let dir = tmp_dir("rebuild");
        let key = fast_key();
        let mut s = VolumeStore::open(&dir, &key, "v", DEFAULT_VOLUME_MAX_SIZE).unwrap();
        s.put("a", "/a", b"alpha", 1, &key).unwrap();
        s.put("b", "/b", b"bravo", 2, &key).unwrap();

        // Corrupt the manifest (truncate it to garbage); the volume is intact.
        std::fs::write(dir.join("manifest/manifest.0"), b"garbage").unwrap();

        let s2 = VolumeStore::open(&dir, &key, "v", DEFAULT_VOLUME_MAX_SIZE).unwrap();
        assert_eq!(&*s2.read("a", &key).unwrap(), b"alpha");
        assert_eq!(&*s2.read("b", &key).unwrap(), b"bravo");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn torn_tail_is_ignored_and_overwritten() {
        let dir = tmp_dir("torn");
        let key = fast_key();
        let mut s = VolumeStore::open(&dir, &key, "v", DEFAULT_VOLUME_MAX_SIZE).unwrap();
        s.put("a", "/a", b"alpha", 1, &key).unwrap();
        let end = s.manifests[0].end_offset;
        // Append random trailing garbage (a torn frame) beyond the committed end.
        {
            let mut f = OpenOptions::new().write(true).open(dir.join("volume/vol.0")).unwrap();
            f.seek(SeekFrom::Start(end)).unwrap();
            f.write_all(&[0xAB; 37]).unwrap();
            f.sync_all().unwrap();
        }
        let mut s2 = VolumeStore::open(&dir, &key, "v", DEFAULT_VOLUME_MAX_SIZE).unwrap();
        assert_eq!(&*s2.read("a", &key).unwrap(), b"alpha");
        s2.put("b", "/b", b"bravo", 2, &key).unwrap();
        assert_eq!(&*s2.read("b", &key).unwrap(), b"bravo");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn foreign_vault_id_cannot_read_documents() {
        // The manifest + frames are AEAD-bound to the vault id. Opening under a
        // different id can't decrypt them, so the document is not exposed. (In the
        // real flow the id always comes from the already-decrypted vault, so this
        // is a defense-in-depth property; tampering that drops a referenced doc is
        // caught by the vault-level manifest⊆referenced check in Phase 3.)
        let dir = tmp_dir("foreign");
        let key = fast_key();
        let mut s = VolumeStore::open(&dir, &key, "vault-A", DEFAULT_VOLUME_MAX_SIZE).unwrap();
        s.put("a", "/a", b"secret", 1, &key).unwrap();
        let other = VolumeStore::open(&dir, &key, "vault-B", DEFAULT_VOLUME_MAX_SIZE).unwrap();
        assert!(!other.contains("a"), "documents are not readable under a foreign vault id");
        std::fs::remove_dir_all(&dir).ok();
    }
}
