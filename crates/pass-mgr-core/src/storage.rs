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
//!
//! --- Rust orientation for non-Rust readers (this file) ---
//! - `&T` is a *shared/read-only borrow* (a pointer the callee may read but not
//!   own); `&mut T` is an *exclusive borrow* (may mutate). Passing `&x` lends `x`
//!   without giving it away. `.clone()` makes an independent owned copy.
//! - `Result<T, E>` is either `Ok(T)` (success) or `Err(E)` (failure); `Option<T>`
//!   is either `Some(T)` or `None`. The `?` operator means "if this is `Err`/`None`,
//!   stop and return it from the current function" — concise error propagation.
//! - `unwrap()`/`expect(..)` extract the inner value but *panic* (abort) if it's
//!   `Err`/`None`; used only where the value is provably present.
//! - `match`/`if let`/`let ... else` are pattern-matching control flow.
//! - `Vec<T>` is a growable array; `String` is an owned text buffer, `&str` a
//!   borrowed view of one; `&[u8]` is a borrowed byte slice; `Path`/`PathBuf` are
//!   the borrowed/owned filesystem-path types.
//! - `#[derive(..)]` auto-generates trait implementations; `impl T { .. }` defines
//!   methods on a type; traits are like interfaces. `Zeroizing<_>` wipes its bytes
//!   from memory when dropped (secret hygiene).

use std::collections::BTreeMap; // ordered map (sorted by key), unlike a hash map
use std::fs::{self, File, OpenOptions}; // filesystem APIs (`self` re-exports the `fs` module itself)
use std::io::{Read, Seek, SeekFrom, Write}; // traits for byte readers/writers and seeking
use std::path::{Path, PathBuf}; // borrowed / owned filesystem paths

use serde::{Deserialize, Serialize}; // (de)serialization derives (used for the manifest <-> JSON)
use thiserror::Error; // derive macro that builds the std `Error` trait + messages for our enum
use zeroize::Zeroizing; // wrapper that zeroes the wrapped bytes on drop (don't leave secrets in RAM)

// `crypto::self` re-exports the module so we can call `crypto::decrypt(..)` etc.;
// `Key`, `CryptoError`, `NONCE_LEN` are pulled in by name.
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
/// Hard ceiling on a single manifest file (DoS guard).
pub const MAX_MANIFEST_SIZE: u64 = 256 * 1024 * 1024;

const FRAME_PREFIX_LEN: u64 = 4; // the `[u32 frame_len]`
/// Worst-case per-frame on-disk overhead (prefix + nonce + tag + the two length
/// prefixes + a full-length virtual path), reserved when deciding partition
/// rollover so a partition does not overshoot its size cap.
const FRAME_OVERHEAD_EST: u64 = 512;

// The error type for this module. `enum` = a tagged union: a value is exactly one
// of these variants. `#[derive(Error, Debug)]` auto-generates the std `Error` trait
// (so `?` works) plus a debug printer. Each `#[error("..")]` is the human-readable
// message; `{0}` interpolates the variant's first field.
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
    // `#[from]` auto-implements `From<CryptoError>`, so a `CryptoError` hit by `?`
    // is automatically converted into `StorageError::Crypto`. `transparent` reuses
    // the inner error's message verbatim.
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    // Same auto-conversion for std I/O errors and serde_json errors: any `?` on a
    // call returning those error types lands in the matching variant here.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("manifest is not valid JSON: {0}")]
    Json(#[from] serde_json::Error),
}

/// One document's entry in a partition manifest.
// `struct` = a record of named fields. The derives auto-generate: JSON
// (de)serialization (Serialize/Deserialize), `.clone()` (Clone), debug printing
// (Debug), and `==` equality (PartialEq/Eq). `pub` fields are visible outside this
// module.
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
// `Default` here adds `Manifest::default()` (all fields zero/empty), used when a
// partition has no manifest yet.
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
// `Copy` means this small struct is duplicated bit-for-bit on assignment (no move),
// so passing it around never invalidates the original. No `pub`, so it's private to
// this module.
#[derive(Clone, Copy, Debug)]
struct Located {
    partition: u32,
    offset: u64,
    length: u64,
}

/// The partitioned document store for one vault directory.
// Owns its directory paths and the decrypted manifests + lookup index in memory.
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

// `impl VolumeStore { .. }` attaches methods to the struct. Methods taking `&self`
// only read the store; `&mut self` may mutate it; functions without a `self`
// parameter (like `open`) are "associated functions" called as `VolumeStore::open`.
impl VolumeStore {
    /// Open (or lazily initialise) the store under `dir`, decrypting every
    /// manifest. A manifest that fails to decrypt/parse is **rebuilt** by scanning
    /// its volume. No volume bytes are read for documents (lazy). Creates nothing
    /// on disk — directories are made on the first write.
    // Borrows its inputs (`&Path`, `&Key`, `&str`) — it only reads them. Returns
    // `Self` (a new `VolumeStore`) on success. `?` inside propagates any error out.
    pub fn open(dir: &Path, key: &Key, vault_id: &str, max_size: u64) -> Result<Self, StorageError> {
        let manifest_dir = dir.join("manifest"); // join = append a path segment, returns a new PathBuf
        let volume_dir = dir.join("volume");
        // `mut` makes `store` reassignable/mutable; we populate its manifests below.
        let mut store = VolumeStore {
            manifest_dir,
            volume_dir,
            vault_id: vault_id.to_string(), // copy the borrowed &str into an owned String
            max_size: max_size.max(1),      // clamp to >= 1 to avoid a zero cap
            manifests: Vec::new(),          // empty growable vec
            index: BTreeMap::new(),         // empty ordered map
        };

        // Load contiguous partitions 0,1,2,... stopping at the first absent one.
        let mut part: u32 = 0;
        loop {
            let mpath = store.manifest_path(part);
            let vpath = store.volume_path(part);
            if !mpath.exists() && !vpath.exists() {
                break; // no more partitions on disk
            }
            // `match` selects a branch by pattern. `load_manifest` returns a Result:
            //   - Ok(m): use the decrypted manifest `m`.
            //   - Err(_) if vpath.exists(): a *guard* — only taken when the volume is
            //     present; rebuild from it (the `?` re-raises a rebuild error).
            //   - Err(e): otherwise propagate the original error.
            let manifest = match store.load_manifest(part, key) {
                Ok(m) => m,
                // Genuine corruption (won't decrypt, won't parse, or truncated) with a
                // present volume → rebuild by scanning the self-describing volume.
                Err(StorageError::Corrupt(_) | StorageError::Crypto(_) | StorageError::Json(_))
                    if vpath.exists() =>
                {
                    store.rebuild_manifest(part, key)?
                }
                // A *missing* manifest (file absent) but present volume → also rebuild.
                // But a manifest that IS present and failed for a transient/operational
                // reason (an I/O glitch, or a momentary size-cap trip) is NOT corruption:
                // propagate it rather than discard a valid manifest — and its
                // authoritative `end_offset` — via a lossy volume scan that silently
                // drops every frame past the first unreadable one.
                Err(_) if vpath.exists() && !mpath.exists() => store.rebuild_manifest(part, key)?,
                Err(e) => return Err(e),
            };
            store.manifests.push(manifest); // append to the vec
            part += 1;
        }
        store.reindex();
        Ok(store) // wrap the finished store as the success value
    }

    // `format!` builds a String; `{part}` interpolates the variable inline.
    fn manifest_path(&self, part: u32) -> PathBuf {
        self.manifest_dir.join(format!("manifest.{part}"))
    }
    fn volume_path(&self, part: u32) -> PathBuf {
        self.volume_dir.join(format!("vol.{part}"))
    }

    /// Rebuild the in-memory id → location index from the loaded manifests.
    // `&mut self`: this method mutates the store (rewrites `index`).
    fn reindex(&mut self) {
        self.index.clear();
        // `.iter().enumerate()` yields `(p, m)` pairs: `p` is the index (the
        // partition number), `m` is a shared reference to each Manifest.
        for (p, m) in self.manifests.iter().enumerate() {
            for e in &m.entries { // `&m.entries` iterates by reference (no copy/move)
                self.index.insert(
                    e.id.clone(), // map keys are owned; clone the id String to store it
                    Located { partition: p as u32, offset: e.offset, length: e.length },
                );
            }
        }
    }

    /// The document ids currently stored (live entries).
    // Return type `impl Iterator<Item = &str>` = "some iterator yielding string
    // slices"; the borrows live as long as `&self`. `.map(closure)` transforms each
    // item; `|s| s.as_str()` is a closure (anonymous fn) turning `&String` -> `&str`.
    pub fn ids(&self) -> impl Iterator<Item = &str> {
        self.index.keys().map(|s| s.as_str())
    }

    pub fn contains(&self, id: &str) -> bool {
        self.index.contains_key(id)
    }

    /// Metadata for a stored document (path/size), if present.
    // Returns `Option<&ManifestEntry>`: `Some(ref)` if found, else `None`. The `?`
    // on `index.get(id)` early-returns `None` when the id is absent. `.get(..)` on a
    // Vec is bounds-checked and also returns an Option. `.and_then(closure)` runs the
    // closure only on `Some`, flattening the nested Option. `.find(predicate)` returns
    // the first entry matching the closure `|e| e.id == id`.
    pub fn entry(&self, id: &str) -> Option<&ManifestEntry> {
        let loc = self.index.get(id)?;
        self.manifests
            .get(loc.partition as usize)
            .and_then(|m| m.entries.iter().find(|e| e.id == id))
    }

    /// Iterate every stored document's metadata.
    // `.flat_map` maps each manifest to its entries-iterator, then concatenates them
    // into one flat stream of `&ManifestEntry`.
    pub fn entries(&self) -> impl Iterator<Item = &ManifestEntry> {
        self.manifests.iter().flat_map(|m| m.entries.iter())
    }

    /// Iterate the metadata of documents in a single partition (empty if that
    /// partition does not exist).
    // `.get(..)` -> Option; `.into_iter()` turns it into an iterator of 0-or-1 items,
    // so a missing partition yields nothing (no panic).
    pub fn partition_entries(&self, part: u32) -> impl Iterator<Item = &ManifestEntry> {
        self.manifests.get(part as usize).into_iter().flat_map(|m| m.entries.iter())
    }

    pub fn partition_count(&self) -> usize {
        self.manifests.len()
    }

    /// `(committed, live)` on-disk volume bytes: `committed` is the sum of each
    /// partition's `end_offset` (the authoritative valid length), and `live` is
    /// the sum of the on-disk frame lengths still referenced by a manifest entry.
    /// `committed - live` is the **reclaimable garbage** — dead frames left by
    /// updates and deletes — that a `compact` rewrite would remove.
    pub fn space_stats(&self) -> (u64, u64) {
        let committed: u64 = self.manifests.iter().fold(0u64, |a, m| a.saturating_add(m.end_offset));
        // Sum live bytes from the UNIQUE index (one entry per id), not by summing all
        // manifest entries — a duplicate id across partitions (only reachable via a
        // crafted/corrupt authenticated manifest) would otherwise be double-counted,
        // making `committed - live` underflow-saturate to 0 and under-report garbage.
        let live: u64 = self.index.values().fold(0u64, |a, loc| a.saturating_add(loc.length));
        (committed, live)
    }

    /// Update the per-partition size cap for **future** placement decisions
    /// (existing partitions are untouched). Clamped to at least 1 byte.
    pub fn set_max_size(&mut self, max_size: u64) {
        self.max_size = max_size.max(1);
    }

    // --- Reads (lazy: open the one volume, read one frame) -------------------

    /// Decrypt and return one stored document.
    // Returns the plaintext wrapped in `Zeroizing` so the secret bytes are wiped from
    // memory when the caller drops them.
    pub fn read(&self, id: &str, key: &Key) -> Result<Zeroizing<Vec<u8>>, StorageError> {
        // `.get(id)` -> Option<&Located>; `.ok_or_else(..)` converts `None` into an
        // `Err(NotFound)`, then `?` early-returns it. The leading `*` dereferences the
        // borrowed `Located` to a copy (cheap — it is `Copy`).
        let loc = *self.index.get(id).ok_or_else(|| StorageError::NotFound(id.to_string()))?;
        let mut f = File::open(self.volume_path(loc.partition))?; // `?` propagates I/O errors
        let file_len = f.metadata()?.len();
        // Destructure the returned 3-tuple into three named bindings. `&mut f` lends
        // the file exclusively (the callee seeks/reads it); `&self.aad(..)` borrows a
        // freshly built AAD byte vector.
        let (frame_id, frame_path, bytes) =
            read_frame_at(&mut f, file_len, loc.offset, loc.length, key, &self.aad(loc.partition))?;
        // The frame's id/path are authenticated (inside the AEAD plaintext) but the
        // AAD binds only vault_id+partition, so any equal-length authentic frame in
        // the same partition would otherwise decrypt here. Verify the frame's id
        // (and path) match the manifest entry, so a relocated/substituted frame
        // cannot be served under the wrong document identity.
        if frame_id != id {
            return Err(StorageError::Corrupt(format!("frame id mismatch in partition {}", loc.partition)));
        }
        // A "let-chain": this `if` body runs only when BOTH (a) `self.entry(id)` is
        // `Some(expected)` (binding `expected`) AND (b) the stored path differs. If the
        // entry is `None`, the whole condition is false and the body is skipped.
        if let Some(expected) = self.entry(id)
            && frame_path != expected.path
        {
            return Err(StorageError::Corrupt(format!("frame path mismatch for {id}")));
        }
        Ok(bytes)
    }

    // --- Mutations (append + atomic manifest commit) -------------------------

    /// Add or replace a document. A new id goes to the active partition (rolling
    /// to a fresh one if it would exceed `max_size`); an existing id is appended
    /// to **its own** partition (old frame becomes garbage). The append is fsync'd
    /// before the manifest is atomically committed.
    // `&mut self` (mutates the store); takes its inputs by shared borrow — `bytes:
    // &[u8]` is a borrowed byte slice (the doc body, not copied). Returns `Result<(),
    // _>`: `Ok(())` is success with no payload (`()` is the empty/"unit" value).
    pub fn put(&mut self, id: &str, path: &str, bytes: &[u8], uploaded_at: i64, key: &Key) -> Result<(), StorageError> {
        if path.len() > MAX_PATH_LEN {
            return Err(StorageError::PathTooLong);
        }
        if bytes.len() as u64 > MAX_DOC_SIZE { // `as u64` is an explicit numeric cast
            return Err(StorageError::TooLarge);
        }

        let part = self.target_partition(id, bytes.len() as u64);
        let frame = encode_frame(key, &self.vault_id, part, id, path, bytes)?;
        self.ensure_dirs()?;

        // (1) Append the frame at the committed end_offset; fsync the volume.
        // `.map(|m| m.end_offset)` reads the field out of the Option if present;
        // `.unwrap_or(0)` supplies 0 for a not-yet-existing partition.
        let start = self.manifests.get(part as usize).map(|m| m.end_offset).unwrap_or(0);
        append_frame(&self.volume_path(part), start, &frame)?;
        // Fault point: a crash here (volume durable, manifest NOT yet committed)
        // must leave the frame as an ignored tail past end_offset on reopen.
        crate::fault::point("put.after_append")?;

        // (2) Build and atomically commit the new manifest for that partition.
        // `.cloned()` turns `Option<&Manifest>` into an owned `Option<Manifest>`;
        // `.unwrap_or_default()` yields a fresh empty Manifest for a new partition.
        let mut manifest = self.manifests.get(part as usize).cloned().unwrap_or_default();
        // `.retain(closure)` keeps only entries where the closure is true, i.e. drops
        // any prior entry with this id (an update supersedes the old one).
        manifest.entries.retain(|e| e.id != id); // replace any previous entry
        manifest.entries.push(ManifestEntry {
            id: id.to_string(),     // owned copies of the borrowed &str inputs
            path: path.to_string(),
            size: bytes.len() as u64,
            offset: start,
            length: frame.len() as u64,
            uploaded_at, // field shorthand: same as `uploaded_at: uploaded_at`
        });
        manifest.end_offset = start.saturating_add(frame.len() as u64);
        manifest.seq += 1;
        self.commit_manifest(part, &manifest, key)?; // disk commit point; `?` aborts on failure
        // Fault point: a crash here (both volume + manifest committed) is a fully
        // committed put; reopen must show the document.
        crate::fault::point("put.after_commit")?;

        // Reflect in memory only after the on-disk commit succeeds.
        // If `part` is one past the current end, this is a brand-new partition (push);
        // otherwise overwrite the existing slot (a `move` of `manifest` into the vec).
        if part as usize == self.manifests.len() {
            self.manifests.push(manifest);
        } else {
            self.manifests[part as usize] = manifest;
        }
        self.reindex();
        Ok(())
    }

    /// Remove a document: drop its entry from the partition manifest and commit.
    /// The blob stays in the volume as garbage until reclaimed by a `compact`
    /// volume rewrite (see `OpenVault::compact`).
    pub fn remove(&mut self, id: &str, key: &Key) -> Result<(), StorageError> {
        // `let Some(loc) = .. else { .. }`: if `index.get(id).copied()` is `Some`, bind
        // `loc`; if it's `None` (id not present), run the else block (here: nothing to
        // remove, return success). `.copied()` turns `Option<&Located>` into an owned
        // `Option<Located>` (Located is Copy).
        let Some(loc) = self.index.get(id).copied() else {
            return Ok(());
        };
        let mut manifest = self.manifests[loc.partition as usize].clone(); // work on an owned copy
        manifest.entries.retain(|e| e.id != id); // drop this id's entry (blob stays as garbage)
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
        // `if let Some(loc) = ..` runs the body only when the lookup succeeds, binding
        // the inner value to `loc`. An existing doc stays in its own partition.
        if let Some(loc) = self.index.get(id) {
            return loc.partition;
        }
        // `match` on the last manifest (`Option`): the `Some(m) if ..` arm has a guard
        // (the size check); the next `Some(_)` arm catches a full partition with `_`
        // ignoring the value; `None` means no partitions exist yet.
        match self.manifests.last() {
            // Reserve the worst-case per-frame overhead (prefix + nonce + tag +
            // id/path length prefixes + a full-length path ~= 340 B; round up) so a
            // partition does not overshoot `max_size`.
            Some(m) if m.end_offset.saturating_add(doc_size).saturating_add(FRAME_OVERHEAD_EST) <= self.max_size => {
                (self.manifests.len() - 1) as u32
            }
            Some(_) => self.manifests.len() as u32, // full → new partition
            None => 0,
        }
    }

    fn aad(&self, part: u32) -> Vec<u8> {
        volume_aad(&self.vault_id, part)
    }

    fn ensure_dirs(&self) -> Result<(), StorageError> {
        fs::create_dir_all(&self.manifest_dir)?; // make the dir (and parents); no-op if it exists
        fs::create_dir_all(&self.volume_dir)?;
        harden_dir(&self.manifest_dir); // chmod 0700 on unix (see cfg(unix) defs below)
        harden_dir(&self.volume_dir);
        // Make the volume/ and manifest/ directory entries themselves durable, so a
        // crash right after the first write can't lose the subdirectory that holds
        // a just-committed file.
        // `.parent()` returns `Option<&Path>` (None at filesystem root); `if let`
        // syncs the parent dir only when there is one.
        if let Some(vault_dir) = self.manifest_dir.parent() {
            sync_dir(vault_dir);
        }
        Ok(())
    }

    // --- Manifest I/O --------------------------------------------------------

    fn load_manifest(&self, part: u32, key: &Key) -> Result<Manifest, StorageError> {
        let path = self.manifest_path(part);
        let meta = fs::metadata(&path)?;
        if meta.len() > MAX_MANIFEST_SIZE {
            return Err(StorageError::TooLarge);
        }
        let raw = fs::read(&path)?; // read whole file into a Vec<u8>
        if raw.len() < NONCE_LEN {
            return Err(StorageError::Corrupt(format!("manifest.{part} truncated")));
        }
        // `split_at(n)` returns two slices borrowing `raw`: the nonce prefix and the
        // ciphertext remainder. The decrypted plaintext is wrapped in `Zeroizing` so
        // it is wiped after use.
        let (nonce, ct) = raw.split_at(NONCE_LEN);
        let plain = Zeroizing::new(crypto::decrypt(key, nonce, ct, &manifest_aad(&self.vault_id, part))?);
        // `from_slice` parses JSON into a `Manifest` (type annotation tells serde which
        // type to build). `?` converts a parse error to `StorageError::Json`.
        let manifest: Manifest = serde_json::from_slice(&plain)?;
        Ok(manifest)
    }

    /// Write `manifest.<part>` atomically: temp → fsync → rename → fsync dir.
    fn commit_manifest(&self, part: u32, manifest: &Manifest, key: &Key) -> Result<(), StorageError> {
        self.ensure_dirs()?;
        let plain = Zeroizing::new(serde_json::to_vec(manifest)?); // serialize to JSON bytes, wiped after
        // `random_bytes::<NONCE_LEN>()` is a generic call: `::<N>` picks the array
        // length at compile time, returning `[u8; NONCE_LEN]`.
        let nonce = crypto::random_bytes::<NONCE_LEN>()?;
        let ct = crypto::encrypt_with_nonce(key, &nonce, &plain, &manifest_aad(&self.vault_id, part))?;
        // `with_capacity` pre-allocates the exact size to avoid reallocations.
        let mut blob = Vec::with_capacity(NONCE_LEN + ct.len());
        blob.extend_from_slice(&nonce); // on-disk layout: nonce ‖ ciphertext
        blob.extend_from_slice(&ct);
        write_atomic(&self.manifest_path(part), &blob) // last expression = return value (no `;`)
    }

    /// Reconstruct a partition manifest by scanning its self-describing volume up
    /// to the last decryptable frame (recovery for a lost/corrupt manifest).
    fn rebuild_manifest(&self, part: u32, key: &Key) -> Result<Manifest, StorageError> {
        let mut f = File::open(self.volume_path(part))?;
        let file_len = f.metadata()?.len();
        let aad = volume_aad(&self.vault_id, part);
        Ok(scan_volume(&mut f, file_len, key, &aad))
    }
}

/// Scan a self-describing volume (any `Read + Seek`) from the start, decrypting
/// frame after frame, and rebuild its manifest up to the last good frame. Any
/// torn / garbage / foreign / undersized frame ends the scan, so this never
/// fails — it returns whatever prefix is intact. Used by both the on-disk
/// rebuild path and the fuzzer.
// Generic over `R` with the trait bound `R: Read + Seek` — i.e. `f` can be any type
// that can be read and seeked (a real `File`, or an in-memory `Cursor` in tests/fuzz).
// Returns a `Manifest` directly (never errors): it stops at the first bad frame.
fn scan_volume<R: Read + Seek>(f: &mut R, file_len: u64, key: &Key, aad: &[u8]) -> Manifest {
    let mut offset = 0u64;
    // Last write wins for a repeated id (updates append a newer frame).
    let mut latest: BTreeMap<String, ManifestEntry> = BTreeMap::new(); // id -> newest entry seen
    let mut order: Vec<String> = Vec::new(); // preserve first-seen order of ids
    while offset.checked_add(FRAME_PREFIX_LEN).is_some_and(|end| end <= file_len) {
        match read_frame_at(f, file_len, offset, 0, key, aad) {
            Ok((id, path, bytes)) => {
                // read_frame_at(length=0) parsed the prefix to learn the size;
                // recover the on-disk frame length to advance.
                // `let Ok(..) = .. else { break }`: on failure, stop scanning.
                let Ok(frame_len) = frame_total_len(f, offset) else { break };
                let entry = ManifestEntry {
                    id: id.clone(),
                    path,
                    size: bytes.len() as u64,
                    offset,
                    length: frame_len,
                    uploaded_at: 0,
                };
                // `insert` returns the previous value for this key (or None). If it
                // was None this is the first sighting, so record its order.
                if latest.insert(id.clone(), entry).is_none() {
                    order.push(id);
                }
                offset += frame_len; // advance to the next frame
            }
            // Torn/garbage/foreign frame → end of valid data.
            Err(_) => break, // `_` matches any error without naming it
        }
    }
    // Reassemble entries in first-seen order: `into_iter()` consumes `order` (moving
    // each id out), `filter_map` keeps only ids still in the map (and removes them),
    // `collect()` gathers the results into a Vec.
    let entries: Vec<ManifestEntry> = order.into_iter().filter_map(|id| latest.remove(&id)).collect();
    Manifest { seq: 1, end_offset: offset, entries }
}

// --- Frame & AAD helpers -----------------------------------------------------

// Builds the AEAD "associated data": prefix ‖ vault_id ‖ partition. AAD is
// authenticated-but-not-encrypted context, so a ciphertext only verifies under the
// exact same vault_id+partition it was written with (binding it in place).
fn manifest_aad(vault_id: &str, part: u32) -> Vec<u8> {
    let mut a = MANIFEST_AAD_PREFIX.to_vec(); // copy the static prefix into an owned Vec
    a.extend_from_slice(vault_id.as_bytes()); // `.as_bytes()` views the &str as &[u8]
    a.extend_from_slice(&part.to_le_bytes()); // u32 -> 4 little-endian bytes
    a // return the built vec
}

fn volume_aad(vault_id: &str, part: u32) -> Vec<u8> {
    let mut a = VOLUME_AAD_PREFIX.to_vec();
    a.extend_from_slice(vault_id.as_bytes());
    a.extend_from_slice(&part.to_le_bytes());
    a
}

/// Build a complete on-disk frame: `[u32 frame_len][nonce][ciphertext]`.
fn encode_frame(key: &Key, vault_id: &str, part: u32, id: &str, path: &str, bytes: &[u8]) -> Result<Vec<u8>, StorageError> {
    // Assemble the length-prefixed plaintext: id_len ‖ id ‖ path_len ‖ path ‖ body.
    let mut plain = Vec::with_capacity(8 + id.len() + path.len() + bytes.len());
    plain.extend_from_slice(&(id.len() as u32).to_le_bytes());
    plain.extend_from_slice(id.as_bytes());
    plain.extend_from_slice(&(path.len() as u32).to_le_bytes());
    plain.extend_from_slice(path.as_bytes());
    plain.extend_from_slice(bytes);
    // Shadowing: re-bind `plain` to a Zeroizing wrapper around the same bytes so the
    // plaintext is wiped on drop. The old binding is moved in and inaccessible after.
    let plain = Zeroizing::new(plain);

    let nonce = crypto::random_bytes::<NONCE_LEN>()?; // fresh per-frame nonce
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
fn frame_total_len<R: Read + Seek>(f: &mut R, offset: u64) -> Result<u64, StorageError> {
    f.seek(SeekFrom::Start(offset))?; // move the read cursor to `offset`
    let mut lb = [0u8; 4]; // a fixed 4-byte stack buffer for the length prefix
    f.read_exact(&mut lb)?; // fill it exactly (errors if fewer than 4 bytes remain)
    Ok(FRAME_PREFIX_LEN + u32::from_le_bytes(lb) as u64) // 4-byte prefix + the frame body
}

/// Read and decrypt the frame at `offset` within a reader of length `file_len`.
/// If `expected_len` is non-zero it is a sanity check against the manifest.
/// Returns `(id, path, doc_bytes)`. Every read is bounds-checked so a corrupt
/// length can't over-read or over-allocate.
fn read_frame_at<R: Read + Seek>(
    f: &mut R,
    file_len: u64,
    offset: u64,
    expected_len: u64,
    key: &Key,
    aad: &[u8],
) -> Result<(String, String, Zeroizing<Vec<u8>>), StorageError> {
    // `.into()` converts the string literal into the `String` the Corrupt variant
    // holds. Each check below guards against a corrupt length over-reading/-allocating.
    // `checked_add` so a corrupt/forged near-u64::MAX offset yields a clean Corrupt
    // error instead of wrapping (release) or panicking (debug-overflow). Authentic
    // offsets come from an AEAD-authenticated manifest or a bounded volume scan, so
    // this is defense-in-depth, not a reachable path with a valid vault.
    if offset.checked_add(FRAME_PREFIX_LEN).is_none_or(|end| end > file_len) {
        return Err(StorageError::Corrupt("frame offset past EOF".into()));
    }
    f.seek(SeekFrom::Start(offset))?;
    let mut lb = [0u8; 4];
    f.read_exact(&mut lb)?;
    let frame_len = u32::from_le_bytes(lb) as u64;
    // `||` is logical OR: reject a length that's too small to even hold a nonce, or
    // implausibly large. This bound runs before any allocation.
    if frame_len < NONCE_LEN as u64 || frame_len > MAX_DOC_SIZE + 4096 {
        return Err(StorageError::Corrupt("implausible frame length".into()));
    }
    if offset
        .checked_add(FRAME_PREFIX_LEN)
        .and_then(|x| x.checked_add(frame_len))
        .is_none_or(|end| end > file_len)
    {
        return Err(StorageError::Corrupt("frame overruns EOF".into()));
    }
    // `&&` is logical AND: only check the manifest agreement when a non-zero
    // `expected_len` was supplied (scan_volume passes 0 to skip this).
    if expected_len != 0 && expected_len != FRAME_PREFIX_LEN + frame_len {
        return Err(StorageError::Corrupt("frame length disagrees with manifest".into()));
    }
    let mut buf = vec![0u8; frame_len as usize]; // `vec![v; n]` = a Vec of `n` copies of `v`
    f.read_exact(&mut buf)?;
    let (nonce, ct) = buf.split_at(NONCE_LEN); // split the frame body into nonce ‖ ciphertext
    let plain = Zeroizing::new(crypto::decrypt(key, nonce, ct, aad)?); // AEAD-verify + decrypt
    parse_plaintext(&plain) // returns (id, path, body); its result becomes ours
}

/// Parse `[u32 id_len][id][u32 path_len][path][bytes]` with bounds checks.
fn parse_plaintext(plain: &[u8]) -> Result<(String, String, Zeroizing<Vec<u8>>), StorageError> {
    let mut cur = 0usize; // running offset into `plain`
    // A closure (anonymous helper) that reads the next `n` bytes and advances `cur`.
    // It borrows `cur` mutably (`&mut usize`) so it can update the caller's offset.
    let take = |cur: &mut usize, n: usize| -> Result<&[u8], StorageError> {
        // `checked_add` returns None on integer overflow (instead of wrapping), so a
        // hostile huge length can't wrap past the buffer; `?` turns None-handling into
        // an early error here.
        let end = cur.checked_add(n).ok_or_else(|| StorageError::Corrupt("length overflow".into()))?;
        // `plain.get(range)` is bounds-checked, returning None if the range exceeds the
        // slice — so a lying length yields an error, never an out-of-bounds read.
        let s = plain.get(*cur..end).ok_or_else(|| StorageError::Corrupt("short frame".into()))?;
        *cur = end; // `*cur` writes through the mutable borrow
        Ok(s)
    };
    // `.try_into().unwrap()` converts the 4-byte slice to a `[u8; 4]` array; it cannot
    // fail here because `take(.., 4)` returned exactly 4 bytes, so the unwrap is safe.
    let id_len = u32::from_le_bytes(take(&mut cur, 4)?.try_into().unwrap()) as usize;
    // `String::from_utf8` validates UTF-8; `.map_err(..)` rewrites its error into our
    // Corrupt variant; `?` propagates it. `.to_vec()` copies the borrowed bytes into
    // an owned Vec the String can take ownership of.
    let id = String::from_utf8(take(&mut cur, id_len)?.to_vec()).map_err(|_| StorageError::Corrupt("bad id utf8".into()))?;
    let path_len = u32::from_le_bytes(take(&mut cur, 4)?.try_into().unwrap()) as usize;
    let path = String::from_utf8(take(&mut cur, path_len)?.to_vec()).map_err(|_| StorageError::Corrupt("bad path utf8".into()))?;
    let bytes = Zeroizing::new(plain[cur..].to_vec()); // everything after the headers is the body
    Ok((id, path, bytes))
}

// --- Crash-safe filesystem helpers ------------------------------------------

/// Append `frame` to the volume at `start`, truncating any torn tail beyond it,
/// then fsync. Opens read/write (create if absent).
fn append_frame(path: &Path, start: u64, frame: &[u8]) -> Result<(), StorageError> {
    // Refuse to write through a symlink planted at the volume path: an attacker
    // with write access to the vault dir could otherwise redirect our writes (and
    // the 0600 chmod) to an arbitrary file the user can write. The atomic
    // manifest/vault writes use O_EXCL + rename; this append path opens the file
    // directly, so it needs its own guard.
    // This stat is a fast, friendly EARLY rejection — but it is NOT the security
    // boundary, because the file could be swapped for a symlink between this check
    // and the open below (a TOCTOU race). The atomic guarantee comes from opening
    // with O_NOFOLLOW (see below), which makes the kernel refuse a final-component
    // symlink at open time. `symlink_metadata` does not follow the link.
    if let Ok(meta) = fs::symlink_metadata(path)
        && meta.file_type().is_symlink()
    {
        return Err(StorageError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "refusing to write through a symlink at the volume path",
        )));
    }
    let mut opts = OpenOptions::new(); // builder for how to open the file
    opts.read(true).write(true).create(true); // chained builder calls
    // `#[cfg(unix)]` compiles this block ONLY on unix targets (conditional
    // compilation). It sets 0600 perms and, crucially, adds `O_NOFOLLOW` so the
    // open itself fails atomically (ELOOP) if the path's final component is a
    // symlink — closing the TOCTOU window the stat above cannot. `custom_flags` is
    // a safe API (no `unsafe`); the flag only affects the final component, matching
    // the stat's scope. Legitimate `vol.<N>` files are regular files, so this never
    // rejects a valid append.
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600); // owner read/write only
        opts.custom_flags(libc::O_NOFOLLOW);
    }
    let mut f = opts.open(path)?;
    harden_file(path); // belt-and-suspenders chmod (no-op on non-unix)
    f.seek(SeekFrom::Start(start))?;
    crate::fault::point("volume.write")?; // inject ENOSPC before the volume append
    f.write_all(frame)?; // `frame: &[u8]` is borrowed, not consumed
    // Drop any pre-existing garbage tail beyond the new committed end.
    f.set_len(start + frame.len() as u64)?;
    f.sync_all()?; // fsync: force the bytes (and metadata) to durable storage
    // Make the (possibly newly created) vol.<N> directory entry durable BEFORE its
    // referencing manifest is committed, so a crash can never leave a committed
    // manifest pointing at a volume the filesystem never durably linked.
    if let Some(dir) = path.parent() {
        sync_dir(dir);
    }
    Ok(())
}

/// Atomic write: unique hidden temp in the same dir → fsync → rename → fsync dir.
fn write_atomic(path: &Path, data: &[u8]) -> Result<(), StorageError> {
    // `.filter(closure)` keeps the parent only if the closure is true (here: non-empty),
    // otherwise yields None.
    let dir = path.parent().filter(|p| !p.as_os_str().is_empty());
    // `.and_then` chains another Option-returning step (bytes -> valid UTF-8 name);
    // `.unwrap_or("f")` supplies a fallback name if either step yields None.
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("f");
    // Build a random hex suffix: map each random byte to a 2-char hex string, then
    // `.collect()` concatenates them into one String (target type from the annotation).
    let suffix: String = crypto::random_bytes::<8>()?.iter().map(|b| format!("{b:02x}")).collect();
    let tmp = match dir {
        Some(d) => d.join(format!(".{name}.{suffix}.tmp")), // hidden temp beside the target
        None => PathBuf::from(format!(".{name}.{suffix}.tmp")),
    };
    {
        // Inner scope so the file `f` is dropped (closed) at the closing brace, before
        // the rename below.
        let mut opts = OpenOptions::new();
        opts.write(true).create_new(true); // create_new fails if the temp already exists (O_EXCL)
        #[cfg(unix)] // unix-only permission setting
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp)?;
        // Write then fsync, chained: `and_then(|()| ..)` runs the sync only if the write
        // succeeded. On any error (incl. an injected ENOSPC), close the file and remove
        // the temp before returning — the live target is never touched.
        if let Err(e) = crate::fault::point("atomic.write")
            .and_then(|()| f.write_all(data))
            .and_then(|()| f.sync_all())
        {
            drop(f); // close explicitly before deleting
            let _ = fs::remove_file(&tmp); // `let _ =` deliberately ignores the result
            return Err(e.into()); // `.into()` converts io::Error -> StorageError
        }
    }
    // Atomic step: rename temp over the target. On a crash, either the old or new file
    // is fully present — never a half-written one. The fault point models a failure
    // (e.g. ENOSPC) at the rename; on any error the temp is removed and the live
    // target is left untouched.
    if let Err(e) =
        crate::fault::point("atomic.rename").map_err(StorageError::from).and_then(|()| Ok(fs::rename(&tmp, path)?))
    {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    if let Some(d) = dir {
        sync_dir(d); // fsync the directory so the rename itself is durable
    }
    Ok(())
}

// These functions are defined twice: the `#[cfg(unix)]` version is compiled on unix;
// the `#[cfg(not(unix))]` version (a no-op) is compiled everywhere else. Only one of
// each pair exists in any given build, so callers don't need to branch.

#[cfg(unix)]
fn sync_dir(dir: &Path) {
    // Open the directory and fsync it (commits the directory entry itself). Errors are
    // ignored (`if let Ok` / `let _`) — best-effort durability.
    if let Ok(f) = File::open(dir) {
        let _ = f.sync_all();
    }
}
#[cfg(not(unix))]
fn sync_dir(_dir: &Path) {} // no-op; `_dir` underscore-prefix marks it intentionally unused

#[cfg(unix)]
fn harden_file(path: &Path) {
    use std::os::unix::fs::PermissionsExt; // brings `set_mode` into scope
    if let Ok(meta) = fs::metadata(path) {
        let mut perms = meta.permissions();
        perms.set_mode(0o600); // owner read/write only
        let _ = fs::set_permissions(path, perms);
    }
}
#[cfg(not(unix))]
fn harden_file(_path: &Path) {} // no-op off unix (permission bits don't apply the same way)

#[cfg(unix)]
fn harden_dir(dir: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = fs::metadata(dir) {
        let mut perms = meta.permissions();
        perms.set_mode(0o700); // owner-only directory access
        let _ = fs::set_permissions(dir, perms);
    }
}
#[cfg(not(unix))]
fn harden_dir(_dir: &Path) {} // no-op off unix

/// Fuzz entry points: feed arbitrary bytes into the untrusted-input parsers.
/// The invariant is strict — these must only ever return (`Ok`/`Err` internally),
/// never panic, hang, or over-allocate, no matter the input.
// `pub mod fuzz` is a nested public sub-module.
pub mod fuzz {
    use super::*; // re-import everything from the parent module (this file)
    use std::io::Cursor; // an in-memory `Read + Seek` over a byte buffer
    use std::sync::OnceLock; // a thread-safe cell initialised at most once

    /// A cheap, process-wide key so fuzzing the scanner doesn't pay an Argon2
    /// derivation per input (decryption fails on arbitrary bytes regardless; the
    /// key value is irrelevant to the parse/bounds logic under test).
    // Returns `&'static Key`: a reference valid for the whole program lifetime
    // (`'static`), since the key lives in a process-wide cell.
    fn fuzz_key() -> &'static Key {
        // `static` is a single global; `OnceLock` lets us lazily build the key on first
        // use and reuse it thereafter.
        static KEY: OnceLock<Key> = OnceLock::new();
        // `get_or_init(closure)` runs the closure once to populate the cell, then always
        // returns the stored reference. `.expect(..)` panics with this message if the
        // derivation fails (acceptable in a fuzz harness).
        KEY.get_or_init(|| {
            crypto::derive_key(b"fuzz", b"sixteen-byte-slt", &crypto::KdfParams { m_cost: 8, t_cost: 1, p_cost: 1 })
                .expect("fuzz key derivation")
        })
    }

    /// The decrypted-manifest JSON parser (post-decrypt path).
    pub fn manifest(buf: &[u8]) {
        let _ = serde_json::from_slice::<Manifest>(buf);
    }

    /// The hand-rolled decrypted-frame plaintext parser
    /// (`[u32 id_len][id][u32 path_len][path][bytes]`) — the highest-risk
    /// length-prefixed surface for an out-of-bounds read or over-allocation.
    pub fn frame(buf: &[u8]) {
        let _ = parse_plaintext(buf);
    }

    /// The volume scan/rebuild path over arbitrary bytes: exercises the frame
    /// length prefix, the bounds checks, and the seek/advance loop.
    pub fn scan_volume(buf: &[u8]) {
        let aad = volume_aad("fuzz", 0);
        let mut cur = Cursor::new(buf); // wrap the bytes so they look like a seekable file
        // `super::scan_volume` disambiguates the parent's function from this module's
        // same-named wrapper. `let _ =` discards the returned Manifest (we only care
        // that it doesn't panic/over-allocate).
        let _ = super::scan_volume(&mut cur, buf.len() as u64, fuzz_key(), &aad);
    }
}

// `#[cfg(test)]` compiles this whole module ONLY under `cargo test`, so the tests add
// no code to the shipped binary. Each `#[test]` fn is a test case; `assert!` /
// `assert_eq!` panic (fail the test) when their condition is false. `.unwrap()` here
// is fine because a panic in a test is just a test failure.
#[cfg(test)]
mod tests {
    use super::*; // pull in everything from the parent module under test
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

    // ---- Phase 7: parsers, AAD binding, bounds, nonce uniqueness, crash matrix --

    /// Build a decrypted-frame plaintext `[u32 id_len][id][u32 path_len][path][body]`.
    fn frame_plaintext(id: &str, path: &str, body: &[u8]) -> Vec<u8> {
        let mut p = Vec::new();
        p.extend_from_slice(&(id.len() as u32).to_le_bytes());
        p.extend_from_slice(id.as_bytes());
        p.extend_from_slice(&(path.len() as u32).to_le_bytes());
        p.extend_from_slice(path.as_bytes());
        p.extend_from_slice(body);
        p
    }

    #[test]
    fn frame_plaintext_round_trips_and_rejects_malformed() {
        let p = frame_plaintext("the-id", "/loc/file.pdf", b"body bytes");
        let (id, path, body) = parse_plaintext(&p).unwrap();
        assert_eq!(id, "the-id");
        assert_eq!(path, "/loc/file.pdf");
        assert_eq!(&body[..], b"body bytes");
        // Too short for even the id-length prefix.
        assert!(parse_plaintext(b"\x01\x00").is_err());
        // id_len claims more bytes than are present.
        let mut short = (99u32).to_le_bytes().to_vec();
        short.extend_from_slice(b"abc");
        assert!(matches!(parse_plaintext(&short), Err(StorageError::Corrupt(_))));
        // id_len = u32::MAX must not wrap or over-allocate.
        let mut huge = u32::MAX.to_le_bytes().to_vec();
        huge.extend_from_slice(b"x");
        assert!(parse_plaintext(&huge).is_err());
    }

    #[test]
    fn read_frame_at_bounds_and_per_blob_aad() {
        let dir = tmp_dir("frame");
        let key = fast_key();
        let aad0 = volume_aad("v", 0);
        let frame = encode_frame(&key, "v", 0, "id", "/p", b"payload").unwrap();
        let vol = dir.join("vol");
        append_frame(&vol, 0, &frame).unwrap();
        let mut f = File::open(&vol).unwrap();
        let len = f.metadata().unwrap().len();
        // Correct read, including the expected-length sanity check.
        let (id, path, body) = read_frame_at(&mut f, len, 0, len, &key, &aad0).unwrap();
        assert_eq!((id.as_str(), path.as_str(), &body[..]), ("id", "/p", &b"payload"[..]));
        // Per-blob AAD binding: a frame for partition 0 won't authenticate as 1.
        assert!(read_frame_at(&mut f, len, 0, 0, &key, &volume_aad("v", 1)).is_err());
        // Foreign vault-id AAD also fails.
        assert!(read_frame_at(&mut f, len, 0, 0, &key, &volume_aad("other", 0)).is_err());
        // An expected-length that disagrees with the manifest is rejected.
        assert!(read_frame_at(&mut f, len, 0, len + 1, &key, &aad0).is_err());
        // Offset past EOF.
        assert!(read_frame_at(&mut f, len, len + 1, 0, &key, &aad0).is_err());
        // A corrupt length prefix (u32::MAX) is rejected, not over-read.
        {
            let mut w = OpenOptions::new().write(true).open(&vol).unwrap();
            w.write_all(&u32::MAX.to_le_bytes()).unwrap();
            w.sync_all().unwrap();
        }
        let mut f2 = File::open(&vol).unwrap();
        let len2 = f2.metadata().unwrap().len();
        assert!(read_frame_at(&mut f2, len2, 0, 0, &key, &aad0).is_err());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn manifest_aad_binds_vault_id_and_partition() {
        let dir = tmp_dir("maad");
        let key = fast_key();
        let mut s = VolumeStore::open(&dir, &key, "vault-A", DEFAULT_VOLUME_MAX_SIZE).unwrap();
        s.put("a", "/a", b"data", 1, &key).unwrap();
        let raw = std::fs::read(dir.join("manifest/manifest.0")).unwrap();
        let (nonce, ct) = raw.split_at(NONCE_LEN);
        // The right AAD decrypts; the wrong vault id or partition does not.
        assert!(crypto::decrypt(&key, nonce, ct, &manifest_aad("vault-A", 0)).is_ok());
        assert!(crypto::decrypt(&key, nonce, ct, &manifest_aad("vault-B", 0)).is_err());
        assert!(crypto::decrypt(&key, nonce, ct, &manifest_aad("vault-A", 1)).is_err());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn frame_nonces_are_unique_across_writes() {
        let dir = tmp_dir("nonce");
        let key = fast_key();
        let mut s = VolumeStore::open(&dir, &key, "v", DEFAULT_VOLUME_MAX_SIZE).unwrap();
        for i in 0..50 {
            s.put(&format!("id{i}"), "/p", b"identical body", i as i64, &key).unwrap();
        }
        let bytes = std::fs::read(dir.join("volume/vol.0")).unwrap();
        let mut nonces = std::collections::BTreeSet::new();
        let mut off = 0usize;
        while off + 4 <= bytes.len() {
            let flen = u32::from_le_bytes(bytes[off..off + 4].try_into().unwrap()) as usize;
            let nstart = off + 4;
            if nstart + NONCE_LEN > bytes.len() {
                break;
            }
            nonces.insert(bytes[nstart..nstart + NONCE_LEN].to_vec());
            off = nstart + flen;
        }
        assert_eq!(nonces.len(), 50, "every frame uses a distinct nonce");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn wrong_key_cannot_read_blob() {
        let dir = tmp_dir("wrongkey");
        let key = fast_key();
        let mut s = VolumeStore::open(&dir, &key, "v", DEFAULT_VOLUME_MAX_SIZE).unwrap();
        s.put("a", "/a", b"secret", 1, &key).unwrap();
        let other =
            derive_key(b"different", b"sixteen-byte-slt", &KdfParams { m_cost: 256, t_cost: 1, p_cost: 1 }).unwrap();
        assert!(s.read("a", &other).is_err(), "a foreign key cannot decrypt the blob");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn mid_file_corrupt_frame_stops_rebuild_at_last_good() {
        let dir = tmp_dir("midcorrupt");
        let key = fast_key();
        let mut s = VolumeStore::open(&dir, &key, "v", DEFAULT_VOLUME_MAX_SIZE).unwrap();
        s.put("a", "/a", b"alpha", 1, &key).unwrap();
        let b_off = s.manifests[0].end_offset; // where b's frame will start
        s.put("b", "/b", b"bravo", 2, &key).unwrap();
        s.put("c", "/c", b"charlie", 3, &key).unwrap();
        // Flip a byte inside b's ciphertext (just past its 4-byte len + nonce).
        {
            let mut w = OpenOptions::new().read(true).write(true).open(dir.join("volume/vol.0")).unwrap();
            let pos = b_off + 4 + NONCE_LEN as u64;
            w.seek(SeekFrom::Start(pos)).unwrap();
            let mut byte = [0u8; 1];
            w.read_exact(&mut byte).unwrap();
            w.seek(SeekFrom::Start(pos)).unwrap();
            w.write_all(&[byte[0] ^ 0xFF]).unwrap();
            w.sync_all().unwrap();
        }
        // Clobber the manifest to force a rebuild by scanning the volume.
        std::fs::write(dir.join("manifest/manifest.0"), b"x").unwrap();
        let s2 = VolumeStore::open(&dir, &key, "v", DEFAULT_VOLUME_MAX_SIZE).unwrap();
        assert!(s2.contains("a"), "frames before the corruption recover");
        assert!(!s2.contains("b") && !s2.contains("c"), "the scan stops at the corrupt frame");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn stray_temp_file_does_not_disturb_open() {
        // A crash mid manifest temp-write leaves a hidden ".*.tmp" sibling; it must
        // be ignored (only manifest.<N> is authoritative).
        let dir = tmp_dir("tmp");
        let key = fast_key();
        let mut s = VolumeStore::open(&dir, &key, "v", DEFAULT_VOLUME_MAX_SIZE).unwrap();
        s.put("a", "/a", b"data", 1, &key).unwrap();
        std::fs::write(dir.join("manifest/.manifest.0.deadbeef.tmp"), b"garbage temp").unwrap();
        let s2 = VolumeStore::open(&dir, &key, "v", DEFAULT_VOLUME_MAX_SIZE).unwrap();
        assert_eq!(&*s2.read("a", &key).unwrap(), b"data");
        assert_eq!(s2.partition_count(), 1);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn frame_substitution_within_partition_is_rejected() {
        // Two equal-length, individually-authentic frames in the same partition.
        let dir = tmp_dir("swap");
        let key = fast_key();
        let mut s = VolumeStore::open(&dir, &key, "v", DEFAULT_VOLUME_MAX_SIZE).unwrap();
        s.put("a", "/x", b"AAAAAAAAAA", 1, &key).unwrap();
        s.put("b", "/y", b"BBBBBBBBBB", 2, &key).unwrap();
        let ea = s.entry("a").unwrap().clone();
        let eb = s.entry("b").unwrap().clone();
        assert_eq!(ea.length, eb.length, "frames must be equal length for the swap");
        // Swap the two frames' bytes in the volume (the manifest is untouched).
        let volp = dir.join("volume/vol.0");
        let mut bytes = std::fs::read(&volp).unwrap();
        let (oa, ob, len) = (ea.offset as usize, eb.offset as usize, ea.length as usize);
        let fa = bytes[oa..oa + len].to_vec();
        let fb = bytes[ob..ob + len].to_vec();
        bytes[oa..oa + len].copy_from_slice(&fb);
        bytes[ob..ob + len].copy_from_slice(&fa);
        std::fs::write(&volp, &bytes).unwrap();
        // The substituted frame's authenticated id no longer matches the manifest.
        let s2 = VolumeStore::open(&dir, &key, "v", DEFAULT_VOLUME_MAX_SIZE).unwrap();
        assert!(matches!(s2.read("a", &key), Err(StorageError::Corrupt(_))), "swap into a detected");
        assert!(matches!(s2.read("b", &key), Err(StorageError::Corrupt(_))), "swap into b detected");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn append_frame_refuses_to_write_through_a_symlink() {
        let dir = tmp_dir("symlink");
        let key = fast_key();
        std::fs::create_dir_all(dir.join("volume")).unwrap();
        let target = dir.join("secret_target");
        std::fs::write(&target, b"do not touch").unwrap();
        std::os::unix::fs::symlink(&target, dir.join("volume/vol.0")).unwrap();
        let mut s = VolumeStore::open(&dir, &key, "v", DEFAULT_VOLUME_MAX_SIZE).unwrap();
        assert!(matches!(s.put("a", "/a", b"data", 1, &key), Err(StorageError::Io(_))));
        assert_eq!(std::fs::read(&target).unwrap(), b"do not touch", "symlink target untouched");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn manifest_seq_advances_on_each_committed_change() {
        // The per-partition manifest sequence counter advances on every committed put
        // and remove (locks the format invariant; kills `seq += 1` -> `seq *= 1`).
        let dir = tmp_dir("seq");
        let key = fast_key();
        let mut s = VolumeStore::open(&dir, &key, "v", DEFAULT_VOLUME_MAX_SIZE).unwrap();
        s.put("a", "/a", b"one", 1, &key).unwrap();
        let after_put = s.manifests[0].seq;
        s.put("a", "/a", b"two", 2, &key).unwrap(); // update the same id
        let after_update = s.manifests[0].seq;
        s.remove("a", &key).unwrap();
        let after_remove = s.manifests[0].seq;
        assert!(after_update > after_put, "seq advances on update ({after_put} -> {after_update})");
        assert!(after_remove > after_update, "seq advances on remove ({after_update} -> {after_remove})");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn missing_manifest_on_higher_partition_is_rebuilt() {
        // Kills the `&&` -> `||` mutant in the partition scan: a partition with a
        // present volume but missing manifest must still be loaded (rebuilt).
        let dir = tmp_dir("higherrebuild");
        let key = fast_key();
        let mut s = VolumeStore::open(&dir, &key, "v", 1024).unwrap();
        let big = vec![5u8; 600];
        s.put("a", "/a", &big, 1, &key).unwrap();
        s.put("b", "/b", &big, 2, &key).unwrap();
        assert!(s.partition_count() >= 2, "docs span >= 2 partitions");
        std::fs::remove_file(dir.join("manifest/manifest.1")).unwrap();
        let s2 = VolumeStore::open(&dir, &key, "v", 1024).unwrap();
        assert!(s2.contains("a"), "partition 0 intact");
        assert!(s2.contains("b"), "partition 1 rebuilt from its volume");
        assert_eq!(&*s2.read("b", &key).unwrap(), &big[..]);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn read_frame_at_rejects_subnonce_frame_length() {
        // Kills the `||` -> `&&` mutant in the plausibility check: a frame_len below
        // NONCE_LEN must be rejected, not cause an OOB split_at on a short buffer.
        let dir = tmp_dir("subnonce");
        let key = fast_key();
        let aad = volume_aad("v", 0);
        let vol = dir.join("vol");
        let mut raw = 10u32.to_le_bytes().to_vec(); // frame_len = 10 (< NONCE_LEN = 24)
        raw.extend_from_slice(&[0u8; 10]);
        std::fs::write(&vol, &raw).unwrap();
        let mut f = File::open(&vol).unwrap();
        let len = f.metadata().unwrap().len();
        assert!(read_frame_at(&mut f, len, 0, 0, &key, &aad).is_err());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn volume_and_manifest_files_are_hardened() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tmp_dir("perms");
        let key = fast_key();
        let mut s = VolumeStore::open(&dir, &key, "v", DEFAULT_VOLUME_MAX_SIZE).unwrap();
        s.put("a", "/a", b"data", 1, &key).unwrap();
        let mode = |p: PathBuf| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(dir.join("volume/vol.0")), 0o600, "volume file is 0600");
        assert_eq!(mode(dir.join("manifest/manifest.0")), 0o600, "manifest file is 0600");
        assert_eq!(mode(dir.join("volume")), 0o700, "volume dir is 0700");
        assert_eq!(mode(dir.join("manifest")), 0o700, "manifest dir is 0700");
        std::fs::remove_dir_all(&dir).ok();
    }

    // `proptest!` is property-based testing: instead of fixed inputs, it generates many
    // random inputs matching each parameter's strategy (e.g. the regex `"[ -~]{0,40}"`
    // or `vec(any::<u8>(), 0..200)`) and asserts the property holds for all of them.
    // `prop_assert_eq!` is the property-test form of `assert_eq!`.
    // ---- Full-disk (ENOSPC) fault injection (cargo test --features fault-injection) ----

    #[cfg(feature = "fault-injection")]
    #[test]
    fn enospc_on_volume_append_leaves_prior_state_intact() {
        let dir = tmp_dir("enospc-vol");
        let key = fast_key();
        let mut s = VolumeStore::open(&dir, &key, "v", DEFAULT_VOLUME_MAX_SIZE).unwrap();
        s.put("a", "/a", b"alpha", 1, &key).unwrap();
        // Disk fills exactly as the next document's frame is about to be written.
        crate::fault::fail_at("volume.write", 1);
        let err = s.put("b", "/b", b"bravo", 2, &key).unwrap_err();
        crate::fault::clear();
        assert!(matches!(err, StorageError::Io(_)), "put fails cleanly, got {err:?}");
        // Reopen: the failed put left no trace; the prior doc is intact and a later
        // put now succeeds.
        let mut s2 = VolumeStore::open(&dir, &key, "v", DEFAULT_VOLUME_MAX_SIZE).unwrap();
        assert!(s2.contains("a") && !s2.contains("b"));
        assert_eq!(&*s2.read("a", &key).unwrap(), b"alpha");
        s2.put("b", "/b", b"bravo", 2, &key).unwrap();
        assert_eq!(&*s2.read("b", &key).unwrap(), b"bravo");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(feature = "fault-injection")]
    #[test]
    fn enospc_on_manifest_commit_ignores_the_uncommitted_frame() {
        let dir = tmp_dir("enospc-man");
        let key = fast_key();
        let mut s = VolumeStore::open(&dir, &key, "v", DEFAULT_VOLUME_MAX_SIZE).unwrap();
        s.put("a", "/a", b"alpha", 1, &key).unwrap();
        // The volume append succeeds but the manifest commit hits a full disk: the
        // new frame is now a torn tail past the committed end_offset.
        crate::fault::fail_at("atomic.write", 1);
        assert!(s.put("b", "/b", b"bravo", 2, &key).is_err());
        crate::fault::clear();
        let mut s2 = VolumeStore::open(&dir, &key, "v", DEFAULT_VOLUME_MAX_SIZE).unwrap();
        assert!(s2.contains("a") && !s2.contains("b"), "uncommitted frame is invisible");
        assert_eq!(&*s2.read("a", &key).unwrap(), b"alpha");
        // The torn tail is overwritten by the next successful put — no corruption.
        s2.put("c", "/c", b"charlie", 3, &key).unwrap();
        assert_eq!(&*s2.read("a", &key).unwrap(), b"alpha");
        assert_eq!(&*s2.read("c", &key).unwrap(), b"charlie");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(feature = "fault-injection")]
    #[test]
    fn enospc_on_manifest_rename_keeps_old_manifest() {
        let dir = tmp_dir("enospc-ren");
        let key = fast_key();
        let mut s = VolumeStore::open(&dir, &key, "v", DEFAULT_VOLUME_MAX_SIZE).unwrap();
        s.put("a", "/a", b"alpha", 1, &key).unwrap();
        crate::fault::fail_at("atomic.rename", 1);
        assert!(s.put("b", "/b", b"bravo", 2, &key).is_err());
        crate::fault::clear();
        // No stray manifest temp is loaded; the old manifest stands.
        let s2 = VolumeStore::open(&dir, &key, "v", DEFAULT_VOLUME_MAX_SIZE).unwrap();
        assert!(s2.contains("a") && !s2.contains("b"));
        assert_eq!(&*s2.read("a", &key).unwrap(), b"alpha");
        std::fs::remove_dir_all(&dir).ok();
    }

    use proptest::prelude::*;
    proptest! {
        /// Length-prefixed frames round-trip for arbitrary id/path/body, even with
        /// separators or non-ASCII bytes embedded in the (authenticated) plaintext.
        #[test]
        fn prop_frame_plaintext_round_trips(
            id in "[ -~]{0,40}",
            path in "[ -~]{0,80}",
            body in proptest::collection::vec(any::<u8>(), 0..200),
        ) {
            let p = frame_plaintext(&id, &path, &body);
            let (rid, rpath, rbody) = parse_plaintext(&p).unwrap();
            prop_assert_eq!(rid, id);
            prop_assert_eq!(rpath, path);
            prop_assert_eq!(&rbody[..], &body[..]);
        }

        /// The hand-rolled parser only ever returns Ok/Err on arbitrary bytes.
        #[test]
        fn prop_parse_plaintext_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
            let _ = parse_plaintext(&bytes);
        }

        /// Manifests serialize/parse round-trip for arbitrary contents.
        #[test]
        fn prop_manifest_json_round_trips(seq in any::<u64>(), end in any::<u64>(), n in 0usize..6) {
            let entries: Vec<ManifestEntry> = (0..n)
                .map(|i| ManifestEntry {
                    id: format!("id{i}"),
                    path: format!("/p/{i}"),
                    size: i as u64,
                    offset: i as u64 * 10,
                    length: 7,
                    uploaded_at: i as i64,
                })
                .collect();
            let m = Manifest { seq, end_offset: end, entries };
            let back: Manifest = serde_json::from_slice(&serde_json::to_vec(&m).unwrap()).unwrap();
            prop_assert_eq!(m, back);
        }

        /// Scanning arbitrary bytes as a volume never panics/over-allocates.
        #[test]
        fn prop_scan_volume_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
            let key = fast_key();
            let aad = volume_aad("v", 0);
            let mut cur = std::io::Cursor::new(&bytes);
            let _ = scan_volume(&mut cur, bytes.len() as u64, &key, &aad);
        }
    }


    // --- mutation-testing kill-tests (round 7: cargo-mutants survivor closure) ---
    #[test]
    fn mut_const_size_caps_have_exact_values() {
        // Kills the `*` -> `+` mutants on lines 58/62/64: pin the EXACT byte values
        // of the module size caps. With `+`, e.g. MAX_DOC_SIZE would be 64+1024+1024
        // = 3072 instead of 67108864, so each equality below fails under the mutant.
        assert_eq!(MAX_DOC_SIZE, 64 * 1024 * 1024);
        assert_eq!(MAX_DOC_SIZE, 67_108_864u64);
        assert_eq!(DEFAULT_VOLUME_MAX_SIZE, 256 * 1024 * 1024);
        assert_eq!(DEFAULT_VOLUME_MAX_SIZE, 268_435_456u64);
        assert_eq!(MAX_MANIFEST_SIZE, 256 * 1024 * 1024);
        assert_eq!(MAX_MANIFEST_SIZE, 268_435_456u64);
    }

    #[test]
    fn mut_put_rejects_at_doc_size_boundary() {
        // Pins the MAX_DOC_SIZE cap on line 354 (`bytes.len() as u64 > MAX_DOC_SIZE`):
        //   - a doc of EXACTLY MAX_DOC_SIZE must be ACCEPTED  (kills `>` -> `>=`)
        //   - a doc of MAX_DOC_SIZE + 1   must be REJECTED  (kills `>` -> `==`)
        let dir = tmp_dir("dcap");
        let key = fast_key();
        let mut s = VolumeStore::open(&dir, &key, "v", DEFAULT_VOLUME_MAX_SIZE).unwrap();
        // One allocation of cap+1 bytes, reused as both slices.
        let buf = vec![0u8; MAX_DOC_SIZE as usize + 1];
        // Over-cap by one byte: real code rejects with TooLarge before any write.
        assert!(
            matches!(s.put("over", "/o", &buf[..], 1, &key), Err(StorageError::TooLarge)),
            "a document of MAX_DOC_SIZE + 1 must be rejected (kills `>` -> `==`)"
        );
        // Exactly at the cap: real code accepts it (kills `>` -> `>=`).
        s.put("atcap", "/c", &buf[..MAX_DOC_SIZE as usize], 2, &key)
            .expect("a document of exactly MAX_DOC_SIZE must be accepted (kills `>` -> `>=`)");
        assert!(s.contains("atcap"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn mut_load_manifest_truncation_boundary_is_nonce_len() {
        // Pins line 478 (`raw.len() < NONCE_LEN`):
        //   - NONCE_LEN - 1 bytes  -> Corrupt("truncated")   (reject side)
        //   - EXACTLY NONCE_LEN    -> NOT the truncated branch; it proceeds to decrypt
        //     an empty ciphertext, which fails AEAD verification -> Crypto.
        // Under `<` -> `<=`, the NONCE_LEN-exact file would be rejected as Corrupt,
        // so the `Crypto` assertion below would fail. That distinguishes the mutant.
        let dir = tmp_dir("manlen");
        let key = fast_key();
        let s = VolumeStore::open(&dir, &key, "v", DEFAULT_VOLUME_MAX_SIZE).unwrap();
        std::fs::create_dir_all(dir.join("manifest")).unwrap();
        let mpath = dir.join("manifest/manifest.0");

        // One byte short of a nonce: truncated on either operator.
        std::fs::write(&mpath, vec![0u8; NONCE_LEN - 1]).unwrap();
        assert!(
            matches!(s.load_manifest(0, &key), Err(StorageError::Corrupt(_))),
            "a sub-nonce manifest is truncated/corrupt"
        );

        // Exactly NONCE_LEN bytes: real code does NOT take the truncated branch; it
        // decrypts an empty ciphertext, which fails -> Crypto (NOT Corrupt).
        std::fs::write(&mpath, vec![0u8; NONCE_LEN]).unwrap();
        assert!(
            matches!(s.load_manifest(0, &key), Err(StorageError::Crypto(_))),
            "a manifest of exactly NONCE_LEN bytes must reach decrypt (kills `<` -> `<=`)"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn mut_load_manifest_rejects_oversize_before_read() {
        // Pins line 474 (`meta.len() > MAX_MANIFEST_SIZE`) on the over-cap side:
        // a (sparse) manifest of MAX_MANIFEST_SIZE + 1 bytes is rejected with
        // TooLarge BEFORE the file is read into memory. Under `>` -> `==`, cap+1 is
        // not equal to the cap, so the guard would be false and the file would be
        // read (no TooLarge), failing this assertion.
        let dir = tmp_dir("manbig");
        let key = fast_key();
        let s = VolumeStore::open(&dir, &key, "v", DEFAULT_VOLUME_MAX_SIZE).unwrap();
        std::fs::create_dir_all(dir.join("manifest")).unwrap();
        let mpath = dir.join("manifest/manifest.0");
        // Sparse allocation: logical length cap+1, ~no physical bytes / no big read.
        let f = OpenOptions::new().write(true).create(true).truncate(true).open(&mpath).unwrap();
        f.set_len(MAX_MANIFEST_SIZE + 1).unwrap();
        f.sync_all().unwrap();
        drop(f);
        assert!(
            matches!(s.load_manifest(0, &key), Err(StorageError::TooLarge)),
            "an over-cap manifest must be rejected with TooLarge (kills `>` -> `==`)"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn mut_open_corrupt_manifest_with_volume_is_rebuilt() {
        // Pins line 196 guard `vpath.exists()` toward `true`: a CORRUPT (Corrupt/
        // Crypto/Json) manifest WITH its volume present must be rebuilt, so open
        // succeeds and the document is recoverable. Under guard -> `false`, the
        // rebuild arm is skipped, the corrupt manifest falls through to the
        // `Err(e) => return Err(e)` arm, and open() fails.
        let dir = tmp_dir("open-corrupt-rebuild");
        let key = fast_key();
        let mut s = VolumeStore::open(&dir, &key, "v", DEFAULT_VOLUME_MAX_SIZE).unwrap();
        s.put("a", "/a", b"alpha", 1, &key).unwrap();
        // Corrupt the manifest in place; the volume (vol.0) stays intact.
        std::fs::write(dir.join("manifest/manifest.0"), b"garbage").unwrap();
        let s2 = VolumeStore::open(&dir, &key, "v", DEFAULT_VOLUME_MAX_SIZE)
            .expect("corrupt manifest + present volume must rebuild (kills line 196 guard -> false)");
        assert!(s2.contains("a"), "document recovered by volume rebuild");
        assert_eq!(&*s2.read("a", &key).unwrap(), b"alpha");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn mut_open_corrupt_manifest_without_volume_propagates() {
        // Pins line 196 guard `vpath.exists()` toward `true`: when a manifest is
        // present-but-corrupt and its volume is ABSENT, open must PROPAGATE the
        // corruption error (Corrupt), NOT attempt a rebuild. Under guard -> `true`,
        // the rebuild arm runs, File::open on the missing volume fails, and open
        // returns an Io error instead of Corrupt.
        let dir = tmp_dir("open-corrupt-novol");
        let key = fast_key();
        std::fs::create_dir_all(dir.join("manifest")).unwrap();
        // Sub-nonce garbage -> load_manifest returns Corrupt("truncated").
        std::fs::write(dir.join("manifest/manifest.0"), b"garbage").unwrap();
        // No volume/ dir at all: vpath does not exist.
        // `let-else` instead of `.unwrap_err()` (VolumeStore isn't Debug).
        let Err(err) = VolumeStore::open(&dir, &key, "v", DEFAULT_VOLUME_MAX_SIZE) else {
            panic!("a corrupt manifest with no volume must error, not rebuild (kills line 196 guard -> true)");
        };
        assert!(
            matches!(err, StorageError::Corrupt(_)),
            "a corrupt manifest with no volume must propagate Corrupt, not rebuild; got {err:?}"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn mut_open_non_corruption_error_with_present_manifest_is_not_rebuilt() {
        // Pins line 206 (`vpath.exists() && !mpath.exists()`): a manifest that is
        // PRESENT but fails load for a NON-corruption reason (an I/O error, here a
        // path that is a directory -> EISDIR on read) must NOT be silently rebuilt
        // over via a lossy volume scan; the error is propagated and open() fails.
        // Under `&&` -> `||` (or the guard -> true), `vpath.exists() || !mpath.exists()`
        // is true (the volume is present), the manifest is rebuilt, and open()
        // succeeds instead — which this test detects as a failure.
        let dir = tmp_dir("open-iofail");
        let key = fast_key();
        let mut s = VolumeStore::open(&dir, &key, "v", DEFAULT_VOLUME_MAX_SIZE).unwrap();
        s.put("a", "/a", b"alpha", 1, &key).unwrap(); // valid vol.0 + manifest.0
        // Replace manifest.0 (a file) with a directory: it still "exists" (mpath
        // present) but fs::read on it errors with Io, not a corruption variant.
        let mpath = dir.join("manifest/manifest.0");
        std::fs::remove_file(&mpath).unwrap();
        std::fs::create_dir(&mpath).unwrap();
        assert!(mpath.exists(), "manifest path still present (as a directory)");
        assert!(dir.join("volume/vol.0").exists(), "volume present");
        assert!(
            VolumeStore::open(&dir, &key, "v", DEFAULT_VOLUME_MAX_SIZE).is_err(),
            "a present manifest with a non-corruption (I/O) error must propagate, not rebuild \
             (kills line 206 `&&` -> `||` and the guard -> true)"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn mut_read_frame_at_eof_and_overrun_bounds() {
        // Pins the EOF bounds in read_frame_at against three mutation clusters:
        //   * line 632 `end > file_len`  -> `==` / `>=`  (the 4-byte prefix bound)
        //   * line 647 `end > file_len`  -> `==` / `>=`  (the whole-frame bound)
        //   * line 646 `+ frame_len`     -> `-` / `*` / `/` (the overrun offset math)
        // Strategy: build one genuine, fully-valid frame, then probe file_len at the
        // exact byte boundaries so a one-step operator change flips parse<->reject.
        let dir = tmp_dir("mut-eof");
        let key = fast_key();
        let aad = volume_aad("v", 0);
        let frame = encode_frame(&key, "v", 0, "id", "/p", b"payload").unwrap();
        let vol = dir.join("vol");
        append_frame(&vol, 0, &frame).unwrap();
        let mut f = File::open(&vol).unwrap();
        let total = f.metadata().unwrap().len(); // == 4 + frame_len, the full frame size

        // (1) file_len EXACTLY equal to the frame size must PARSE. Kills line 647
        //     `>` -> `>=`/`==` (they would reject at `end == file_len`) and line 646
        //     `+` -> `-` (underflow -> None -> reject) and `+` -> `*` (4*frame_len
        //     overshoots `total` -> reject). All of those would turn this Ok into Err.
        let (id, path, body) = read_frame_at(&mut f, total, 0, 0, &key, &aad).unwrap();
        assert_eq!((id.as_str(), path.as_str(), &body[..]), ("id", "/p", &b"payload"[..]));

        // (2) file_len one byte SHORT must be rejected as an overrun. The real file
        //     still holds every byte, so only the bound (not read_exact) can catch it.
        //     Kills line 646 `+` -> `/`: `4 / frame_len == 0 <= total-1` would wrongly
        //     pass the check, then read_exact would succeed and the frame would decrypt.
        match read_frame_at(&mut f, total - 1, 0, 0, &key, &aad) {
            Err(StorageError::Corrupt(m)) => assert_eq!(m, "frame overruns EOF", "one byte short overruns"),
            other => panic!("expected Corrupt overrun at total-1, got {other:?}"),
        }

        // (3) file_len == 4 (only the prefix is in bounds). The real code does NOT
        //     reject at line 632 (`4 > 4` is false): it reads the prefix, then the
        //     whole-frame check at 644 rejects with "frame overruns EOF". A `>=`/`==`
        //     mutation at line 632 would instead reject early with the DIFFERENT
        //     message "frame offset past EOF", so the message pins the operator.
        match read_frame_at(&mut f, 4, 0, 0, &key, &aad) {
            Err(StorageError::Corrupt(m)) => assert_eq!(m, "frame overruns EOF", "prefix bound is `>`, not `>=`/`==`"),
            other => panic!("expected Corrupt overrun at file_len=4, got {other:?}"),
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn mut_read_frame_at_lower_plausibility_bound() {
        // Pins line 641 col 18 `frame_len < NONCE_LEN` -> `<=`. At the exact boundary
        // frame_len == NONCE_LEN the real code must NOT reject as "implausible"; it
        // proceeds (empty ciphertext) and fails later in AEAD decryption. A `<=`
        // mutant would short-circuit with "implausible frame length" at the boundary.
        let dir = tmp_dir("mut-lower");
        let key = fast_key();
        let aad = volume_aad("v", 0);
        let vol = dir.join("vol");
        // frame_len == NONCE_LEN (24): a body of exactly the nonce, zero ciphertext.
        let mut raw = (NONCE_LEN as u32).to_le_bytes().to_vec();
        raw.extend_from_slice(&[0u8; NONCE_LEN]);
        std::fs::write(&vol, &raw).unwrap();
        let mut f = File::open(&vol).unwrap();
        let len = f.metadata().unwrap().len(); // == 4 + NONCE_LEN, so no overrun
        match read_frame_at(&mut f, len, 0, 0, &key, &aad) {
            // Real behaviour: reaches decrypt (empty ct) and fails there, NOT at the
            // plausibility check.
            Err(StorageError::Corrupt(m)) => {
                assert_ne!(m, "implausible frame length", "frame_len == NONCE_LEN is the inclusive lower edge")
            }
            Err(_) => {} // a non-Corrupt error (e.g. Crypto) is exactly the real path
            Ok(_) => panic!("frame_len == NONCE_LEN has empty ciphertext and must not parse"),
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn mut_read_frame_at_upper_plausibility_bound() {
        // Pins line 641 col 50 `frame_len > MAX_DOC_SIZE + 4096` -> `==`/`>=` and
        // col 65 the `MAX_DOC_SIZE + 4096` addend -> `-`/`*`. Each probe writes only a
        // 4-byte length prefix and calls with file_len = 4, so whichever branch does
        // NOT reject at 641 instead rejects at the overrun check (644) -- no huge
        // allocation is ever reached. The resulting Corrupt message names the branch.
        let dir = tmp_dir("mut-upper");
        let key = fast_key();
        let aad = volume_aad("v", 0);
        let probe = |frame_len: u64| -> StorageError {
            let vol = dir.join(format!("vol-{frame_len}"));
            std::fs::write(&vol, (frame_len as u32).to_le_bytes()).unwrap();
            let mut f = File::open(&vol).unwrap();
            read_frame_at(&mut f, 4, 0, 0, &key, &aad).expect_err("4-byte file cannot hold a frame body")
        };
        let msg = |e: StorageError| match e {
            StorageError::Corrupt(m) => m,
            other => panic!("expected Corrupt, got {other:?}"),
        };

        // (a) frame_len == real bound: NOT "implausible" (real uses strict `>`), so it
        //     falls through to the overrun check. `>=`/`==` mutants would reject here
        //     with "implausible frame length"; the `+`->`-` mutant lowers the bound so
        //     a value == real bound would also become "implausible".
        assert_eq!(msg(probe(MAX_DOC_SIZE + 4096)), "frame overruns EOF", "real upper edge is exclusive");

        // (b) frame_len == MAX_DOC_SIZE: below the real bound (not implausible), but a
        //     `+`->`-` mutant (bound = MAX_DOC_SIZE - 4096) would flag it implausible.
        assert_eq!(msg(probe(MAX_DOC_SIZE)), "frame overruns EOF", "addend is `+`, not `-`");

        // (c) frame_len far above the real bound but far below MAX_DOC_SIZE*4096: the
        //     real code rejects it as implausible. A `+`->`*` mutant inflates the bound
        //     so high that this value passes 641 and only trips the overrun check.
        assert_eq!(msg(probe(100_000_000)), "implausible frame length", "addend is `+`, not `*`");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(all(unix, feature = "fault-injection"))]
    #[test]
    fn mut_write_atomic_puts_temp_in_target_dir() {
        // Pins line 751 `path.parent().filter(|p| !p.as_os_str().is_empty())`: deleting
        // the `!` makes `dir = None` for a normal path, so the temp is created in CWD
        // instead of beside the target. We make the target's parent dir read-only and
        // arm the `atomic.write` fault point (which fires only AFTER the temp is opened):
        //   * real (`!`): temp is `parent/.name.tmp` in a read-only dir -> create_new
        //     open fails with EACCES BEFORE the fault point -> the injected ENOSPC is
        //     never produced.
        //   * mutant (no `!`): temp is `.name.tmp` in (writable) CWD -> open succeeds ->
        //     the fault point fires -> error message is the injected ENOSPC.
        use std::os::unix::fs::PermissionsExt;
        let base = tmp_dir("mut-atomic");
        let target = base.join("manifest.x");
        crate::fault::fail_at("atomic.write", 1);
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o500)).unwrap();
        let err = write_atomic(&target, b"payload").expect_err("write_atomic must fail here");
        // Restore perms so cleanup (and any later test on this thread) is unaffected.
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700)).unwrap();
        crate::fault::clear();
        // Real code never reached the fault point (open failed in the read-only dir).
        // The mutant did reach it, so it would carry the injected-ENOSPC text.
        assert!(matches!(err, StorageError::Io(_)), "expected an I/O error, got {err:?}");
        assert!(
            !format!("{err}").contains("injected"),
            "temp must be created in the (read-only) target dir, not CWD: got {err}"
        );
        std::fs::remove_dir_all(&base).ok();
    }

    // Kills: storage.rs harden_file (line ~817) body -> ().
    // The volume append path opens vol.<N> with create-time mode 0600, so a freshly
    // created file would be 0600 even with the mutant. We therefore call harden_file
    // directly on a file we deliberately created at 0644: only harden_file's set_mode
    // can pull it to 0600. With the body replaced by `()`, the file stays 0644.
    #[cfg(unix)]
    #[test]
    fn mut_harden_file_chmods_to_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tmp_dir("hardenfile");
        let f = dir.join("blob.bin");
        fs::write(&f, b"x").unwrap();
        let mut p = fs::metadata(&f).unwrap().permissions();
        p.set_mode(0o644);
        fs::set_permissions(&f, p).unwrap();
        assert_eq!(fs::metadata(&f).unwrap().permissions().mode() & 0o777, 0o644);

        harden_file(&f);
        assert_eq!(
            fs::metadata(&f).unwrap().permissions().mode() & 0o777,
            0o600,
            "harden_file must chmod the file to 0600"
        );
        std::fs::remove_dir_all(&dir).ok();
    }
}
