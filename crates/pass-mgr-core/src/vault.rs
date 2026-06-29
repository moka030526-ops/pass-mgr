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

// `use` brings names into scope (like `import` elsewhere). `std::fs::{self, ..}`
// imports the `fs` module itself AND the listed items from it.
use std::fs::{self, OpenOptions};
use std::io::Write; // a *trait* (interface); brought in so `.write_all()` is callable
use std::path::{Path, PathBuf}; // `Path` = borrowed path (like `&str`); `PathBuf` = owned (like `String`)

use thiserror::Error; // a derive macro that auto-generates the std `Error` impl for our enum
use zeroize::Zeroizing; // wrapper that overwrites (zeroes) its contents on drop — for secrets

// `crate::` = this crate's own modules. `{self, ..}` again pulls in the module
// name plus the listed types/constants from it.
use crate::crypto::{self, CryptoError, KdfParams, Key, NONCE_LEN, SALT_LEN};
use crate::records::{self, Change, Vault};
use crate::storage::{self, MAX_DOC_SIZE, ManifestEntry, StorageError, VolumeStore};
use crate::types::TypeLists;

// THROWAWAY: one-shot owner-first / ts-in-filename document-path migration + history
// deletion + compaction. Delete this line and `src/vault/migrate.rs` to remove it.
pub mod migrate;

/// A decrypted document returned to the CLI: its manifest metadata plus its
/// plaintext bytes (which wipe on drop).
// `type` is an alias (a nickname for a longer type). A tuple `(A, B)` pairs two
// values. `Vec<u8>` is a growable byte array; wrapping it in `Zeroizing` means the
// plaintext bytes are scrubbed from memory when this value goes out of scope.
pub type DecryptedDoc = (ManifestEntry, Zeroizing<Vec<u8>>);

// `const` = compile-time constant. `&[u8; 8]` is a shared reference (`&`, a
// read-only borrow) to a fixed-size array of 8 bytes. `b"..."` is a byte-string
// literal; `\0` is a NUL byte. `u8` = unsigned 8-bit int; `usize` = pointer-sized
// unsigned int (used for lengths/indices).
const MAGIC: &[u8; 8] = b"PMVAULT\0";
const FORMAT_VERSION: u8 = 4;
const HEADER_LEN: usize = 61;
/// Hard ceiling on the vault file read into memory before any auth/decrypt — a
/// DoS guard against a crafted, oversized `vault.pmv` (the record JSON is small;
/// 256 MiB is far above any legitimate vault).
const MAX_VAULT_SIZE: u64 = 256 * 1024 * 1024;
/// Fixed vault-file name inside the user's directory.
const VAULT_FILE: &str = "vault.pmv";
/// Staging directory used during a password-change re-encryption.
const REKEY_DIR: &str = ".rekey";
const REKEY_READY: &str = "READY";
/// Single-writer advisory lock file inside the vault directory.
#[cfg(feature = "single-writer-lock")]
const LOCK_FILE: &str = "pass-mgr.lock";
/// Upper bound on the opt-in in-place redundancy depth (§12.8): the number of prior
/// `vault.pmv` generations retained. Each generation is a small encrypted copy, so a
/// few is plenty; this caps disk use and lingering old-secret copies.
const MAX_REDUNDANCY: u32 = 10;
/// Sane bounds for `volume_max_size` adopted from an UNTRUSTED import mirror
/// (`import_tree`): a floor so a tiny value can't fragment the store into a huge
/// number of partitions, and a generous ceiling that still rejects absurd values.
const MIN_VOLUME_MAX_SIZE: u64 = 64 * 1024; // 64 KiB
const MAX_VOLUME_MAX_SIZE: u64 = 64 * 1024 * 1024 * 1024; // 64 GiB

// Sanity bounds for KDF parameters now live on `KdfParams` (crypto.rs) as
// `KdfParams::validate()`, so the read path (Header::parse, a pre-derivation DoS
// guard) and the write paths (create/import_tree) share one definition and can
// never disagree (which would let a vault be written that can never be reopened).

// An `enum` is a tagged union: a value is exactly ONE of the listed variants,
// some of which carry data (e.g. `NotFound(PathBuf)`). This is the single error
// type every fallible function here returns.
// `#[derive(...)]` auto-generates trait impls: `Error` (from thiserror, using the
// `#[error("...")]` strings as the human-readable message) and `Debug` (a
// developer-facing dump). `{0}` in those strings interpolates the variant's data.
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
    #[error("cannot remove a document that a record still references (unlink it from the record first)")]
    StillReferenced,
    #[error("an interrupted password change is pending; reopen with --write to finish recovery")]
    RekeyPending,
    #[error("vault is open read-only (relaunch with --write to make changes)")]
    ReadOnly,
    #[error("another writable session already has this vault open (close it, or open read-only)")]
    Locked,
    #[error("no such partition: {0}")]
    NoSuchPartition(u32),
    // `#[from]` generates a conversion so a `StorageError` (etc.) automatically
    // becomes a `VaultError` — this is what lets the `?` operator (used below)
    // bubble up errors of other types without manual wrapping. `transparent`
    // means this variant just forwards the inner error's message unchanged.
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
// A `struct` groups named fields (like a record/object). `#[derive(Clone)]` lets
// callers make an independent copy with `.clone()`; `Debug` enables `{:?}` dumps.
// `[u8; SALT_LEN]` is a fixed-length byte array whose length is the constant.
#[derive(Debug, Clone)]
struct Header {
    params: KdfParams,
    salt: [u8; SALT_LEN],
    nonce: [u8; NONCE_LEN],
}

// `impl Header { ... }` attaches methods to the `Header` type (like defining the
// methods of a class). Methods taking `&self` borrow the value read-only.
impl Header {
    // Serialize this header to its fixed 61-byte on-disk form. `&self` = read-only
    // borrow of the header; the return type is an owned 61-byte array.
    fn to_bytes(&self) -> [u8; HEADER_LEN] {
        let mut b = [0u8; HEADER_LEN]; // `mut` = mutable; an array of 61 zero bytes
        // `b[0..8]` is a slice (a view) of bytes 0..7; `copy_from_slice` fills it.
        // `&self.params...` takes a borrow of each field. `to_le_bytes()` encodes an
        // integer as little-endian bytes (matching the on-disk format).
        b[0..8].copy_from_slice(MAGIC);
        b[8] = FORMAT_VERSION;
        b[9..13].copy_from_slice(&self.params.m_cost.to_le_bytes());
        b[13..17].copy_from_slice(&self.params.t_cost.to_le_bytes());
        b[17..21].copy_from_slice(&self.params.p_cost.to_le_bytes());
        b[21..37].copy_from_slice(&self.salt);
        b[37..61].copy_from_slice(&self.nonce);
        b // last expression with no `;` is the return value (no `return` needed)
    }

    // Parse a header out of untrusted file bytes. `buf: &[u8]` is a read-only byte
    // slice. The return type `Result<Header, VaultError>` is "either an `Ok(Header)`
    // on success, or an `Err(VaultError)` on failure" — Rust's checked-error type.
    fn parse(buf: &[u8]) -> Result<Header, VaultError> {
        if buf.len() < HEADER_LEN {
            return Err(VaultError::Truncated); // early-return an error variant
        }
        if &buf[0..8] != MAGIC {
            return Err(VaultError::BadMagic);
        }
        if buf[8] != FORMAT_VERSION {
            return Err(VaultError::BadVersion(buf[8]));
        }
        // `from_le_bytes` rebuilds a u32 from 4 little-endian bytes. `try_into()`
        // converts the variable-length slice into the fixed `[u8; 4]` it needs and
        // returns a `Result`; `.unwrap()` takes the `Ok` value or panics. It is
        // safe here because the length was already checked to be >= HEADER_LEN, so
        // these fixed sub-ranges always exist.
        let params = KdfParams {
            m_cost: u32::from_le_bytes(buf[9..13].try_into().unwrap()),
            t_cost: u32::from_le_bytes(buf[13..17].try_into().unwrap()),
            p_cost: u32::from_le_bytes(buf[17..21].try_into().unwrap()),
        };
        // Reject out-of-range params BEFORE the (expensive, memory-hard) derivation —
        // a tampered/forged header cannot force an unbounded Argon2 allocation.
        params.validate().map_err(|_| VaultError::BadParams)?;
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&buf[21..37]);
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&buf[37..61]);
        // Build and return the header. `Header { params, salt, nonce }` is field
        // shorthand: each field is set from the like-named local variable.
        Ok(Header { params, salt, nonce })
    }
}

/// An unlocked vault: the decrypted data, the derived key + KDF salt/params, and
/// the partitioned document store. The key zeroizes on drop; `vault` zeroizes via
/// its own `ZeroizeOnDrop`.
// Fields are private by default (encapsulated); only `vault` is marked `pub`, so
// callers can read/edit records directly but everything security-sensitive (the
// key, the lock) is reachable only through this module's methods.
pub struct OpenVault {
    pub vault: Vault,
    key: Key, // the symmetric encryption key derived from the passwords
    params: KdfParams,
    salt: [u8; SALT_LEN],
    /// The vault *file* (`<dir>/vault.pmv`).
    path: PathBuf,
    previous_access: i64,
    previous_generation: u64,
    read_only: bool,
    storage: VolumeStore,
    /// Set by the open path when the live `vault.pmv` was unreadable and the vault
    /// was recovered from an in-place redundant copy (§12.8) — a human-readable
    /// notice the front-ends surface so the user knows a roll-forward/rollback
    /// happened. `None` on a normal open.
    recovery_notice: Option<String>,
    /// Held for a writable session: the OS advisory lock on `pass-mgr.lock`.
    /// `None` for read-only opens. Released automatically when this `OpenVault`
    /// drops (including on process crash), so the lock never goes stale.
    // `Option<T>` is "either `Some(value)` or `None`" — Rust's null-free optional.
    // The leading `_` says "stored only to keep it alive, not read"; when this
    // struct is dropped the `WriteLock` is dropped too, which releases the lock.
    _write_lock: Option<WriteLock>,
}

/// Outcome of deleting a category (asset type / account type / account subtype) via
/// `OpenVault::remove_*`. Distinct from a hard `VaultError` so the UI can react with a
/// helpful message instead of a generic failure: the refusals (`InUse`/`HasSubtypes`)
/// are normal "can't do that yet" states, not errors. (Read-only opens still return
/// `Err(VaultError::ReadOnly)`; an actual save failure still returns `Err`.)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CategoryRemoval {
    /// Deleted from the list and the change was persisted.
    Removed,
    /// The type/subtype was not in the list (nothing to do).
    NotFound,
    /// Refused: this many LIVE records still reference it (history does not count).
    InUse(usize),
    /// Refused: an account type that still has subtypes defined (delete those first).
    HasSubtypes,
}

/// An OS advisory lock on `<dir>/pass-mgr.lock`, held for the lifetime of a
/// writable [`OpenVault`]. The lock is taken on the open file handle, so the
/// kernel releases it when the handle closes — no stale lock file to clean up.
struct WriteLock {
    #[cfg(feature = "single-writer-lock")]
    _file: fs::File,
}

impl WriteLock {
    /// Acquire the single-writer lock for `dir`. Errors with
    /// [`VaultError::Locked`] if another writable session already holds it.
    // `Self` is shorthand for the type being impl'd (here `WriteLock`).
    #[cfg(feature = "single-writer-lock")]
    fn acquire(dir: &Path) -> Result<Self, VaultError> {
        let path = dir.join(LOCK_FILE); // `.join()` appends a path component
        // The lock file carries no contents; never truncate it (avoids racing a
        // concurrent holder's handle), just ensure it exists and is lockable.
        // The trailing `?` propagates any I/O error: on `Err` it returns it from
        // this function immediately (after `#[from]`-converting it to VaultError).
        let file = OpenOptions::new().read(true).write(true).create(true).truncate(false).open(&path)?;
        // NOTE: deliberately do NOT chmod this path. `open(create)` follows a
        // symlink, and `harden_file` (metadata + set_permissions) would then chmod
        // the symlink's *target* — a chmod-through-symlink primitive an attacker
        // could aim at another of the user's files. The lock file holds no secrets,
        // and its parent directory is already 0700, so leaving it at the default
        // umask mode is safe. (append_frame guards its own path the same way.)
        // `match` examines every possible variant of the Result and picks one arm.
        // `try_lock` returns `Ok(())` if we got the lock, or specific errors otherwise.
        match file.try_lock() {
            Ok(()) => Ok(WriteLock { _file: file }),
            Err(fs::TryLockError::WouldBlock) => Err(VaultError::Locked), // someone else holds it
            Err(fs::TryLockError::Error(e)) => Err(VaultError::Io(e)),   // `e` binds the inner error
        }
    }

    /// No-op stand-in when the `single-writer-lock` feature is disabled (the mobile
    /// build). A single app process serializes all vault access behind one mutex, so
    /// there is no second writable process to exclude — this never returns `Locked`.
    /// The crash-safe atomic-commit + rekey roll-forward design already tolerates a
    /// crash without the lock, so dropping it only removes cross-process exclusion.
    #[cfg(not(feature = "single-writer-lock"))]
    fn acquire(_dir: &Path) -> Result<Self, VaultError> {
        Ok(WriteLock {})
    }
}

// With the lock feature ON, `WriteLock` owns an `fs::File` whose own `Drop` releases the
// OS lock, so the struct already has drop glue and explicit `drop(lock)` is meaningful. With
// the feature OFF the struct is empty and has none, which makes `drop(lock)` a `clippy::
// drop_non_drop` lint (and reads as a no-op). Give the disabled build a trivial `Drop` so
// every explicit `drop(lock)` / lock-release site compiles and reads the same on both configs.
#[cfg(not(feature = "single-writer-lock"))]
impl Drop for WriteLock {
    fn drop(&mut self) {}
}

// The main API surface of the vault: all the public operations live as methods here.
impl OpenVault {
    /// Create a brand-new vault in the directory containing `path`
    /// (`<dir>/vault.pmv`), protected by two passwords.
    // `path: PathBuf` is taken *by value* (this function now owns it / can keep it).
    // `pw1: &[u8]` / `pw2: &[u8]` are read-only borrows of the password bytes — the
    // caller keeps ownership, and we never copy or store them.
    pub fn create(path: PathBuf, pw1: &[u8], pw2: &[u8], params: KdfParams) -> Result<Self, VaultError> {
        if path.exists() {
            return Err(VaultError::AlreadyExists(path));
        }
        // Validate params on the WRITE path with the same bounds the READ path
        // (Header::parse) enforces, so we can never write a vault the reader would
        // later refuse to open (BadParams) — including its mirror/ring copies.
        params.validate().map_err(|_| VaultError::BadParams)?;
        let dir = parent_dir(&path); // `&path` lends the path without giving it away
        fs::create_dir_all(&dir)?;
        harden_dir(&dir);
        // fsync the new vault directory's own entry into its parent, so a power loss
        // right after the first save can't lose the directory that holds vault.pmv.
        sync_parent_dir(&dir);
        // Take the single-writer lock before writing anything into the directory.
        let write_lock = Some(WriteLock::acquire(&dir)?);
        // Re-check existence UNDER the lock. The pre-lock `exists()` above is a TOCTOU: a
        // competing creator could have written `vault.pmv` between that check and now. Once
        // we hold the single-writer lock this check is authoritative — without it the later
        // `save()` would `rename` a fresh, EMPTY vault over the winner's file and destroy it
        // (data loss), not merely report a confusing error.
        if path.exists() {
            return Err(VaultError::AlreadyExists(path));
        }
        // Discard any stale `.rekey` staging left in this directory. A fresh create
        // gets a brand-new vault id/key, so an unrelated leftover staging must never
        // be rolled forward over it by the next open's `recover_pending_rekey`
        // (matches `staged_rewrite`'s stale-staging clear). Best-effort.
        let _ = fs::remove_dir_all(dir.join(REKEY_DIR));
        // `::<SALT_LEN>` is a turbofish: it pins the generic length parameter so the
        // call returns a `[u8; SALT_LEN]` of random bytes.
        let salt = crypto::random_bytes::<SALT_LEN>()?;
        let key = crypto::derive_key_chained(pw1, pw2, &salt, &params)?;

        let mut vault = Vault::default(); // `default()` builds an empty/zeroed value
        vault.version = FORMAT_VERSION;
        vault.last_opened_at = records::unix_now();
        vault.id = records::random_id()?; // binds the volumes/manifests to this vault
        vault.categories = TypeLists::with_defaults();
        vault.audit.push(Change::new("vault_created", String::new()));

        let storage = VolumeStore::open(&dir, &key, &vault.id, vault.settings.volume_max_size)?;

        // Construct the struct, moving each local into the matching field. After
        // this, those locals are owned by `open` and can't be used again.
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
            recovery_notice: None,
            _write_lock: write_lock,
        };
        open.save()?; // first on-disk commit of the new vault file
        Ok(open)
    }

    // The three `open*` methods are thin wrappers that forward to `open_inner`
    // with the read-only flag set appropriately (a small convenience API).
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
        // Sweep stale atomic-write temps left by a crash mid-save (best-effort,
        // writable only). They are encrypted (no plaintext leak) but sweeping keeps
        // the dir tidy and avoids old-key temps lingering after a password change.
        if !read_only {
            sweep_stale_temps(&dir);
        }

        // Destructuring assignment: the returned tuple is unpacked into bindings at
        // once. `mut vault` is mutable so we can update its timestamp. The 4th element
        // is `Some(notice)` when the live `vault.pmv` was unreadable and we recovered
        // from an in-place redundant copy (§12.8); `None` on a normal open.
        let (mut vault, header, key, notice) = decrypt_with_redundancy(&path, pw1, pw2)?;
        let previous_access = vault.last_opened_at;
        let previous_generation = vault.generation;
        vault.last_opened_at = records::unix_now();

        // A concurrent writer's rekey can swap volume/manifest to the NEW key after a
        // read-only open already read the OLD vault.pmv (a reader-vs-writer race,
        // §9.16). In that window the store won't decrypt / a referenced doc looks
        // missing — surface a clear, retryable `RekeyPending` rather than an alarming
        // Crypto/`ArchiveMismatch`. Best-effort: re-checking `.rekey` catches the
        // in-flight case (a rekey that fully completed mid-read is the rare tail).
        let storage = match VolumeStore::open(&dir, &key, &vault.id, vault.settings.volume_max_size) {
            Ok(s) => s,
            Err(e) => {
                if dir.join(REKEY_DIR).exists() {
                    return Err(VaultError::RekeyPending);
                }
                return Err(e.into());
            }
        };
        // Consistency: every document a record references must be present.
        // `for id in ...` iterates the returned Vec, binding each element to `id`.
        for id in referenced_doc_ids(&vault) {
            if !storage.contains(&id) { // `!` is boolean NOT
                if dir.join(REKEY_DIR).exists() {
                    return Err(VaultError::RekeyPending);
                }
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
            recovery_notice: notice,
            _write_lock: write_lock,
        };
        // Best-effort refresh of last-opened; skipped entirely in read-only mode.
        // `let _ =` discards the Result: if this write fails we still hand back the
        // opened vault (the refresh is non-essential). When we recovered from a
        // redundant copy, this same save also HEALS the live tree — it rewrites a
        // fresh `vault.pmv` (+ mirror) from the recovered state. On a heal we pass
        // `rotate_ring=false` so the corrupt outgoing primary is NOT ringed into a
        // generation slot (it would otherwise void that slot with un-decryptable bytes).
        if !read_only {
            let rotate_ring = open.recovery_notice.is_none();
            let _ = open.save_internal(rotate_ring);
        }
        Ok(open)
    }

    /// Decrypt the vault and return its contents **without** modifying any file.
    // Note these `export*` functions take `&Path` (a borrow) and are "associated
    // functions" you call as `OpenVault::export(...)` — they don't need a live
    // `OpenVault`; they open, read, and drop everything internally.
    pub fn export(path: &Path, pw1: &[u8], pw2: &[u8]) -> Result<Vault, VaultError> {
        // The `_header` / `_key` names start with `_` to say "intentionally unused".
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
        // Refuse to read a half-committed rekey tree (old vault.pmv vs new-key
        // volume/manifest); this read-only path cannot finish the roll-forward.
        if dir.join(REKEY_DIR).exists() {
            return Err(VaultError::RekeyPending);
        }
        let store = VolumeStore::open(&dir, &key, &vault.id, vault.settings.volume_max_size)?;
        // Collect entries first so the immutable borrow for reads is clean.
        let entries: Vec<ManifestEntry> = selected_entries(&store, part)?;
        let mut out = Vec::new(); // a growable, initially-empty result vector
        for e in entries { // `e` is moved out of the vector on each iteration
            let bytes = store.read(&e.id, &key)?; // decrypt this doc's plaintext
            out.push((e, bytes)); // append the (entry, plaintext) pair
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
        if dir.join(REKEY_DIR).exists() {
            return Err(VaultError::RekeyPending);
        }
        let store = VolumeStore::open(&dir, &key, &vault.id, vault.settings.volume_max_size)?;
        selected_entries(&store, part)
    }

    /// Decrypt the **entire** vault directory into a plaintext mirror at `out`
    /// (DESIGN.md §6.3): `out/vault.json`, `out/manifest/manifest.<N>.json`, and
    /// `out/volume/vol.<N>/<id>` (the raw decrypted document bytes). This reuses the
    /// standard decrypt + store-read paths — it adds no new crypto — and refuses a
    /// half-committed rekey. The inverse is [`OpenVault::import_tree`].
    ///
    /// WARNING: the output is UNENCRYPTED (every password + document in the clear);
    /// see DESIGN.md §9.17. Files are written 0600 with `create_new` (no clobber).
    pub fn export_tree(path: &Path, pw1: &[u8], pw2: &[u8], out: &Path) -> Result<(), VaultError> {
        let (vault, _header, key) = decrypt_file(path, pw1, pw2)?;
        let dir = parent_dir(path);
        if dir.join(REKEY_DIR).exists() {
            return Err(VaultError::RekeyPending);
        }
        let store = VolumeStore::open(&dir, &key, &vault.id, vault.settings.volume_max_size)?;

        fs::create_dir_all(out)?;
        harden_dir(out);
        // vault.json — pretty for human inspection; the buffer wipes on drop and is
        // serialized without a mid-write realloc that would strand cleartext (see
        // serialize_secret_json).
        let vault_json = serialize_secret_json(&vault, true)?;
        write_new_bytes(&out.join("vault.json"), &vault_json)?;

        let man_dir = out.join("manifest");
        let vol_root = out.join("volume");
        // Walk every partition: write its manifest as JSON and each blob by id.
        for p in 0..store.partition_count() as u32 {
            let entries: Vec<ManifestEntry> = store.partition_entries(p).cloned().collect();
            fs::create_dir_all(&man_dir)?;
            harden_dir(&man_dir);
            let man_json = serde_json::to_vec_pretty(&entries)?;
            write_new_bytes(&man_dir.join(format!("manifest.{p}.json")), &man_json)?;
            let vol_dir = vol_root.join(format!("vol.{p}"));
            fs::create_dir_all(&vol_dir)?;
            harden_dir(&vol_dir);
            for e in &entries {
                // Symmetry with `import_tree`: the id becomes a filename here
                // (`vol_dir.join(&e.id)`), so enforce the same lowercase-hex allowlist
                // on the WRITE side too. With a genuine vault the id is always safe
                // (authenticated, 32 hex chars); this just guarantees export can never
                // traverse out of `vol_dir` even if a future path admitted a stray id.
                if !is_safe_blob_id(&e.id) {
                    return Err(VaultError::Storage(StorageError::Corrupt(format!("unsafe document id in vault: {:?}", e.id))));
                }
                let bytes = store.read(&e.id, &key)?; // decrypts + verifies id/path
                write_new_bytes(&vol_dir.join(&e.id), &bytes)?;
            }
        }
        Ok(())
    }

    /// Create a **new** encrypted vault (at the `vault.pmv` path `dest`) from a
    /// plaintext mirror at `src` (as produced by [`export_tree`]), under two new
    /// passwords. Preserves the records, categories, settings, and vault `id` from
    /// `src/vault.json` and re-encrypts every document from the mirror — reusing
    /// the same `VolumeStore::put` + atomic vault writer a password change uses (no
    /// duplicated crypto), then returns a fully-validated handle via the normal
    /// open path. Refuses to overwrite an existing vault.
    pub fn import_tree(
        src: &Path,
        dest: &Path,
        pw1: &[u8],
        pw2: &[u8],
        params: KdfParams,
    ) -> Result<OpenVault, VaultError> {
        if dest.exists() {
            return Err(VaultError::AlreadyExists(dest.to_path_buf()));
        }
        // Same write-path param validation as `create` (see there): never build a
        // vault whose params the reader would later reject.
        params.validate().map_err(|_| VaultError::BadParams)?;
        // Read + validate the mirror's vault JSON (size-capped, symlink-rejected;
        // wipe the buffer after parsing). The mirror is untrusted input.
        let vault_json = Zeroizing::new(read_capped(&src.join("vault.json"), MAX_VAULT_SIZE)?);
        let mut vault: Vault = serde_json::from_slice(&vault_json)?;
        if vault.version != FORMAT_VERSION {
            return Err(VaultError::BadVersion(vault.version));
        }
        // The mirror is UNTRUSTED. `vault.id` becomes the AEAD AAD domain for every
        // volume/manifest, and `volume_max_size` drives partition placement — sanitize
        // both rather than adopting crafted values. The id is normally 32 random hex
        // chars (`records::random_id`); reject anything that isn't a short ASCII
        // alphanumeric token. Clamp the volume size into a sane range; cap the
        // redundancy depth. (Per-blob ids are separately checked by `is_safe_blob_id`.)
        if vault.id.is_empty() || vault.id.len() > 64 || !vault.id.bytes().all(|b| b.is_ascii_alphanumeric()) {
            return Err(VaultError::Storage(StorageError::Corrupt(format!("unsafe vault id in mirror: {:?}", vault.id))));
        }
        vault.settings.volume_max_size = vault.settings.volume_max_size.clamp(MIN_VOLUME_MAX_SIZE, MAX_VOLUME_MAX_SIZE);
        vault.settings.redundancy = vault.settings.redundancy.min(MAX_REDUNDANCY);
        // Drop any tombstones carried in the mirror. The store is rebuilt below by re-putting
        // only the LIVE manifest entries, so no tombstoned frame can exist in the new tree
        // (the same reasoning staged_rewrite uses when it clears deleted_docs). Keeping them
        // would let the set grow unbounded across export/import cycles and, worse, a carried
        // tombstone whose id collides with a re-imported live blob would silently suppress it.
        vault.deleted_docs.clear();
        // The mirror's `categories` were adopted WHOLESALE from the untrusted vault.json. import_tree
        // is the FOURTH untrusted-category path (alongside plan_merge_from / apply_merge_from /
        // sync_types_from_records) and the ONLY one that does not route through the add_* mutators, so
        // a crafted mirror could otherwise inject bidi/zero-width/control-spoofed type names straight
        // into TypeLists (then rendered raw in the Config screen + the type/subtype dropdowns). Rebuild
        // the lists through display_safe + the case-insensitive add_* dedup, exactly like
        // sync_types_from_records, so import stays consistent with the rest of the triad.
        let raw_cats = std::mem::take(&mut vault.categories);
        let mut clean = crate::types::TypeLists::default();
        for t in &raw_cats.asset {
            let t = records::display_safe(t.trim());
            if !t.is_empty() {
                clean.add_asset_type(&t);
            }
        }
        for at in &raw_cats.account {
            let t = records::display_safe(at.name.trim());
            if t.is_empty() {
                continue;
            }
            clean.add_account_type(&t);
            for st in &at.subtypes {
                let st = records::display_safe(st.trim());
                if !st.is_empty() {
                    clean.add_account_subtype(&t, &st);
                }
            }
        }
        vault.categories = clean;
        let dir = parent_dir(dest);
        fs::create_dir_all(&dir)?;
        harden_dir(&dir);
        // Hold the single-writer lock for the WHOLE build. The `dest.exists()` check
        // above is a TOCTOU on its own — two concurrent imports into the same fresh
        // directory could both pass it and then interleave their volume/manifest
        // writes into a corrupt, mixed tree. The lock makes the build exclusive, in
        // keeping with the create/open paths (which lock before writing anything). It
        // is released before the final `OpenVault::open` re-acquires it below.
        let build_lock = WriteLock::acquire(&dir)?;
        let salt = crypto::random_bytes::<SALT_LEN>()?;
        let key = crypto::derive_key_chained(pw1, pw2, &salt, &params)?;

        // Re-encrypt every document from the mirror into a fresh store under the
        // new key (fresh per-blob nonces). Partitions are re-placed by the imported
        // volume_max_size, so the layout reflects the imported settings.
        let mut store = VolumeStore::open(&dir, &key, &vault.id, vault.settings.volume_max_size)?;
        let man_dir = src.join("manifest");
        let vol_root = src.join("volume");
        // `read_capped`/`read_bounded` apply O_NOFOLLOW to the FINAL path component only,
        // so a symlinked `manifest/`, `volume/`, or `vol.<p>/` in an untrusted mirror
        // could still redirect reads outside the mirror. Reject symlinked intermediate
        // directories up front (the per-partition `vol.<p>` dirs are checked in the loop).
        reject_symlink_dir(&man_dir)?;
        reject_symlink_dir(&vol_root)?;
        // Reject a mirror that lists the same blob id more than once (across ALL
        // partitions). A duplicate id makes `store.put` append a SECOND frame for one
        // id while only one manifest entry survives — and a later manifest-loss rebuild
        // + volume truncation could then resurrect the OLDER frame, silently rolling
        // the document back to a superseded version (audit R-8). Genuine exports never
        // reuse an id (each is a fresh random hex), so this only rejects crafted mirrors.
        let mut seen_ids: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut p = 0u32;
        loop {
            let man_path = man_dir.join(format!("manifest.{p}.json"));
            if !man_path.exists() {
                break; // partitions are contiguous from 0
            }
            let entries: Vec<ManifestEntry> = serde_json::from_slice(&read_capped(&man_path, storage::MAX_MANIFEST_SIZE)?)?;
            let vol_dir = vol_root.join(format!("vol.{p}"));
            reject_symlink_dir(&vol_dir)?; // don't read blobs through a symlinked partition dir
            for e in &entries {
                // The mirror is untrusted input: the blob is read from
                // `vol.<p>/<id>`, so a crafted id containing a path separator or
                // `..` would traverse out of the mirror. Require a plain filename.
                if !is_safe_blob_id(&e.id) {
                    return Err(VaultError::Storage(StorageError::Corrupt(format!("unsafe document id in mirror: {:?}", e.id))));
                }
                if !seen_ids.insert(e.id.clone()) {
                    return Err(VaultError::Storage(StorageError::Corrupt(format!("duplicate document id in mirror: {:?}", e.id))));
                }
                // The mirror also supplies the virtual path verbatim; reject control
                // bytes so a crafted mirror can't store a path that injects terminal
                // escapes or NULs into the UI / future consumers. (Length is bounded
                // by `store.put`.)
                if !is_safe_doc_path(&e.path) {
                    return Err(VaultError::Storage(StorageError::Corrupt(format!("unsafe document path in mirror: {:?}", e.path))));
                }
                // Size-capped + symlink-rejected read (no OOM, no /dev/zero or
                // arbitrary-file read through a planted symlink).
                let bytes = Zeroizing::new(read_capped(&vol_dir.join(&e.id), MAX_DOC_SIZE)?);
                store.put(&e.id, &e.path, &bytes, e.uploaded_at, &key)?;
            }
            p += 1;
        }
        // FAIL CLOSED on a NON-CONTIGUOUS mirror, exactly like `VolumeStore::open`: the loop
        // above stops at the first absent `manifest.<N>.json`, so a lost MIDDLE partition (a
        // partial copy or selective restore of the mirror) while a HIGHER one survives would
        // otherwise be silently dropped — importing a vault missing every document in the
        // orphaned higher partitions. Detect a surviving higher manifest and refuse.
        if let Some(hi) = highest_mirror_manifest(&man_dir)
            && hi >= p
        {
            return Err(VaultError::Storage(StorageError::Corrupt(format!(
                "non-contiguous partitions in mirror: imported {p} but manifest.{hi}.json still exists \
                 (a middle partition is missing)"
            ))));
        }
        drop(store);

        // Write the encrypted vault (the final commit point), then open it through
        // the normal path so validation + the referenced⊆stored consistency check
        // + the single-writer lock all apply to the freshly-built vault.
        write_vault_file(dest, &vault, &key, &salt, params)?;
        // Release the build lock before reopening: `OpenVault::open` takes its own
        // single-writer lock, which (being a second handle in this process) would
        // otherwise collide with the one still held here.
        drop(build_lock);
        OpenVault::open(dest.to_path_buf(), pw1, pw2)
    }

    /// Re-encrypt the vault and write it atomically, bumping the write-generation.
    // `&mut self` is an *exclusive* borrow: this method may mutate the vault, and
    // while it runs no one else can read or write the same `OpenVault`.
    // `Result<(), VaultError>` returns `()` (the empty/unit value) on success —
    // i.e. "succeeded, no data to hand back".
    pub fn save(&mut self) -> Result<(), VaultError> {
        self.save_internal(true)
    }

    /// The save path. `rotate_ring` is `true` for a normal save — the outgoing
    /// generation is ringed into `bak1`. It is `false` for a recovery HEAL save
    /// (§12.8): there the outgoing `vault.pmv` is the corrupt file we just recovered
    /// *around*, so it must NOT be preserved as a "generation" (that would silently
    /// void a ring slot with garbage).
    fn save_internal(&mut self, rotate_ring: bool) -> Result<(), VaultError> {
        if self.read_only {
            return Err(VaultError::ReadOnly);
        }
        // `saturating_add` increments but clamps at the max value instead of
        // overflowing/panicking — a monotonically rising version counter.
        self.vault.generation = self.vault.generation.saturating_add(1);

        // Opt-in in-place redundancy (§12.8). `0` = off (the default): a single
        // `vault.pmv`, exactly as before. `N >= 1` = keep `N` prior generations and a
        // same-generation mirror so a bit-rotted vault file can be recovered in place.
        let depth = self.vault.settings.redundancy;

        // Capture the OUTGOING generation's bytes BEFORE the primary is overwritten,
        // but ring them in only AFTER the new primary commits (below) — so a FAILED
        // save never shifts/degrades the ring. Skipped on a heal (the outgoing
        // primary is known-bad) and on the first save (nothing to retain yet).
        //
        // Distinguish "no current primary yet" (NotFound → legitimately None, first save)
        // from a real read error. A blanket `.ok()` would collapse a transient EIO/EACCES —
        // or a TooLarge corruption signal — on the outgoing primary into None, silently
        // skipping the ring rotation AND letting us overwrite a primary we could not even
        // read. Instead, fail the save on any non-NotFound error so the caller retries; the
        // new primary is not written yet, so nothing is lost.
        let prev = if rotate_ring && depth > 0 {
            match read_capped_vault(&self.path) {
                Ok(bytes) => Some(bytes),
                Err(VaultError::NotFound(_)) => None,
                Err(e) => return Err(e),
            }
        } else {
            None
        };

        // The single authoritative commit point — identical to the non-redundant
        // path. If this fails (e.g. ENOSPC) the whole save fails, the live file is
        // untouched (atomic temp+rename), AND the ring is untouched (not yet rotated).
        write_vault_file(&self.path, &self.vault, &self.key, &self.salt, self.params)?;

        if depth > 0 {
            match &prev {
                // Normal save: ring the outgoing generation into bak1 (atomic +
                // symlink-safe), shifting the rest and pruning beyond `depth`.
                Some(bytes) => rotate_generations(&self.path, depth, bytes),
                // First save, or a heal: no outgoing generation to ring in — just
                // prune any slots beyond the configured depth (e.g. after lowering it).
                None => prune_generations_above(&self.path, depth),
            }
            // Best-effort same-generation mirror: a fresh, independent encryption of
            // the same vault (its own random nonce). Failing it does not fail the
            // save — the primary already committed.
            // Fault point (crash-test only): a crash/ENOSPC here is AFTER the
            // authoritative primary commit, so it must leave the vault openable from
            // the primary. On an injected ENOSPC the best-effort mirror is skipped.
            if crate::fault::point("redundancy.mirror").is_ok() {
                let _ = write_vault_file(&mirror_path(&self.path), &self.vault, &self.key, &self.salt, self.params);
            }
        } else {
            // Redundancy off: remove any copies left over from a previously-enabled
            // state, so disabling the feature also stops leaving old secrets on disk.
            cleanup_redundancy(&self.path);
        }
        // The change is now durably committed (write_vault_file above succeeded, else we
        // returned early). Refresh the `last_update_<UTC>` marker — strictly AFTER the commit,
        // never before, so a failed save can't bump it. Best-effort; see touch_last_update.
        touch_last_update(&parent_dir(&self.path));
        Ok(())
    }

    /// Best-effort regeneration of the in-place redundancy copies (mirror + `bak1`)
    /// under the CURRENT key, without bumping the generation. Used right after a
    /// rekey/compaction commit so the configured protection is restored immediately
    /// instead of being absent until the next ordinary save (§12.8).
    fn refresh_redundancy_copies(&self) {
        let depth = self.vault.settings.redundancy;
        if depth == 0 {
            return;
        }
        // Fault point (crash-test only): a crash here leaves the just-committed vault
        // with no redundant copies until the next save — recovery from the primary is
        // unaffected (it is the authoritative, already-durable tree).
        let _ = crate::fault::point("redundancy.refresh");
        // A fresh mirror of the just-committed vault, and a bak1 copy of the live
        // primary (the post-rekey generations legitimately reset to the new epoch).
        let _ = write_vault_file(&mirror_path(&self.path), &self.vault, &self.key, &self.salt, self.params);
        if let Ok(bytes) = read_capped_vault(&self.path) {
            let _ = write_bytes_atomic(&bak_path(&self.path, 1), &bytes);
        }
        prune_generations_above(&self.path, depth);
    }

    /// Set the in-place redundancy depth (§12.8): `0` = off, `N >= 1` = keep a
    /// same-generation mirror plus `N` prior generations of `vault.pmv`. Clamped to
    /// [`MAX_REDUNDANCY`]. Persists immediately (the new copies appear on this save).
    pub fn set_redundancy(&mut self, depth: u32) -> Result<(), VaultError> {
        if self.read_only {
            return Err(VaultError::ReadOnly);
        }
        let depth = depth.min(MAX_REDUNDANCY);
        self.vault.settings.redundancy = depth;
        self.vault.audit.push(Change::new("redundancy_changed", depth.to_string()));
        self.save()
    }

    /// The current in-place redundancy depth (`0` = off).
    pub fn redundancy(&self) -> u32 {
        self.vault.settings.redundancy
    }

    /// A notice if this vault was recovered from a redundant copy on open (§12.8),
    /// for the front-ends to surface; `None` on a normal open.
    pub fn recovery_notice(&self) -> Option<&str> {
        self.recovery_notice.as_deref()
    }

    /// Snapshot this OPEN vault's on-disk tree into `dest_dir` (the last-saved state;
    /// encrypted files copied as-is). Use this from an open session instead of the
    /// free [`backup`] function: a writable session already holds the single-writer
    /// lock, and re-acquiring it (as the free function does) would self-deadlock —
    /// flock binds to the open file description, so a second in-process acquire returns
    /// `Locked`. A read-only session holds no lock, so this acquires one for the
    /// duration of the snapshot (to exclude a concurrent writer in another process).
    pub fn backup(&self, dest_dir: &Path) -> Result<PathBuf, VaultError> {
        if !self.path.exists() {
            return Err(VaultError::NotFound(self.path.clone()));
        }
        let src_dir = parent_dir(&self.path);
        if self.read_only {
            // No write lock held by this session — take one for the snapshot.
            let _lock = WriteLock::acquire(&src_dir)?;
            backup_snapshot(&self.path, &src_dir, dest_dir)
        } else {
            // Writable session already holds the lock; reuse it (do NOT re-acquire).
            backup_snapshot(&self.path, &src_dir, dest_dir)
        }
    }

    /// Re-key under two new passwords via a **full re-encryption** of the vault and
    /// the entire document store, staged then rolled forward so a crash leaves
    /// either the old or the new tree fully working (never a mix).
    pub fn change_password(&mut self, pw1: &[u8], pw2: &[u8]) -> Result<(), VaultError> {
        if self.read_only {
            return Err(VaultError::ReadOnly);
        }
        // Derive a brand-new key under a fresh salt, then drive the shared staged
        // full-rewrite: re-encrypt every live document and the vault under the new
        // key, stage it, and atomically swap it in. `Some(...)` tells
        // `staged_rewrite` to ADOPT the new key/salt once the commit succeeds; the
        // transform records the rotation in the audit log.
        let new_salt = crypto::random_bytes::<SALT_LEN>()?;
        let new_key = crypto::derive_key_chained(pw1, pw2, &new_salt, &self.params)?;
        self.staged_rewrite(Some((new_key, new_salt)), |v| {
            v.audit.push(Change::new("password_changed", String::new()));
        })
    }

    /// The shared **staged full-rewrite** behind both `change_password` and
    /// `compact`. It re-encrypts every *live* document (and the vault) into the
    /// `.rekey` staging directory, writes a `READY` marker, then atomically swaps
    /// the new tree into place via `commit_rekey`. A crash before `READY` is
    /// discarded on reopen (the old tree stands); a crash after it rolls forward
    /// (`recover_pending_rekey`). On a partial commit the live handle is poisoned
    /// (`read_only`) so the caller must reopen and finish the idempotent commit.
    ///
    /// `new_key` is `Some((key, salt))` to re-key (the staged tree is encrypted
    /// under the new key, adopted on success) or `None` to reuse the current
    /// key/salt (compaction — reads and writes both use `self.key`, with fresh
    /// per-frame nonces). `transform` mutates the staged vault clone before it is
    /// written (e.g. trim history, append an audit event). The write-generation is
    /// always bumped so the committed tree is detectably newer than any snapshot.
    fn staged_rewrite(
        &mut self,
        new_key: Option<(Key, [u8; SALT_LEN])>,
        transform: impl FnOnce(&mut Vault),
    ) -> Result<(), VaultError> {
        if self.read_only {
            return Err(VaultError::ReadOnly);
        }
        let dir = parent_dir(&self.path);
        let staging = dir.join(REKEY_DIR);
        let _ = fs::remove_dir_all(&staging); // clear any stale staging
        fs::create_dir_all(&staging)?;
        harden_dir(&staging);
        // fsync the vault dir so the `.rekey` directory ENTRY itself is durable before
        // any staged content (and the READY marker) is written into it — otherwise a
        // power loss could lose the whole staging directory, defeating the roll-forward.
        sync_parent_dir(&staging);

        // The key/salt the STAGED tree is encrypted under: the new key when
        // re-keying, else the current key (compaction). Reads always decrypt under
        // the CURRENT key (`self.key`). `match &new_key` borrows, so `new_key`
        // stays available to move out of after the staged tree is written.
        let (write_key, write_salt) = match &new_key {
            Some((k, s)) => (k, s),
            None => (&self.key, &self.salt),
        };

        // Re-encrypt every LIVE document into the fresh staged store. Iterating
        // `self.storage.ids()` yields the manifest-referenced blobs (dead frames from
        // updates/deletes are dropped here — this is what makes the rewrite double as a
        // volume compaction), EXCEPT any id carrying a deletion tombstone. A tombstoned
        // id can only be present because a manifest-loss rebuild re-admitted a deleted
        // frame; excluding it here means a delete stays deleted instead of being baked
        // in permanently (audit R-2). Unreferenced-but-not-deleted orphans (e.g. a doc
        // added but not yet linked) are deliberately KEPT, preserving the "compaction
        // never silently drops a not-yet-reclaimed blob" guarantee.
        let mut new_store =
            VolumeStore::open(&staging, write_key, &self.vault.id, self.vault.settings.volume_max_size)?;
        // Keep a blob if it is NOT tombstoned, OR if a record still references it. Dropping
        // a referenced-but-tombstoned blob would leave a dangling reference in the rewritten
        // vault (`deleted_docs.clear()` below wipes the tombstone) and brick it on next open
        // with ArchiveMismatch. That contradictory "referenced AND tombstoned" state should
        // not arise via the API (remove_document refuses a referenced id), but a crash that
        // lost the unlink-save while persisting the tombstone, then a manifest-loss rebuild,
        // can produce it — so reference wins here and the document is healed back to live.
        let referenced = referenced_doc_ids(&self.vault);
        let ids: Vec<String> = self
            .storage
            .ids()
            .filter(|id| !self.vault.deleted_docs.iter().any(|d| d == id) || referenced.iter().any(|r| r == id))
            .map(|s| s.to_string())
            .collect();
        for id in &ids {
            let bytes = self.storage.read(id, &self.key)?; // decrypt under the CURRENT key
            // `id` came from `self.storage.ids()` (the in-memory index), so its manifest
            // `entry` must exist. Fail CLOSED if it doesn't rather than silently writing
            // an empty path / `uploaded_at = 0`: a missing entry means the index and
            // manifest have desynced, and silently defaulting would bake corrupt metadata
            // into the rewritten store with no error (audit — `unwrap_or_default` removed).
            let entry = self
                .storage
                .entry(id)
                .ok_or_else(|| StorageError::Corrupt(format!("index/manifest desync: no manifest entry for {id}")))?;
            new_store.put(id, &entry.path, &bytes, entry.uploaded_at, write_key)?; // encrypt under the staged key
        }
        drop(new_store); // flush/close the staged store before commit

        // If the live tree has a volume directory (possibly full of garbage) but
        // the staged store wrote no partitions — e.g. every document was deleted,
        // the maximum-garbage case — materialize empty staged `volume/`+`manifest/`
        // dirs so `commit_rekey` swaps the garbage dirs OUT. Otherwise `replace_dir`
        // no-ops on the absent staged dirs and the live garbage would survive.
        if self.storage.partition_count() > 0 {
            for sub in ["volume", "manifest"] {
                let d = staging.join(sub);
                fs::create_dir_all(&d)?;
                harden_dir(&d);
            }
        }

        // Stage the rewritten vault: clone, bump the write-generation, apply the
        // caller's transform, write it, then mark the staging complete with READY.
        let mut staged_vault = self.vault.clone();
        staged_vault.generation = staged_vault.generation.saturating_add(1);
        // The staged volume was just re-encrypted from the (tombstone-filtered) live
        // ids, so no tombstoned frame exists on disk anymore — drop the tombstones so
        // the set can't grow without bound across rekeys/compactions.
        staged_vault.deleted_docs.clear();
        transform(&mut staged_vault);
        write_vault_file(&staging.join(VAULT_FILE), &staged_vault, write_key, write_salt, self.params)?;
        write_new_bytes(&staging.join(REKEY_READY), b"ready")?;
        sync_parent_dir(&staging.join(REKEY_READY));

        // commit_rekey moves volume/ then manifest/ then vault.pmv (the final commit
        // point). A partial failure leaves a half-new tree while this handle is
        // stale: poison it so the caller must reopen (which finishes the idempotent
        // roll-forward). A crash here recovers the same way on the next open.
        if let Err(e) = commit_rekey(&dir, &staging) {
            self.read_only = true; // poison this handle so the caller must reopen
            return Err(e);
        }

        // The on-disk tree is now the committed new tree. Adopt the new key/salt
        // when re-keying (moving `new_key` in drops & zeroizes the old `Key`); for
        // compaction the key/salt are unchanged. Then reopen the store so the
        // in-memory index reflects the re-keyed/compacted volume.
        if let Some((k, s)) = new_key {
            self.key = k;
            self.salt = s;
        }
        self.vault = staged_vault;
        self.previous_generation = self.vault.generation;
        match VolumeStore::open(&dir, &self.key, &self.vault.id, self.vault.settings.volume_max_size) {
            Ok(store) => {
                self.storage = store;
                // commit_rekey cleared the old-key redundancy copies; regenerate them
                // under the NEW key NOW so the configured protection isn't absent in
                // the window until the next ordinary save (§12.8). Best-effort.
                self.refresh_redundancy_copies();
                Ok(())
            }
            Err(e) => {
                self.read_only = true; // mismatched handle; force a fresh open
                Err(e.into())
            }
        }
    }

    /// Reclaim space without changing the passwords. `opts.volume` rewrites the
    /// document store keeping only live blobs (dropping the dead frames left by
    /// updates/deletes), reusing the crash-safe staged rewrite above. `opts.json`
    /// trims each record's per-edit `history` (older than the cutoff, or all),
    /// leaving the vault-level `audit` intact and appending a `compacted` event.
    /// Either or both may run; refused on a read-only handle. Returns a report of
    /// what was reclaimed.
    pub fn compact(&mut self, opts: &CompactOptions) -> Result<CompactReport, VaultError> {
        if self.read_only {
            return Err(VaultError::ReadOnly);
        }
        // Measure reclaimable garbage and removable history BEFORE mutating, so the
        // report reflects the change (the staged rewrite reproduces live frames at
        // their original size, so committed-after ≈ live-before).
        let (committed, live) = self.storage.space_stats();
        let bytes_reclaimed = if opts.volume { committed.saturating_sub(live) } else { 0 };
        let history_removed = if opts.json {
            records::history_stats(&self.vault, opts.history_cutoff, opts.drop_all_history)
        } else {
            0
        };
        let partitions_before = self.storage.partition_count();
        let detail = compaction_detail(opts, bytes_reclaimed, history_removed);

        if opts.volume {
            // Re-pack the volume AND (optionally) trim history in one atomic commit.
            // The closure captures only Copy values + the owned `detail` string, so
            // it does not borrow `self` (no conflict with `&mut self`).
            let (cutoff, drop_all, do_json) = (opts.history_cutoff, opts.drop_all_history, opts.json);
            self.staged_rewrite(None, move |v| {
                if do_json {
                    records::compact_history(v, cutoff, drop_all);
                }
                v.audit.push(Change::new("compacted", detail));
            })?;
        } else {
            // JSON-only: trim history in place, then the normal atomic vault save
            // (which bumps the generation). The volume is untouched.
            records::compact_history(&mut self.vault, opts.history_cutoff, opts.drop_all_history);
            self.vault.audit.push(Change::new("compacted", detail));
            self.save()?;
        }

        Ok(CompactReport {
            bytes_reclaimed,
            history_removed,
            partitions_before,
            partitions_after: self.storage.partition_count(),
        })
    }

    /// Compute what `compact` *would* reclaim without writing anything (used by
    /// `--dry-run`; safe on a read-only handle). `partitions_after` mirrors the
    /// current count — the post-compaction count is only known after a real run.
    pub fn compact_dry_run(&self, opts: &CompactOptions) -> CompactReport {
        let (committed, live) = self.storage.space_stats();
        CompactReport {
            bytes_reclaimed: if opts.volume { committed.saturating_sub(live) } else { 0 },
            history_removed: if opts.json {
                records::history_stats(&self.vault, opts.history_cutoff, opts.drop_all_history)
            } else {
                0
            },
            partitions_before: self.storage.partition_count(),
            partitions_after: self.storage.partition_count(),
        }
    }

    // Simple read-only getters: `&self` borrows the vault, and each returns a copy
    // of a small `Copy` field (integers copy implicitly, so no `.clone()` needed).
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

    /// Set the per-partition volume-size cap (bytes, clamped to the same
    /// [MIN_VOLUME_MAX_SIZE, MAX_VOLUME_MAX_SIZE] window as import_tree). Updates the
    /// saved settings and the live store so the change governs **future** placement this
    /// session, then persists. Existing partitions are untouched.
    pub fn set_volume_max_size(&mut self, bytes: u64) -> Result<(), VaultError> {
        if self.read_only {
            return Err(VaultError::ReadOnly);
        }
        // Clamp to the same bounds import_tree uses (single source of truth): a sub-64-KiB cap
        // would put nearly every new document in its own partition (vol.N/manifest.N + fsync +
        // dir-sync per doc) — self-inflicted disk/inode/IO amplification — and an absurd ceiling
        // is likewise rejected. A floor of 1 (the old value) did NOT prevent this fragmentation.
        let bytes = bytes.clamp(MIN_VOLUME_MAX_SIZE, MAX_VOLUME_MAX_SIZE);
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
        // `source` is a user-chosen file. `fs::metadata` follows symlinks, so a
        // symlink to a real document is fine, but a non-regular file (character
        // device like /dev/zero, a FIFO, …) reports len()==0 yet reads unboundedly —
        // reject it up front so it can't drive an OOM.
        let meta = fs::metadata(source)?;
        if !meta.file_type().is_file() {
            return Err(VaultError::Storage(StorageError::Corrupt(format!(
                "document source is not a regular file: {}",
                source.display()
            ))));
        }
        if meta.len() > MAX_DOC_SIZE {
            return Err(VaultError::TooLarge);
        }
        let vpath = virtual_path(location, filename);
        if vpath.len() > storage::MAX_PATH_LEN {
            return Err(VaultError::Storage(StorageError::PathTooLong));
        }
        // Read into memory wrapped in `Zeroizing` (plaintext wiped on drop), with a
        // HARD ceiling rather than the unbounded `fs::read`: a file that grows between
        // the stat and the read — or a special file that slips past the is_file()
        // check on an exotic filesystem — still cannot exhaust memory.
        let data = Zeroizing::new(read_file_capped(source, MAX_DOC_SIZE)?);
        let id = records::random_id()?;
        self.storage.put(&id, &vpath, &data, records::unix_now(), &self.key)?;
        Ok(id)
    }

    /// Permanently remove a stored document by id (drops its manifest entry; the
    /// blob lingers as garbage until reclaimed by a `compact` volume rewrite).
    ///
    /// Refuses to remove a blob that a record still references: dropping it would save
    /// a dangling reference and brick the vault on the next open (`referenced ⊄ stored`
    /// → `ArchiveMismatch`). Callers must unlink the document from its record first
    /// (the UIs already do); a stray call now fails closed with `StillReferenced`
    /// instead of corrupting the vault.
    pub fn remove_document(&mut self, file_id: &str) -> Result<(), VaultError> {
        if self.read_only {
            return Err(VaultError::ReadOnly);
        }
        if referenced_doc_ids(&self.vault).iter().any(|r| r == file_id) {
            return Err(VaultError::StillReferenced);
        }
        // Tombstone the id so that, if a later manifest-loss rebuild re-admits the
        // still-physically-present frame, the readers below suppress it and the next
        // volume rewrite drops it for good — a lazy delete can't be resurrected
        // (audit R-2). Deduplicated; cleared by `staged_rewrite` after the rewrite.
        //
        // Persist the tombstone BEFORE physically dropping the manifest entry, not after:
        // the two are separate durable commits, and a crash in the gap must fail SAFE. The
        // tombstone-then-remove order leaves "tombstone without removal" on a crash (the
        // doc reads as deleted and is idempotently re-removable / dropped by the next
        // compaction) instead of "removal without tombstone" (the deleted frame silently
        // resurrects on a later manifest-loss rebuild). Callers persist the record→doc
        // unlink before calling this; the extra save here makes the tombstone durable too.
        let id = file_id.to_string();
        if !self.vault.deleted_docs.contains(&id) {
            self.vault.deleted_docs.push(id);
            self.save()?;
        }
        self.storage.remove(file_id, &self.key)?;
        Ok(())
    }

    /// True if `file_id` has been tombstoned by `remove_document` — used to suppress
    /// a frame that a manifest-loss rebuild may have resurrected.
    fn is_tombstoned(&self, file_id: &str) -> bool {
        self.vault.deleted_docs.iter().any(|d| d == file_id)
    }

    /// Decrypt and return one stored document.
    pub fn read_document(&self, file_id: &str) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        // A tombstoned id is treated as absent even if a rebuild resurrected its frame.
        if self.is_tombstoned(file_id) {
            return Err(VaultError::Storage(StorageError::NotFound(file_id.to_string())));
        }
        Ok(self.storage.read(file_id, &self.key)?)
    }

    /// Write a stored document out to `dest` as an **unencrypted** copy (O_EXCL +
    /// 0600; fails if `dest` exists).
    pub fn export_document(&self, file_id: &str, dest: &Path) -> Result<(), VaultError> {
        let data = self.read_document(file_id)?;
        write_new_bytes(dest, &data)?;
        sync_parent_dir(dest); // dir entry durable too (best-effort; no-op off unix), like CSV export
        Ok(())
    }

    /// Export a stored document into `root`, **recreating its virtual folder structure**
    /// under it (`<root>/<location>/<filename>`) and creating the intermediate dirs
    /// (0700). The plaintext file is written 0600; if the target already exists a `_N`
    /// suffix is used so an export never overwrites. Returns the path written.
    ///
    /// The virtual path's components are already sanitized when a document is stored, but
    /// each is re-cleaned here (drop empty / `.` / `..` / separator-bearing components) as
    /// defense in depth, so the result can never escape `root`. Used by the UIs so the
    /// user sets ONE export directory and every export lands in the same tree layout
    /// instead of being prompted for a path each time.
    pub fn export_document_into(&self, file_id: &str, root: &Path) -> Result<PathBuf, VaultError> {
        let vpath =
            self.doc_path(file_id).ok_or_else(|| StorageError::NotFound(file_id.to_string()))?;
        let mut dest = root.to_path_buf();
        for part in vpath.split('/') {
            let p = part.trim();
            if p.is_empty() || p == "." || p == ".." || p.contains(['\\', ':', '\0']) {
                continue; // never let a component traverse out of `root`
            }
            // Defense-in-depth for already-stored docs: neutralize a Windows reserved device
            // name in any component (`con`, `nul`, `com1`, …) so the export writes a real file
            // on Windows instead of opening a device or colliding. New docs are already
            // sanitized at store time by `records::doc_filename`; this covers legacy paths.
            // Trailing dots/spaces are likewise stripped (silently dropped by the Win32 layer).
            // Neutralize control + bidi/zero-width spoof chars (e.g. U+202E RLO) exactly as
            // the store-time sanitizer `records::doc_filename` does, so a legacy or merge-
            // imported manifest path can't write a SPOOFED real filename on disk (e.g.
            // `invoice\u{202e}fdp.exe` rendering as `invoiceexe.pdf` in the heir's file
            // manager). New docs are sanitized at store time; this is the legacy backstop.
            let p = records::display_safe(p.trim_end_matches(['.', ' ']));
            if p.is_empty() {
                continue;
            } else if records::is_windows_reserved_name(&p) {
                dest.push(format!("_{p}"));
            } else {
                dest.push(&p);
            }
        }
        if dest == root {
            // Degenerate virtual path — fall back to an id-named file under root.
            dest.push(format!("{file_id}.bin"));
        }
        let data = self.read_document(file_id)?;
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)?;
            harden_dir(parent);
        }
        let dest = unique_export_path(dest); // never overwrite an existing export
        write_new_bytes(&dest, &data)?;
        sync_parent_dir(&dest); // dir entry durable too (best-effort; no-op off unix), like CSV export
        Ok(dest)
    }

    /// The virtual path ("/loc/filename") of a stored document, for UI display.
    // `&str` is a borrowed string slice (read-only view); `String` is owned. The
    // `Option<String>` return is `Some(path)` if the id exists, else `None`.
    pub fn doc_path(&self, file_id: &str) -> Option<String> {
        if self.is_tombstoned(file_id) {
            return None;
        }
        // `.map(|e| e.path.clone())` transforms a `Some(entry)` into `Some(owned_path)`,
        // leaving `None` as `None`. We `.clone()` because `e` is only a borrow.
        self.storage.entry(file_id).map(|e| e.path.clone())
    }

    /// Whether a document id is present in the store (and not tombstoned).
    pub fn has_document(&self, file_id: &str) -> bool {
        self.storage.contains(file_id) && !self.is_tombstoned(file_id)
    }

    // --- Cross-vault merge: "update this vault from another vault" ------------
    //
    // A one-way, ADDITIVE pull: records that are newer (by `updated_at`) or entirely
    // new in `source` are copied into `self`, along with the document blobs they
    // reference. Nothing in `self` is ever deleted. See `crate::merge` for the
    // semantics and `docs/DESIGN.md` for the security/crash-safety rationale.

    /// Compute the patch that [`apply_merge_from`](Self::apply_merge_from) would apply,
    /// for previewing. Read-only: touches no files and mutates nothing. `source` must be
    /// a *separate* already-open vault (opened with its own two passwords).
    ///
    /// A record is selected when its id is absent from `self` (New) or its `updated_at`
    /// is strictly greater than the same-id record in `self` (Updated). A selected record
    /// whose referenced document cannot be safely resolved — tombstoned in `self`, missing
    /// from `source`, or carrying an unsafe id/path — is reported in `skipped` and NOT
    /// applied (so the merge can never brick the vault or resurrect a deleted-then-garbage
    /// frame). Every displayed path is validated control/bidi-safe.
    pub fn plan_merge_from(&self, source: &OpenVault) -> Result<crate::merge::MergePlan, VaultError> {
        use std::collections::BTreeMap;
        // The source is UNTRUSTED: its `vault.id` is AEAD-authenticated but attacker-chosen,
        // and it is rendered in the preview AND recorded in this vault's audit log. Apply the
        // same allowlist `import_tree` uses (short ASCII-alphanumeric) so a crafted source
        // can't inject control/bidi bytes into the UI or persist them into our audit.
        let sid = &source.vault.id;
        if sid.is_empty() || sid.len() > 64 || !sid.bytes().all(|b| b.is_ascii_alphanumeric()) {
            return Err(VaultError::Storage(StorageError::Corrupt(format!("unsafe vault id in merge source: {sid:?}"))));
        }
        let mut plan = crate::merge::MergePlan { source_vault_id: source.vault.id.clone(), ..Default::default() };
        // Dedup the blob plan by id (a doc can be referenced by several records).
        let mut blobs: BTreeMap<String, crate::merge::PlannedBlob> = BTreeMap::new();

        // Resolve every doc id a selected record references. Returns `Err(reason)` if the
        // record must be blocked, else `Ok(())` having recorded each doc in `blobs`.
        // `&mut blobs` is threaded in because a closure can't capture it while `self` is
        // also borrowed by the outer iteration.
        let resolve = |this: &OpenVault,
                       docs: &[String],
                       blobs: &mut BTreeMap<String, crate::merge::PlannedBlob>|
         -> Result<(), String> {
            for id in docs {
                if !is_safe_blob_id(id) {
                    return Err("references a document with an unsafe id".into());
                }
                if this.vault.deleted_docs.iter().any(|t| t == id) {
                    // Tombstoned here: a lingering deleted frame may still exist, so
                    // re-adding the same id in place would risk a duplicate frame (R-8).
                    return Err("references a document deleted in this vault (compact to unblock)".into());
                }
                if this.storage.contains(id) {
                    blobs.entry(id.clone()).or_insert(crate::merge::PlannedBlob {
                        id: id.clone(),
                        path: this.storage.entry(id).map(|e| e.path.clone()).unwrap_or_default(),
                        size: this.storage.entry(id).map(|e| e.size).unwrap_or(0),
                        already_present: true,
                    });
                    continue;
                }
                // Must be copied from the source — it has to be there (source opened
                // consistent) and carry a safe, displayable path.
                match source_entry_validated(source, id)? {
                    Some((path, size)) => {
                        blobs.entry(id.clone()).or_insert(crate::merge::PlannedBlob {
                            id: id.clone(),
                            path,
                            size,
                            already_present: false,
                        });
                    }
                    None => return Err("references a document missing from the source vault".into()),
                }
            }
            Ok(())
        };

        // One closure per collection, run via the generic `plan_collection` helper so the
        // recency diff + blocked-record handling is written once. `docs_of` extracts the
        // blob ids a record references (empty for Instruction/Account).
        self.plan_collection(crate::merge::RecordKind::Instruction, &self.vault.instructions, &source.vault.instructions, |_r| Vec::new(), &resolve, &mut blobs, &mut plan)?;
        self.plan_collection(crate::merge::RecordKind::TrustWill, &self.vault.trust_wills, &source.vault.trust_wills, |r| r.file.iter().cloned().collect(), &resolve, &mut blobs, &mut plan)?;
        self.plan_collection(crate::merge::RecordKind::Asset, &self.vault.assets, &source.vault.assets, |r| r.statement.iter().cloned().collect(), &resolve, &mut blobs, &mut plan)?;
        self.plan_collection(crate::merge::RecordKind::Account, &self.vault.accounts, &source.vault.accounts, |_r| Vec::new(), &resolve, &mut blobs, &mut plan)?;
        self.plan_collection(crate::merge::RecordKind::RealEstate, &self.vault.real_estate, &source.vault.real_estate, |r| r.documents.clone(), &resolve, &mut blobs, &mut plan)?;
        self.plan_collection(crate::merge::RecordKind::TaxFiling, &self.vault.tax_filings, &source.vault.tax_filings, |r| r.documents.clone(), &resolve, &mut blobs, &mut plan)?;
        self.plan_collection(crate::merge::RecordKind::GeneralDocument, &self.vault.general_documents, &source.vault.general_documents, |r| r.file.iter().cloned().collect(), &resolve, &mut blobs, &mut plan)?;

        plan.blobs = blobs.into_values().collect();

        // Reconcile category TYPES: collect the asset/account types + subtypes the to-apply
        // records use that this vault's editable lists lack. Without this, a merged record's
        // type wouldn't appear in Config or the dropdowns. Read-only here; `apply` adds them.
        let cats = &self.vault.categories;
        let mut seen_cat: std::collections::HashSet<String> = std::collections::HashSet::new();
        let accepted_ids = |kind: crate::merge::RecordKind| -> std::collections::HashSet<&str> {
            plan.records.iter().filter(|r| r.kind == kind).map(|r| r.id.as_str()).collect()
        };
        let asset_ids = accepted_ids(crate::merge::RecordKind::Asset);
        // Only the FIRST source occurrence of an accepted id is actually applied
        // (merge_records is first-occurrence-wins), so a later DUPLICATE id carrying a
        // different type must not seed a phantom category that no applied record uses.
        let mut done_assets: std::collections::HashSet<&str> = std::collections::HashSet::new();
        for a in &source.vault.assets {
            if !asset_ids.contains(a.id.as_str()) || !done_assets.insert(a.id.as_str()) {
                continue;
            }
            // Sanitize the UNTRUSTED source type with display_safe UP FRONT, then make the
            // existence + dedup decisions on that SAME value apply_merge_from stores — otherwise
            // two raw types that sanitize equal, or a raw type that sanitizes to an existing
            // category, make the previewed new-category count drift from what apply actually adds
            // (and a crafted source vault must never inject bidi/escape chars into the screen the
            // user authorizes). `to_ascii_lowercase` matches the apply-time `eq_ignore_ascii_case`.
            let t = records::display_safe(a.asset_type.trim());
            if !t.is_empty()
                && !cats.asset.iter().any(|x| x.eq_ignore_ascii_case(&t))
                && seen_cat.insert(format!("a\u{1f}{}", t.to_ascii_lowercase()))
            {
                plan.new_categories.push(format!("asset type \u{201c}{t}\u{201d}"));
            }
        }
        let acct_ids = accepted_ids(crate::merge::RecordKind::Account);
        let mut done_accounts: std::collections::HashSet<&str> = std::collections::HashSet::new();
        for a in &source.vault.accounts {
            if !acct_ids.contains(a.id.as_str()) || !done_accounts.insert(a.id.as_str()) {
                continue; // first-occurrence-wins, like the asset loop above
            }
            let t = records::display_safe(a.account_type.trim()); // sanitized up front, as above
            if !t.is_empty() {
                if !cats.account.iter().any(|x| x.name.eq_ignore_ascii_case(&t))
                    && seen_cat.insert(format!("c\u{1f}{}", t.to_ascii_lowercase()))
                {
                    plan.new_categories.push(format!("account type \u{201c}{t}\u{201d}"));
                }
                let st = records::display_safe(a.account_subtype.trim());
                if !st.is_empty()
                    && !cats.subtypes_for(&t).iter().any(|x| x.eq_ignore_ascii_case(&st))
                    && seen_cat.insert(format!("s\u{1f}{}\u{1f}{}", t.to_ascii_lowercase(), st.to_ascii_lowercase()))
                {
                    plan.new_categories.push(format!("subtype \u{201c}{st}\u{201d} under \u{201c}{t}\u{201d}"));
                }
            }
        }

        Ok(plan)
    }

    /// Generic per-collection planner: run the recency diff, then for each selected source
    /// record resolve its referenced docs; on success record a [`PlannedRecord`], on a
    /// block record a [`SkippedRecord`]. Shared by all seven collections.
    #[allow(clippy::too_many_arguments)]
    fn plan_collection<R: crate::records::Record>(
        &self,
        kind: crate::merge::RecordKind,
        current: &[R],
        src: &[R],
        docs_of: impl Fn(&R) -> Vec<String>,
        resolve: &impl Fn(&OpenVault, &[String], &mut std::collections::BTreeMap<String, crate::merge::PlannedBlob>) -> Result<(), String>,
        blobs: &mut std::collections::BTreeMap<String, crate::merge::PlannedBlob>,
        plan: &mut crate::merge::MergePlan,
    ) -> Result<(), VaultError> {
        for sel in crate::merge::collection_changes(current, src) {
            let s = &src[sel.source_index];
            let docs = docs_of(s);
            // Resolve into a fresh PER-RECORD scratch map: a blocked record (resolve -> Err)
            // must not leak its docs into the committed plan's blob list. Using a small empty
            // map and `extend`-ing on success keeps the planner linear in total doc references
            // (the old `blobs.clone()` per record was O(records x accumulated-blobs); `resolve`
            // only inserts via entry().or_insert(), so the deduped union is identical).
            let mut scratch = std::collections::BTreeMap::new();
            match resolve(self, &docs, &mut scratch) {
                Ok(()) => {
                    blobs.extend(scratch);
                    plan.records.push(crate::merge::PlannedRecord {
                        kind,
                        change: sel.change,
                        id: s.id().to_string(),
                        // Sanitize the UNTRUSTED source label for display: this string is
                        // rendered into the CLI/TUI merge preview the user authorizes, so a
                        // crafted source vault must not inject terminal escapes or bidi/zero-
                        // width characters that spoof which records are being merged in.
                        label: records::display_safe(&s.label()),
                        current_updated_at: sel.current_updated_at,
                        source_updated_at: s.updated_at(),
                    });
                }
                Err(reason) => plan.skipped.push(crate::merge::SkippedRecord {
                    kind,
                    id: s.id().to_string(),
                    label: records::display_safe(&s.label()), // untrusted source label — see above
                    reason,
                }),
            }
        }
        Ok(())
    }

    /// Apply the merge from `source` into `self`: copy the needed document blobs, replace/
    /// insert the newer/new records, append a vault-level audit entry, and atomically save.
    /// Recomputes the plan internally against the live `source` (so the applied set always
    /// matches a freshly-built [`plan_merge_from`]), then commits **add-only**:
    ///
    /// 1. copy each needed blob into this vault's volume (each `storage.put` is individually
    ///    durable; an interrupted copy only leaves harmless orphan frames),
    /// 2. replace/insert the records (in memory),
    /// 3. one atomic `save()` of `vault.pmv` — the single commit point.
    ///
    /// Because nothing is ever removed or rewritten, this needs no staged multi-file commit:
    /// every referenced blob is durable *before* the `vault.pmv` that references it, so the
    /// open-time `referenced ⊆ stored` invariant always holds (a crash leaves the old vault
    /// plus harmless garbage). Requires `--write`.
    pub fn apply_merge_from(&mut self, source: &OpenVault) -> Result<crate::merge::MergeReport, VaultError> {
        if self.read_only {
            return Err(VaultError::ReadOnly);
        }
        // Recompute the plan against the live source — never trust a caller-held plan, and
        // skip the work entirely when there is nothing to do.
        let plan = self.plan_merge_from(source)?;
        let mut report = crate::merge::MergeReport::default();
        if plan.is_empty() {
            report.records_skipped = plan.skipped.len();
            return Ok(report);
        }

        // (1) Copy every not-already-present blob into THIS vault's volume, re-encrypted
        // under our key + vault id (a fresh nonce; never a frame byte-copy). Re-validate
        // each id/path defensively at the moment of use.
        for b in &plan.blobs {
            if b.already_present {
                continue;
            }
            if !is_safe_blob_id(&b.id) || !is_safe_doc_path(&b.path) {
                return Err(VaultError::Storage(StorageError::Corrupt(format!("unsafe document in merge source: {:?}", b.id))));
            }
            // Skip if it somehow already arrived (idempotent re-put guard: never append a
            // second frame for one id — the R-8 hazard).
            if self.storage.contains(&b.id) {
                continue;
            }
            let entry = source
                .storage
                .entry(&b.id)
                .ok_or_else(|| VaultError::Storage(StorageError::Corrupt(format!("merge source lost document {:?}", b.id))))?;
            let bytes = source.storage.read(&b.id, &source.key)?; // bounded + id/path-verified
            self.storage.put(&b.id, &entry.path, &bytes, entry.uploaded_at, &self.key)?;
            report.blobs_copied += 1;
            report.bytes_copied = report.bytes_copied.saturating_add(entry.size);
        }

        // (1b) FAIL-CLOSED, *before* mutating any record: every document the accepted records
        // reference must now be in the store (just-copied or already present). `plan.blobs`
        // is exactly that referenced set, so checking it here — rather than over the merged
        // vault after the mutation — means a storage anomaly aborts with BOTH the on-disk and
        // the in-memory vault still intact (no half-merged, never-committed state to leak).
        for b in &plan.blobs {
            if !self.storage.contains(&b.id) {
                return Err(VaultError::ArchiveMismatch);
            }
        }

        // (2) Group the accepted ids by collection, then replace/insert verbatim.
        let accepted = |kind: crate::merge::RecordKind| -> std::collections::HashSet<&str> {
            plan.records.iter().filter(|r| r.kind == kind).map(|r| r.id.as_str()).collect()
        };
        let (a1, u1) = crate::merge::merge_records(&mut self.vault.instructions, &source.vault.instructions, &accepted(crate::merge::RecordKind::Instruction));
        let (a2, u2) = crate::merge::merge_records(&mut self.vault.trust_wills, &source.vault.trust_wills, &accepted(crate::merge::RecordKind::TrustWill));
        let (a3, u3) = crate::merge::merge_records(&mut self.vault.assets, &source.vault.assets, &accepted(crate::merge::RecordKind::Asset));
        let (a4, u4) = crate::merge::merge_records(&mut self.vault.accounts, &source.vault.accounts, &accepted(crate::merge::RecordKind::Account));
        let (a5, u5) = crate::merge::merge_records(&mut self.vault.real_estate, &source.vault.real_estate, &accepted(crate::merge::RecordKind::RealEstate));
        let (a6, u6) = crate::merge::merge_records(&mut self.vault.tax_filings, &source.vault.tax_filings, &accepted(crate::merge::RecordKind::TaxFiling));
        let (a7, u7) = crate::merge::merge_records(&mut self.vault.general_documents, &source.vault.general_documents, &accepted(crate::merge::RecordKind::GeneralDocument));
        report.records_added = a1 + a2 + a3 + a4 + a5 + a6 + a7;
        report.records_updated = u1 + u2 + u3 + u4 + u5 + u6 + u7;
        report.records_skipped = plan.skipped.len();

        // (2b) Reconcile category TYPES so the merged records' asset/account types + subtypes
        // appear in Config and the dropdowns (the lists' add_* are case-insensitive dedup, and
        // the subtype add finds the type just added above). Persisted by the single save below.
        let asset_ids = accepted(crate::merge::RecordKind::Asset);
        // Dedup by id (first-occurrence-wins) so a duplicate source id with a different
        // type can't add an orphan category type whose only "user" was the un-applied dup.
        let mut done_assets: std::collections::HashSet<&str> = std::collections::HashSet::new();
        for a in &source.vault.assets {
            if !asset_ids.contains(a.id.as_str()) || !done_assets.insert(a.id.as_str()) {
                continue;
            }
            // Sanitize the UNTRUSTED source type with display_safe BEFORE storing it, exactly
            // as plan_merge_from did for the approval preview — otherwise the category the user
            // approved (cleaned) and the one persisted (raw, possibly bidi/zero-width-spoofed)
            // would diverge, letting a crafted source vault slip a spoofed type into the lists.
            let t = records::display_safe(a.asset_type.trim());
            if !t.is_empty() && self.vault.categories.add_asset_type(&t) {
                report.categories_added += 1;
            }
        }
        let acct_ids = accepted(crate::merge::RecordKind::Account);
        let mut done_accounts: std::collections::HashSet<&str> = std::collections::HashSet::new();
        for a in &source.vault.accounts {
            if !acct_ids.contains(a.id.as_str()) || !done_accounts.insert(a.id.as_str()) {
                continue; // first-occurrence-wins, like the asset loop above
            }
            let t = records::display_safe(a.account_type.trim()); // sanitized to match the preview
            if !t.is_empty() {
                if self.vault.categories.add_account_type(&t) {
                    report.categories_added += 1;
                }
                let st = records::display_safe(a.account_subtype.trim());
                if !st.is_empty() && self.vault.categories.add_account_subtype(&t, &st) {
                    report.categories_added += 1;
                }
            }
        }

        // Vault-level audit entry — counts only, no record contents or document ids.
        let short = plan.source_vault_id.get(..8).unwrap_or(plan.source_vault_id.as_str());
        self.vault.audit.push(records::Change::new(
            "merged",
            format!(
                "from vault {short}: {} new, {} updated, {} document(s) copied, {} type(s) added",
                report.records_added, report.records_updated, report.blobs_copied, report.categories_added
            ),
        ));

        // (3) The single atomic commit. The referenced⊆stored invariant was already verified
        // in (1b) before any mutation, so we only have to guard the save itself: if it fails
        // (e.g. ENOSPC), the in-memory vault now holds the merged records + audit entry but
        // the on-disk vault is still the old one — POISON the handle so a later unrelated
        // save() can never silently flush this never-committed merge (mirrors `compact`'s
        // partial-commit poisoning). The caller must reopen.
        if let Err(e) = self.save() {
            self.read_only = true;
            return Err(e);
        }
        Ok(report)
    }

    // --- Category lists (stored in the vault) --------------------------------

    // Returns a *borrow* (`&TypeLists`) into the vault rather than a copy: the
    // caller may read the category lists but the data stays owned by the vault.
    pub fn categories(&self) -> &TypeLists {
        &self.vault.categories
    }

    /// How many live asset/liability records use `name` as their `asset_type`
    /// (trimmed, case-insensitive). `0` means the configured type is unused — safe to remove,
    /// and flagged as such in the Config screen. This is the single source of truth for the
    /// "in use?" question (`remove_asset_type` uses it too). Matching is trimmed on BOTH sides
    /// so it keys off the same normalized value `add_*`/`sync_types_from_records` store — a
    /// whitespace-padded record value (legacy/imported data) still counts as in use.
    pub fn asset_type_usage(&self, name: &str) -> usize {
        let name = name.trim();
        self.vault.assets.iter().filter(|a| a.asset_type.trim().eq_ignore_ascii_case(name)).count()
    }

    /// How many live accounts use `name` as their `account_type` (trimmed, case-insensitive).
    /// `0` means the configured type is unused. Shared with `remove_account_type`.
    pub fn account_type_usage(&self, name: &str) -> usize {
        let name = name.trim();
        self.vault.accounts.iter().filter(|a| a.account_type.trim().eq_ignore_ascii_case(name)).count()
    }

    /// How many live accounts use the (`type_name`, `subtype`) pair (trimmed, case-insensitive).
    /// `0` means the configured subtype is unused. Shared with `remove_account_subtype`.
    pub fn account_subtype_usage(&self, type_name: &str, subtype: &str) -> usize {
        let (type_name, subtype) = (type_name.trim(), subtype.trim());
        self.vault
            .accounts
            .iter()
            .filter(|a| {
                a.account_type.trim().eq_ignore_ascii_case(type_name)
                    && a.account_subtype.trim().eq_ignore_ascii_case(subtype)
            })
            .count()
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

    /// Scan every record and add any asset/account **type** + account **subtype** it uses that
    /// is missing from the editable category lists (§4.2), so types brought in by a merge,
    /// `import-tree`, or older data show up in Config and the dropdowns. Returns the number of
    /// category entries added; a no-op returns `Ok(0)` without writing. Requires `--write`.
    ///
    /// **Purely additive**: this only inserts missing entries — it NEVER deletes a configured
    /// type or subtype, including ones no record currently uses. (Removal is a deliberate,
    /// per-entry action via `remove_*`.) This is what makes it safe to run automatically at
    /// vault open.
    pub fn sync_types_from_records(&mut self) -> Result<usize, VaultError> {
        if self.read_only {
            return Err(VaultError::ReadOnly);
        }
        // Snapshot the category list + audit length so a save failure rolls the in-memory
        // state back to match disk. Sync now runs automatically at open, so it must be
        // all-or-nothing: never leave memory holding types the persisted vault doesn't.
        let cats_before = self.vault.categories.clone();
        let audit_len = self.vault.audit.len();
        let mut added = 0usize;
        // Snapshot the type strings first so the immutable record borrow is released before the
        // category lists are mutated (the `add_*` are case-insensitive dedup).
        let asset_types: Vec<String> = self.vault.assets.iter().map(|a| a.asset_type.clone()).collect();
        for t in &asset_types {
            // Sanitize with display_safe BEFORE the type enters the category list. A record's
            // type field can be UNTRUSTED (it arrived via merge or import_tree), and this sync
            // runs automatically on every writable open — so without this, a bidi/zero-width-
            // spoofed record type would be re-injected RAW here, silently undoing the exact
            // sanitization apply_merge_from does (idempotent + a no-op for normal names).
            let t = records::display_safe(t.trim());
            if !t.is_empty() && self.vault.categories.add_asset_type(&t) {
                added += 1;
            }
        }
        let accts: Vec<(String, String)> =
            self.vault.accounts.iter().map(|a| (a.account_type.clone(), a.account_subtype.clone())).collect();
        for (t, st) in &accts {
            let t = records::display_safe(t.trim()); // sanitize untrusted record type, as above
            if t.is_empty() {
                continue;
            }
            if self.vault.categories.add_account_type(&t) {
                added += 1;
            }
            let st = records::display_safe(st.trim());
            if !st.is_empty() && self.vault.categories.add_account_subtype(&t, &st) {
                added += 1;
            }
        }
        if added > 0 {
            self.vault.audit.push(records::Change::new("types_synced", format!("{added} category type(s) added from records")));
            if let Err(e) = self.save() {
                // Roll the in-memory additions (and the audit entry) back so memory matches
                // the unchanged on-disk vault.
                self.vault.categories = cats_before;
                self.vault.audit.truncate(audit_len);
                return Err(e);
            }
        }
        Ok(added)
    }

    /// Delete an Asset/Liability type — only if **no live asset/liability record**
    /// still has that `asset_type`. (History never blocks: a `Change.detail` string
    /// is not the `asset_type` field, so it is not scanned here.) See [`CategoryRemoval`].
    pub fn remove_asset_type(&mut self, name: &str) -> Result<CategoryRemoval, VaultError> {
        if self.read_only {
            return Err(VaultError::ReadOnly);
        }
        let used = self.asset_type_usage(name);
        if used > 0 {
            return Ok(CategoryRemoval::InUse(used));
        }
        let removed = self.mutate_categories(|c| c.remove_asset_type(name))?;
        Ok(if removed { CategoryRemoval::Removed } else { CategoryRemoval::NotFound })
    }

    /// Delete an account type — refused if it still has **subtypes defined**
    /// (delete those first) or if any **live account** still has that `account_type`.
    pub fn remove_account_type(&mut self, name: &str) -> Result<CategoryRemoval, VaultError> {
        if self.read_only {
            return Err(VaultError::ReadOnly);
        }
        // Block while subtypes exist (chosen policy): the user removes each subtype
        // first, then the now-empty type.
        if !self.vault.categories.subtypes_for(name).is_empty() {
            return Ok(CategoryRemoval::HasSubtypes);
        }
        let used = self.account_type_usage(name);
        if used > 0 {
            return Ok(CategoryRemoval::InUse(used));
        }
        let removed = self.mutate_categories(|c| c.remove_account_type(name))?;
        Ok(if removed { CategoryRemoval::Removed } else { CategoryRemoval::NotFound })
    }

    /// Delete a subtype under an account type — only if **no live account** has that
    /// (`account_type`, `account_subtype`) pair.
    pub fn remove_account_subtype(&mut self, type_name: &str, subtype: &str) -> Result<CategoryRemoval, VaultError> {
        if self.read_only {
            return Err(VaultError::ReadOnly);
        }
        let used = self.account_subtype_usage(type_name, subtype);
        if used > 0 {
            return Ok(CategoryRemoval::InUse(used));
        }
        let removed = self.mutate_categories(|c| c.remove_account_subtype(type_name, subtype))?;
        Ok(if removed { CategoryRemoval::Removed } else { CategoryRemoval::NotFound })
    }

    // Shared helper for the three `add_*` methods above. `edit: impl FnOnce(...)`
    // accepts any closure (here `|c| c.add_*(...)`) that takes an exclusive borrow
    // of the category lists and returns whether it actually changed something.
    // `FnOnce` means the closure is callable at least once. This is the generics +
    // higher-order-function pattern: behavior is passed in as a parameter.
    fn mutate_categories(&mut self, edit: impl FnOnce(&mut TypeLists) -> bool) -> Result<bool, VaultError> {
        if self.read_only {
            return Err(VaultError::ReadOnly);
        }
        if edit(&mut self.vault.categories) { // run the closure; only persist if it changed state
            self.save()?;
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

/// The directory containing the vault file (its parent, or "." if none).
fn parent_dir(vault_file: &Path) -> PathBuf {
    // `.parent()` yields an `Option<&Path>`. The `match` has a guarded arm:
    // `Some(p) if <cond>` matches only when there's a parent AND it's non-empty;
    // `_` is the catch-all (covers `None` and the empty-parent case).
    match vault_file.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(), // own a copy of the borrowed path
        _ => PathBuf::from("."), // fall back to the current directory
    }
}

/// Normalize `location` and join `filename` into a virtual path "/a/b/file".
/// Exposed to the UIs so they can validate path length against
/// [`storage::MAX_PATH_LEN`] with the exact string the core will store.
// `pub(crate)` = visible to the rest of this crate but not external callers.
pub fn virtual_path(location: &str, filename: &str) -> String {
    let loc = normalize_dir(location);
    // `if ... { } else { }` is an *expression* here: the chosen branch's value is
    // returned. `format!` builds a `String` (like sprintf); `{filename}` inlines it.
    if loc.is_empty() { format!("/{filename}") } else { format!("{loc}/{filename}") }
}

/// Manifest entries selected by an optional partition filter. `Some(n)` returns
/// only partition `n`'s entries (erroring if `n` is out of range); `None`
/// returns every partition's entries.
fn selected_entries(store: &VolumeStore, part: Option<u32>) -> Result<Vec<ManifestEntry>, VaultError> {
    // Branch on whether a specific partition was requested (`Some(p)`) or not (`None`).
    match part {
        Some(p) => {
            // `p as usize` is an explicit numeric cast (u32 -> usize) so it can be
            // compared against the count, which is a `usize`.
            if p as usize >= store.partition_count() {
                return Err(VaultError::NoSuchPartition(p));
            }
            // Iterator: yield this partition's entries (each a `&ManifestEntry`),
            // `.cloned()` turns each borrow into an owned value, `.collect()` into a Vec.
            Ok(store.partition_entries(p).cloned().collect())
        }
        None => Ok(store.entries().cloned().collect()), // all partitions
    }
}

/// True if `id` is a safe single path component to use as a blob filename when
/// reading an (untrusted) import mirror: non-empty, no path separators, no NUL,
/// and not a `.`/`..` traversal. Real ids are random hex, so this never rejects a
/// genuine export — it only stops a crafted mirror from escaping its directory.
fn is_safe_blob_id(id: &str) -> bool {
    // Blob ids we generate are always 32 lowercase hex chars (`records::random_id`),
    // so a hex-digit allowlist is both correct and the tightest safe check for an
    // UNTRUSTED import mirror's ids. Crucially it rejects every filesystem-escape
    // vector that the old `!contains(['/','\\','\0'])` denylist missed on Windows:
    // `:` (NTFS alternate-data-stream `foo:bar` / drive-relative `C:evil`), reserved
    // device names (NUL/CON/COM1 — they contain non-hex letters), control bytes,
    // trailing dot/space, and `.`/`..`. The id is later used as a real filename on
    // both import-read (`vol.<p>/<id>`) and export-write, so this must hold.
    // LOWERCASE hex only: `records::random_id` emits lowercase, and accepting
    // uppercase too would let an import-planted `AA..` and a real `aa..` coexist on
    // Linux but COLLIDE on a case-insensitive filesystem (APFS/NTFS), breaking a
    // later `export_tree`/backup-via-mirror with an EEXIST mid-walk.
    !id.is_empty() && id.len() <= 64 && id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// True if an untrusted mirror's virtual document path is safe to store. The path
/// is display-oriented (e.g. `trust-wills/auto/ts/deed.pdf`); reject control bytes
/// (NUL, newlines, terminal-escape injection) AND Unicode bidi/format/zero-width
/// chars (display-spoofing — see `records::is_spoofy_format_char`). Length is
/// enforced separately by `VolumeStore::put`.
fn is_safe_doc_path(path: &str) -> bool {
    !path.contains(|c: char| c.is_control() || records::is_spoofy_format_char(c))
}

/// Highest `N` for which a file named exactly `manifest.<N>.json` exists in `dir` (strict
/// `<decimal>` between the fixed prefix/suffix), or `None`. Used by `import_tree` to detect a
/// non-contiguous mirror (a missing middle partition), mirroring `VolumeStore::open`'s guard.
fn highest_mirror_manifest(dir: &Path) -> Option<u32> {
    let mut hi: Option<u32> = None;
    let rd = fs::read_dir(dir).ok()?;
    for entry in rd.flatten() {
        if let Some(name) = entry.file_name().to_str()
            && let Some(rest) = name.strip_prefix("manifest.")
            && let Some(num) = rest.strip_suffix(".json")
            && !num.is_empty()
            && num.bytes().all(|b| b.is_ascii_digit())
            && let Ok(n) = num.parse::<u32>()
        {
            hi = Some(hi.map_or(n, |h| h.max(n)));
        }
    }
    hi
}

/// Look up a blob in the merge SOURCE's store: returns its `(validated path, size)` if
/// present, `Ok(None)` if the source lacks it, or `Err(reason)` if its stored path is
/// unsafe to display/store. The id is assumed already `is_safe_blob_id`-checked by the
/// caller. Used by `plan_merge_from` to build (and gate) the blob-copy plan.
fn source_entry_validated(source: &OpenVault, id: &str) -> Result<Option<(String, u64)>, String> {
    match source.storage.entry(id) {
        None => Ok(None),
        Some(e) => {
            if !is_safe_doc_path(&e.path) {
                return Err("references a document with an unsafe path".into());
            }
            // Enforce the SAME length bound `VolumeStore::put` enforces at apply time, so an
            // over-long source path surfaces as a skipped record in the PREVIEW instead of
            // aborting the merge with a hard error after the user already approved the plan.
            if e.path.len() > crate::storage::MAX_PATH_LEN {
                return Err("references a document whose path is too long".into());
            }
            // Likewise enforce the MAX_DOC_SIZE bound `VolumeStore::put` checks at apply time.
            // `storage::read` accepts a frame slightly larger than MAX_DOC_SIZE, so a hand-crafted
            // source volume could otherwise pass this preview and then abort apply_merge_from with
            // TooLarge AFTER the user approved the plan. Surface it as a skipped preview record.
            if e.size > crate::storage::MAX_DOC_SIZE {
                return Err("references a document that is too large".into());
            }
            Ok(Some((e.path.clone(), e.size)))
        }
    }
}

/// Reject a path that is a symlink, used to guard the INTERMEDIATE directories of an
/// untrusted import mirror (`manifest/`, `volume/`, `vol.<p>/`). `read_capped`/
/// `read_bounded` apply O_NOFOLLOW to the final component only, so without this a
/// symlinked parent directory could still redirect a blob/manifest read outside the
/// mirror. A non-existent path is fine here (the subsequent read fails on its own).
fn reject_symlink_dir(path: &Path) -> Result<(), VaultError> {
    if let Ok(meta) = fs::symlink_metadata(path)
        && meta.file_type().is_symlink()
    {
        return Err(VaultError::Storage(StorageError::Corrupt(format!(
            "refusing to import through a symlinked directory: {}",
            path.display()
        ))));
    }
    Ok(())
}

/// Read a file from an UNTRUSTED import mirror with a size ceiling, rejecting a
/// symlink at the path. Mirrors the stat-before-read discipline used everywhere
/// else (load_manifest, decrypt_file, add_document) so a crafted mirror cannot
/// OOM the import (a multi-GB manifest/blob) or redirect a read through a symlink
/// (e.g. to `/dev/zero` or an arbitrary file).
fn read_capped(path: &Path, max: u64) -> Result<Vec<u8>, VaultError> {
    let meta = fs::symlink_metadata(path)?;
    if meta.file_type().is_symlink() {
        return Err(VaultError::Storage(StorageError::Corrupt(format!("mirror entry is a symlink: {}", path.display()))));
    }
    // Bound the READ itself (not just a pre-stat), so a file that grows between the
    // stat and the read can't bypass the ceiling or OOM the import (matches
    // `read_file_capped`).
    read_bounded(path, max)
}

/// Read at most `max + 1` bytes from `path`, erroring `TooLarge` if the file holds
/// more than `max`. The `+ 1` lets us detect an over-size file without ever
/// allocating beyond the ceiling, regardless of a concurrent grow-after-stat.
fn read_bounded(path: &Path, max: u64) -> Result<Vec<u8>, VaultError> {
    use std::io::Read;
    // Open WITHOUT following a final-component symlink. `read_capped` pre-checks with
    // `symlink_metadata`, but that is a SEPARATE syscall from this open — a TOCTOU an
    // attacker who controls the (untrusted) mirror directory can win by swapping a
    // regular file for a symlink in between, redirecting the read to an arbitrary file
    // (e.g. /etc/shadow) and laundering its bytes into the importer's vault. O_NOFOLLOW
    // closes the race at the open itself, matching `storage::append_frame` and the
    // single-instance lock open. (On non-unix the pre-check remains the guard.)
    #[cfg(unix)]
    let f = {
        use std::os::unix::fs::OpenOptionsExt;
        fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW).open(path)?
    };
    #[cfg(not(unix))]
    let f = fs::File::open(path)?;
    let mut buf = Vec::new();
    f.take(max.saturating_add(1)).read_to_end(&mut buf)?;
    if buf.len() as u64 > max {
        return Err(VaultError::TooLarge);
    }
    Ok(buf)
}

/// Read a file with a hard size ceiling (unlike `fs::read`, which allocates without
/// bound). Reads at most `max + 1` bytes — one past the limit — so an over-size
/// source is detected and rejected without ever allocating more than `max + 1`.
/// Follows symlinks (the caller has already vetted the target with `fs::metadata`).
fn read_file_capped(path: &Path, max: u64) -> Result<Vec<u8>, VaultError> {
    use std::io::Read;
    let f = fs::File::open(path)?;
    let mut buf = Vec::new();
    // `take(max + 1)` bounds the read; `read_to_end` grows `buf` only as needed (so a
    // small file does not pre-allocate the whole ceiling). The returned Vec is moved
    // into the caller's `Zeroizing` wrapper, so its bytes are wiped on drop.
    f.take(max.saturating_add(1)).read_to_end(&mut buf)?;
    if buf.len() as u64 > max {
        return Err(VaultError::TooLarge);
    }
    Ok(buf)
}

/// Options for [`OpenVault::compact`]. `volume` re-packs the document store
/// (drops dead frames); `json` trims each record's per-edit history. When
/// `drop_all_history` is false, `history_cutoff` (Unix seconds) keeps entries
/// with `at >= cutoff` and drops older ones; when true, all history is removed.
#[derive(Clone, Copy, Debug, Default)]
pub struct CompactOptions {
    pub volume: bool,
    pub json: bool,
    pub history_cutoff: Option<i64>,
    pub drop_all_history: bool,
}

/// What a compaction reclaimed. Also returned by `compact_dry_run` as a
/// pre-flight estimate (its `partitions_after` mirrors `partitions_before`).
#[derive(Clone, Copy, Debug, Default)]
pub struct CompactReport {
    pub bytes_reclaimed: u64,
    pub history_removed: usize,
    pub partitions_before: usize,
    pub partitions_after: usize,
}

/// One-line summary of a compaction run, recorded in the vault `audit` log.
fn compaction_detail(opts: &CompactOptions, bytes_reclaimed: u64, history_removed: usize) -> String {
    let mode = match (opts.volume, opts.json) {
        (true, true) => "volume+history",
        (true, false) => "volume",
        (false, true) => "history",
        (false, false) => "noop",
    };
    format!("{mode}: reclaimed {bytes_reclaimed} bytes, removed {history_removed} history entries")
}

/// Doc ids referenced by any record (Trust&Will `file`, Asset `statement`, every
/// Taxes filing's and Real Estate property's `documents`, and each General
/// Document's `file`).
fn referenced_doc_ids(vault: &Vault) -> Vec<String> {
    let mut ids = Vec::new();
    // `for t in &vault.trust_wills` iterates by shared reference (doesn't consume
    // the vault's vector). `if let Some(f) = &t.file` runs the body only when the
    // optional field holds a value, binding the inner id to `f`. `.clone()` because
    // `f` is borrowed but we need an owned `String` in the result list.
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
    // Taxes tab: every document attached to a filing year is referenced, so
    // compaction (`--volume`) never reclaims a tax document.
    for t in &vault.tax_filings {
        for f in &t.documents {
            ids.push(f.clone());
        }
    }
    // Real Estate documents (deeds, policies, statements) are referenced too, so
    // compaction (`--volume`) never reclaims them.
    for re in &vault.real_estate {
        for f in &re.documents {
            ids.push(f.clone());
        }
    }
    // General Documents each reference a single attached file.
    for g in &vault.general_documents {
        if let Some(f) = &g.file {
            ids.push(f.clone());
        }
    }
    ids
}

/// Read, parse, and decrypt the vault file at `path`. Performs no writes.
fn decrypt_file(path: &Path, pw1: &[u8], pw2: &[u8]) -> Result<(Vault, Header, Key), VaultError> {
    let raw = read_capped_vault(path)?;
    decode_vault_bytes(&raw, pw1, pw2)
}

/// Read a `vault.pmv`-shaped file with the DoS size cap applied *before* the read
/// (a crafted, oversized file is rejected before allocation, not after). A missing
/// file maps to [`VaultError::NotFound`].
fn read_capped_vault(path: &Path) -> Result<Vec<u8>, VaultError> {
    use std::io::Read;
    // Open first so the cap can be enforced on the READ (a bounded `take`), not on a
    // separate stat that a concurrent grow could outrun. A missing file maps to
    // NotFound (the create flow + redundancy recovery rely on this).
    let f = match fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(VaultError::NotFound(path.to_path_buf())),
        Err(e) => return Err(e.into()),
    };
    let mut buf = Vec::new();
    f.take(MAX_VAULT_SIZE.saturating_add(1)).read_to_end(&mut buf)?;
    if buf.len() as u64 > MAX_VAULT_SIZE {
        return Err(VaultError::TooLarge);
    }
    Ok(buf)
}

/// Parse the header, derive the key from the two passwords, AEAD-verify+decrypt, and
/// deserialize the JSON vault. The full header (incl. nonce) is the AEAD associated
/// data, so any header tamper or bit-rot fails the tag (fail closed).
fn decode_vault_bytes(raw: &[u8], pw1: &[u8], pw2: &[u8]) -> Result<(Vault, Header, Key), VaultError> {
    let header = Header::parse(raw)?;
    let key = crypto::derive_key_chained(pw1, pw2, &header.salt, &header.params)?;
    let (vault, _) = decode_vault_with_key(raw, &key)?;
    Ok((vault, header, key))
}

/// Like [`decode_vault_bytes`] but with the key **already derived** — used by the
/// redundancy recovery path so the (expensive, memory-hard) key derivation runs
/// once even when several copies must be tried (also stops a wrong password from
/// triggering N Argon2 runs).
fn decode_vault_with_key(raw: &[u8], key: &Key) -> Result<(Vault, Header), VaultError> {
    let header = Header::parse(raw)?;
    let ciphertext = &raw[HEADER_LEN..]; // everything after the fixed-size header
    let aad = header.to_bytes();
    // Decrypt into a `Zeroizing` buffer so the plaintext JSON is wiped on drop.
    let plaintext = Zeroizing::new(crypto::decrypt(key, &header.nonce, ciphertext, &aad)?);
    let vault: Vault = serde_json::from_slice(&plaintext)?;
    // Defense-in-depth / forward-compat: the header byte is the authoritative version gate
    // (Header::parse), but the AEAD-authenticated JSON body carries its own `version` too.
    // Assert they agree so the two signals can't diverge silently — a future version-
    // conditional decode must never be fed a body whose version disagrees with the header.
    // Mirrors the equivalent check on the import path.
    if vault.version != FORMAT_VERSION {
        return Err(VaultError::BadVersion(vault.version));
    }
    Ok((vault, header))
}

/// Open `vault.pmv`, transparently falling back to the opt-in in-place redundant
/// copies (§12.8) when the live file is unreadable. Returns `Some(notice)` as the
/// 4th element when recovery happened. Order: the live file, then the
/// same-generation mirror (no data loss), then prior generations newest-first.
fn decrypt_with_redundancy(
    path: &Path,
    pw1: &[u8],
    pw2: &[u8],
) -> Result<(Vault, Header, Key, Option<String>), VaultError> {
    // Normal path — the live file reads cleanly.
    let primary_err = match decrypt_file(path, pw1, pw2) {
        Ok((v, h, k)) => return Ok((v, h, k, None)),
        Err(e) => e, // live file missing / too big / bit-rotted / wrong password
    };

    // The live file is unreadable. If no redundant copy exists, surface the original
    // error unchanged (so a wrong password still reads as "wrong password").
    let candidates = redundancy_candidates(path);
    if candidates.is_empty() {
        return Err(primary_err);
    }
    let mirror = mirror_path(path);

    // PASS 1 — collect up to MAX_RECOVERY_SALTS distinct candidate salts by reading
    // ONLY each candidate's fixed-size header (cheap), then derive one key per distinct
    // salt. CRITICAL: the live header is NOT a trusted key-derivation source — a
    // corruption confined to its salt/params would defeat recovery even with a perfect
    // mirror — so we derive from each *candidate* salt. All same-epoch copies share one
    // salt, so this is ~1 Argon2 in practice (an older generation adds at most one
    // more). The cap bounds an attacker who plants many distinct-salt + maxed-param
    // candidates from forcing one expensive chained derivation per salt on every open.
    const MAX_RECOVERY_SALTS: usize = 3;
    let mut keys: Vec<Key> = Vec::new();
    let mut key_salts: Vec<[u8; SALT_LEN]> = Vec::new();
    // Remember, per candidate, the index into `keys` of the key derived from THAT
    // candidate's own header salt (None if its header is unreadable or its salt was
    // dropped at the cap). PASS 2 uses this to try the right key first and avoid the
    // full candidates × keys cross-product.
    let mut cand_key: Vec<Option<usize>> = Vec::with_capacity(candidates.len());
    for c in &candidates {
        let Ok(header) = read_header_of(c) else {
            cand_key.push(None);
            continue;
        };
        if let Some(pos) = key_salts.iter().position(|s| s == &header.salt) {
            cand_key.push(Some(pos)); // key for this salt already derived
            continue;
        }
        if keys.len() >= MAX_RECOVERY_SALTS {
            cand_key.push(None); // refuse to derive past the bound (planted distinct-salt DoS guard)
            continue;
        }
        match crypto::derive_key_chained(pw1, pw2, &header.salt, &header.params) {
            Ok(key) => {
                keys.push(key);
                key_salts.push(header.salt);
                cand_key.push(Some(keys.len() - 1));
            }
            Err(_) => cand_key.push(None),
        }
    }
    if keys.is_empty() {
        return Err(primary_err); // no candidate header parsed / wrong password
    }

    // PASS 2 — try EACH candidate against ONLY the key derived from its OWN header salt,
    // holding at most one candidate buffer in memory at a time (an earlier version slurped
    // every candidate up front, risking OOM from planted max-size copies). Trying a
    // different-salt ("sibling") key is pointless and was removed: the salt is part of the
    // AEAD associated data (`Header::to_bytes` covers bytes 21..37), so for any candidate a
    // wrong-salt key fails the tag AND a corrupted-salt header makes its body undecryptable
    // under any key — there is no cross-salt recovery to be had. This bounds recovery to
    // EXACTLY O(candidates) full AEAD decrypts, closing a CPU-amplification DoS where a
    // vault-dir-write attacker plants many max-size distinct-salt copies.
    for (idx, c) in candidates.iter().enumerate() {
        let Ok(raw) = read_capped_vault_nofollow(c) else { continue };
        let Some(k) = cand_key[idx] else { continue }; // header unreadable / salt past the cap
        if let Ok((vault, hdr)) = decode_vault_with_key(&raw, &keys[k]) {
            let key = keys.swap_remove(k); // take ownership of the matching key
            // Wording is keyed on the SOURCE only as a coarse hint — NOT a generation claim.
            // After a rekey/compact, `refresh_redundancy_copies` rewrites the mirror AND bak1
            // at the CURRENT generation, so a bak is frequently the same generation as the
            // lost primary; asserting it is an "earlier generation — data lost" cried wolf
            // (audit R-12). Both notices say only that the latest change *may* be missing.
            let notice = if *c == mirror {
                "The main vault file was unreadable and was recovered from its mirror copy \
                 (normally the latest state — but if a save was interrupted before the \
                 mirror was written, the most recent change may be missing). Re-save, and \
                 refresh your off-device backups.".to_string()
            } else {
                "The main vault file and its mirror were unreadable; recovered from a \
                 redundant copy. If a recent save was interrupted, the most recent \
                 change(s) may be missing. Re-save, and refresh your off-device backups.".to_string()
            };
            return Ok((vault, hdr, key, Some(notice)));
        }
        // `raw` is dropped here before the next candidate is read (bounded memory).
    }
    // No copy decrypted under any candidate-derived key — wrong password, or every
    // copy is also corrupt. Return the live file's original error.
    Err(primary_err)
}

/// Read and parse ONLY the fixed-size header of a vault file. Used by redundancy
/// recovery to learn a candidate's salt/params without pulling the whole (possibly
/// attacker-inflated) file into memory.
fn read_header_of(path: &Path) -> Result<Header, VaultError> {
    use std::io::Read;
    // O_NOFOLLOW: recovery candidates (mirror/bakN) live in the same vault directory the
    // storage layer already treats as attacker-reachable; every other read of that dir uses
    // O_NOFOLLOW (read_bounded, append_frame, the lock). This was the lone recovery read that
    // followed a final-component symlink — close it so a planted `vault.pmv.mirror -> /etc/…`
    // can't redirect the read. (On non-unix, a plain open.)
    let mut f = open_read_nofollow(path)?;
    let mut buf = [0u8; HEADER_LEN];
    f.read_exact(&mut buf)?;
    Header::parse(&buf)
}

/// Open a file for reading WITHOUT following a final-component symlink (O_NOFOLLOW on unix;
/// plain open elsewhere). Used by the redundancy-recovery candidate reads, whose paths sit
/// in the attacker-reachable vault directory — matching the discipline in `read_bounded`
/// and `storage::append_frame`.
fn open_read_nofollow(path: &Path) -> std::io::Result<fs::File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW).open(path)
    }
    #[cfg(not(unix))]
    {
        fs::File::open(path)
    }
}

/// Like [`read_capped_vault`] but O_NOFOLLOW (for attacker-reachable recovery candidates).
fn read_capped_vault_nofollow(path: &Path) -> Result<Vec<u8>, VaultError> {
    use std::io::Read;
    let f = match open_read_nofollow(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(VaultError::NotFound(path.to_path_buf())),
        Err(e) => return Err(e.into()),
    };
    let mut buf = Vec::new();
    f.take(MAX_VAULT_SIZE.saturating_add(1)).read_to_end(&mut buf)?;
    if buf.len() as u64 > MAX_VAULT_SIZE {
        return Err(VaultError::TooLarge);
    }
    Ok(buf)
}

// --- In-place redundancy file management (§12.8) -----------------------------

/// `vault.pmv` -> `vault.pmv<suffix>` (append, not replace-extension).
fn with_suffix(primary: &Path, suffix: &str) -> PathBuf {
    let mut name = primary.file_name().map(|n| n.to_os_string()).unwrap_or_else(|| std::ffi::OsString::from(VAULT_FILE));
    name.push(suffix);
    match primary.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.join(name),
        _ => PathBuf::from(name),
    }
}

/// The same-generation mirror path (`vault.pmv.mirror`).
fn mirror_path(primary: &Path) -> PathBuf {
    with_suffix(primary, ".mirror")
}

/// The k-th retained prior generation (`vault.pmv.bak1` = newest prior).
fn bak_path(primary: &Path, k: u32) -> PathBuf {
    with_suffix(primary, &format!(".bak{k}"))
}

/// Write `bytes` to `dst` atomically and **symlink-safely**: a fresh O_EXCL temp
/// (0600, never follows a symlink) is written and fsync'd, then renamed over `dst`
/// — and a rename REPLACES any symlink planted at `dst` rather than following it.
/// This matches vault.pmv's own write discipline; using `fs::copy` here would follow
/// a planted symlink and redirect the (encrypted) write + chmod to an arbitrary file.
fn write_bytes_atomic(dst: &Path, bytes: &[u8]) -> Result<(), VaultError> {
    // Fault point (crash-test only): abort/ENOSPC while writing a bak generation.
    crate::fault::point("redundancy.bak").map_err(VaultError::from)?;
    let tmp = sibling_tmp(dst)?;
    if let Err(e) = write_new_file(&tmp, bytes, &[]) {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    if let Err(e) = fs::rename(&tmp, dst).map_err(VaultError::from) {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    sync_parent_dir(dst);
    Ok(())
}

/// Remove stale `*.tmp` siblings left by a crash mid atomic-write — `.vault.pmv*.tmp`
/// (primary/mirror/bak temps) in the vault dir and `.manifest*.tmp` in `manifest/` —
/// AND any orphaned `.<name>.old` directory trees from a rekey. Best-effort, writable
/// opens only. The temps are encrypted (no plaintext leak), but sweeping keeps the
/// directory tidy and avoids OLD-KEY material lingering after a rekey.
fn sweep_stale_temps(dir: &Path) {
    let sweep = |d: &Path, prefix: &str| {
        if let Ok(rd) = fs::read_dir(d) {
            for entry in rd.flatten() {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                if name.starts_with(prefix) && name.ends_with(".tmp") {
                    let _ = fs::remove_file(entry.path());
                }
            }
        }
    };
    sweep(dir, &format!(".{VAULT_FILE}")); // .vault.pmv* / .vault.pmv.mirror* / .vault.pmv.bakN*
    sweep(&dir.join("manifest"), ".manifest"); // .manifest.N* manifest-commit temps
    // `.last_update_<ts>.<rand>.tmp` temps leaked by `touch_last_update` if a crash lands between
    // its fsync and rename. The live marker (`last_update_<ts>`, no leading dot, no `.tmp`) is never
    // matched, so only orphaned temps are reaped — otherwise they would accumulate across crashes.
    sweep(dir, ".last_update_");
    // Reap orphaned `.volume.old` / `.manifest.old` trees. `replace_dir`'s OWN cleanup of
    // its `.old` sibling runs at the START of the next commit, but only on a RE-ENTRANT
    // rekey (staging still present). If the trailing best-effort `remove_dir_all` failed
    // AFTER the rekey fully committed (staging gone), recover_pending_rekey returns early on
    // later opens and replace_dir is never re-entered — so an `.old` dir full of OLD-KEY
    // ciphertext would linger forever, defeating change_password's forward secrecy. Reaping
    // it on every writable open closes that gap. The live dirs (`volume`/`manifest`) have no
    // `.old` suffix, so this can never touch them.
    for sub in ["volume", "manifest"] {
        let _ = fs::remove_dir_all(sibling_old(&dir.join(sub)));
    }
}

/// Remove every retained generation numbered above `depth` (e.g. after the depth is
/// lowered), so the on-disk generation count never exceeds the configured retention.
fn prune_generations_above(primary: &Path, depth: u32) {
    for k in (depth.min(MAX_REDUNDANCY) + 1)..=MAX_REDUNDANCY {
        let _ = fs::remove_file(bak_path(primary, k));
    }
}

/// Ring the outgoing generation (`prev_bytes` — the just-replaced `vault.pmv`) into
/// the ring: drop the oldest, shift the rest down, write `prev_bytes` as `bak1`
/// (atomic + symlink-safe), then prune any slot beyond `depth`. Called AFTER the new
/// primary has committed, so a failed save never disturbs the ring. Best-effort (a
/// partial/odd copy is skipped on recovery, since each is AEAD-validated when used).
fn rotate_generations(primary: &Path, depth: u32, prev_bytes: &[u8]) {
    let depth = depth.min(MAX_REDUNDANCY);
    if depth == 0 {
        return;
    }
    // Fault point (crash-test only): abort mid ring-rotation — AFTER the authoritative
    // primary commit — to prove the primary still opens (the ring is best-effort).
    let _ = crate::fault::point("redundancy.rotate");
    let _ = fs::remove_file(bak_path(primary, depth)); // the oldest falls off the ring
    for k in (1..depth).rev() {
        let from = bak_path(primary, k);
        if from.exists() {
            let _ = fs::rename(&from, bak_path(primary, k + 1)); // bak{k} -> bak{k+1}
        }
    }
    let _ = write_bytes_atomic(&bak_path(primary, 1), prev_bytes); // outgoing -> bak1
    prune_generations_above(primary, depth);
    // Make the whole ring shift (renames + drop + prune) durable as a unit. (The bak1
    // write already fsync'd the dir, but the prune removals after it had not been; one
    // fsync here covers them so a power loss can't resurrect a pruned generation.)
    sync_parent_dir(&bak_path(primary, 1));
}

/// Remove every redundant copy (mirror + all generations). Safe to call on every
/// non-redundant save. The fast-path no-op (the common default, when no copies
/// exist) keys on `redundancy_candidates` so it can never skip an orphaned
/// higher-numbered generation — it returns only when there is genuinely nothing to
/// remove (each `remove_file` on a non-existent path is itself a cheap ENOENT).
fn cleanup_redundancy(primary: &Path) {
    if redundancy_candidates(primary).is_empty() {
        return;
    }
    let _ = fs::remove_file(mirror_path(primary));
    for k in 1..=MAX_REDUNDANCY {
        let _ = fs::remove_file(bak_path(primary, k));
    }
}

/// Existing redundant copies in recovery-preference order: mirror (same generation,
/// no data loss) first, then prior generations newest-first.
fn redundancy_candidates(primary: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let m = mirror_path(primary);
    if m.exists() {
        out.push(m);
    }
    for k in 1..=MAX_REDUNDANCY {
        let b = bak_path(primary, k);
        if b.exists() {
            out.push(b);
        }
    }
    out
}

/// Encrypt `vault` under `key` and write it atomically to `path` (new nonce, full
/// header as AAD, temp → fsync → rename → dir fsync).
/// Serialize a SECRET-bearing value (the decrypted `Vault`) to JSON in a single,
/// exactly-sized [`Zeroizing`] buffer so the plaintext (every password) is never stranded
/// in freed heap. `serde_json::to_vec`/`to_string_pretty` start from an empty `Vec` and
/// grow it by reallocation, freeing each smaller buffer WITHOUT zeroizing — leaving partial
/// cleartext JSON fragments behind on every save/export/decrypt. To avoid that we measure
/// the exact serialized length first (a counting pass that holds NO plaintext buffer), then
/// serialize once into a buffer pre-sized to exactly that length, so it never reallocates.
/// `pub` so the desktop CLI's `decrypt` can reuse the same hardened path.
pub fn serialize_secret_json<T: serde::Serialize>(value: &T, pretty: bool) -> Result<Zeroizing<Vec<u8>>, serde_json::Error> {
    // A `Write` sink that only counts bytes — no allocation, so the measuring pass can't
    // strand plaintext.
    struct CountingWriter(usize);
    impl std::io::Write for CountingWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0 = self.0.saturating_add(buf.len());
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut counter = CountingWriter(0);
    if pretty {
        serde_json::to_writer_pretty(&mut counter, value)?;
    } else {
        serde_json::to_writer(&mut counter, value)?;
    }
    // capacity == exact len => the second (real) pass never grows the Vec, so no smaller
    // buffer is ever freed unwiped. The whole buffer is zeroized on drop.
    let mut buf = Zeroizing::new(Vec::<u8>::with_capacity(counter.0));
    if pretty {
        serde_json::to_writer_pretty(&mut *buf, value)?;
    } else {
        serde_json::to_writer(&mut *buf, value)?;
    }
    Ok(buf)
}

fn write_vault_file(
    path: &Path,
    vault: &Vault,
    key: &Key,
    salt: &[u8; SALT_LEN],
    params: KdfParams,
) -> Result<(), VaultError> {
    // Serialize the vault to JSON bytes (wiped on drop, no realloc strand), pick a fresh
    // random nonce, and build the header. `*salt` dereferences the `&[u8; N]` borrow to
    // copy the array by value into the new `Header`.
    let plaintext = serialize_secret_json(vault, false)?;
    let nonce = crypto::random_bytes::<NONCE_LEN>()?;
    let header = Header { params, salt: *salt, nonce };
    let header_bytes = header.to_bytes();
    let ciphertext = crypto::encrypt_with_nonce(key, &nonce, &plaintext, &header_bytes)?;

    // A *let-chain*: the block runs only if `path.parent()` is `Some(parent)` AND
    // that parent is non-empty. `parent` is in scope for the whole condition + body.
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)?;
        harden_dir(parent);
    }
    // Atomic write: stage to a temp sibling file, then rename over the target.
    // A rename is atomic on POSIX, so a reader never sees a half-written vault.
    let tmp = sibling_tmp(path)?;
    // `if let Err(e) = ...` = handle just the failure case. On error (incl. an
    // injected ENOSPC), best-effort delete the temp (`let _ =` ignores that
    // cleanup's own result) then return — the live vault.pmv is never touched.
    if let Err(e) = crate::fault::point("vault.write").map_err(VaultError::from).and_then(|()| {
        write_new_file(&tmp, &header_bytes, &ciphertext)
    }) {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    if let Err(e) =
        crate::fault::point("vault.rename").map_err(VaultError::from).and_then(|()| Ok(fs::rename(&tmp, path)?))
    {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    sync_parent_dir(path); // fsync the directory so the rename is durable on disk
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
        return Ok(()); // nothing pending — the common case
    }
    if read_only {
        return Err(VaultError::RekeyPending); // can't write, so can't recover; report it
    }
    if staging.join(REKEY_READY).exists() {
        commit_rekey(dir, &staging)?; // marker present -> the new tree is complete -> finish it
    } else {
        let _ = fs::remove_dir_all(&staging); // no marker -> incomplete -> throw it away (best-effort)
    }
    Ok(())
}

/// Commit a staged rekey by moving the new tree into place: volumes and manifests
/// first, then the vault file **last** (the commit point). Idempotent: re-running
/// after a partial move finishes the remaining items.
fn commit_rekey(dir: &Path, staging: &Path) -> Result<(), VaultError> {
    replace_dir(&dir.join("volume"), &staging.join("volume"))?;
    // Fault point: a crash here (new volume in place, old manifest+vault still
    // live, .rekey still present with READY) must roll forward on the next open.
    crate::fault::point("rekey.after_volume")?;
    replace_dir(&dir.join("manifest"), &staging.join("manifest"))?;
    crate::fault::point("rekey.after_manifest")?;
    replace_path(&dir.join(VAULT_FILE), &staging.join(VAULT_FILE))?;
    crate::fault::point("rekey.after_vault")?;
    // The in-place redundancy copies (mirror + prior generations) are now under the
    // OLD key/garbage layout — drop them. The next normal save regenerates them under
    // the new key (if redundancy is still enabled). Idempotent across a re-run.
    cleanup_redundancy(&dir.join(VAULT_FILE));
    sync_parent_dir(&dir.join(VAULT_FILE));
    let _ = fs::remove_dir_all(staging);
    // A rekey/compact is also a committed vault change — refresh the marker AFTER the swap.
    touch_last_update(dir);
    Ok(())
}

/// Replace `live` with `staged` (a directory) if `staged` still exists.
fn replace_dir(live: &Path, staged: &Path) -> Result<(), VaultError> {
    let old = sibling_old(live); // a temporary ".<name>.old" path next to `live`
    // Sweep any leftover ".<name>.old" FIRST — before the early return below. A
    // crash AFTER `rename(staged, live)` but BEFORE the trailing cleanup leaves the
    // OLD-key-encrypted dir behind; recovery re-enters here with `staged` already
    // gone, so cleaning up only after the `staged.exists()` guard would leak that
    // old-key ciphertext on disk forever (defeating change_password's forward
    // secrecy). Doing it here makes the cleanup unconditional and idempotent.
    let _ = fs::remove_dir_all(&old);
    if !staged.exists() {
        return Ok(());
    }
    if live.exists() {
        fs::rename(live, &old)?; // move the current dir aside...
    }
    fs::rename(staged, live)?; // ...then move the staged dir into its place
    // Make THIS swap durable before the caller proceeds to the next one. Without this
    // barrier the directory renames in `commit_rekey` (volume → manifest → vault.pmv)
    // can reach disk out of program order on a power loss, leaving a NEW-key vault.pmv
    // durable while volume/manifest are still OLD-key — an unopenable vault that the
    // roll-forward cannot repair. The fsync forces new-volume-durable-before-new-vault.
    sync_parent_dir(live);
    let _ = fs::remove_dir_all(&old); // drop the old copy (best-effort; harmless if it lingers)
    Ok(())
}

/// Replace `live` with `staged` (a file) if `staged` still exists.
fn replace_path(live: &Path, staged: &Path) -> Result<(), VaultError> {
    if !staged.exists() {
        return Ok(());
    }
    fs::rename(staged, live)?;
    // Durability barrier — same reasoning as `replace_dir`: the vault.pmv rename is the
    // rekey commit point and must be durable before staging (with its READY marker) is
    // removed, so a crash never loses the commit while erasing its source of truth.
    sync_parent_dir(live);
    Ok(())
}

fn sibling_old(path: &Path) -> PathBuf {
    // `.file_name()` -> `Option<&OsStr>`; `.and_then(|n| n.to_str())` chains another
    // optional step (the name may not be valid UTF-8, giving `None`); `.unwrap_or("x")`
    // supplies a fallback name if either step yielded `None`.
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("x");
    match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.join(format!(".{name}.old")),
        _ => PathBuf::from(format!(".{name}.old")),
    }
}

/// Normalize a virtual directory path to `/a/b/c` form (empty string == root).
fn normalize_dir(path: &str) -> String {
    // Iterator pipeline: split on '/', `.filter(|p| !p.is_empty())` drops empty
    // segments (so "a//b" and trailing slashes collapse), then `.collect()` gathers
    // the kept `&str` pieces into a `Vec`. The closure `|p| !p.is_empty()` is the test.
    let parts: Vec<&str> = path.split('/').filter(|p| !p.is_empty()).collect();
    if parts.is_empty() { String::new() } else { format!("/{}", parts.join("/")) }
}

fn rand_suffix() -> Result<String, CryptoError> {
    // 8 random bytes -> `.iter()` over them -> `.map(|b| format!("{b:02x}"))` formats
    // each as a 2-digit lowercase hex string -> `.collect()` concatenates into one
    // `String` (a 16-char hex suffix). `?` propagates a failure of the RNG call.
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
    // CLI/standalone path: no open session holds the lock, so acquire it for the WHOLE
    // snapshot. An ALREADY-OPEN session must instead use `OpenVault::backup` — calling
    // this free function from a session that already holds the lock self-deadlocks,
    // because flock binds to the open file description and a second in-process
    // acquire returns `WouldBlock` → `Locked`. Holding the lock makes the multi-file
    // copy atomic vs. a concurrent rekey (which would otherwise pair an old-key
    // vault.pmv with a new-key store). On the mobile build (no single-writer-lock
    // feature) this is a no-op — that build serializes all access behind one mutex.
    let _lock = WriteLock::acquire(&src_dir)?;
    backup_snapshot(vault_path, &src_dir, dest_dir)
}

/// The lock-free body of a backup snapshot: copy `vault.pmv` + `manifest/` +
/// `volume/` into a fresh timestamped dir under `dest_dir` as a consistent set
/// (encrypted files as-is, nothing decrypted). The CALLER must already hold the
/// single-writer lock for `src_dir` — the free `backup` acquires it; an open
/// session's `OpenVault::backup` reuses (or, when read-only, acquires) its own.
fn backup_snapshot(vault_path: &Path, src_dir: &Path, dest_dir: &Path) -> Result<PathBuf, VaultError> {
    // Don't snapshot a tree mid-rekey: the volume/manifest may be the new key while
    // vault.pmv is still the old one, yielding an unopenable backup. With the lock
    // held a present `.rekey` means a *crashed* rekey; finish/discard it via --write.
    if src_dir.join(REKEY_DIR).exists() {
        return Err(VaultError::RekeyPending);
    }
    // Refuse a symlink at the SOURCE vault.pmv: `fs::copy` below FOLLOWS it, which
    // would copy an arbitrary file's bytes (whatever the link targets) into the
    // backup set — the same exfiltration F-14 closed for `copy_dir`, here for the
    // top-level file. `symlink_metadata` inspects the link itself, not its target.
    if fs::symlink_metadata(vault_path).map(|m| m.file_type().is_symlink()).unwrap_or(false) {
        return Err(VaultError::Storage(StorageError::Corrupt("vault file is a symlink".to_string())));
    }
    // Refuse a symlinked destination directory: an attacker who can write the vault
    // dir could otherwise point the backup into the very tree we are reading, or at
    // arbitrary files the user can write. (A non-existent dest is fine — created below.)
    if let Ok(meta) = fs::symlink_metadata(dest_dir)
        && meta.file_type().is_symlink()
    {
        return Err(VaultError::Storage(StorageError::Corrupt("backup destination is a symlink".to_string())));
    }
    fs::create_dir_all(dest_dir)?;
    harden_dir(dest_dir);

    let stamp = compact_timestamp(records::unix_now());
    let mut target = dest_dir.join(format!("backup-{stamp}"));
    let mut n = 1;
    // Find a non-colliding name: keep appending `_n` while the path already exists.
    while target.exists() {
        target = dest_dir.join(format!("backup-{stamp}_{n}")); // reassign `target` (it's `mut`)
        n += 1;
    }
    fs::create_dir_all(&target)?;
    harden_dir(&target);

    fs::copy(vault_path, target.join(VAULT_FILE))?;
    harden_file(&target.join(VAULT_FILE))?;
    // Iterate a literal array of the two subdirectory names; `sub` binds each in turn.
    for sub in ["manifest", "volume"] {
        let s = src_dir.join(sub);
        if s.exists() {
            copy_dir(&s, &target.join(sub))?;
        }
    }
    // Belt-and-suspenders for the lock-less (mobile) build: re-check `.rekey`. With the
    // write lock held (desktop) no writer can have started a rekey during the copy, so
    // this can only fire on the lock-less build; harmless to keep on both.
    if src_dir.join(REKEY_DIR).exists() {
        let _ = fs::remove_dir_all(&target);
        return Err(VaultError::RekeyPending);
    }
    Ok(target.join(VAULT_FILE))
}

/// Recursively copy a directory tree (files hardened to 0600 on Unix).
fn copy_dir(src: &Path, dst: &Path) -> Result<(), VaultError> {
    fs::create_dir_all(dst)?;
    harden_dir(dst);
    // `read_dir` yields each entry as a `Result`; `let entry = entry?;` unwraps it
    // (propagating any I/O error), shadowing the loop variable with the unwrapped value.
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let from = entry.path();
        let to = dst.join(entry.file_name());
        // `entry.file_type()` reflects the directory entry itself and does NOT follow
        // symlinks — unlike `Path::is_dir` and `fs::copy`, which both dereference. A
        // same-UID attacker who plants a symlink in the vault tree (e.g.
        // `volume/vol.7 -> /etc/passwd`, or a dir symlink for runaway recursion) would
        // otherwise have its target copied into the backup. Refuse symlink entries.
        let ft = entry.file_type()?;
        if ft.is_symlink() {
            return Err(VaultError::Storage(StorageError::Corrupt(format!(
                "refusing to back up a symlink in the vault tree: {}",
                from.display()
            ))));
        } else if ft.is_dir() {
            copy_dir(&from, &to)?; // recurse into real subdirectories
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

// `#[cfg(unix)]` is *conditional compilation*: this version of the function is
// compiled ONLY on Unix-like systems. The `#[cfg(not(unix))]` twin below is
// compiled everywhere else. Exactly one definition of `harden_file` exists per
// build, so the rest of the code can call it unconditionally.
#[cfg(unix)]
pub fn harden_file(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt; // trait that adds `.set_mode()` to permissions
    let mut perms = fs::metadata(path)?.permissions();
    perms.set_mode(0o600); // owner read/write only — no access for group/others
    fs::set_permissions(path, perms)
}
#[cfg(not(unix))]
pub fn harden_file(_path: &Path) -> std::io::Result<()> {
    Ok(()) // no-op on non-Unix; the `_path` name marks the arg as intentionally unused
}

// Same Unix / non-Unix split as `harden_file`, but for directories (0700 =
// owner-only access). Returns nothing and ignores errors (best-effort hardening).
#[cfg(unix)]
pub fn harden_dir(dir: &Path) {
    use std::os::unix::fs::PermissionsExt;
    // `if let Ok(meta) = ...` runs the body only when the metadata read succeeded.
    if let Ok(meta) = fs::metadata(dir) {
        let mut perms = meta.permissions();
        perms.set_mode(0o700); // owner: read/write/execute; group & others: nothing
        let _ = fs::set_permissions(dir, perms); // best-effort; ignore the result
    }
}
#[cfg(not(unix))]
pub fn harden_dir(_dir: &Path) {} // no-op on non-Unix (empty body)

/// Open a brand-new file with `create_new` (O_EXCL; no symlink-follow) + 0600.
fn create_new_0600(path: &Path) -> std::io::Result<std::fs::File> {
    let mut opts = OpenOptions::new();
    // `.create_new(true)` = fail if the path already exists (atomic O_EXCL). This
    // refuses to clobber an existing file and won't follow a planted symlink.
    opts.write(true).create_new(true);
    // A `#[cfg(unix)]` on a *block*: this whole `{ ... }` is compiled only on Unix.
    // There it sets the file's creation mode to 0600 (owner read/write only).
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt; // brings `.mode()` into scope
        opts.mode(0o600);
    }
    opts.open(path)
}

fn write_new_file(path: &Path, part1: &[u8], part2: &[u8]) -> Result<(), VaultError> {
    let mut f = create_new_0600(path)?; // `f` is mutable: writing to it changes its state
    harden_file(path)?;
    f.write_all(part1)?; // write the header bytes...
    f.write_all(part2)?; // ...then the ciphertext bytes
    f.sync_all()?; // flush to disk (fsync) before returning, for durability
    Ok(())
}

/// Create a brand-new file and write a single buffer (O_EXCL + 0600); removes the
/// partial file on a write error. Shared by `export_document` and the CLI.
/// Return `p` if it does not exist, else a sibling with a `_N` suffix, so an export
/// never silently overwrites an existing file (mirrors the CLI extract's behaviour).
fn unique_export_path(p: PathBuf) -> PathBuf {
    if !p.exists() {
        return p;
    }
    let parent = p.parent().map(PathBuf::from).unwrap_or_default();
    let stem = p.file_stem().and_then(|s| s.to_str()).unwrap_or("file").to_string();
    let ext = p.extension().and_then(|s| s.to_str()).map(|e| format!(".{e}")).unwrap_or_default();
    for n in 1..10_000 {
        let cand = parent.join(format!("{stem}_{n}{ext}"));
        if !cand.exists() {
            return cand;
        }
    }
    p // pathological fallback: let the O_EXCL write surface the collision as an error
}

/// Write `data` to `<dir>/<filename>`, creating `dir` (and parents) if missing, NEVER
/// overwriting an existing file (a `_N` suffix is appended, like document export), with
/// 0600 perms, an fsync of the file contents, AND an fsync of the parent directory so the
/// new file's directory entry is crash-durable. Returns the path actually written. Backs
/// the front-ends' "Export to CSV" action, which drops a timestamped CSV into the export dir.
pub fn write_export_bytes(dir: &Path, filename: &str, data: &[u8]) -> Result<PathBuf, VaultError> {
    fs::create_dir_all(dir)?;
    harden_dir(dir); // best-effort 0700 on the export dir (no-op off unix)
    let path = unique_export_path(dir.join(filename));
    write_new_bytes(&path, data)?;
    // Make the freshly-created file's directory entry durable too — the contents are
    // fsync'd in write_new_bytes, but without this the link can be lost on power loss
    // right after the call returns. Best-effort, no-op off unix (matches the other writers).
    sync_parent_dir(&path);
    Ok(path)
}

pub fn write_new_bytes(path: &Path, data: &[u8]) -> Result<(), VaultError> {
    let mut f = create_new_0600(path)?;
    // Harden perms, then write + fsync, as one fail-cleanup unit: if hardening OR the
    // write OR the fsync fails, close the handle and unlink the just-created file so a
    // failure never leaves a partial (or empty) file behind — the no-clobber / "partial
    // file removed on error" contract the CSV and document exporters rely on.
    let res = harden_file(path).and_then(|()| f.write_all(data)).and_then(|()| f.sync_all());
    if let Err(e) = res {
        drop(f); // close the handle before unlinking (matters on some platforms)
        let _ = fs::remove_file(path);
        return Err(e.into());
    }
    Ok(())
}

// fsync the *directory* so a rename/create is durable (a crash can't lose it).
// Only meaningful on Unix; the non-Unix twin is a no-op.
#[cfg(unix)]
fn sync_parent_dir(path: &Path) {
    // `.filter(...)` keeps the parent only if non-empty; `.unwrap_or_else(closure)`
    // computes the fallback `"."` lazily (the closure runs only when needed).
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or_else(|| Path::new("."));
    if let Ok(dir) = fs::File::open(parent) {
        let _ = dir.sync_all(); // best-effort directory fsync
    }
}
#[cfg(not(unix))]
fn sync_parent_dir(_path: &Path) {}

/// Refresh the vault directory's single `last_update_<UTC>` marker after a committed change.
///
/// A glanceable CONVENIENCE hint — its NAME *and* contents are the commit time
/// (`YYYYMMDD-HHMMSS` UTC) — so an external backup/sync can notice "the vault changed" without
/// decrypting it. Called ONLY after the vault content is durably committed ([`OpenVault::
/// save_internal`], [`commit_rekey`]), NEVER before: a failed/aborted save leaves it untouched.
/// It is NOT written for the desktop `prefs.json` (a separate, non-vault file).
///
/// AUTHORITATIVE source of truth is `vault.pmv`'s own mtime, which the filesystem updates
/// atomically with the temp+rename commit (zero gap). This marker can lag the real commit by one
/// in the tiny crash window *between* the vault commit and this write, so a sync tool needing a
/// HARD guarantee should key off `vault.pmv`'s mtime and treat this only as a fast hint.
///
/// Written atomically (unique temp → fsync → rename → dir fsync) so a concurrent reader never
/// sees a half-written/empty marker and a crash can't leave it partial. Entirely BEST-EFFORT:
/// the vault is already durably committed by the time this runs, so any failure here just leaves
/// a slightly stale/missing hint and must never fail the operation. Ignored by every dir scan
/// (the partition/manifest scanners match strict `vol.<N>`/`manifest.<N>` inside the `volume/`
/// and `manifest/` SUBDIRS, not the vault root where this lives).
fn touch_last_update(dir: &Path) {
    let ts = records::compact_utc(records::unix_now());
    let name = format!("last_update_{ts}");
    let marker = dir.join(&name);
    // Write the NEW marker first (atomic temp → fsync → rename → dir fsync). Writing before
    // removing the old one means there is never a window with NO marker; putting the timestamp
    // in the NAME means a same-second re-save reuses the same path (the rename just refreshes it)
    // rather than self-deleting in the cleanup below.
    let content = format!("{ts}\n");
    let Ok(tmp) = sibling_tmp(&marker) else { return };
    if write_new_file(&tmp, content.as_bytes(), &[]).is_err() {
        let _ = fs::remove_file(&tmp);
        return; // leave the previous marker in place rather than risk a gap
    }
    if fs::rename(&tmp, &marker).is_err() {
        let _ = fs::remove_file(&tmp);
        return;
    }
    sync_parent_dir(&marker);
    // Remove any OTHER (older-named) `last_update_*` so exactly one remains. Skipping the file we
    // just wrote keeps a same-second re-save (identical name) from deleting itself.
    if let Ok(entries) = fs::read_dir(dir) {
        for e in entries.flatten() {
            let n = e.file_name();
            let ns = n.to_string_lossy();
            if ns.starts_with("last_update_") && ns != name {
                let _ = fs::remove_file(e.path());
            }
        }
    }
}

/// Fuzzing entry point (hidden). The vault-file header parser; see `fuzz/`.
// `mod fuzz { ... }` declares an inner module (a namespace). `#[doc(hidden)]`
// keeps it out of generated docs. It just exposes the header parser so a fuzzer
// can feed it arbitrary bytes; `super::` means "the parent module" (this file).
#[doc(hidden)]
pub mod fuzz {
    pub fn header(buf: &[u8]) {
        let _ = super::Header::parse(buf); // discard result; we only care that it doesn't crash
    }
}

// Everything below is the test suite. `#[cfg(test)]` compiles this module ONLY
// when running `cargo test` — it is never part of the shipped binary. Each
// `#[test]` function is an independent check the test runner executes; `assert!`
// / `assert_eq!` fail (panic) the test if a condition doesn't hold. `.unwrap()`
// is used liberally here because a panic in a test is just a test failure.
#[cfg(test)]
mod tests {
    use super::*; // pull every item from the parent module (this file) into the tests

    // ---- Documents: taxes + real estate (hardening) ------------------------

    #[test]
    fn referenced_doc_ids_spans_all_four_record_kinds() {
        // referenced_doc_ids must surface ids from Trust&Will.file, Asset.statement,
        // every Taxes filing's documents, every Real Estate property's documents, and
        // each General Document's file.
        let path = tmp_path("refids");
        let mut v = OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();
        let src = write_src("refids", b"x");

        let tw_id = v.add_document("/wills", "will.pdf", &src).unwrap();
        let asset_id = v.add_document("/assets", "stmt.pdf", &src).unwrap();
        let tax_id1 = v.add_document("taxes/2024", "w2.pdf", &src).unwrap();
        let tax_id2 = v.add_document("taxes/2024", "1099.pdf", &src).unwrap();
        let re_id1 = v.add_document("real-estate/main", "deed.pdf", &src).unwrap();
        let re_id2 = v.add_document("real-estate/main", "policy.pdf", &src).unwrap();
        let gen_id = v.add_document("general-documents/passport", "passport.pdf", &src).unwrap();

        let mut tw = records::TrustWill::new().unwrap();
        tw.file = Some(tw_id.clone());
        records::upsert(&mut v.vault.trust_wills, tw);

        let mut asset = records::AssetLiability::new().unwrap();
        asset.statement = Some(asset_id.clone());
        records::upsert(&mut v.vault.assets, asset);

        let mut tax = records::TaxFiling::new().unwrap();
        tax.year = "2024".into();
        tax.documents.push(tax_id1.clone());
        tax.documents.push(tax_id2.clone());
        records::upsert(&mut v.vault.tax_filings, tax);

        let mut re = records::RealEstate::new().unwrap();
        re.address = "Main".into();
        re.documents.push(re_id1.clone());
        re.documents.push(re_id2.clone());
        records::upsert(&mut v.vault.real_estate, re);

        let mut g = records::GeneralDocument::new().unwrap();
        g.title = "Passport".into();
        g.file = Some(gen_id.clone());
        records::upsert(&mut v.vault.general_documents, g);

        let ids = referenced_doc_ids(&v.vault);
        for want in [&tw_id, &asset_id, &tax_id1, &tax_id2, &re_id1, &re_id2, &gen_id] {
            assert!(ids.contains(want), "referenced_doc_ids missing {want}; got {ids:?}");
        }
        assert_eq!(ids.len(), 7, "exactly the seven referenced ids, got {ids:?}");

        cleanup(&path);
        fs::remove_file(&src).ok();
    }

    #[test]
    fn referenced_doc_ids_empty_when_no_attachments() {
        // Records with no attached files contribute nothing.
        let path = tmp_path("refidsempty");
        let mut v = OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();
        records::upsert(&mut v.vault.trust_wills, records::TrustWill::new().unwrap());
        records::upsert(&mut v.vault.assets, records::AssetLiability::new().unwrap());
        let mut tax = records::TaxFiling::new().unwrap();
        tax.year = "2024".into();
        records::upsert(&mut v.vault.tax_filings, tax);
        let mut re = records::RealEstate::new().unwrap();
        re.address = "x".into();
        records::upsert(&mut v.vault.real_estate, re);
        assert!(referenced_doc_ids(&v.vault).is_empty(), "no attachments -> no referenced ids");
        cleanup(&path);
    }

    #[test]
    fn add_read_document_under_taxes_and_real_estate_locations() {
        // add_document under the shared tax/RE virtual folders, then read_document
        // returns the exact bytes; doc_path reflects the normalized virtual path.
        let path = tmp_path("addread");
        let mut v = OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();
        let tax_body = vec![1u8; 500];
        let re_body = vec![2u8; 600];
        let tax_src = write_src("addread-tax", &tax_body);
        let re_src = write_src("addread-re", &re_body);

        let tax_loc = records::tax_doc_location("2024"); // "taxes/2024"
        let re_loc = records::real_estate_doc_location("123 Main St"); // "real-estate/123mainst"
        let tax_id = v.add_document(&tax_loc, "w2.pdf", &tax_src).unwrap();
        let re_id = v.add_document(&re_loc, "deed.pdf", &re_src).unwrap();

        assert_eq!(&*v.read_document(&tax_id).unwrap(), &tax_body[..]);
        assert_eq!(&*v.read_document(&re_id).unwrap(), &re_body[..]);
        assert_eq!(v.doc_path(&tax_id).unwrap(), "/taxes/2024/w2.pdf");
        assert_eq!(v.doc_path(&re_id).unwrap(), "/real-estate/123mainst/deed.pdf");
        assert!(v.has_document(&tax_id) && v.has_document(&re_id));

        cleanup(&path);
        fs::remove_file(&tax_src).ok();
        fs::remove_file(&re_src).ok();
    }

    #[test]
    fn export_document_writes_plaintext_for_tax_and_re_docs() {
        // export_document writes the decrypted bytes out (O_EXCL, 0600); a second
        // export to the same path must fail (no clobber).
        let path = tmp_path("expdoc");
        let mut v = OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();
        let body = vec![7u8; 333];
        let src = write_src("expdoc", &body);
        let tax_id = v.add_document("taxes/2023", "1099.pdf", &src).unwrap();
        let re_id = v.add_document("real-estate/addr", "policy.pdf", &src).unwrap();

        let out_dir = parent_dir(&path).join("out");
        fs::create_dir_all(&out_dir).unwrap();
        let tax_out = out_dir.join("tax.bin");
        let re_out = out_dir.join("re.bin");
        v.export_document(&tax_id, &tax_out).unwrap();
        v.export_document(&re_id, &re_out).unwrap();
        assert_eq!(fs::read(&tax_out).unwrap(), body);
        assert_eq!(fs::read(&re_out).unwrap(), body);
        // O_EXCL: re-exporting onto an existing path is refused.
        assert!(v.export_document(&tax_id, &tax_out).is_err(), "export must not clobber");

        cleanup(&path);
        fs::remove_file(&src).ok();
    }

    #[test]
    fn compact_volume_keeps_tax_and_re_docs_simultaneously() {
        // Both a tax doc and an RE doc are referenced at once; a single
        // `compact --volume` reclaims garbage while keeping BOTH present.
        let path = tmp_path("cvolboth");
        let mut v = OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();
        let tax_body = vec![3u8; 400];
        let re_body = vec![4u8; 450];
        let tax_src = write_src("cvolboth-tax", &tax_body);
        let re_src = write_src("cvolboth-re", &re_body);

        let tax_id = v.add_document("taxes/2024", "w2.pdf", &tax_src).unwrap();
        let mut tax = records::TaxFiling::new().unwrap();
        tax.year = "2024".into();
        tax.documents.push(tax_id.clone());
        records::upsert(&mut v.vault.tax_filings, tax);

        let re_id = v.add_document("real-estate/main", "deed.pdf", &re_src).unwrap();
        let mut re = records::RealEstate::new().unwrap();
        re.address = "Main".into();
        re.documents.push(re_id.clone());
        records::upsert(&mut v.vault.real_estate, re);

        // Dead frames so compaction has reclaimable garbage around the two live docs.
        for i in 0..4 {
            let id = v.add_document("/g", &format!("g{i}.bin"), &tax_src).unwrap();
            v.remove_document(&id).unwrap();
        }
        v.save().unwrap();

        let opts = volume_opts();
        assert!(v.compact_dry_run(&opts).bytes_reclaimed > 0, "garbage should be reclaimable");
        v.compact(&opts).unwrap();
        // Garbage gone, BOTH docs still readable and intact.
        assert_eq!(v.compact_dry_run(&opts).bytes_reclaimed, 0, "garbage fully reclaimed");
        assert_eq!(&*v.read_document(&tax_id).unwrap(), &tax_body[..], "tax doc kept");
        assert_eq!(&*v.read_document(&re_id).unwrap(), &re_body[..], "RE doc kept");
        drop(v);

        // Reopens cleanly (referenced subset of stored holds) with both docs intact.
        let re_open = OpenVault::open(path.clone(), b"a", b"b").unwrap();
        assert_eq!(&*re_open.read_document(&tax_id).unwrap(), &tax_body[..]);
        assert_eq!(&*re_open.read_document(&re_id).unwrap(), &re_body[..]);
        assert!(!parent_dir(&path).join(REKEY_DIR).exists(), "no staging debris");

        cleanup(&path);
        fs::remove_file(&tax_src).ok();
        fs::remove_file(&re_src).ok();
    }

    #[test]
    fn deleting_tax_filing_then_reclaiming_docs_and_compacting_frees_all() {
        // Mirrors the GUI/TUI delete flow: remove the record, save, then
        // remove_document each attached blob, then `compact --volume` reclaims them.
        let path = tmp_path("deltax");
        let mut v = OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();
        let src = write_src("deltax", &vec![6u8; 500]);
        let mut docs = Vec::new();
        let mut tax = records::TaxFiling::new().unwrap();
        tax.year = "2024".into();
        for i in 0..3 {
            let id = v.add_document("taxes/2024", &format!("d{i}.pdf"), &src).unwrap();
            tax.documents.push(id.clone());
            docs.push(id);
        }
        let tax_id = tax.id.clone();
        records::upsert(&mut v.vault.tax_filings, tax);
        // Keep one unrelated live doc so the store does not go fully empty.
        let mut keep_tax = records::TaxFiling::new().unwrap();
        keep_tax.year = "2025".into();
        let keep = v.add_document("taxes/2025", "keep.pdf", &src).unwrap();
        keep_tax.documents.push(keep.clone());
        records::upsert(&mut v.vault.tax_filings, keep_tax);
        v.save().unwrap();

        // Delete the 2024 filing record, persist, then reclaim each of its blobs.
        assert!(records::remove(&mut v.vault.tax_filings, &tax_id, &mut v.vault.audit, "Tax filing"));
        v.save().unwrap();
        for id in &docs {
            v.remove_document(id).unwrap();
        }
        // The deleted filing's blobs are now dead frames; compaction reclaims them.
        let opts = volume_opts();
        assert!(v.compact_dry_run(&opts).bytes_reclaimed > 0, "deleted-filing blobs are reclaimable");
        v.compact(&opts).unwrap();
        assert_eq!(v.compact_dry_run(&opts).bytes_reclaimed, 0, "all 2024 docs reclaimed");
        // The deleted docs are gone; the kept one survives.
        for id in &docs {
            assert!(!v.has_document(id), "deleted tax doc {id} should be gone");
        }
        assert_eq!(&*v.read_document(&keep).unwrap(), &vec![6u8; 500][..], "kept doc survives");
        drop(v);
        let re = OpenVault::open(path.clone(), b"a", b"b").unwrap();
        assert_eq!(&*re.read_document(&keep).unwrap(), &vec![6u8; 500][..]);
        cleanup(&path);
        fs::remove_file(&src).ok();
    }

    #[test]
    fn deleting_real_estate_property_then_reclaiming_docs_and_compacting_frees_all() {
        // Same flow for a Real Estate property holding several documents.
        let path = tmp_path("delre");
        let mut v = OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();
        let src = write_src("delre", &vec![8u8; 480]);
        let mut docs = Vec::new();
        let mut re = records::RealEstate::new().unwrap();
        re.address = "999 Removed Ave".into();
        for i in 0..4 {
            let id = v.add_document("real-estate/999removedave", &format!("d{i}.pdf"), &src).unwrap();
            re.documents.push(id.clone());
            docs.push(id);
        }
        let re_id = re.id.clone();
        records::upsert(&mut v.vault.real_estate, re);
        // An unrelated kept property doc.
        let mut keep_re = records::RealEstate::new().unwrap();
        keep_re.address = "1 Keep St".into();
        let keep = v.add_document("real-estate/1keepst", "keep.pdf", &src).unwrap();
        keep_re.documents.push(keep.clone());
        records::upsert(&mut v.vault.real_estate, keep_re);
        v.save().unwrap();

        assert!(records::remove(&mut v.vault.real_estate, &re_id, &mut v.vault.audit, "Real Estate"));
        v.save().unwrap();
        for id in &docs {
            v.remove_document(id).unwrap();
        }
        let opts = volume_opts();
        assert!(v.compact_dry_run(&opts).bytes_reclaimed > 0);
        v.compact(&opts).unwrap();
        assert_eq!(v.compact_dry_run(&opts).bytes_reclaimed, 0, "all property docs reclaimed");
        for id in &docs {
            assert!(!v.has_document(id), "deleted RE doc {id} should be gone");
        }
        assert_eq!(&*v.read_document(&keep).unwrap(), &vec![8u8; 480][..]);
        drop(v);
        let reopen = OpenVault::open(path.clone(), b"a", b"b").unwrap();
        assert_eq!(&*reopen.read_document(&keep).unwrap(), &vec![8u8; 480][..]);
        cleanup(&path);
        fs::remove_file(&src).ok();
    }

    #[test]
    fn records_remove_alone_leaves_blobs_as_orphans_compaction_keeps_them() {
        // By design: `records::remove` only drops the record JSON; it does NOT touch
        // the store. Until the caller also calls remove_document, the blobs are still
        // LIVE manifest entries, so `compact --volume` conservatively KEEPS them
        // (regression guard against compaction silently dropping not-yet-reclaimed docs).
        let path = tmp_path("orphanre");
        let mut v = OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();
        let src = write_src("orphanre", &vec![5u8; 300]);
        let id = v.add_document("real-estate/x", "deed.pdf", &src).unwrap();
        let mut re = records::RealEstate::new().unwrap();
        re.address = "X".into();
        re.documents.push(id.clone());
        let re_id = re.id.clone();
        records::upsert(&mut v.vault.real_estate, re);
        v.save().unwrap();

        // Remove ONLY the record (forget to reclaim the blob).
        assert!(records::remove(&mut v.vault.real_estate, &re_id, &mut v.vault.audit, "Real Estate"));
        v.save().unwrap();
        // The blob is now unreferenced but still a live store entry, so there is no
        // reclaimable garbage and compaction keeps it readable.
        let opts = volume_opts();
        assert_eq!(v.compact_dry_run(&opts).bytes_reclaimed, 0, "orphan is still a live frame");
        v.compact(&opts).unwrap();
        assert_eq!(&*v.read_document(&id).unwrap(), &vec![5u8; 300][..], "orphan blob preserved");
        cleanup(&path);
        fs::remove_file(&src).ok();
    }

    #[test]
    fn remove_document_persists_tombstone_across_reopen() {
        // Regression (deep-hunt): `remove_document` must make its anti-resurrection
        // tombstone DURABLE. The UI flow saves the record→doc unlink BEFORE calling
        // remove_document, so if remove_document only pushed the tombstone in memory it
        // would be lost on close — and a later manifest-loss rebuild could resurrect the
        // deleted frame. Here we mimic that flow (no further save after remove_document)
        // and assert the tombstone survives a reopen.
        let path = tmp_path("tombstone");
        let mut v = OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();
        let src = write_src("tombstone", &vec![7u8; 256]);
        let id = v.add_document("general-documents/x", "doc.pdf", &src).unwrap();
        let mut g = records::GeneralDocument::new().unwrap();
        g.title = "X".into();
        g.file = Some(id.clone());
        records::upsert(&mut v.vault.general_documents, g);
        v.save().unwrap(); // UI persists the link first...

        // ...then unlinks + reclaims. Persist the unlink, then remove the blob WITHOUT a
        // further save (exactly the UI ordering).
        v.vault.general_documents[0].file = None;
        v.save().unwrap();
        v.remove_document(&id).unwrap();
        drop(v);

        let re = OpenVault::open(path.clone(), b"a", b"b").unwrap();
        assert!(re.vault.deleted_docs.iter().any(|d| d == &id), "tombstone persisted across reopen");
        assert!(re.is_tombstoned(&id), "reopened handle treats the id as deleted");
        cleanup(&path);
        fs::remove_file(&src).ok();
    }

    #[test]
    fn serialize_secret_json_matches_serde_and_never_reallocates() {
        // The zero-reallocation serializer must produce byte-identical JSON to serde_json
        // (so nothing else changes) AND end up with capacity == len (the measuring pass sized
        // it exactly, so the real pass never grew/freed an intermediate cleartext buffer).
        let mut vault = Vault::default();
        vault.version = FORMAT_VERSION;
        let mut acc = records::Account::new().unwrap();
        acc.title = "Bank".into();
        acc.owner = "Alice".into();
        acc.password = "s3cret-with-some-length-to-force-growth".into();
        records::upsert(&mut vault.accounts, acc);

        let compact = serialize_secret_json(&vault, false).unwrap();
        assert_eq!(&compact[..], serde_json::to_vec(&vault).unwrap().as_slice(), "compact matches serde");
        assert_eq!(compact.capacity(), compact.len(), "exact capacity => no realloc strand");

        let pretty = serialize_secret_json(&vault, true).unwrap();
        assert_eq!(&pretty[..], serde_json::to_vec_pretty(&vault).unwrap().as_slice(), "pretty matches serde");
        assert_eq!(pretty.capacity(), pretty.len(), "exact capacity => no realloc strand");
    }

    #[test]
    fn remove_document_refuses_a_still_referenced_id() {
        // Regression (deep-hunt): removing a blob a record still references would save a
        // dangling reference and brick the vault on next open. remove_document must refuse.
        let path = tmp_path("stillref");
        let mut v = OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();
        let src = write_src("stillref", &[9u8; 200]);
        let id = v.add_document("general-documents/x", "doc.pdf", &src).unwrap();
        let mut g = records::GeneralDocument::new().unwrap();
        g.title = "X".into();
        g.file = Some(id.clone());
        records::upsert(&mut v.vault.general_documents, g);
        v.save().unwrap();

        // Still referenced -> refused, vault untouched.
        assert!(matches!(v.remove_document(&id), Err(VaultError::StillReferenced)));
        assert!(v.has_document(&id), "blob retained after refused removal");
        // Unlink first, then it succeeds and the vault still opens cleanly.
        v.vault.general_documents[0].file = None;
        v.save().unwrap();
        v.remove_document(&id).unwrap();
        drop(v);
        let re = OpenVault::open(path.clone(), b"a", b"b").unwrap();
        assert!(!re.has_document(&id), "removed after unlink");
        cleanup(&path);
        fs::remove_file(&src).ok();
    }

    #[test]
    fn compact_heals_a_referenced_but_tombstoned_blob_instead_of_bricking() {
        // Regression (deep-hunt): a crash-derived "referenced AND tombstoned" state must not
        // make compact/rekey drop the blob (which would brick the next open). Reference wins:
        // the document is kept and the vault stays openable.
        let path = tmp_path("refxtomb");
        let mut v = OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();
        let src = write_src("refxtomb", &[1u8; 220]);
        let id = v.add_document("general-documents/x", "doc.pdf", &src).unwrap();
        let mut g = records::GeneralDocument::new().unwrap();
        g.title = "X".into();
        g.file = Some(id.clone());
        records::upsert(&mut v.vault.general_documents, g);
        // Force the contradictory state directly (the API now refuses to create it): the doc
        // is referenced by the record AND carries a tombstone.
        v.vault.deleted_docs.push(id.clone());
        v.save().unwrap();

        v.compact(&volume_opts()).unwrap();
        assert!(v.has_document(&id), "referenced blob survived compaction (reference wins)");
        assert!(v.vault.deleted_docs.is_empty(), "tombstones cleared after rewrite");
        assert_eq!(&*v.read_document(&id).unwrap(), &[1u8; 220][..], "content intact");
        drop(v);
        let re = OpenVault::open(path.clone(), b"a", b"b").unwrap();
        assert!(re.has_document(&id), "vault reopens cleanly, document healed back to live");
        cleanup(&path);
        fs::remove_file(&src).ok();
    }

    #[test]
    fn many_documents_on_one_record_all_survive_save_reopen_read() {
        // A single record holding MANY (8) documents: every distinct byte pattern
        // survives save -> reopen -> read.
        let path = tmp_path("manydocs");
        let mut v = OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();
        let mut tax = records::TaxFiling::new().unwrap();
        tax.year = "2024".into();
        let mut ids = Vec::new();
        for i in 0u8..8 {
            // Distinct content per doc so a cross-wired id would be caught.
            let body = vec![i; 200 + i as usize * 13];
            let src = write_src(&format!("manydocs-{i}"), &body);
            let id = v.add_document("taxes/2024", &format!("doc{i}.pdf"), &src).unwrap();
            fs::remove_file(&src).ok();
            tax.documents.push(id.clone());
            ids.push((id, body));
        }
        records::upsert(&mut v.vault.tax_filings, tax);
        v.save().unwrap();
        drop(v);

        let reopened = OpenVault::open(path.clone(), b"a", b"b").unwrap();
        assert_eq!(reopened.vault.tax_filings[0].documents.len(), 8, "all 8 ids persisted");
        for (id, body) in &ids {
            assert_eq!(&*reopened.read_document(id).unwrap(), &body[..], "doc {id} survives reopen");
        }
        cleanup(&path);
    }

    #[test]
    fn removing_one_of_several_docs_leaves_the_others_readable() {
        // Remove the middle of several documents on a record; the rest stay readable
        // and the removed one is gone.
        let path = tmp_path("rmone");
        let mut v = OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();
        let mut ids = Vec::new();
        for i in 0u8..5 {
            let body = vec![i + 1; 150];
            let src = write_src(&format!("rmone-{i}"), &body);
            let id = v.add_document("taxes/2024", &format!("f{i}.pdf"), &src).unwrap();
            fs::remove_file(&src).ok();
            ids.push((id, body));
        }
        // Remove index 2.
        let (gone_id, _) = ids.remove(2);
        v.remove_document(&gone_id).unwrap();
        assert!(!v.has_document(&gone_id), "removed doc is gone");
        assert!(matches!(v.read_document(&gone_id), Err(VaultError::Storage(StorageError::NotFound(_)))));
        // The rest are intact.
        for (id, body) in &ids {
            assert_eq!(&*v.read_document(id).unwrap(), &body[..], "remaining doc {id} readable");
        }
        drop(v);
        let re = OpenVault::open(path.clone(), b"a", b"b").unwrap();
        for (id, body) in &ids {
            assert_eq!(&*re.read_document(id).unwrap(), &body[..]);
        }
        assert!(!re.has_document(&gone_id));
        cleanup(&path);
    }

    #[test]
    fn add_document_path_length_boundary() {
        // virtual_path("", name) == "/" + name. MAX_PATH_LEN (256) bytes is accepted;
        // one byte over is rejected with PathTooLong.
        let path = tmp_path("pathlen");
        let mut v = OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();
        let src = write_src("pathlen", b"body");

        // Exactly MAX_PATH_LEN: "/" + 255 chars = 256 bytes.
        let at_limit = "x".repeat(storage::MAX_PATH_LEN - 1);
        assert_eq!(virtual_path("", &at_limit).len(), storage::MAX_PATH_LEN);
        let id = v.add_document("", &at_limit, &src).unwrap();
        assert_eq!(&*v.read_document(&id).unwrap(), b"body");

        // One byte over: "/" + 256 chars = 257 bytes -> PathTooLong.
        let over = "y".repeat(storage::MAX_PATH_LEN);
        assert_eq!(virtual_path("", &over).len(), storage::MAX_PATH_LEN + 1);
        let err = v.add_document("", &over, &src).unwrap_err();
        assert!(matches!(err, VaultError::Storage(StorageError::PathTooLong)), "got {err:?}");

        cleanup(&path);
        fs::remove_file(&src).ok();
    }

    #[test]
    fn add_document_path_length_boundary_with_location() {
        // The boundary holds when the length comes from location + filename together.
        // virtual_path("/taxes/2024", name) == "/taxes/2024/" + name (12-byte prefix).
        let path = tmp_path("pathlen2");
        let mut v = OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();
        let src = write_src("pathlen2", b"body");
        let prefix = virtual_path("/taxes/2024", ""); // "/taxes/2024/"
        let fill = storage::MAX_PATH_LEN - prefix.len();
        let name = "z".repeat(fill);
        assert_eq!(virtual_path("/taxes/2024", &name).len(), storage::MAX_PATH_LEN);
        let id = v.add_document("/taxes/2024", &name, &src).unwrap();
        assert_eq!(&*v.read_document(&id).unwrap(), b"body");

        let over = "z".repeat(fill + 1);
        let err = v.add_document("/taxes/2024", &over, &src).unwrap_err();
        assert!(matches!(err, VaultError::Storage(StorageError::PathTooLong)), "got {err:?}");
        cleanup(&path);
        fs::remove_file(&src).ok();
    }
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
        // `drop(v)` ends `v`'s lifetime right here (instead of at the end of scope),
        // which runs its destructor and releases the single-writer lock so the
        // reopen below can take it. This `drop`-to-release pattern recurs throughout.
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
        // `matches!(value, Pattern)` is true if `value` fits the pattern. Here `_`
        // inside the variant ignores the contained path — we only check the *kind*
        // of error. Used throughout these tests to assert a specific failure.
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
    fn add_document_rejects_non_regular_source() {
        let path = tmp_path("nonreg");
        let mut v = OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();
        // A directory is not a regular file; add_document must refuse it rather than
        // attempt an unbounded read (the /dev/zero / FIFO class of zero-length-but-
        // endless inputs that would otherwise drive an OOM).
        let dir_src = std::env::temp_dir().join(format!("pmsrc-dir-{}", nanos()));
        fs::create_dir_all(&dir_src).unwrap();
        let err = v.add_document("/d", "f.txt", &dir_src).unwrap_err();
        assert!(matches!(err, VaultError::Storage(StorageError::Corrupt(_))));
        let _ = fs::remove_dir_all(&dir_src);
        cleanup(&path);
    }

    #[test]
    fn redundancy_off_by_default_writes_no_extra_files() {
        let path = tmp_path("redoff");
        let v = OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();
        assert_eq!(v.redundancy(), 0, "redundancy is off by default");
        drop(v);
        assert!(!mirror_path(&path).exists(), "no mirror when off");
        assert!(!bak_path(&path, 1).exists(), "no generations when off");
        cleanup(&path);
    }

    #[test]
    fn redundancy_writes_mirror_and_generations() {
        let path = tmp_path("redon");
        let mut v = OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();
        v.set_redundancy(2).unwrap(); // depth 2 + mirror
        records::upsert(&mut v.vault.accounts, sample_account("u1", "p1"));
        v.save().unwrap();
        records::upsert(&mut v.vault.accounts, sample_account("u2", "p2"));
        v.save().unwrap();
        drop(v);
        assert!(mirror_path(&path).exists(), "mirror is written");
        assert!(bak_path(&path, 1).exists(), "newest prior generation kept");
        assert!(bak_path(&path, 2).exists(), "second prior generation kept");
        assert!(!bak_path(&path, 3).exists(), "ring is bounded to the configured depth");
        cleanup(&path);
    }

    #[test]
    fn recovers_from_mirror_when_primary_ciphertext_corrupt() {
        let path = tmp_path("redmir");
        let mut v = OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();
        v.set_redundancy(1).unwrap();
        records::upsert(&mut v.vault.accounts, sample_account("keep-me", "p"));
        v.save().unwrap();
        drop(v);
        // Flip a ciphertext byte (header still parses) so the live file fails the AEAD
        // tag but the same-generation mirror is intact — recovery loses no data.
        let mut bytes = fs::read(&path).unwrap();
        bytes[HEADER_LEN] ^= 0xff;
        fs::write(&path, &bytes).unwrap();
        let v2 = OpenVault::open(path.clone(), b"a", b"b").unwrap();
        assert!(v2.recovery_notice().is_some(), "recovery is reported");
        let users: Vec<&str> = v2.vault.accounts.iter().map(|a| a.username.as_str()).collect();
        assert!(users.contains(&"keep-me"), "mirror restores the exact latest state");
        cleanup(&path);
    }

    #[test]
    fn salt_is_authenticated_so_a_salt_damaged_copy_is_unrecoverable() {
        // The salt lives in the AEAD associated data (Header::to_bytes covers bytes 21..37),
        // so corrupting a COPY's header salt makes its body undecryptable under ANY key (wrong
        // key from the bad salt, and a wrong AAD even with a sibling key). This pins WHY
        // recovery only uses each candidate's own-salt key (no cross-salt "sibling" fallback):
        // here the live primary AND the mirror's salt are damaged, leaving no intact-header
        // copy, so the open must FAIL closed rather than appear to recover.
        let path = tmp_path("redsaltauth");
        let mut v = OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();
        v.set_redundancy(1).unwrap();
        records::upsert(&mut v.vault.accounts, sample_account("keep-me", "p"));
        v.save().unwrap();
        drop(v);
        let flip = |p: &Path, off: usize| {
            let mut b = fs::read(p).unwrap();
            b[off] ^= 0xff;
            fs::write(p, &b).unwrap();
        };
        flip(&path, 70); // primary body -> recovery runs
        flip(&mirror_path(&path), 21); // mirror header SALT -> body authenticated under the old salt, unrecoverable
        flip(&bak_path(&path, 1), 70); // the only other copy: body corrupt -> not recoverable either
        assert!(
            OpenVault::open(path.clone(), b"a", b"b").is_err(),
            "a salt-damaged copy cannot be recovered (salt is authenticated); with no intact copy, open fails closed"
        );
        cleanup(&path);
    }

    #[test]
    fn recovers_from_generation_when_primary_and_mirror_corrupt() {
        let path = tmp_path("redbak");
        let mut v = OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();
        v.set_redundancy(1).unwrap();
        records::upsert(&mut v.vault.accounts, sample_account("keep-me", "p")); // state A
        v.save().unwrap();
        records::upsert(&mut v.vault.accounts, sample_account("newer", "p")); // state B
        v.save().unwrap();
        drop(v);
        // Destroy BOTH the live file and its mirror; only the prior generation (= A) survives.
        fs::write(&path, b"not a vault at all").unwrap();
        fs::write(mirror_path(&path), b"corrupt mirror").unwrap();
        let v2 = OpenVault::open(path.clone(), b"a", b"b").unwrap();
        assert!(v2.recovery_notice().is_some(), "recovery is reported");
        let users: Vec<&str> = v2.vault.accounts.iter().map(|a| a.username.as_str()).collect();
        assert!(users.contains(&"keep-me"), "the prior generation's data survives");
        assert!(!users.contains(&"newer"), "the most recent change was rolled back (expected for a generation)");
        cleanup(&path);
    }

    #[test]
    fn recovery_caps_distinct_salt_derivations_to_bound_open_dos() {
        // Red-team finding: an attacker who can write the vault dir plants candidate
        // copies each with a DISTINCT salt + valid header to force one expensive
        // Argon2 derivation per salt on every open. decrypt_with_redundancy caps the
        // number of distinct salts it derives (MAX_RECOVERY_SALTS = 3). Here a VALID
        // copy is placed only AFTER three distinct junk salts, so the cap is reached
        // before it and recovery fails closed — proving the bound fires. (Honest 1-2
        // salt recovery is covered by the recovers_from_* tests above, which still
        // pass, so the cap does not regress real recovery.)
        let path = tmp_path("redcap");
        let mut v = OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();
        records::upsert(&mut v.vault.accounts, sample_account("keep-me", "p"));
        v.save().unwrap();
        drop(v);

        let valid = fs::read(&path).unwrap(); // decryptable under the real (salt_T) key
        // A candidate that PARSES (valid header) but never decodes: a distinct salt
        // (bytes 21..37) makes the derived key — and the AAD — wrong, and we also
        // break a ciphertext byte. The recovery loop derives once per such salt.
        let junk = |salt_byte: u8| {
            let mut b = valid.clone();
            for x in b.iter_mut().take(37).skip(21) {
                *x = salt_byte; // distinct 16-byte salt
            }
            b[HEADER_LEN] ^= 0xff; // corrupt the ciphertext too
            b
        };
        // Candidate order is mirror, bak1, bak2, bak3: put three distinct junk salts
        // first, then the valid copy at bak3 (the 4th candidate).
        fs::write(mirror_path(&path), junk(0x11)).unwrap();
        fs::write(bak_path(&path, 1), junk(0x22)).unwrap();
        fs::write(bak_path(&path, 2), junk(0x33)).unwrap();
        fs::write(bak_path(&path, 3), &valid).unwrap();
        fs::write(&path, b"not a vault").unwrap(); // corrupt the live file -> recovery runs

        assert!(
            OpenVault::open(path.clone(), b"a", b"b").is_err(),
            "a valid copy reachable only past the distinct-salt cap is NOT recovered (DoS bound holds)"
        );
        cleanup(&path);
    }

    #[test]
    fn wrong_password_still_fails_with_redundancy_enabled() {
        let path = tmp_path("redpw");
        let mut v = OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();
        v.set_redundancy(2).unwrap();
        v.save().unwrap();
        drop(v);
        // A wrong password must fail (every copy fails the same way) — never a false
        // "recovery". (Also a regression guard that this stays ~one Argon2, not N.)
        let res = OpenVault::open(path.clone(), b"a", b"WRONG");
        assert!(matches!(res, Err(VaultError::Crypto(_))), "wrong password must be a crypto error");
        cleanup(&path);
    }

    #[test]
    fn disabling_redundancy_removes_existing_copies() {
        let path = tmp_path("reddis");
        let mut v = OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();
        v.set_redundancy(2).unwrap();
        v.save().unwrap();
        assert!(mirror_path(&path).exists());
        v.set_redundancy(0).unwrap(); // turning it off cleans up the extra copies
        drop(v);
        assert!(!mirror_path(&path).exists(), "mirror removed when disabled");
        assert!(!bak_path(&path, 1).exists(), "generations removed when disabled");
        cleanup(&path);
    }

    #[test]
    fn rekey_regenerates_redundancy_under_new_key() {
        let path = tmp_path("redrekey");
        let mut v = OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();
        v.set_redundancy(2).unwrap();
        v.save().unwrap();
        assert!(mirror_path(&path).exists());
        v.change_password(b"c", b"d").unwrap();
        drop(v);
        // The stale OLD-key copies are cleared and FRESH copies are regenerated under
        // the NEW key immediately (no redundancy gap until the next save, §12.8).
        assert!(mirror_path(&path).exists(), "mirror regenerated after rekey");
        assert!(bak_path(&path, 1).exists(), "a generation regenerated after rekey");
        // The regenerated mirror decodes under the NEW passwords (not the old ones).
        let raw = read_capped_vault(&mirror_path(&path)).unwrap();
        assert!(decode_vault_bytes(&raw, b"c", b"d").is_ok(), "mirror is under the new key");
        assert!(decode_vault_bytes(&raw, b"a", b"b").is_err(), "mirror is NOT under the old key");
        // The vault still opens cleanly under the NEW passwords (no recovery needed).
        let v2 = OpenVault::open(path.clone(), b"c", b"d").unwrap();
        assert!(v2.recovery_notice().is_none());
        cleanup(&path);
    }

    #[test]
    fn recovers_from_mirror_when_primary_salt_corrupt() {
        // Regression for the HIGH finding: recovery must NOT derive the key from the
        // corrupt live header. Flipping a byte inside the salt region leaves the
        // header parseable but makes the key derived from it useless; the mirror's
        // (intact) salt must be used instead.
        let path = tmp_path("redsalt");
        let mut v = OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();
        v.set_redundancy(1).unwrap();
        records::upsert(&mut v.vault.accounts, sample_account("keep-me", "p"));
        v.save().unwrap();
        drop(v);
        let mut bytes = fs::read(&path).unwrap();
        bytes[21] ^= 0xff; // the salt starts at header offset 21
        fs::write(&path, &bytes).unwrap();
        let v2 = OpenVault::open(path.clone(), b"a", b"b").unwrap();
        assert!(v2.recovery_notice().is_some(), "recovery is reported");
        let users: Vec<&str> = v2.vault.accounts.iter().map(|a| a.username.as_str()).collect();
        assert!(users.contains(&"keep-me"), "recovered the exact latest state from the mirror");
        cleanup(&path);
    }

    #[test]
    fn reducing_redundancy_prunes_excess_generations() {
        let path = tmp_path("redprune");
        let mut v = OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();
        v.set_redundancy(5).unwrap();
        for i in 0..6 {
            records::upsert(&mut v.vault.accounts, sample_account(&format!("u{i}"), "p"));
            v.save().unwrap();
        }
        assert!(bak_path(&path, 5).exists(), "depth 5 fills the ring up to bak5");
        v.set_redundancy(2).unwrap(); // lower the depth -> excess generations must be pruned
        drop(v);
        assert!(bak_path(&path, 1).exists() && bak_path(&path, 2).exists(), "kept within the new depth");
        assert!(
            !bak_path(&path, 3).exists() && !bak_path(&path, 4).exists() && !bak_path(&path, 5).exists(),
            "generations beyond the new depth are pruned (no stale old secrets left)"
        );
        cleanup(&path);
    }

    #[test]
    fn redundant_copies_decode_to_expected_generations() {
        let path = tmp_path("redgens");
        let mut v = OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();
        v.set_redundancy(2).unwrap();
        for i in 0..3 {
            records::upsert(&mut v.vault.accounts, sample_account(&format!("u{i}"), "p"));
            v.save().unwrap();
        }
        drop(v);
        let gen_of = |p: &Path| {
            let raw = read_capped_vault(p).unwrap();
            decode_vault_bytes(&raw, b"a", b"b").unwrap().0.generation
        };
        let prim = gen_of(&path);
        assert_eq!(gen_of(&mirror_path(&path)), prim, "mirror == current generation (lossless)");
        assert_eq!(gen_of(&bak_path(&path, 1)), prim - 1, "bak1 == previous generation");
        assert_eq!(gen_of(&bak_path(&path, 2)), prim - 2, "bak2 == two generations back");
        cleanup(&path);
    }

    #[test]
    fn create_discards_stale_rekey_staging() {
        // A leftover `.rekey/READY` from an aborted rekey of a since-removed vault must
        // NOT be rolled forward over a freshly created vault on the next open.
        let path = tmp_path("crrekey");
        let dir = parent_dir(&path);
        let staging = dir.join(REKEY_DIR);
        fs::create_dir_all(&staging).unwrap();
        fs::write(staging.join(VAULT_FILE), b"bogus stale staged vault").unwrap();
        fs::write(staging.join(REKEY_READY), b"ready").unwrap();
        {
            let _v = OpenVault::create(path.clone(), b"c", b"d", fast()).unwrap();
        }
        assert!(!staging.exists(), "create() cleared the stale staging");
        // Without the fix, the next open would roll the bogus stage over vault.pmv and fail.
        let v = OpenVault::open(path.clone(), b"c", b"d").unwrap();
        assert!(v.recovery_notice().is_none());
        cleanup(&path);
    }

    #[cfg(unix)]
    #[test]
    fn redundancy_bak_write_is_symlink_safe() {
        // A symlink planted at a bak path must be REPLACED by the atomic write, not
        // followed (which would clobber the symlink's target + chmod it).
        use std::os::unix::fs::symlink;
        let path = tmp_path("redsym");
        let mut v = OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();
        v.set_redundancy(1).unwrap();
        v.save().unwrap();
        drop(v);
        let victim = std::env::temp_dir().join(format!("redsym-victim-{}", nanos()));
        fs::write(&victim, b"do not touch").unwrap();
        let b1 = bak_path(&path, 1);
        let _ = fs::remove_file(&b1);
        symlink(&victim, &b1).unwrap(); // bak1 -> victim
        // Reopening (writable) triggers a heal/refresh save that rotates the ring.
        let mut v2 = OpenVault::open(path.clone(), b"a", b"b").unwrap();
        records::upsert(&mut v2.vault.accounts, sample_account("x", "y"));
        v2.save().unwrap();
        drop(v2);
        assert_eq!(fs::read(&victim).unwrap(), b"do not touch", "the symlink target must be untouched");
        assert!(
            !fs::symlink_metadata(&b1).unwrap().file_type().is_symlink(),
            "bak1 is now a real file, not the planted symlink"
        );
        let _ = fs::remove_file(&victim);
        cleanup(&path);
    }

    #[cfg(feature = "fault-injection")]
    #[test]
    fn failed_save_does_not_degrade_generation_ring() {
        // Regression: the ring must be rotated only AFTER the primary commits, so a
        // failed save leaves the retained generations untouched.
        let path = tmp_path("redfault");
        let mut v = OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();
        v.set_redundancy(2).unwrap();
        for i in 0..3 {
            records::upsert(&mut v.vault.accounts, sample_account(&format!("u{i}"), "p"));
            v.save().unwrap();
        }
        let b1_before = fs::read(bak_path(&path, 1)).unwrap();
        let b2_before = fs::read(bak_path(&path, 2)).unwrap();
        crate::fault::fail_at("vault.write", 1);
        records::upsert(&mut v.vault.accounts, sample_account("late", "p"));
        let res = v.save();
        crate::fault::clear();
        assert!(res.is_err(), "save fails when the primary write fails");
        assert_eq!(fs::read(bak_path(&path, 1)).unwrap(), b1_before, "bak1 untouched after a failed save");
        assert_eq!(fs::read(bak_path(&path, 2)).unwrap(), b2_before, "bak2 untouched after a failed save");
        cleanup(&path);
    }

    #[cfg(unix)]
    #[test]
    fn generation_recovery_with_unreadable_mirror_reports_loss_not_mirror() {
        // Regression: when the mirror's READ fails (so it drops out of the candidate
        // blobs), recovery from a prior generation must NOT be mislabeled as a
        // lossless mirror recovery — the notice must warn that the latest change may be
        // missing. (The notice intentionally hedges with "may be missing" rather than
        // asserting a definite "earlier generation": at recovery time we cannot read
        // the lost primary's generation, and after a rekey a bak is often the CURRENT
        // generation — asserting loss there cried wolf, audit R-12. The non-mirror
        // wording still prompts the user to re-save and refresh backups.)
        let path = tmp_path("redmislabel");
        let mut v = OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();
        v.set_redundancy(1).unwrap();
        records::upsert(&mut v.vault.accounts, sample_account("old", "p")); // state A -> becomes bak1
        v.save().unwrap();
        records::upsert(&mut v.vault.accounts, sample_account("new", "p")); // state B -> primary + mirror
        v.save().unwrap();
        drop(v);
        // Live file corrupt; mirror replaced by a DIRECTORY so its read fails (EISDIR)
        // and it drops out of the candidate blobs; only bak1 (=A) survives → recovery
        // is from an earlier generation, which must be reported as such.
        fs::write(&path, b"garbage not a vault").unwrap();
        fs::remove_file(mirror_path(&path)).unwrap();
        fs::create_dir(mirror_path(&path)).unwrap();
        let v2 = OpenVault::open(path.clone(), b"a", b"b").unwrap();
        let notice = v2.recovery_notice().unwrap_or("");
        assert!(
            notice.contains("may be missing") && !notice.contains("its mirror copy"),
            "must warn of possible loss and NOT claim a lossless mirror recovery, got: {notice:?}"
        );
        assert!(!notice.contains("no data lost"), "must NOT claim no data lost, got: {notice:?}");
        let users: Vec<&str> = v2.vault.accounts.iter().map(|a| a.username.as_str()).collect();
        assert!(users.contains(&"old") && !users.contains(&"new"), "recovered the prior generation A");
        cleanup(&path);
    }

    /// A fresh directory for an import-mirror source.
    fn tmp_src(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("pmsrc-mirror-{tag}-{}", nanos()));
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn add_and_read_a_moderately_large_document() {
        // A ~256 KiB document must round-trip — well under MAX_DOC_SIZE (64 MiB) but
        // far above the trivial test docs, so it also catches a mutation that shrinks
        // the size cap to a tiny value (which would then wrongly reject it).
        let path = tmp_path("biggish");
        let mut v = OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();
        let body = vec![0x5Au8; 256 * 1024];
        let src = write_src("big", &body);
        let id = v.add_document("/d", "big.bin", &src).unwrap();
        assert_eq!(&*v.read_document(&id).unwrap(), &body[..], "large doc round-trips intact");
        let _ = fs::remove_file(&src);
        cleanup(&path);
    }

    #[test]
    fn import_tree_rejects_unsafe_vault_id() {
        let src = tmp_src("badid");
        let mut vault = Vault::default();
        vault.version = FORMAT_VERSION;
        vault.id = "../../etc/passwd".into(); // not a safe ASCII-alnum token
        fs::write(src.join("vault.json"), serde_json::to_vec(&vault).unwrap()).unwrap();
        let dest = tmp_path("impbadid");
        let res = OpenVault::import_tree(&src, &dest, b"a", b"b", fast());
        assert!(res.is_err(), "an unsafe vault id in the untrusted mirror is rejected");
        let _ = fs::remove_dir_all(&src);
        let _ = fs::remove_dir_all(parent_dir(&dest));
    }

    #[test]
    fn is_safe_blob_id_allows_only_hex_and_blocks_escapes() {
        // Real ids: 32 lowercase hex chars.
        assert!(is_safe_blob_id(&records::random_id().unwrap()));
        assert!(is_safe_blob_id("00ff"));
        // Filesystem-escape / device vectors that the old denylist missed:
        for bad in [
            "", "..", ".", "a/b", "a\\b", "a\0b", // separators / dot / nul
            "C:evil", "secret:hidden",            // Windows drive-relative / NTFS ADS
            "NUL", "CON", "COM1", "LPT1",          // Windows reserved device names
            "foo.", "foo ", " foo",                // trailing dot / spaces
            "deadbeefg",                            // non-hex letter
            "DEADBEEF", "AAbb",                     // UPPERCASE hex (R-11: case-insensitive-FS collision)
            &"a".repeat(65),                        // over-length
        ] {
            assert!(!is_safe_blob_id(bad), "must reject {bad:?}");
        }
    }

    #[test]
    fn is_safe_doc_path_rejects_control_and_bidi() {
        assert!(is_safe_doc_path("trust-wills/auto/ts/deed.pdf"));
        assert!(!is_safe_doc_path("a\nb"));
        assert!(!is_safe_doc_path("a\x1b[2Jb")); // terminal escape
        assert!(!is_safe_doc_path("a\0b"));
        // R-5: Unicode bidi/format/zero-width chars (NOT caught by is_control).
        assert!(!is_safe_doc_path("invoice\u{202e}fdp.scr"), "RLO override rejected");
        assert!(!is_safe_doc_path("a\u{200b}b"), "zero-width space rejected");
        assert!(!is_safe_doc_path("a\u{2066}b"), "bidi isolate rejected");
        assert!(!is_safe_doc_path("\u{feff}name"), "BOM rejected");
    }

    #[test]
    fn create_rejects_kdf_params_the_reader_would_refuse() {
        // Write path must enforce the same bounds as Header::parse, so a vault can
        // never be written that is then permanently unopenable (BadParams).
        let path = tmp_path("createbadparams");
        let bad = KdfParams { m_cost: KdfParams::MAX_M_COST + 1, t_cost: 3, p_cost: 1 };
        let res = OpenVault::create(path.clone(), b"a", b"b", bad);
        assert!(matches!(res, Err(VaultError::BadParams)), "create must reject out-of-range params");
        assert!(!path.exists(), "no vault file is written when params are rejected");
        let _ = fs::remove_dir_all(parent_dir(&path));
    }

    #[test]
    fn import_tree_clamps_absurd_volume_size() {
        let src = tmp_src("bigvol");
        let mut vault = Vault::default();
        vault.version = FORMAT_VERSION;
        vault.id = "abc123def456".into(); // valid token
        vault.settings.volume_max_size = u64::MAX; // absurd, untrusted
        fs::write(src.join("vault.json"), serde_json::to_vec(&vault).unwrap()).unwrap();
        let dest = tmp_path("impbigvol");
        let v = OpenVault::import_tree(&src, &dest, b"c", b"d", fast()).unwrap();
        assert!(v.volume_max_size() <= MAX_VOLUME_MAX_SIZE, "absurd volume_max_size clamped on import");
        assert!(v.volume_max_size() >= MIN_VOLUME_MAX_SIZE);
        drop(v);
        let _ = fs::remove_dir_all(&src);
        cleanup(&dest);
    }

    #[test]
    fn read_only_open_does_not_write_redundancy_or_touch_primary() {
        let path = tmp_path("ro");
        {
            let mut v = OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();
            v.set_redundancy(2).unwrap();
            v.save().unwrap();
        }
        // Remove the redundancy copies; a READ-ONLY open must not regenerate them or
        // rewrite the primary (no auto-save, no heal, no rotation on a read-only open).
        let _ = fs::remove_file(mirror_path(&path));
        for k in 1..=MAX_REDUNDANCY {
            let _ = fs::remove_file(bak_path(&path, k));
        }
        let before = fs::metadata(&path).unwrap().len();
        {
            let v = OpenVault::open_read_only(path.clone(), b"a", b"b").unwrap();
            assert!(v.recovery_notice().is_none());
            drop(v);
        }
        assert!(!mirror_path(&path).exists(), "read-only open wrote a mirror");
        assert!(!bak_path(&path, 1).exists(), "read-only open wrote a generation");
        assert_eq!(fs::metadata(&path).unwrap().len(), before, "primary unchanged on read-only open");
        cleanup(&path);
    }

    #[test]
    fn stale_temp_files_swept_on_writable_open() {
        let path = tmp_path("tmpsweep");
        {
            let _ = OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();
        }
        let dir = parent_dir(&path);
        // Simulate atomic-write temps leaked by a crash mid-save.
        let stale_primary = dir.join(".vault.pmv.deadbeef.tmp");
        let stale_mirror = dir.join(".vault.pmv.mirror.cafef00d.tmp");
        // A leaked last_update marker temp (crash between write_new_file and rename) must also be
        // reaped — otherwise distinct-named orphans accumulate across crashes.
        let stale_marker_tmp = dir.join(".last_update_19990101-000000.deadbeef.tmp");
        fs::write(&stale_primary, b"leaked encrypted temp").unwrap();
        fs::write(&stale_mirror, b"leaked encrypted temp").unwrap();
        fs::write(&stale_marker_tmp, b"19990101-000000\n").unwrap();
        assert_eq!(markers(&dir).len(), 1, "create() left one live marker");
        {
            let _ = OpenVault::open(path.clone(), b"a", b"b").unwrap(); // writable open sweeps
        }
        assert!(!stale_primary.exists(), "stale primary .tmp swept on writable open");
        assert!(!stale_mirror.exists(), "stale mirror .tmp swept on writable open");
        assert!(!stale_marker_tmp.exists(), "leaked last_update marker temp swept too");
        // The LIVE marker (no leading dot, no .tmp) must survive the sweep.
        assert_eq!(markers(&dir).len(), 1, "the live last_update marker survives the sweep");
        cleanup(&path);
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
    fn header_parse_param_and_length_boundaries() {
        // Build a 61-byte header with the given KDF params (no ciphertext needed:
        // Header::parse validates magic/version/params/length only).
        fn header_bytes(m: u32, t: u32, p: u32) -> [u8; HEADER_LEN] {
            let mut b = [0u8; HEADER_LEN];
            b[0..8].copy_from_slice(MAGIC);
            b[8] = FORMAT_VERSION;
            b[9..13].copy_from_slice(&m.to_le_bytes());
            b[13..17].copy_from_slice(&t.to_le_bytes());
            b[17..21].copy_from_slice(&p.to_le_bytes());
            b
        }
        // Exactly at each bound: accepted (kills `< ` -> `<=`, `>` -> `>=`).
        assert!(Header::parse(&header_bytes(8, 1, 1)).is_ok());
        assert!(
            Header::parse(&header_bytes(KdfParams::MAX_M_COST, KdfParams::MAX_T_COST, KdfParams::MAX_P_COST)).is_ok()
        );
        // One step outside each bound: rejected (kills the `||` and comparison mutants).
        for h in [
            header_bytes(7, 1, 1),
            header_bytes(KdfParams::MAX_M_COST + 1, 1, 1),
            header_bytes(8, 0, 1),
            header_bytes(8, KdfParams::MAX_T_COST + 1, 1),
            header_bytes(8, 1, 0),
            header_bytes(8, 1, KdfParams::MAX_P_COST + 1),
        ] {
            assert!(matches!(Header::parse(&h), Err(VaultError::BadParams)), "params should be rejected");
        }
        // Exactly HEADER_LEN bytes is NOT truncated; one byte short is (kills `<`->`<=`).
        assert!(Header::parse(&header_bytes(8, 1, 1)[..]).is_ok());
        assert!(matches!(Header::parse(&header_bytes(8, 1, 1)[..HEADER_LEN - 1]), Err(VaultError::Truncated)));
        // Bad magic / unsupported version.
        let mut bad_magic = header_bytes(8, 1, 1);
        bad_magic[0] ^= 0xFF;
        assert!(matches!(Header::parse(&bad_magic), Err(VaultError::BadMagic)));
        let mut bad_version = header_bytes(8, 1, 1);
        bad_version[8] = FORMAT_VERSION + 1;
        assert!(matches!(Header::parse(&bad_version), Err(VaultError::BadVersion(_))));
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
    fn body_version_disagreeing_with_header_is_rejected() {
        // decode_vault_with_key re-checks the AEAD-authenticated body's `version` against
        // the header as defense-in-depth. A single-byte flip can't reach this branch (it
        // fails the Poly1305 tag first), so the exhaustive byte-flip test never covers it
        // and a mutant deleting the check survives. Craft a body whose version disagrees
        // UNDER A VALID TAG and assert it is rejected with BadVersion.
        let params = KdfParams { m_cost: 256, t_cost: 1, p_cost: 1 };
        let salt = [0x11u8; SALT_LEN];
        let nonce = [0x22u8; NONCE_LEN];
        let key = crypto::derive_key(b"k", &salt, &params).unwrap();
        let header = Header { params, salt, nonce };
        let aad = header.to_bytes();
        let mut body = Vault::default();
        body.version = FORMAT_VERSION - 1; // authenticated, but the WRONG version
        let json = serde_json::to_vec(&body).unwrap();
        let ct = crypto::encrypt_with_nonce(&key, &nonce, &json, &aad).unwrap();
        let mut raw = aad.to_vec();
        raw.extend_from_slice(&ct);
        // The tag verifies (we are past AEAD), but body.version != FORMAT_VERSION.
        let err = decode_vault_with_key(&raw, &key).unwrap_err();
        assert!(
            matches!(err, VaultError::BadVersion(v) if v == FORMAT_VERSION - 1),
            "expected BadVersion, got {err:?}"
        );
    }

    #[test]
    fn every_single_byte_flip_of_a_valid_vault_is_rejected_without_panic() {
        // Exhaustive tamper matrix over the WHOLE open path (parse → KDF → AEAD → JSON →
        // referenced⊆stored), complementing the byte-level parser fuzzers: flip one bit
        // of EVERY byte of a valid `vault.pmv` and assert the open fails closed — never
        // a panic, never a silent accept. This pins the guarantee that the entire file
        // (magic/version/params/salt/nonce as AAD + ciphertext + Poly1305 tag) is
        // integrity-protected, not just the three header offsets checked above.
        let path = tmp_path("byteflip");
        OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();
        let good = fs::read(&path).unwrap();
        // Default: flip EVERY byte (exhaustive). Under a long mutation-testing run this
        // ~3000-open test dominates each mutant's wall-time, so `PASSMGR_TAMPER_SAMPLE`
        // thins it to a representative stride (header bytes are always hit because the
        // header is <61 bytes; the stride then samples the ciphertext + tag).
        let step = if std::env::var_os("PASSMGR_TAMPER_SAMPLE").is_some() { 7 } else { 1 };
        for off in (0..good.len()).step_by(step) {
            for bit in [0x01u8, 0x80u8] {
                let mut bad = good.clone();
                bad[off] ^= bit;
                if bad == good {
                    continue;
                }
                fs::write(&path, &bad).unwrap();
                // `is_err()` requires the open to RETURN an error — a panic here would
                // fail the test (libtest treats a panic as a failure), which is the
                // point: no single-byte corruption may crash the opener.
                assert!(
                    OpenVault::open(path.clone(), b"a", b"b").is_err(),
                    "flipping bit {bit:#x} of byte {off} was accepted (integrity gap)"
                );
            }
        }
        // The untouched file still opens — proves the matrix wasn't vacuously passing.
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
    fn export_document_into_recreates_structure_and_never_overwrites() {
        let path = tmp_path("exintodir");
        let mut v = OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();
        let src = write_src("exinto", b"the deed");
        let id = v.add_document("/real-estate/123main", "deed.pdf", &src).unwrap();
        let root = parent_dir(&path).join("exports");
        // First export recreates the document's virtual path under `root`.
        let p1 = v.export_document_into(&id, &root).unwrap();
        let vpath = v.doc_path(&id).unwrap();
        assert_eq!(p1, root.join(vpath.trim_start_matches('/')), "structure recreated under root");
        assert_eq!(std::fs::read(&p1).unwrap(), b"the deed");
        // A second export of the same document must NOT overwrite — it gets a `_N` sibling.
        let p2 = v.export_document_into(&id, &root).unwrap();
        assert_ne!(p1, p2, "second export never overwrites the first");
        assert!(p2.file_name().unwrap().to_string_lossy().contains("_1"), "got {p2:?}");
        assert_eq!(std::fs::read(&p2).unwrap(), b"the deed");
        std::fs::remove_dir_all(&root).ok();
        fs::remove_file(&src).ok();
        cleanup(&path);
    }

    #[test]
    fn export_document_into_never_escapes_root_for_adversarial_names() {
        // Security invariant: no matter what the (user-controlled) document filename/location
        // is, the export path stays strictly UNDER `root` and writes a real file. Covers
        // traversal, separators, reserved device names, and unicode.
        let path = tmp_path("exadv");
        let mut v = OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();
        let root = parent_dir(&path).join("exports");
        let canon_root = {
            fs::create_dir_all(&root).unwrap();
            root.canonicalize().unwrap()
        };
        let names = [
            "../../../../etc/passwd",
            "..\\..\\windows\\system32",
            "a/b/c.pdf",
            "con.pdf",
            "nul",
            "  ...  ",
            "deed\u{202e}fdp.exe",
            &"x".repeat(400),
        ];
        for (i, name) in names.iter().enumerate() {
            let src = write_src(&format!("exadv-{i}"), b"payload");
            // The UI sanitizes the filename (records::doc_filename) before add_document, so do
            // that here too; and inject traversal via the LOCATION (a defense-in-depth check
            // that export drops `..`/separators even when the stored virtual path carries them).
            let fname = records::doc_filename(name);
            let loc = format!("/general-documents/../../sneaky/{}", records::doc_slug(name, "fb"));
            let Ok(id) = v.add_document(&loc, &fname, &src) else {
                fs::remove_file(&src).ok();
                continue; // a path rejected at store time is itself a safe outcome
            };
            let dest = v.export_document_into(&id, &root).unwrap();
            let canon_dest = dest.canonicalize().unwrap();
            assert!(canon_dest.starts_with(&canon_root), "escaped root: name={name:?} -> {canon_dest:?}");
            assert_eq!(std::fs::read(&canon_dest).unwrap(), b"payload", "exported content intact for {name:?}");
            fs::remove_file(&src).ok();
        }
        std::fs::remove_dir_all(&root).ok();
        cleanup(&path);
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
    fn write_export_bytes_creates_dir_hardens_and_never_clobbers() {
        let dir = std::env::temp_dir().join(format!("pmcsv-{}", nanos()));
        assert!(!dir.exists(), "starts from a non-existent dir");
        // Creates the (missing) export dir and writes the file 0600.
        let p1 = write_export_bytes(&dir, "accounts-20240101-000000.csv", b"col\r\na\r\n").unwrap();
        assert!(p1.exists());
        assert_eq!(fs::read(&p1).unwrap(), b"col\r\na\r\n");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(fs::metadata(&p1).unwrap().permissions().mode() & 0o777, 0o600, "export file is 0600");
        }
        // Same dir+filename again must NOT clobber — it gets a `_N` suffix and the first
        // file is left byte-for-byte intact.
        let p2 = write_export_bytes(&dir, "accounts-20240101-000000.csv", b"other\r\n").unwrap();
        assert_ne!(p1, p2, "second export does not overwrite the first");
        assert!(p2.file_name().unwrap().to_string_lossy().contains("_1"), "got: {p2:?}");
        assert_eq!(fs::read(&p1).unwrap(), b"col\r\na\r\n", "first export untouched by the second");
        fs::remove_dir_all(&dir).ok();
    }

    // Names of the `last_update_*` marker files currently in `dir`.
    fn markers(dir: &Path) -> Vec<String> {
        let mut v: Vec<String> = fs::read_dir(dir)
            .unwrap()
            .flatten()
            .filter_map(|e| {
                let n = e.file_name().to_string_lossy().into_owned();
                n.starts_with("last_update_").then_some(n)
            })
            .collect();
        v.sort();
        v
    }

    #[test]
    fn save_writes_a_single_last_update_marker_after_commit() {
        let path = tmp_path("lastupd");
        let mut v = OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();
        let dir = path.parent().unwrap().to_path_buf();
        // create() does its first on-disk commit (open.save()), so a marker already exists —
        // the marker tracks "last time vault.pmv was committed", which includes creation.
        let ms = markers(&dir);
        assert_eq!(ms.len(), 1, "exactly one marker after the create commit: {ms:?}");
        let ts = ms[0].strip_prefix("last_update_").unwrap();
        assert_eq!(ts.len(), 15, "name carries a compact_utc YYYYMMDD-HHMMSS: {}", ms[0]);
        // Contents = the same timestamp (+ newline); name and content agree.
        assert_eq!(fs::read_to_string(dir.join(&ms[0])).unwrap(), format!("{ts}\n"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(fs::metadata(dir.join(&ms[0])).unwrap().permissions().mode() & 0o777, 0o600, "marker is 0600");
        }
        // A subsequent committed save keeps it at exactly one (the old one is replaced).
        v.save().unwrap();
        assert_eq!(markers(&dir).len(), 1, "still exactly one marker after another save: {:?}", markers(&dir));
        cleanup(&path);
    }

    #[test]
    fn save_replaces_any_existing_last_update_markers() {
        let path = tmp_path("lastupd2");
        let mut v = OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();
        let dir = path.parent().unwrap().to_path_buf();
        v.save().unwrap();
        // Plant a STALE marker (as if from an earlier, different-second save).
        fs::write(dir.join("last_update_19990101-000000"), b"19990101-000000\n").unwrap();
        assert_eq!(markers(&dir).len(), 2, "two markers planted");
        v.save().unwrap();
        let ms = markers(&dir);
        assert_eq!(ms.len(), 1, "exactly one marker remains after the next save: {ms:?}");
        assert!(!ms[0].contains("19990101"), "the stale marker was replaced: {ms:?}");
        cleanup(&path);
    }

    #[test]
    fn read_only_session_does_not_touch_the_last_update_marker() {
        let path = tmp_path("lastupd-ro");
        drop(OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap());
        let dir = path.parent().unwrap().to_path_buf();
        let before = markers(&dir);
        assert_eq!(before.len(), 1, "create left one marker");
        // A read-only (heir) session never saves, so it must not add or replace the marker.
        drop(OpenVault::open_read_only(path.clone(), b"a", b"b").unwrap());
        assert_eq!(markers(&dir), before, "read-only open left the marker unchanged");
        cleanup(&path);
    }

    #[test]
    fn last_update_marker_does_not_break_reopen() {
        let path = tmp_path("lastupd-reopen");
        let id;
        {
            let mut v = OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();
            let src = write_src("lu", b"doc bytes");
            id = v.add_document("/d", "f.txt", &src).unwrap(); // add_document persists -> marks
            fs::remove_file(&src).ok();
        }
        let dir = path.parent().unwrap().to_path_buf();
        assert_eq!(markers(&dir).len(), 1, "one marker after add_document: {:?}", markers(&dir));
        // Reopen with the marker sitting in the vault root — must open cleanly, data intact
        // (the marker is ignored by the partition/manifest scanners, which read the subdirs).
        let v = OpenVault::open(path.clone(), b"a", b"b").unwrap();
        assert_eq!(&v.read_document(&id).unwrap()[..], b"doc bytes", "doc survives a reopen-with-marker");
        cleanup(&path);
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

    #[cfg(feature = "single-writer-lock")]
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

    /// Complement of the test above for the `single-writer-lock`-off build (the
    /// mobile/FFI configuration): `WriteLock::acquire` is a no-op, so a second
    /// writable open must succeed rather than fail with `Locked`. This pins the no-op
    /// `acquire` under that config (run with `--no-default-features`), and documents
    /// that the cargo-mutants survivor on that `#[cfg(not(...))]` line is a phantom —
    /// it is dead code in the default (feature-on) build cargo-mutants compiles.
    #[cfg(not(feature = "single-writer-lock"))]
    #[test]
    fn no_op_lock_allows_a_second_writable_open() {
        let path = tmp_path("noop_lock");
        let v = OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();
        // No cross-process lock is taken, so a second writable open is allowed.
        assert!(OpenVault::open(path.clone(), b"a", b"b").is_ok());
        drop(v);
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
    fn export_then_import_tree_round_trips() {
        // Seed a vault with an account, three docs across partitions, and a record
        // that references one doc (so the consistency check is exercised on import).
        let (path, docs) = seed_multi_partition("exptree", b"o1", b"o2");
        {
            let mut v = OpenVault::open(path.clone(), b"o1", b"o2").unwrap();
            let mut tw = crate::records::TrustWill::new().unwrap();
            tw.file = Some(docs[0].0.clone());
            records::upsert(&mut v.vault.trust_wills, tw);
            v.save().unwrap();
        }
        // Decrypt to a plaintext mirror.
        let mirror = std::env::temp_dir().join(format!("pmmirror-{}", nanos()));
        OpenVault::export_tree(&path, b"o1", b"o2", &mirror).unwrap();
        assert!(mirror.join("vault.json").exists());
        assert!(mirror.join("manifest/manifest.0.json").exists());
        assert!(mirror.join("volume/vol.0").join(&docs[0].0).exists());

        // Rebuild a fresh encrypted vault from the mirror under NEW passwords.
        let dest_dir = std::env::temp_dir().join(format!("pmimport-{}", nanos()));
        let dest = dest_dir.join(VAULT_FILE);
        drop(OpenVault::import_tree(&mirror, &dest, b"n1", b"n2", fast()).unwrap());

        // Only the new passwords open it; every record and document round-tripped.
        assert!(OpenVault::open(dest.clone(), b"o1", b"o2").is_err(), "old passwords must not work");
        let v = OpenVault::open(dest.clone(), b"n1", b"n2").unwrap();
        assert_eq!(v.vault.accounts.len(), 1);
        assert_eq!(v.vault.trust_wills.len(), 1);
        for (id, body) in &docs {
            assert_eq!(&v.read_document(id).unwrap()[..], &body[..], "doc {id} survives the round-trip");
        }
        // import-tree refuses to overwrite an existing vault.
        assert!(matches!(
            OpenVault::import_tree(&mirror, &dest, b"x", b"y", fast()),
            Err(VaultError::AlreadyExists(_))
        ));

        std::fs::remove_dir_all(&mirror).ok();
        std::fs::remove_dir_all(&dest_dir).ok();
        cleanup(&path);
    }

    #[test]
    fn import_tree_sanitizes_spoofed_category_names() {
        // import_tree adopts vault.categories WHOLESALE from an UNTRUSTED mirror. add_* never
        // sanitizes, so the source stores RAW spoofed names (simulating a crafted mirror); import
        // must display_safe-neutralize them — the fourth untrusted-category path, now consistent
        // with plan/apply/sync.
        let path = tmp_path("imp-cat-src");
        let mut v = OpenVault::create(path.clone(), b"o1", b"o2", fast()).unwrap();
        v.vault.categories.add_asset_type("Bank\u{202e}x"); // RLO override (stored raw)
        v.vault.categories.add_account_type("Cre\u{200b}dit"); // zero-width space
        v.vault.categories.add_account_subtype("Cre\u{200b}dit", "Vi\u{200c}sa");
        v.save().unwrap();

        let mirror = std::env::temp_dir().join(format!("pmcatmirror-{}", nanos()));
        OpenVault::export_tree(&path, b"o1", b"o2", &mirror).unwrap();
        let dest_dir = std::env::temp_dir().join(format!("pmcatimp-{}", nanos()));
        let dest = dest_dir.join(VAULT_FILE);
        drop(OpenVault::import_tree(&mirror, &dest, b"n1", b"n2", fast()).unwrap());

        let imported = OpenVault::open(dest.clone(), b"n1", b"n2").unwrap();
        let san_asset = records::display_safe("Bank\u{202e}x");
        let san_type = records::display_safe("Cre\u{200b}dit");
        let san_sub = records::display_safe("Vi\u{200c}sa");
        assert!(imported.vault.categories.asset.iter().any(|x| x.as_str() == san_asset));
        assert!(
            !imported.vault.categories.asset.iter().any(|x| x.as_str().contains('\u{202e}')),
            "raw bidi-spoofed asset type must NOT survive import"
        );
        assert!(
            imported
                .vault
                .categories
                .account
                .iter()
                .any(|a| a.name == san_type && a.subtypes.iter().any(|s| s.as_str() == san_sub)),
            "account type + subtype sanitized on import: {:?}",
            imported.vault.categories.account
        );
        assert!(
            !imported.vault.categories.account.iter().any(|a| a.name.contains('\u{200b}')),
            "raw zero-width-spoofed account type must NOT survive import"
        );

        std::fs::remove_dir_all(&mirror).ok();
        std::fs::remove_dir_all(&dest_dir).ok();
        cleanup(&path);
    }

    #[test]
    fn import_tree_rejects_a_non_contiguous_mirror() {
        // A mirror with a missing MIDDLE manifest must FAIL CLOSED, never silently drop the
        // documents in the surviving higher partitions — symmetric with VolumeStore::open's
        // non-contiguous-partition guard. (seed_multi_partition spans partitions 0,1,2.)
        let (path, _docs) = seed_multi_partition("impgap", b"o1", b"o2");
        let mirror = std::env::temp_dir().join(format!("pmgap-{}", nanos()));
        OpenVault::export_tree(&path, b"o1", b"o2", &mirror).unwrap();
        assert!(mirror.join("manifest/manifest.2.json").exists(), "seed should span >= 3 partitions");
        // Lose the MIDDLE manifest (1); 0 and 2 survive → a gap the loop would silently truncate.
        std::fs::remove_file(mirror.join("manifest/manifest.1.json")).unwrap();
        let dest = std::env::temp_dir().join(format!("pmgapd-{}", nanos())).join(VAULT_FILE);
        assert!(
            matches!(
                OpenVault::import_tree(&mirror, &dest, b"n1", b"n2", fast()),
                Err(VaultError::Storage(StorageError::Corrupt(_)))
            ),
            "a non-contiguous mirror (missing middle manifest) must be rejected"
        );
        std::fs::remove_dir_all(&mirror).ok();
        std::fs::remove_dir_all(parent_dir(&dest)).ok();
        cleanup(&path);
    }

    #[test]
    fn import_tree_rejects_oversized_manifest() {
        // A crafted mirror with an oversized manifest must be rejected before the
        // wholesale read (no OOM), like every other manifest-ingest path.
        let (path, _docs) = seed_multi_partition("impbig", b"o1", b"o2");
        let mirror = std::env::temp_dir().join(format!("pmbig-{}", nanos()));
        OpenVault::export_tree(&path, b"o1", b"o2", &mirror).unwrap();
        {
            // Sparse-extend manifest.0.json past the cap (no real bytes written).
            let f = OpenOptions::new().write(true).open(mirror.join("manifest/manifest.0.json")).unwrap();
            f.set_len(storage::MAX_MANIFEST_SIZE + 1).unwrap();
        }
        let dest = std::env::temp_dir().join(format!("pmbigd-{}", nanos())).join(VAULT_FILE);
        assert!(matches!(
            OpenVault::import_tree(&mirror, &dest, b"n1", b"n2", fast()),
            Err(VaultError::TooLarge)
        ));
        std::fs::remove_dir_all(&mirror).ok();
        std::fs::remove_dir_all(parent_dir(&dest)).ok();
        cleanup(&path);
    }

    #[cfg(unix)]
    #[test]
    fn import_tree_rejects_symlink_blob() {
        // A blob replaced by a symlink (e.g. -> /dev/zero or an arbitrary file) is
        // rejected rather than followed.
        let (path, docs) = seed_multi_partition("impsym", b"o1", b"o2");
        let mirror = std::env::temp_dir().join(format!("pmsym-{}", nanos()));
        OpenVault::export_tree(&path, b"o1", b"o2", &mirror).unwrap();
        let blob = mirror.join("volume/vol.0").join(&docs[0].0);
        std::fs::remove_file(&blob).unwrap();
        std::os::unix::fs::symlink("/etc/hostname", &blob).unwrap();
        let dest = std::env::temp_dir().join(format!("pmsymd-{}", nanos())).join(VAULT_FILE);
        assert!(matches!(
            OpenVault::import_tree(&mirror, &dest, b"n1", b"n2", fast()),
            Err(VaultError::Storage(_))
        ));
        std::fs::remove_dir_all(&mirror).ok();
        std::fs::remove_dir_all(parent_dir(&dest)).ok();
        cleanup(&path);
    }

    #[cfg(unix)]
    #[test]
    fn import_tree_rejects_symlinked_partition_dir() {
        // A symlinked INTERMEDIATE directory (here vol.0 -> elsewhere) must be rejected:
        // `read_capped`'s O_NOFOLLOW only guards the final component, so without the
        // `reject_symlink_dir` guard a symlinked `vol.<p>/` would redirect blob reads
        // outside the mirror (audit U-2).
        let (path, _docs) = seed_multi_partition("impsymdir", b"o1", b"o2");
        let mirror = std::env::temp_dir().join(format!("pmsymdir-{}", nanos()));
        OpenVault::export_tree(&path, b"o1", b"o2", &mirror).unwrap();
        let vol0 = mirror.join("volume/vol.0");
        let elsewhere = mirror.join("volume/elsewhere");
        std::fs::rename(&vol0, &elsewhere).unwrap(); // move the real partition aside...
        std::os::unix::fs::symlink(&elsewhere, &vol0).unwrap(); // ...and symlink to it
        let dest = std::env::temp_dir().join(format!("pmsymdird-{}", nanos())).join(VAULT_FILE);
        assert!(matches!(
            OpenVault::import_tree(&mirror, &dest, b"n1", b"n2", fast()),
            Err(VaultError::Storage(_))
        ));
        std::fs::remove_dir_all(&mirror).ok();
        std::fs::remove_dir_all(parent_dir(&dest)).ok();
        cleanup(&path);
    }

    #[test]
    fn set_volume_max_size_governs_future_placement() {
        let path = tmp_path("volcfg");
        let mut v = OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();
        // Default cap (256 MiB) is large: two ~30 KiB docs share partition 0.
        let src = write_src("vc", &vec![7u8; 30_000]);
        v.add_document("/a", "a.bin", &src).unwrap();
        v.add_document("/b", "b.bin", &src).unwrap();
        // Shrink the cap live; it persists and updates the running store. A sub-floor request
        // (1024) is clamped UP to MIN_VOLUME_MAX_SIZE (64 KiB) so a tiny cap can't fragment the
        // store into one partition per document. At the 64 KiB floor the two existing ~30 KiB
        // docs still fit partition 0, but a third no longer does.
        v.set_volume_max_size(1024).unwrap();
        assert_eq!(v.volume_max_size(), MIN_VOLUME_MAX_SIZE, "sub-floor cap clamped up to the 64 KiB floor");
        // A further doc now rolls into a fresh partition.
        v.add_document("/c", "c.bin", &src).unwrap();
        drop(v);
        // All three manifest entries survive; the third is in its own partition.
        let p1 = OpenVault::export_manifests(&path, b"a", b"b", Some(1)).unwrap();
        assert_eq!(p1.len(), 1, "the post-resize doc landed in partition 1");
        let all = OpenVault::export_manifests(&path, b"a", b"b", None).unwrap();
        assert_eq!(all.len(), 3);
        // The persisted (clamped) setting is read back on reopen.
        let reopened = OpenVault::open(path.clone(), b"a", b"b").unwrap();
        assert_eq!(reopened.volume_max_size(), MIN_VOLUME_MAX_SIZE);
        cleanup(&path);
        fs::remove_file(&src).ok();
    }

    #[test]
    fn set_volume_max_size_clamps_to_min_and_max() {
        let path = tmp_path("volclamp");
        let mut v = OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();
        v.set_volume_max_size(1).unwrap(); // absurdly small -> floored
        assert_eq!(v.volume_max_size(), MIN_VOLUME_MAX_SIZE);
        v.set_volume_max_size(u64::MAX).unwrap(); // absurdly large -> capped
        assert_eq!(v.volume_max_size(), MAX_VOLUME_MAX_SIZE);
        cleanup(&path);
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
    fn replace_dir_sweeps_leftover_old_when_staged_already_gone() {
        // Regression: a crash AFTER `rename(staged, live)` but BEFORE the `.old`
        // cleanup leaves the OLD-key-encrypted dir behind. Recovery re-enters
        // replace_dir with `staged` already gone; it must still sweep `.<name>.old`
        // (not skip cleanup via the early return) or that old-key ciphertext leaks
        // on disk forever, defeating change_password's forward secrecy.
        let base = std::env::temp_dir().join(format!("pmreplace-{}", nanos()));
        let live = base.join("volume");
        fs::create_dir_all(&live).unwrap();
        fs::write(live.join("current"), b"new-key data").unwrap();
        // Simulate the leaked old-key dir from the crash window.
        let old = sibling_old(&live);
        fs::create_dir_all(&old).unwrap();
        fs::write(old.join("blob"), b"OLD-KEY CIPHERTEXT").unwrap();
        // `staged` does not exist (it was already renamed into place before the crash).
        let staged = base.join(".rekey").join("volume");

        replace_dir(&live, &staged).unwrap();

        assert!(!old.exists(), "leftover .volume.old (old-key data) must be swept on recovery");
        assert!(live.exists() && live.join("current").exists(), "live dir is left intact");
        let _ = fs::remove_dir_all(&base);
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

    #[test]
    fn oversized_vault_file_is_rejected() {
        let path = tmp_path("toobig");
        OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();
        // Sparse-extend vault.pmv beyond the cap (no real bytes written); the
        // metadata-size guard must reject it before the wholesale read.
        {
            let f = OpenOptions::new().write(true).open(&path).unwrap();
            f.set_len(MAX_VAULT_SIZE + 1).unwrap();
        }
        assert!(matches!(OpenVault::open(path.clone(), b"a", b"b"), Err(VaultError::TooLarge)));
        cleanup(&path);
    }

    #[test]
    fn orphaned_blob_after_unlink_save_opens_cleanly() {
        // The fixed delete/detach order saves the unlinked vault FIRST, then drops
        // the blob. A crash in that window leaves an orphaned blob (harmless) but no
        // dangling reference; this reproduces that state and asserts a clean reopen.
        let path = tmp_path("orphan");
        let mut v = OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();
        let src = write_src("orphan", b"body");
        let id = v.add_document("/d", "f.txt", &src).unwrap();
        let mut tw = crate::records::TrustWill::new().unwrap();
        tw.file = Some(id.clone());
        records::upsert(&mut v.vault.trust_wills, tw.clone());
        v.save().unwrap();
        // Unlink the record and save (the blob is still present == orphan).
        tw.file = None;
        records::upsert(&mut v.vault.trust_wills, tw);
        v.save().unwrap();
        drop(v); // simulate a crash before the blob reclaim runs
        let reopened = OpenVault::open(path.clone(), b"a", b"b").unwrap();
        assert!(reopened.has_document(&id), "orphan blob lingers but is harmless");
        cleanup(&path);
        fs::remove_file(&src).ok();
    }

    #[test]
    fn pending_rekey_blocks_read_facilities_and_backup() {
        let (path, _docs) = seed_multi_partition("rkblock", b"a", b"b");
        stage_ready_rekey(&path, b"a", b"b", b"n1", b"n2"); // a complete READY staging
        assert!(matches!(
            OpenVault::export_documents(&path, b"a", b"b", None),
            Err(VaultError::RekeyPending)
        ));
        assert!(matches!(
            OpenVault::export_manifests(&path, b"a", b"b", None),
            Err(VaultError::RekeyPending)
        ));
        let dest = std::env::temp_dir().join(format!("pmbk-{}", nanos()));
        assert!(matches!(backup(&path, &dest), Err(VaultError::RekeyPending)));
        let _ = fs::remove_dir_all(&dest);
        cleanup(&path);
    }

    // Property-based testing: instead of fixed inputs, `proptest!` generates many
    // random inputs matching the given specs (the `in "regex"` strings) and checks
    // the `prop_assert!` invariants hold for all of them. `prelude::*` imports its
    // common names with a single glob.
    // ---- Full-disk (ENOSPC) fault injection (cargo test --features fault-injection) ----

    #[cfg(feature = "fault-injection")]
    #[test]
    fn enospc_on_save_keeps_old_vault() {
        let path = tmp_path("enospc-save");
        {
            let mut v = OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();
            records::upsert(&mut v.vault.accounts, sample_account("u", "p1"));
            v.save().unwrap();
            // The disk fills on the next save; the prior vault.pmv must survive.
            v.vault.accounts[0].password = "p2".into();
            crate::fault::fail_at("vault.write", 1);
            assert!(matches!(v.save(), Err(VaultError::Io(_))));
            crate::fault::clear();
        }
        let re = OpenVault::open(path.clone(), b"a", b"b").unwrap();
        assert_eq!(re.vault.accounts[0].password, "p1", "old vault.pmv intact after a failed save");
        cleanup(&path);
    }

    #[cfg(feature = "fault-injection")]
    #[test]
    fn enospc_during_rekey_discards_staging_and_old_passwords_work() {
        let path = tmp_path("enospc-rekey");
        let mut v = OpenVault::create(path.clone(), b"o1", b"o2", fast()).unwrap();
        let src = write_src("rk", b"will body");
        let id = v.add_document("/w", "w.txt", &src).unwrap();
        records::upsert(&mut v.vault.accounts, sample_account("u", "p"));
        v.save().unwrap();
        // The disk fills while re-encrypting documents into the .rekey staging tree,
        // BEFORE the READY marker is written.
        crate::fault::fail_at("volume.write", 1);
        let err = v.change_password(b"n1", b"n2").unwrap_err();
        crate::fault::clear();
        assert!(matches!(err, VaultError::Storage(_)), "rekey staging fails cleanly, got {err:?}");
        drop(v); // release the lock before reopening
        // No READY was written, so the staging is discarded on reopen: the OLD
        // passwords still open the intact vault; the new ones do not.
        assert!(OpenVault::open(path.clone(), b"n1", b"n2").is_err());
        let re = OpenVault::open(path.clone(), b"o1", b"o2").unwrap();
        assert_eq!(re.vault.accounts.len(), 1);
        assert_eq!(&*re.read_document(&id).unwrap(), b"will body");
        assert!(!parent_dir(&path).join(REKEY_DIR).exists(), "staging discarded");
        cleanup(&path);
        fs::remove_file(&src).ok();
    }

    #[cfg(feature = "fault-injection")]
    #[test]
    fn enospc_at_rekey_manifest_commit_discards_staging() {
        // Same as above but the disk fills at the staged MANIFEST commit (after the
        // staged volume append) rather than the volume write — still no READY, so
        // the staging is discarded and the old vault stands intact.
        let path = tmp_path("enospc-rekey2");
        let mut v = OpenVault::create(path.clone(), b"o1", b"o2", fast()).unwrap();
        let src = write_src("rk2", b"trust body");
        let id = v.add_document("/t", "t.txt", &src).unwrap();
        v.save().unwrap();
        crate::fault::fail_at("atomic.write", 1);
        let err = v.change_password(b"n1", b"n2").unwrap_err();
        crate::fault::clear();
        assert!(matches!(err, VaultError::Storage(_)), "got {err:?}");
        drop(v);
        assert!(OpenVault::open(path.clone(), b"n1", b"n2").is_err());
        let re = OpenVault::open(path.clone(), b"o1", b"o2").unwrap();
        assert_eq!(&*re.read_document(&id).unwrap(), b"trust body");
        assert!(!parent_dir(&path).join(REKEY_DIR).exists(), "staging discarded");
        cleanup(&path);
        fs::remove_file(&src).ok();
    }

    // ---- Compaction --------------------------------------------------------

    /// A vault with one live, record-referenced document plus `garbage` extra
    /// documents that are added then immediately removed, leaving dead frames in
    /// the volume. Returns the vault path and the id of the live ("keep") doc.
    fn seed_with_garbage(tag: &str, garbage: usize) -> (PathBuf, String) {
        let path = tmp_path(tag);
        let mut v = OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();
        let src = write_src(tag, &vec![9u8; 400]);
        let keep = v.add_document("/keep", "keep.bin", &src).unwrap();
        let mut tw = records::TrustWill::new().unwrap();
        tw.file = Some(keep.clone());
        records::upsert(&mut v.vault.trust_wills, tw);
        // Dead frames: add then remove (drops the manifest entry; frame lingers).
        for i in 0..garbage {
            let id = v.add_document("/g", &format!("g{i}.bin"), &src).unwrap();
            v.remove_document(&id).unwrap();
        }
        v.save().unwrap();
        fs::remove_file(&src).ok();
        (path, keep)
    }

    fn volume_opts() -> CompactOptions {
        CompactOptions { volume: true, json: false, history_cutoff: None, drop_all_history: false }
    }

    #[test]
    fn compact_volume_reclaims_garbage_and_keeps_live_docs() {
        let (path, keep) = seed_with_garbage("cvol", 3);
        let mut v = OpenVault::open(path.clone(), b"a", b"b").unwrap();
        let opts = volume_opts();
        let before = v.compact_dry_run(&opts).bytes_reclaimed;
        assert!(before > 0, "garbage should be reclaimable, got {before}");
        let report = v.compact(&opts).unwrap();
        assert_eq!(report.bytes_reclaimed, before);
        // No garbage remains, and the live doc is still readable.
        assert_eq!(v.compact_dry_run(&opts).bytes_reclaimed, 0, "garbage fully reclaimed");
        assert_eq!(&*v.read_document(&keep).unwrap(), &vec![9u8; 400][..]);
        assert!(v.vault.audit.iter().any(|c| c.action == "compacted"));
        drop(v);
        // Reopens cleanly (consistency check passes), doc intact, no staging debris.
        let re = OpenVault::open(path.clone(), b"a", b"b").unwrap();
        assert_eq!(&*re.read_document(&keep).unwrap(), &vec![9u8; 400][..]);
        assert!(!parent_dir(&path).join(REKEY_DIR).exists());
        cleanup(&path);
    }

    #[test]
    fn compact_volume_keeps_tax_documents() {
        // Regression guard: a Taxes filing's documents must be treated as live by
        // referenced_doc_ids, so `compact --volume` never reclaims them.
        let path = tmp_path("cvoltax");
        let mut v = OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();
        let src = write_src("cvoltax", &vec![7u8; 300]);
        let keep = v.add_document("taxes/2024", "w2.pdf", &src).unwrap();
        let mut t = records::TaxFiling::new().unwrap();
        t.year = "2024".into();
        t.documents.push(keep.clone());
        records::upsert(&mut v.vault.tax_filings, t);
        // Dead frames so compaction actually has work to do around the live doc.
        for i in 0..3 {
            let id = v.add_document("/g", &format!("g{i}.bin"), &src).unwrap();
            v.remove_document(&id).unwrap();
        }
        v.save().unwrap();
        fs::remove_file(&src).ok();
        drop(v); // release the single-writer lock before reopening

        let mut v = OpenVault::open(path.clone(), b"a", b"b").unwrap();
        v.compact(&volume_opts()).unwrap();
        assert_eq!(&*v.read_document(&keep).unwrap(), &vec![7u8; 300][..], "tax doc survives compaction");
        drop(v);
        // And the vault still opens (the referenced ⊆ stored consistency holds).
        let re = OpenVault::open(path.clone(), b"a", b"b").unwrap();
        assert_eq!(&*re.read_document(&keep).unwrap(), &vec![7u8; 300][..]);
        cleanup(&path);
    }

    #[test]
    fn compact_volume_keeps_real_estate_documents() {
        // Regression guard: a property's documents must be treated as live by
        // referenced_doc_ids, so `compact --volume` never reclaims them.
        let path = tmp_path("cvolre");
        let mut v = OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();
        let src = write_src("cvolre", &vec![5u8; 320]);
        let keep = v.add_document("real-estate/123mainst", "deed.pdf", &src).unwrap();
        let mut re = records::RealEstate::new().unwrap();
        re.address = "123 Main St".into();
        re.documents.push(keep.clone());
        records::upsert(&mut v.vault.real_estate, re);
        for i in 0..3 {
            let id = v.add_document("/g", &format!("g{i}.bin"), &src).unwrap();
            v.remove_document(&id).unwrap();
        }
        v.save().unwrap();
        fs::remove_file(&src).ok();
        drop(v);

        let mut v = OpenVault::open(path.clone(), b"a", b"b").unwrap();
        v.compact(&volume_opts()).unwrap();
        assert_eq!(&*v.read_document(&keep).unwrap(), &vec![5u8; 320][..], "RE doc survives compaction");
        drop(v);
        let re = OpenVault::open(path.clone(), b"a", b"b").unwrap();
        assert_eq!(&*re.read_document(&keep).unwrap(), &vec![5u8; 320][..]);
        cleanup(&path);
    }

    #[test]
    fn compact_volume_when_all_docs_deleted_shrinks_to_nothing() {
        // Maximum-garbage case: every document removed. The staged store has zero
        // partitions, so compaction must still swap the garbage volume/manifest out
        // (regression guard for the all-deleted reclaim fix in `staged_rewrite`).
        let (path, docs) = seed_multi_partition("calldel", b"a", b"b");
        let mut v = OpenVault::open(path.clone(), b"a", b"b").unwrap();
        for (id, _) in &docs {
            v.remove_document(id).unwrap();
        }
        let opts = volume_opts();
        assert!(v.compact_dry_run(&opts).bytes_reclaimed > 0);
        v.compact(&opts).unwrap();
        assert_eq!(v.compact_dry_run(&opts).bytes_reclaimed, 0, "all garbage gone");
        assert_eq!(v.storage.partition_count(), 0, "empty store after all-deleted compaction");
        drop(v);
        let re = OpenVault::open(path.clone(), b"a", b"b").unwrap();
        assert_eq!(re.storage.partition_count(), 0);
        cleanup(&path);
    }

    #[test]
    fn compact_json_trims_history_by_cutoff_and_keeps_audit() {
        let path = tmp_path("cjson");
        let mut v = OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();
        records::upsert(&mut v.vault.accounts, sample_account("u", "p"));
        // Controlled history: one old, one recent entry (plus the upsert "created").
        v.vault.accounts[0].history.push(records::Change { at: 1_000, action: "updated".into(), detail: "old".into() });
        v.vault.accounts[0].history.push(records::Change { at: 9_000, action: "updated".into(), detail: "newer".into() });
        v.save().unwrap();
        let audit_before = v.vault.audit.len();
        let opts = CompactOptions { volume: false, json: true, history_cutoff: Some(3_000), drop_all_history: false };
        let removed = v.compact(&opts).unwrap().history_removed;
        assert_eq!(removed, 1, "only the at=1000 entry is older than the cutoff");
        // The old entry is gone; the recent one (and the created one) remain.
        assert!(v.vault.accounts[0].history.iter().all(|c| c.at >= 3_000));
        assert!(v.vault.accounts[0].history.iter().any(|c| c.at == 9_000));
        // Audit preserved and gained exactly the compaction event.
        assert_eq!(v.vault.audit.len(), audit_before + 1);
        assert!(v.vault.audit.iter().any(|c| c.action == "compacted"));
        drop(v);
        let re = OpenVault::open(path.clone(), b"a", b"b").unwrap();
        assert!(re.vault.accounts[0].history.iter().all(|c| c.at >= 3_000));
        cleanup(&path);
    }

    #[test]
    fn compact_json_drop_all_clears_history_only() {
        let path = tmp_path("cjsonall");
        let mut v = OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();
        records::upsert(&mut v.vault.accounts, sample_account("u", "p"));
        v.vault.accounts[0].history.push(records::Change { at: 1, action: "updated".into(), detail: "x".into() });
        v.save().unwrap();
        let opts = CompactOptions { volume: false, json: true, history_cutoff: None, drop_all_history: true };
        v.compact(&opts).unwrap();
        assert!(v.vault.accounts[0].history.is_empty(), "all record history dropped");
        assert!(v.vault.audit.iter().any(|c| c.action == "compacted"), "audit retained");
        cleanup(&path);
    }

    #[test]
    fn compact_both_reclaims_and_trims_in_one_commit() {
        let (path, keep) = seed_with_garbage("cboth", 2);
        let mut v = OpenVault::open(path.clone(), b"a", b"b").unwrap();
        records::upsert(&mut v.vault.accounts, sample_account("u", "p"));
        v.vault.accounts[0].history.push(records::Change { at: 1, action: "updated".into(), detail: "old".into() });
        v.save().unwrap();
        let opts = CompactOptions { volume: true, json: true, history_cutoff: None, drop_all_history: true };
        let report = v.compact(&opts).unwrap();
        assert!(report.bytes_reclaimed > 0 && report.history_removed >= 1);
        drop(v);
        let re = OpenVault::open(path.clone(), b"a", b"b").unwrap();
        assert_eq!(&*re.read_document(&keep).unwrap(), &vec![9u8; 400][..]);
        assert!(re.vault.accounts.iter().all(|a| a.history.is_empty()));
        cleanup(&path);
    }

    #[test]
    fn compact_on_clean_vault_is_a_safe_noop_rewrite() {
        let path = tmp_path("cclean");
        let mut v = OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();
        let src = write_src("cc", b"body");
        let id = v.add_document("/d", "d.bin", &src).unwrap();
        let mut tw = records::TrustWill::new().unwrap();
        tw.file = Some(id.clone());
        records::upsert(&mut v.vault.trust_wills, tw);
        v.save().unwrap();
        fs::remove_file(&src).ok();
        let report = v.compact(&volume_opts()).unwrap();
        assert_eq!(report.bytes_reclaimed, 0, "nothing to reclaim on a clean vault");
        assert_eq!(&*v.read_document(&id).unwrap(), b"body", "doc intact after no-op rewrite");
        cleanup(&path);
    }

    #[test]
    fn compact_refused_on_read_only_handle() {
        let path = tmp_path("cro");
        OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();
        let mut ro = OpenVault::open_read_only(path.clone(), b"a", b"b").unwrap();
        assert!(matches!(ro.compact(&volume_opts()), Err(VaultError::ReadOnly)));
        cleanup(&path);
    }

    #[test]
    fn compact_bumps_write_generation() {
        let (path, _keep) = seed_with_garbage("cgen", 1);
        let mut v = OpenVault::open(path.clone(), b"a", b"b").unwrap();
        let before = v.vault.generation;
        v.compact(&volume_opts()).unwrap();
        assert!(v.vault.generation > before, "compaction advances the generation");
        cleanup(&path);
    }

    #[cfg(feature = "fault-injection")]
    #[test]
    fn enospc_during_compact_staging_leaves_original_tree_intact() {
        // The disk fills while re-encrypting into the .compact staging tree, BEFORE
        // READY. The compaction fails cleanly, the handle is poisoned, and the
        // ORIGINAL (uncompacted) vault still opens with its live doc intact.
        let (path, keep) = seed_with_garbage("cenospc", 2);
        let mut v = OpenVault::open(path.clone(), b"a", b"b").unwrap();
        crate::fault::fail_at("volume.write", 1);
        let err = v.compact(&volume_opts()).unwrap_err();
        crate::fault::clear();
        assert!(matches!(err, VaultError::Storage(_)), "got {err:?}");
        drop(v);
        let re = OpenVault::open(path.clone(), b"a", b"b").unwrap();
        assert_eq!(&*re.read_document(&keep).unwrap(), &vec![9u8; 400][..]);
        assert!(!parent_dir(&path).join(REKEY_DIR).exists(), "staging discarded");
        cleanup(&path);
    }

    #[test]
    fn compact_json_only_leaves_volume_garbage_untouched() {
        // JSON-only compaction must not rewrite the volume: the dead bytes stay.
        let (path, _keep) = seed_with_garbage("cjvol", 2);
        let mut v = OpenVault::open(path.clone(), b"a", b"b").unwrap();
        records::upsert(&mut v.vault.accounts, sample_account("u", "p"));
        v.vault.accounts[0].history.push(records::Change { at: 1, action: "u".into(), detail: String::new() });
        v.save().unwrap();
        let before = v.compact_dry_run(&volume_opts()).bytes_reclaimed;
        assert!(before > 0, "there should be reclaimable volume garbage");
        let opts = CompactOptions { volume: false, json: true, history_cutoff: None, drop_all_history: true };
        let report = v.compact(&opts).unwrap();
        assert_eq!(report.bytes_reclaimed, 0, "json-only reclaims no volume bytes");
        assert!(report.history_removed >= 1);
        // The volume garbage is exactly as before — untouched by a json-only run.
        assert_eq!(v.compact_dry_run(&volume_opts()).bytes_reclaimed, before);
        cleanup(&path);
    }

    #[test]
    fn compact_preserves_unreferenced_orphan_blobs() {
        // Compaction copies every live manifest entry (storage.ids()), so an
        // unreferenced orphan blob is conservatively kept (never silently dropped),
        // while genuinely dead frames (removed) are reclaimed.
        let path = tmp_path("corphan");
        let mut v = OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();
        let src = write_src("co", &vec![3u8; 300]);
        let referenced = v.add_document("/r", "r.bin", &src).unwrap();
        let mut tw = records::TrustWill::new().unwrap();
        tw.file = Some(referenced.clone());
        records::upsert(&mut v.vault.trust_wills, tw);
        let orphan = v.add_document("/o", "o.bin", &src).unwrap(); // never linked → orphan
        let garbage = v.add_document("/g", "g.bin", &src).unwrap();
        v.remove_document(&garbage).unwrap(); // dead frame
        v.save().unwrap();
        fs::remove_file(&src).ok();

        v.compact(&volume_opts()).unwrap();
        assert!(v.has_document(&referenced));
        assert!(v.has_document(&orphan), "unreferenced orphan is preserved by compaction");
        assert!(!v.has_document(&garbage), "removed doc's frame is reclaimed");
        drop(v);
        let re = OpenVault::open(path.clone(), b"a", b"b").unwrap();
        assert!(re.has_document(&referenced) && re.has_document(&orphan));
        cleanup(&path);
    }

    #[test]
    fn deleted_document_stays_deleted_after_manifest_loss_and_compact() {
        // R-2: a `remove_document`'d blob must not be resurrected by a manifest-loss
        // rebuild (which re-scans the volume) and must not be baked back in by compact.
        let path = tmp_path("r2tomb");
        let mut v = OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();
        let src = write_src("r2", &vec![7u8; 300]);
        let id = v.add_document("/secret", "will.pdf", &src).unwrap();
        let mut tw = records::TrustWill::new().unwrap();
        tw.file = Some(id.clone());
        let tw_id = tw.id.clone();
        records::upsert(&mut v.vault.trust_wills, tw);
        v.save().unwrap();
        // Delete it the way the UI does: detach from the record AND remove the blob.
        if let Some(t) = v.vault.trust_wills.iter_mut().find(|t| t.id == tw_id) {
            t.file = None;
        }
        v.remove_document(&id).unwrap();
        v.save().unwrap();
        assert!(!v.has_document(&id), "deleted");
        // Attacker deletes the partition manifest (encrypted `manifest.0`, no
        // extension), forcing a volume-scan rebuild on the next open.
        fs::remove_file(parent_dir(&path).join("manifest").join("manifest.0")).unwrap();
        drop(v);
        let mut v2 = OpenVault::open(path.clone(), b"a", b"b").unwrap();
        assert!(!v2.has_document(&id), "tombstone suppresses the resurrected frame");
        assert!(v2.read_document(&id).is_err(), "resurrected deleted doc is not readable");
        v2.compact(&volume_opts()).unwrap();
        assert!(!v2.has_document(&id), "compact dropped the tombstoned frame for good");
        drop(v2);
        // After the rewrite the tombstone set is cleared (the frame is physically gone).
        let v3 = OpenVault::open(path.clone(), b"a", b"b").unwrap();
        assert!(v3.vault.deleted_docs.is_empty(), "tombstones cleared after volume rewrite");
        cleanup(&path);
        fs::remove_file(&src).ok();
    }

    #[test]
    fn import_tree_rejects_duplicate_blob_id_in_mirror() {
        // R-8: a mirror listing the same id twice would leave two frames for one id,
        // enabling a later truncation to roll the document back to a stale version.
        let src = tmp_src("dupid");
        fs::create_dir_all(src.join("manifest")).unwrap();
        fs::create_dir_all(src.join("volume").join("vol.0")).unwrap();
        let mut vault = Vault::default();
        vault.version = FORMAT_VERSION;
        vault.id = "abcd1234".into();
        fs::write(src.join("vault.json"), serde_json::to_vec(&vault).unwrap()).unwrap();
        let id = "aa".repeat(16); // 32 lowercase hex
        let entries = serde_json::json!([
            {"id": id, "path": "x/a", "size": 1, "offset": 0, "length": 1, "uploaded_at": 0},
            {"id": id, "path": "x/b", "size": 1, "offset": 1, "length": 1, "uploaded_at": 0},
        ]);
        fs::write(src.join("manifest").join("manifest.0.json"), serde_json::to_vec(&entries).unwrap()).unwrap();
        fs::write(src.join("volume").join("vol.0").join(&id), b"x").unwrap();
        let dest = tmp_path("impdup");
        let res = OpenVault::import_tree(&src, &dest, b"a", b"b", fast());
        assert!(res.is_err(), "duplicate blob id in the mirror manifest must be rejected");
        let _ = fs::remove_dir_all(&src);
        let _ = fs::remove_dir_all(parent_dir(&dest));
    }

    #[test]
    fn open_writable_session_can_back_up_without_self_deadlock() {
        // R-9 regression: an OPEN writable session backs up via OpenVault::backup
        // (reusing its held lock). The free `backup` would self-deadlock here because
        // flock binds to the open file description (a second in-process acquire blocks).
        let path = tmp_path("r9backup");
        let mut v = OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();
        records::upsert(&mut v.vault.accounts, sample_account("u", "p"));
        v.save().unwrap();
        let dest = std::env::temp_dir().join(format!("pmbk-r9-{}", nanos()));
        // The method works while the session is open...
        let bp = v.backup(&dest).expect("OpenVault::backup succeeds while the session holds the lock");
        assert!(bp.exists());
        // ...whereas the free function self-deadlocks (the regression we fixed).
        assert!(matches!(backup(&path, &dest), Err(VaultError::Locked)), "free backup is Locked while a session is open");
        // The produced backup actually opens.
        OpenVault::open(bp.clone(), b"a", b"b").expect("backup is a valid, openable vault");
        drop(v);
        cleanup(&path);
        let _ = fs::remove_dir_all(&dest);
    }

    // --- Category deletion (asset/account types + subtypes) ------------------

    #[test]
    fn remove_asset_type_blocks_when_in_use_then_allows_when_free() {
        let path = tmp_path("rmasset");
        let mut v = OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();
        assert!(v.add_asset_type("Crypto").unwrap());
        // Used by a live asset -> refused with the count.
        let mut al = records::AssetLiability::new().unwrap();
        al.asset_type = "Crypto".into();
        let al_id = al.id.clone();
        records::upsert(&mut v.vault.assets, al);
        v.save().unwrap();
        assert_eq!(v.remove_asset_type("Crypto").unwrap(), CategoryRemoval::InUse(1));
        assert!(v.categories().asset.contains(&"Crypto".to_string()), "kept while in use");
        // Remove the using record -> now deletable; persists across reopen.
        records::remove(&mut v.vault.assets, &al_id, &mut v.vault.audit, "Asset");
        v.save().unwrap();
        assert_eq!(v.remove_asset_type("crypto").unwrap(), CategoryRemoval::Removed); // case-insensitive
        assert_eq!(v.remove_asset_type("Crypto").unwrap(), CategoryRemoval::NotFound);
        drop(v);
        let re = OpenVault::open(path.clone(), b"a", b"b").unwrap();
        assert!(!re.categories().asset.contains(&"Crypto".to_string()), "deletion persisted");
        cleanup(&path);
    }

    #[test]
    fn remove_account_type_blocks_on_subtypes_then_on_use_then_allows() {
        let path = tmp_path("rmacct");
        let mut v = OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();
        v.add_account_type("Bank").unwrap();
        v.add_account_subtype("Bank", "Checking").unwrap();
        // (1) Has a subtype -> blocked (delete subtypes first).
        assert_eq!(v.remove_account_type("Bank").unwrap(), CategoryRemoval::HasSubtypes);
        // (2) A live account uses the subtype -> the subtype can't go yet.
        let mut acc = sample_account("u", "p");
        acc.account_type = "Bank".into();
        acc.account_subtype = "Checking".into();
        let acc_id = acc.id.clone();
        records::upsert(&mut v.vault.accounts, acc);
        v.save().unwrap();
        assert_eq!(v.remove_account_subtype("Bank", "Checking").unwrap(), CategoryRemoval::InUse(1));
        // Move the account off the subtype (history will record the change, but that
        // must NOT block deletion) -> subtype now free.
        let mut edited = v.vault.accounts.iter().find(|a| a.id == acc_id).unwrap().clone();
        edited.account_subtype = String::new();
        records::upsert(&mut v.vault.accounts, edited);
        v.save().unwrap();
        assert_eq!(v.remove_account_subtype("Bank", "Checking").unwrap(), CategoryRemoval::Removed);
        // (3) Type now has no subtypes but the account still uses the TYPE -> InUse.
        assert_eq!(v.remove_account_type("Bank").unwrap(), CategoryRemoval::InUse(1));
        // Move the account off the type entirely -> type now deletable.
        let mut edited = v.vault.accounts.iter().find(|a| a.id == acc_id).unwrap().clone();
        edited.account_type = "Email".into();
        records::upsert(&mut v.vault.accounts, edited);
        v.save().unwrap();
        assert_eq!(v.remove_account_type("Bank").unwrap(), CategoryRemoval::Removed);
        assert!(!v.categories().account_type_names().contains(&"Bank".to_string()));
        cleanup(&path);
    }

    #[test]
    fn category_deletion_ignores_history_only_usage() {
        // The crux of the requested behaviour: a type that appears only in a record's
        // HISTORY (never on a live record) is deletable.
        let path = tmp_path("rmhist");
        let mut v = OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();
        v.add_account_type("Legacy").unwrap();
        let mut acc = sample_account("u", "p");
        acc.account_type = "Legacy".into();
        let id = acc.id.clone();
        records::upsert(&mut v.vault.accounts, acc);
        v.save().unwrap();
        // Edit the account OFF "Legacy"; upsert records `type: "Legacy" -> "Email"`.
        let mut edited = v.vault.accounts.iter().find(|a| a.id == id).unwrap().clone();
        edited.account_type = "Email".into();
        records::upsert(&mut v.vault.accounts, edited);
        v.save().unwrap();
        // Sanity: the history really does mention "Legacy"...
        assert!(
            v.vault.accounts[0].history.iter().any(|c| c.detail.contains("Legacy")),
            "history retains the old type"
        );
        // ...but no LIVE account uses it, so it deletes.
        assert_eq!(v.remove_account_type("Legacy").unwrap(), CategoryRemoval::Removed);
        cleanup(&path);
    }

    #[test]
    fn category_removal_is_blocked_read_only() {
        let path = tmp_path("rmro");
        {
            let mut v = OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();
            v.add_asset_type("Crypto").unwrap();
            v.save().unwrap();
        }
        let mut ro = OpenVault::open_read_only(path.clone(), b"a", b"b").unwrap();
        assert!(matches!(ro.remove_asset_type("Crypto"), Err(VaultError::ReadOnly)));
        assert!(matches!(ro.remove_account_type("Email"), Err(VaultError::ReadOnly)));
        assert!(matches!(ro.remove_account_subtype("Financial", "Bank"), Err(VaultError::ReadOnly)));
        cleanup(&path);
    }

    #[cfg(unix)]
    #[test]
    fn backup_refuses_symlinked_destination() {
        // Defense in depth: an attacker who can write the vault dir must not be able
        // to redirect a backup through a symlinked destination directory.
        let path = tmp_path("bksym");
        OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();
        let realdest = std::env::temp_dir().join(format!("pmbkreal-{}", nanos()));
        fs::create_dir_all(&realdest).unwrap();
        let linkdest = std::env::temp_dir().join(format!("pmbklink-{}", nanos()));
        std::os::unix::fs::symlink(&realdest, &linkdest).unwrap();
        let err = backup(&path, &linkdest).unwrap_err();
        assert!(matches!(err, VaultError::Storage(_)), "symlinked dest refused, got {err:?}");
        // A normal (non-symlink) destination still backs up fine.
        let bp = backup(&path, &realdest).unwrap();
        assert!(bp.exists());
        cleanup(&path);
        let _ = fs::remove_dir_all(&realdest);
        let _ = fs::remove_file(&linkdest);
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

        /// referenced_doc_ids surfaces EVERY attached blob id across all record kinds
        /// (TrustWill.file, Asset.statement, Taxes/RealEstate documents, and
        /// GeneralDocument.file) and nothing extra — the invariant compaction relies
        /// on so a live document is never reclaimed and a delete reclaims exactly a
        /// record's own blobs. (Pure: builds a Vault in memory, no crypto/IO.)
        #[test]
        fn prop_referenced_doc_ids_covers_every_attachment(
            tw in proptest::collection::vec("[a-f0-9]{4}", 0..4),
            asset in proptest::collection::vec("[a-f0-9]{4}", 0..4),
            tax in proptest::collection::vec("[a-f0-9]{4}", 0..6),
            re in proptest::collection::vec("[a-f0-9]{4}", 0..6),
            gen_docs in proptest::collection::vec("[a-f0-9]{4}", 0..4),
        ) {
            let mut v = Vault::default();
            let mut want: Vec<String> = Vec::new();
            for f in &tw {
                let mut r = records::TrustWill::default();
                r.file = Some(f.clone());
                v.trust_wills.push(r);
                want.push(f.clone());
            }
            for f in &asset {
                let mut r = records::AssetLiability::default();
                r.statement = Some(f.clone());
                v.assets.push(r);
                want.push(f.clone());
            }
            let mut tf = records::TaxFiling::default();
            tf.documents = tax.clone();
            v.tax_filings.push(tf);
            want.extend(tax.iter().cloned());
            let mut rp = records::RealEstate::default();
            rp.documents = re.clone();
            v.real_estate.push(rp);
            want.extend(re.iter().cloned());
            for f in &gen_docs {
                let mut r = records::GeneralDocument::default();
                r.file = Some(f.clone());
                v.general_documents.push(r);
                want.push(f.clone());
            }
            let got = referenced_doc_ids(&v);
            for id in &want {
                prop_assert!(got.contains(id), "referenced_doc_ids missing {id}");
            }
            prop_assert_eq!(got.len(), want.len(), "no extra or dropped ids");
        }
    }

    proptest! {
        // Each case creates a real vault and does several Argon2-backed saves, so keep
        // the case count modest.
        #![proptest_config(ProptestConfig { cases: 16, ..ProptestConfig::default() })]

        /// For ANY depth and ANY sequence of saves, the in-place redundancy ring stays
        /// well-formed: the vault opens cleanly from the primary, the mirror is the
        /// current generation, each retained generation decodes with a STRICTLY
        /// DESCENDING generation number (a contiguous ring), and the ring never exceeds
        /// the configured depth. Then corrupting the live file recovers from the mirror.
        #[test]
        fn prop_redundancy_ring_well_formed(depth in 1u32..=4, saves in 1usize..=6) {
            let path = tmp_path("propring");
            let mut v = OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();
            v.set_redundancy(depth).unwrap();
            for i in 0..saves {
                records::upsert(&mut v.vault.accounts, sample_account(&format!("u{i}"), "p"));
                v.save().unwrap();
            }
            let cur_gen = v.vault.generation;
            drop(v);

            let gen_of = |p: &Path| {
                read_capped_vault(p).ok().and_then(|raw| decode_vault_bytes(&raw, b"a", b"b").ok().map(|t| t.0.generation))
            };
            // Mirror is the current generation (lossless copy of the latest save).
            prop_assert_eq!(gen_of(&mirror_path(&path)), Some(cur_gen), "mirror == current generation");
            // Generations strictly descending, contiguous, never above current, count <= depth.
            let mut prev = cur_gen;
            let mut count = 0u32;
            for k in 1..=MAX_REDUNDANCY {
                match gen_of(&bak_path(&path, k)) {
                    Some(g) => {
                        count += 1;
                        prop_assert!(g < prev, "bak{} gen {} not strictly below {}", k, g, prev);
                        prev = g;
                    }
                    None => break, // contiguous ring: no holes
                }
            }
            prop_assert!(count <= depth, "ring depth {} exceeds configured {}", count, depth);

            // The vault opens cleanly from the primary; all saved records present.
            let v2 = OpenVault::open(path.clone(), b"a", b"b").unwrap();
            prop_assert!(v2.recovery_notice().is_none(), "primary intact — no recovery");
            prop_assert_eq!(v2.vault.accounts.len(), saves);
            drop(v2);

            // Corrupt the live file: recovery from the (intact) mirror must succeed.
            std::fs::write(&path, b"garbage not a vault").unwrap();
            let v3 = OpenVault::open(path.clone(), b"a", b"b").unwrap();
            prop_assert!(v3.recovery_notice().is_some(), "recovered from a redundant copy");
            prop_assert_eq!(v3.vault.accounts.len(), saves, "no records lost on mirror recovery");
            drop(v3);
            cleanup(&path);
        }
    }


    // --- mutation-testing kill-tests (round 7: cargo-mutants survivor closure) ---
    #[test]
    fn mut_module_size_consts_have_exact_values() {
        // Pin the DoS-guard / clamp constants to their exact byte counts. A mutation
        // that swaps one of the `*` in `256 * 1024 * 1024` etc. for `+` or `/` changes
        // the value, so asserting against the resolved integer literal (NOT the same
        // arithmetic, which would mutate identically) kills it.
        assert_eq!(MAX_VAULT_SIZE, 268_435_456u64, "MAX_VAULT_SIZE must be exactly 256 MiB");
        assert_eq!(MIN_VOLUME_MAX_SIZE, 65_536u64, "MIN_VOLUME_MAX_SIZE must be exactly 64 KiB");
        assert_eq!(MAX_VOLUME_MAX_SIZE, 68_719_476_736u64, "MAX_VOLUME_MAX_SIZE must be exactly 64 GiB");
    }

    #[test]
    fn mut_import_tree_vault_id_length_boundary() {
        // import_tree line: `id.is_empty() || id.len() > 64 || !alphanumeric`.
        // An id of EXACTLY 64 ascii-alnum chars must be accepted (real: `64 > 64`
        // is false). The `>`->`==`/`>=` mutants would reject 64 -> import fails, so a
        // SUCCESSFUL import at exactly 64 distinguishes the real operator from them.
        let id64: String = "a".repeat(64);
        assert_eq!(id64.len(), 64);
        let src = tmp_src("idlen64");
        let mut vault = Vault::default();
        vault.version = FORMAT_VERSION;
        vault.id = id64;
        fs::write(src.join("vault.json"), serde_json::to_vec(&vault).unwrap()).unwrap();
        let dest = tmp_path("impidlen64");
        let v = OpenVault::import_tree(&src, &dest, b"a", b"b", fast())
            .expect("a 64-char alphanumeric mirror id must import successfully");
        drop(v);
        let _ = fs::remove_dir_all(&src);
        cleanup(&dest);
    }

    #[test]
    fn mut_import_tree_vault_id_over_length_rejected() {
        // An id of 65 ascii-alnum chars violates ONLY the `id.len() > 64` clause
        // (not is_empty, not the alnum check). Real code rejects it. The `||`->`&&`
        // mutant (col 32) would make the chain require is_empty too -> false -> the id
        // passes and the 65-char (still a valid filename) import SUCCEEDS, so a
        // REJECTION here kills `||`->`&&`. The `>`->`==`/`>=` mutants still reject 65,
        // so this test isolates the OR-vs-AND change.
        let id65: String = "a".repeat(65);
        assert_eq!(id65.len(), 65);
        let src = tmp_src("idlen65");
        let mut vault = Vault::default();
        vault.version = FORMAT_VERSION;
        vault.id = id65;
        fs::write(src.join("vault.json"), serde_json::to_vec(&vault).unwrap()).unwrap();
        let dest = tmp_path("impidlen65");
        let res = OpenVault::import_tree(&src, &dest, b"a", b"b", fast());
        assert!(res.is_err(), "a 65-char mirror id exceeds the 64-char cap and must be rejected");
        let _ = fs::remove_dir_all(&src);
        let _ = fs::remove_dir_all(parent_dir(&dest));
    }

    #[test]
    fn mut_import_tree_empty_vault_id_rejected() {
        // The empty-id case violates ONLY the `id.is_empty()` clause. Real code rejects
        // it. The `||`->`&&` mutant would require all three clauses, so an empty id
        // (len 0 > 64 is false) would NOT be rejected here -> complements the 65-char
        // test from the other side of the OR.
        let src = tmp_src("idempty");
        let mut vault = Vault::default();
        vault.version = FORMAT_VERSION;
        vault.id = String::new();
        fs::write(src.join("vault.json"), serde_json::to_vec(&vault).unwrap()).unwrap();
        let dest = tmp_path("impidempty");
        let res = OpenVault::import_tree(&src, &dest, b"a", b"b", fast());
        assert!(res.is_err(), "an empty mirror id must be rejected");
        let _ = fs::remove_dir_all(&src);
        let _ = fs::remove_dir_all(parent_dir(&dest));
    }

    #[test]
    fn mut_add_document_size_cap_boundary() {
        // add_document line: `if meta.len() > MAX_DOC_SIZE { TooLarge }`.
        // A file of EXACTLY MAX_DOC_SIZE must be accepted (real: `cap > cap` is false;
        // read_file_capped also lets exactly `cap` bytes through). The `>`->`==` and
        // `>`->`>=` mutants would reject the at-cap file, so a SUCCESSFUL add at exactly
        // the cap kills both. A file ONE byte over must be rejected with TooLarge,
        // confirming the upper side of the boundary.
        let path = tmp_path("docsizecap");
        let mut v = OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();

        let at_cap = vec![0u8; MAX_DOC_SIZE as usize];
        let at_cap_src = write_src("atcap", &at_cap);
        let id = v
            .add_document("/d", "atcap.bin", &at_cap_src)
            .expect("a document of exactly MAX_DOC_SIZE must be accepted");
        assert_eq!(v.read_document(&id).unwrap().len(), MAX_DOC_SIZE as usize, "at-cap doc round-trips");

        let over_cap = vec![0u8; MAX_DOC_SIZE as usize + 1];
        let over_cap_src = write_src("overcap", &over_cap);
        let res = v.add_document("/d", "overcap.bin", &over_cap_src);
        assert!(matches!(res, Err(VaultError::TooLarge)), "one byte over MAX_DOC_SIZE must be TooLarge");

        let _ = fs::remove_file(&at_cap_src);
        let _ = fs::remove_file(&over_cap_src);
        cleanup(&path);
    }

    #[test]
    fn mut_redundancy_returns_the_set_depth_not_zero() {
        // Kills vault.rs:773 (redundancy() body replaced with 0). The default depth
        // is 0, so we must assert a NON-zero configured value is returned: set it to
        // 3 (below MAX_REDUNDANCY=10, so no clamping) and require the getter echoes 3.
        let path = tmp_path("mut-redun");
        let mut v = OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();
        assert_eq!(v.redundancy(), 0, "precondition: off by default");
        v.set_redundancy(3).unwrap();
        // The mutant returns 0; the real getter returns the stored 3.
        assert_eq!(v.redundancy(), 3, "redundancy() must return the configured depth, not 0");
        cleanup(&path);
    }

    #[test]
    fn mut_opened_generation_returns_real_prior_generation_not_one() {
        // Kills vault.rs:1028 (opened_generation() replaced with 1). A freshly
        // created vault already has generation 1, so a test that only reaches gen 1
        // could not distinguish the mutant. We save twice more so the persisted
        // generation is well above 1, then reopen and require the getter matches it.
        let path = tmp_path("mut-opengen");
        let mut created = OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();
        created.save().unwrap();
        created.save().unwrap();
        let g = created.vault.generation;
        assert!(g > 1, "precondition: persisted generation must exceed 1 to expose the mutant (got {g})");
        drop(created); // release the single-writer lock before reopening

        let reopened = OpenVault::open(path.clone(), b"a", b"b").unwrap();
        // opened_generation() reports the generation read off disk at open time
        // (before this open's own save bumps it). The mutant would return 1.
        assert_eq!(reopened.opened_generation(), g, "opened_generation() must surface the real prior generation, not 1");
        cleanup(&path);
    }

    #[test]
    fn mut_previous_access_returns_real_prior_timestamp_not_0_1_neg1() {
        // Kills vault.rs:1024 (previous_access() replaced with 0 / 1 / -1). On create
        // last_opened_at is stamped with unix_now() and persisted; on reopen that real
        // timestamp becomes previous_access. A genuine timestamp is a large positive
        // value (>= ~1.7e9), so it is distinct from every constant the mutant returns.
        let path = tmp_path("mut-prevaccess");
        let before = records::unix_now();
        let created = OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();
        drop(created); // persist + release the lock

        let after = records::unix_now();
        let reopened = OpenVault::open(path.clone(), b"a", b"b").unwrap();
        let prev = reopened.previous_access();
        // Must be the genuine create-time timestamp, not 0, 1, or -1.
        assert!(prev > 1, "previous_access() must be a real timestamp, not 0/1/-1 (got {prev})");
        assert!(
            prev >= before && prev <= after,
            "previous_access() ({prev}) must fall in [{before}, {after}] — the create-time stamp"
        );
        cleanup(&path);
    }

    #[test]
    fn mut_export_returns_real_vault_records_not_default() {
        // Kills vault.rs:458 (export() replaced with Ok(Default::default())). A
        // Default Vault has an empty account list, an empty id, and generation 0, so
        // we seed a known account and require export() round-trips the REAL contents.
        let path = tmp_path("mut-export");
        let mut v = OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();
        records::upsert(&mut v.vault.accounts, sample_account("octocat", "hunter2"));
        v.save().unwrap();
        drop(v); // release the single-writer lock before the associated-fn export

        let exported = OpenVault::export(&path, b"a", b"b").unwrap();
        // A Default::default() Vault would have none of these.
        assert_eq!(exported.accounts.len(), 1, "export must return the real records, not an empty Default");
        assert_eq!(exported.accounts[0].username, "octocat");
        assert_eq!(exported.accounts[0].password, "hunter2");
        assert!(!exported.id.is_empty(), "real vault has a non-empty id; a Default does not");
        assert!(exported.generation >= 1, "real vault has a bumped generation; a Default is 0");
        cleanup(&path);
    }

    #[test]
    fn mut_read_bounded_cap_boundary() {
        // `read_bounded(path, max)` rejects only when len > max. Pin the exact edge:
        // a file of EXACTLY `max` bytes reads OK (kills `> -> >=`, which would reject
        // len == max), and one byte over is TooLarge (kills dropping the rejection).
        let max: u64 = 16;
        let exact = write_src("rb_exact", &vec![0xABu8; max as usize]);
        let got = read_bounded(&exact, max).expect("a file of exactly `max` bytes must read OK");
        assert_eq!(got.len() as u64, max);
        assert_eq!(got, vec![0xABu8; max as usize]);
        fs::remove_file(&exact).ok();

        let over = write_src("rb_over", &vec![0xCDu8; (max + 1) as usize]);
        assert!(
            matches!(read_bounded(&over, max), Err(VaultError::TooLarge)),
            "one byte over `max` must be TooLarge"
        );
        fs::remove_file(&over).ok();
    }

    #[test]
    fn mut_read_file_capped_cap_boundary() {
        // `read_file_capped(path, max)` rejects only when len > max. The exact-cap-OK
        // case kills both `> -> >=` (would reject len == max) and `> -> ==` (would
        // reject len == max as well); the cap+1 case confirms over-size is rejected.
        let max: u64 = 24;
        let exact = write_src("rfc_exact", &vec![0x11u8; max as usize]);
        let got = read_file_capped(&exact, max).expect("a file of exactly `max` bytes must read OK");
        assert_eq!(got.len() as u64, max);
        assert_eq!(got, vec![0x11u8; max as usize]);
        fs::remove_file(&exact).ok();

        let over = write_src("rfc_over", &vec![0x22u8; (max + 1) as usize]);
        assert!(
            matches!(read_file_capped(&over, max), Err(VaultError::TooLarge)),
            "one byte over `max` must be TooLarge"
        );
        fs::remove_file(&over).ok();
    }

    #[test]
    fn mut_read_capped_vault_notfound_guard() {
        // The NotFound guard (the `Err(e) if e.kind() == NotFound => NotFound` arm):
        // a missing vault path maps specifically to VaultError::NotFound, while a
        // present, readable file does NOT take that arm (it returns its bytes). This
        // pins the guard: deleting it would surface a raw Io error for the missing
        // case, and a guard that always fired would wrongly reject the present file.
        let missing = tmp_path("rcv_missing"); // dir exists, vault.pmv does not
        assert!(!missing.exists());
        assert!(
            matches!(read_capped_vault(&missing), Err(VaultError::NotFound(p)) if p == missing),
            "a missing vault file must map to NotFound with the queried path"
        );

        // A present vault file is read back verbatim (NOT NotFound, NOT an error).
        let present = tmp_path("rcv_present");
        OpenVault::create(present.clone(), b"a", b"b", fast()).unwrap();
        let on_disk = fs::read(&present).unwrap();
        let via = read_capped_vault(&present).expect("a present vault must read OK");
        assert_eq!(via, on_disk, "present file must be returned verbatim");
        assert!(!via.is_empty());
        cleanup(&present);
        cleanup(&missing);
    }

    #[test]
    fn mut_save_internal_heal_does_not_ring_corrupt_primary() {
        // save_internal line 703: `if rotate_ring && depth > 0`. On a recovery HEAL
        // open the save runs with rotate_ring=FALSE, so the (corrupt) outgoing
        // primary must NOT be ringed into bak1 — prev stays None and the good prior
        // generation in bak1 is preserved untouched. Mutating `&&` to `||` makes the
        // condition true on a heal (depth>0), so prev=Some(corrupt-primary) and
        // rotate_generations overwrites bak1 with the un-decryptable primary bytes.
        let path = tmp_path("muthealring");
        let mut v = OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();
        v.set_redundancy(1).unwrap(); // depth 1: one prior generation + a mirror
        records::upsert(&mut v.vault.accounts, sample_account("keep-me", "p")); // state A
        v.save().unwrap();
        records::upsert(&mut v.vault.accounts, sample_account("newer", "p")); // state B
        v.save().unwrap();
        drop(v);

        // After the two saves bak1 holds state A (the prior generation). Snapshot it.
        let bak1_before = fs::read(bak_path(&path, 1)).unwrap();

        // Corrupt BOTH the live file and the same-generation mirror so the open must
        // recover from bak1 (state A) and then HEAL the live tree (rotate_ring=false).
        let sentinel: &[u8] = b"not a vault at all";
        fs::write(&path, sentinel).unwrap();
        fs::write(mirror_path(&path), b"corrupt mirror").unwrap();

        let v2 = OpenVault::open(path.clone(), b"a", b"b").unwrap();
        assert!(v2.recovery_notice().is_some(), "the open must have recovered + healed");
        drop(v2);

        // The heal must not have ringed the corrupt outgoing primary into bak1.
        let bak1_after = fs::read(bak_path(&path, 1)).unwrap();
        assert_ne!(
            bak1_after, sentinel,
            "heal ringed the corrupt primary into bak1 (the `&&`->`||` mutant): bak1 is now garbage"
        );
        assert_eq!(bak1_before, bak1_after, "heal left the good prior generation in bak1 untouched");
        // bak1 is still a real, decryptable vault holding state A (not state B).
        let (recovered, _h, _k) = decode_vault_bytes(&bak1_after, b"a", b"b").unwrap();
        let users: Vec<&str> = recovered.accounts.iter().map(|a| a.username.as_str()).collect();
        assert!(users.contains(&"keep-me"), "bak1 still decrypts to the prior generation");

        cleanup(&path);
    }

    #[test]
    fn mut_staged_rewrite_empty_store_creates_no_volume_dirs() {
        // staged_rewrite line 897: `if self.storage.partition_count() > 0`. A vault
        // with NO documents has zero partitions and (crucially) NO live volume/ or
        // manifest/ dirs. With `> 0` (false) the rewrite must NOT materialize empty
        // staged volume/manifest dirs, so after a change_password (which always runs
        // staged_rewrite) the tree still has no volume/manifest dirs. Mutating `>` to
        // `>=` makes the condition true at count==0, creating empty staged dirs that
        // commit_rekey then swaps INTO the live tree.
        let path = tmp_path("mutstageempty");
        let mut v = OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();
        let dir = parent_dir(&path);
        assert_eq!(v.storage.partition_count(), 0, "an empty vault has zero partitions");
        assert!(!dir.join("volume").exists(), "empty vault: no live volume dir to begin with");
        assert!(!dir.join("manifest").exists(), "empty vault: no live manifest dir to begin with");

        v.change_password(b"c", b"d").unwrap(); // runs staged_rewrite with partition_count()==0
        drop(v);

        assert!(
            !dir.join("volume").exists(),
            "staged_rewrite created an empty volume dir at count==0 (the `>`->`>=` mutant)"
        );
        assert!(
            !dir.join("manifest").exists(),
            "staged_rewrite created an empty manifest dir at count==0 (the `>`->`>=` mutant)"
        );
        // And the rekey still committed: the new passwords open, the old ones don't.
        assert!(OpenVault::open(path.clone(), b"a", b"b").is_err(), "old password rejected after rekey");
        assert!(OpenVault::open(path.clone(), b"c", b"d").is_ok(), "new password opens the rekeyed vault");
        cleanup(&path);
    }

    #[test]
    fn mut_backup_snapshot_collision_counter_increments() {
        // backup_snapshot line 1967: `n += 1`. Three backups into the SAME dest within
        // one timestamp-second must yield `backup-<stamp>`, `backup-<stamp>_1`, then
        // `backup-<stamp>_2` — proving the collision counter is incremented by 1 each
        // probe. Mutating `+= 1` to `-= 1` makes the third name `_0` (not `_2`);
        // `*= 1` pins n at 1 and spins forever on the already-present `_1` (timeout-kill).
        let path = tmp_path("mutbkpcollide");
        let v = OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();
        drop(v);
        let src_dir = parent_dir(&path);
        let dest = std::env::temp_dir().join(format!("pmmutbkp-{}", nanos()));

        // Retry the whole 3-call sequence into a fresh dest if a wall-clock second
        // boundary splits the stamps (rare); this keeps the assertion deterministic
        // without depending on absolute timing.
        let mut third_name = String::new();
        let mut stamp = String::new();
        for attempt in 0..20 {
            let d = dest.join(format!("try{attempt}"));
            let b1 = backup_snapshot(&path, &src_dir, &d).unwrap();
            let b2 = backup_snapshot(&path, &src_dir, &d).unwrap();
            let b3 = backup_snapshot(&path, &src_dir, &d).unwrap();
            let name = |p: &Path| p.parent().unwrap().file_name().unwrap().to_string_lossy().into_owned();
            let (n1, n2, n3) = (name(&b1), name(&b2), name(&b3));
            // All three share the stamp only if no second boundary was crossed.
            let s = n1.clone(); // "backup-<stamp>"
            if n2 == format!("{s}_1") && n3.starts_with(&format!("{s}_")) {
                stamp = s;
                third_name = n3;
                break;
            }
        }
        assert!(!third_name.is_empty(), "could not get three same-stamp backups in 20 tries");
        assert_eq!(
            third_name,
            format!("{stamp}_2"),
            "third colliding backup must be `_2` — proves `n += 1` increments the collision counter"
        );

        fs::remove_dir_all(&dest).ok();
        cleanup(&path);
    }

    // Kills: vault.rs harden_file (line ~2037) body -> Ok(()).
    // harden_file must actually chmod the file to 0600. We deliberately loosen the
    // perms first (to 0644) so create_new_0600's creation-time 0600 cannot mask the
    // mutant; only harden_file's set_mode call can pull it back to 0600. If the body
    // is replaced with `Ok(())`, the file stays 0644 and the assert fails.
    #[cfg(unix)]
    #[test]
    fn mut_harden_file_chmods_to_0600() {
        use std::os::unix::fs::PermissionsExt;
        let path = tmp_path("hardenfile");
        let _v = OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();
        // Loosen to 0644 so only harden_file can restore 0600.
        let mut p = fs::metadata(&path).unwrap().permissions();
        p.set_mode(0o644);
        fs::set_permissions(&path, p).unwrap();
        assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o644);

        harden_file(&path).unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600,
            "harden_file must chmod the file to 0600"
        );
        cleanup(&path);
    }

    // Kills: vault.rs harden_dir (line ~2051) body -> ().
    // Direct-call form: loosen the vault dir to 0755, then harden_dir must restore
    // 0700. A no-op body leaves it at 0755 and fails.
    #[cfg(unix)]
    #[test]
    fn mut_harden_dir_chmods_to_0700() {
        use std::os::unix::fs::PermissionsExt;
        let path = tmp_path("hardendir");
        let _v = OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();
        let dir = parent_dir(&path);
        let mut p = fs::metadata(&dir).unwrap().permissions();
        p.set_mode(0o755);
        fs::set_permissions(&dir, p).unwrap();
        assert_eq!(fs::metadata(&dir).unwrap().permissions().mode() & 0o777, 0o755);

        harden_dir(&dir);
        assert_eq!(
            fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
            0o700,
            "harden_dir must chmod the directory to 0700"
        );
        cleanup(&path);
    }

    // Integration backstop for harden_dir (line ~2051): a freshly created vault's
    // parent directory is created with create_dir_all at the umask (typically 0755)
    // and is tightened to 0700 ONLY by harden_dir. With the body mutated to `()`,
    // the directory keeps its umask perms and this assert catches it. (Also pins the
    // created vault.pmv at 0600 for good measure.)
    #[cfg(unix)]
    #[test]
    fn mut_create_vault_dir_is_0700() {
        use std::os::unix::fs::PermissionsExt;
        let path = tmp_path("createperm");
        let _v = OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();
        let dir = parent_dir(&path);
        assert_eq!(
            fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
            0o700,
            "create() must harden the vault directory to 0700"
        );
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600,
            "create() must leave vault.pmv at 0600"
        );
        cleanup(&path);
    }

    #[test]
    fn mut_sweep_stale_temps_needs_prefix_and_tmp_suffix() {
        // sweep_stale_temps removes a file only if it BOTH starts with the vault prefix
        // AND ends in ".tmp" (the `&&` at line ~1665). An `||` would also wipe unrelated
        // "*.tmp" files and (worse) the live ".vault.pmv.*" data — so a file matching only
        // ONE clause must survive. (Kills the `&&` -> `||` mutant — verified by applying it.)
        let base = tmp_path("sweeptmp"); // tmp_path already created the dir
        let dir = parent_dir(&base);
        let swept = dir.join(format!(".{VAULT_FILE}.abc123.tmp")); // prefix AND .tmp -> removed
        let keep_tmp_only = dir.join("unrelated.tmp"); // .tmp only -> kept (|| would delete)
        let keep_prefix_only = dir.join(format!(".{VAULT_FILE}.mirror")); // prefix only -> kept
        for f in [&swept, &keep_tmp_only, &keep_prefix_only] {
            fs::write(f, b"x").unwrap();
        }
        sweep_stale_temps(&dir);
        assert!(!swept.exists(), "a genuine .vault.pmv.*.tmp temp is swept");
        assert!(keep_tmp_only.exists(), "an unrelated *.tmp must survive (kills && -> ||)");
        assert!(keep_prefix_only.exists(), "a non-.tmp vault sibling must survive (kills && -> ||)");
        cleanup(&base);
    }

    // ---- Cross-vault merge ("update from another vault") --------------------

    use crate::merge::ChangeKind;

    /// An account with a chosen id + updated_at, so two vaults can share a record id.
    fn acct_with(id: &str, user: &str, pw: &str, updated_at: i64) -> Account {
        let mut a = sample_account(user, pw);
        a.id = id.to_string();
        a.title = format!("acct-{id}");
        a.owner = "owner".into();
        a.updated_at = updated_at;
        a.created_at = 1;
        a
    }

    #[test]
    fn merge_pulls_newer_and_new_records_and_copies_blobs() {
        // SOURCE: a newer version of a shared account, a brand-new account, and a general
        // document with an attached blob.
        let s_path = tmp_path("merge-src");
        let mut s = OpenVault::create(s_path.clone(), b"s1", b"s2", fast()).unwrap();
        s.vault.accounts.push(acct_with("shared", "alice", "NEWpw", 200));
        s.vault.accounts.push(acct_with("only-in-source", "bob", "bobpw", 50));
        let doc = write_src("merge-doc", b"top-secret-statement");
        let blob_id = s.add_document("general-documents/passport", "passport.pdf", &doc).unwrap();
        let mut gd = records::GeneralDocument::new().unwrap();
        gd.id = "gd-1".into();
        gd.title = "Passport".into();
        gd.file = Some(blob_id.clone());
        gd.updated_at = 300;
        s.vault.general_documents.push(gd);
        s.save().unwrap();

        // CURRENT: an OLDER version of the shared account, plus a current-only record that
        // the additive merge must leave untouched.
        let c_path = tmp_path("merge-cur");
        let mut c = OpenVault::create(c_path.clone(), b"c1", b"c2", fast()).unwrap();
        c.vault.accounts.push(acct_with("shared", "alice", "OLDpw", 100));
        c.vault.accounts.push(acct_with("only-in-current", "carol", "carolpw", 999));
        c.save().unwrap();

        let source = OpenVault::open_read_only(s_path.clone(), b"s1", b"s2").unwrap();

        // PLAN: 1 updated (shared), 2 new (only-in-source account + the general doc); 1 blob.
        let plan = c.plan_merge_from(&source).unwrap();
        assert_eq!(plan.updated_count(), 1, "shared account is newer in source");
        assert_eq!(plan.new_count(), 2, "source-only account + general document");
        assert_eq!(plan.blobs_to_copy(), 1, "the passport blob must be copied");
        assert_eq!(plan.bytes_to_copy(), b"top-secret-statement".len() as u64);
        assert!(plan.skipped.is_empty());
        // The shared account's preview shows the old->new recency.
        let shared = plan.records.iter().find(|r| r.id == "shared").unwrap();
        assert_eq!(shared.change, ChangeKind::Updated);
        assert_eq!(shared.current_updated_at, Some(100));
        assert_eq!(shared.source_updated_at, 200);

        // APPLY.
        let report = c.apply_merge_from(&source).unwrap();
        assert_eq!((report.records_added, report.records_updated), (2, 1));
        assert_eq!(report.blobs_copied, 1);

        // Shared account updated verbatim (source password + source updated_at preserved).
        let shared = c.vault.accounts.iter().find(|a| a.id == "shared").unwrap();
        assert_eq!(shared.password, "NEWpw");
        assert_eq!(shared.updated_at, 200, "source updated_at preserved (idempotency)");
        // New records present; current-only record untouched.
        assert!(c.vault.accounts.iter().any(|a| a.id == "only-in-source"));
        assert!(c.vault.accounts.iter().any(|a| a.id == "only-in-current" && a.password == "carolpw"));
        assert!(c.vault.general_documents.iter().any(|g| g.id == "gd-1" && g.file.as_deref() == Some(blob_id.as_str())));
        // The copied blob is readable in the destination under the SAME id.
        assert_eq!(&**c.read_document(&blob_id).unwrap(), b"top-secret-statement");
        // A vault-level audit entry records the merge (counts only, no secrets).
        assert!(c.vault.audit.iter().any(|ch| ch.action == "merged"));

        // IDEMPOTENT: a second plan against the same source is empty.
        let plan2 = c.plan_merge_from(&source).unwrap();
        assert!(plan2.is_empty(), "re-merge of identical data is a no-op");

        // The destination reopens cleanly (referenced ⊆ stored holds after the merge).
        drop(c);
        let c2 = OpenVault::open(c_path.clone(), b"c1", b"c2").unwrap();
        assert_eq!(&**c2.read_document(&blob_id).unwrap(), b"top-secret-statement");
        drop(c2);
        cleanup(&s_path);
        cleanup(&c_path);
    }

    #[test]
    fn merge_duplicate_source_id_does_not_add_a_phantom_category_type() {
        // Two SOURCE accounts share id "dup" but carry DIFFERENT account types. merge_records
        // is first-occurrence-wins, so only the first ("Checking") is actually applied — the
        // second ("Phantom") must NOT seed an orphan category type that no applied record uses.
        let s_path = tmp_path("merge-dup-src");
        let mut s = OpenVault::create(s_path.clone(), b"s1", b"s2", fast()).unwrap();
        let mut a1 = acct_with("dup", "alice", "pw", 100);
        a1.account_type = "Checking".into();
        let mut a2 = acct_with("dup", "alice", "pw", 100);
        a2.account_type = "Phantom".into();
        s.vault.accounts.push(a1);
        s.vault.accounts.push(a2);
        s.save().unwrap();
        let source = OpenVault::open_read_only(s_path.clone(), b"s1", b"s2").unwrap();

        let c_path = tmp_path("merge-dup-cur");
        let mut c = OpenVault::create(c_path.clone(), b"c1", b"c2", fast()).unwrap();

        // PLAN: only the first occurrence's type appears in the preview's new categories.
        let plan = c.plan_merge_from(&source).unwrap();
        assert!(plan.new_categories.iter().any(|s| s.contains("Checking")), "first type previewed");
        assert!(
            !plan.new_categories.iter().any(|s| s.contains("Phantom")),
            "the duplicate id's second type must not be a phantom category: {:?}",
            plan.new_categories
        );

        // APPLY: the category list gains "Checking" but never the orphan "Phantom".
        c.apply_merge_from(&source).unwrap();
        assert!(c.vault.categories.account.iter().any(|x| x.name == "Checking"));
        assert!(
            !c.vault.categories.account.iter().any(|x| x.name == "Phantom"),
            "no orphan category type from the un-applied duplicate"
        );
        cleanup(&s_path);
        cleanup(&c_path);
    }

    #[test]
    fn merge_duplicate_source_asset_id_does_not_add_a_phantom_type() {
        // Same first-occurrence-wins dedup as the account test, but exercises the ASSET loop
        // in plan/apply_merge_from (mutation kill-test: `||`->`&&` in the asset dedup guard
        // would process the un-applied duplicate and seed an orphan "Phantom" asset type).
        let s_path = tmp_path("merge-dupa-src");
        let mut s = OpenVault::create(s_path.clone(), b"s1", b"s2", fast()).unwrap();
        let mut a1 = records::AssetLiability::new().unwrap();
        a1.id = "dup".into();
        a1.asset_type = "Bank".into();
        a1.updated_at = 100;
        let mut a2 = records::AssetLiability::new().unwrap();
        a2.id = "dup".into();
        a2.asset_type = "Phantom".into();
        a2.updated_at = 100;
        s.vault.assets.push(a1);
        s.vault.assets.push(a2);
        s.save().unwrap();
        let source = OpenVault::open_read_only(s_path.clone(), b"s1", b"s2").unwrap();

        let c_path = tmp_path("merge-dupa-cur");
        let mut c = OpenVault::create(c_path.clone(), b"c1", b"c2", fast()).unwrap();
        let plan = c.plan_merge_from(&source).unwrap();
        assert!(plan.new_categories.iter().any(|s| s.contains("Bank")), "first asset type previewed");
        assert!(
            !plan.new_categories.iter().any(|s| s.contains("Phantom")),
            "duplicate asset id's second type must not be a phantom: {:?}",
            plan.new_categories
        );
        c.apply_merge_from(&source).unwrap();
        assert!(c.vault.categories.asset.iter().any(|x| x.as_str() == "Bank"));
        assert!(
            !c.vault.categories.asset.iter().any(|x| x.as_str() == "Phantom"),
            "no orphan asset type from the un-applied duplicate"
        );
        cleanup(&s_path);
        cleanup(&c_path);
    }

    #[test]
    fn merge_apply_stores_sanitized_category_type_matching_the_preview() {
        // A crafted SOURCE asset's type carries a bidi override (U+202E). The approval preview
        // shows the SANITIZED name (display_safe -> '_'); apply must persist that SAME sanitized
        // type into the category list, not the raw spoofed string — otherwise what the user
        // approved and what gets stored diverge (preview/apply spoof divergence).
        let s_path = tmp_path("merge-san-src");
        let mut s = OpenVault::create(s_path.clone(), b"s1", b"s2", fast()).unwrap();
        let mut a = records::AssetLiability::new().unwrap();
        a.id = "spoof".into();
        a.asset_type = "Bank\u{202e}x".into();
        a.updated_at = 100;
        s.vault.assets.push(a);
        s.save().unwrap();
        let source = OpenVault::open_read_only(s_path.clone(), b"s1", b"s2").unwrap();

        let c_path = tmp_path("merge-san-cur");
        let mut c = OpenVault::create(c_path.clone(), b"c1", b"c2", fast()).unwrap();
        let sanitized = records::display_safe("Bank\u{202e}x"); // "Bank_x"
        // Preview already shows the sanitized name (round-2 fix); apply must agree.
        let plan = c.plan_merge_from(&source).unwrap();
        assert!(plan.new_categories.iter().any(|s| s.contains(&sanitized)));
        c.apply_merge_from(&source).unwrap();
        assert!(
            c.vault.categories.asset.iter().any(|x| x.as_str() == sanitized),
            "stored category is the sanitized name the user previewed: {:?}",
            c.vault.categories.asset
        );
        assert!(
            !c.vault.categories.asset.iter().any(|x| x.as_str().contains('\u{202e}')),
            "the raw bidi-spoofed type must NOT be persisted"
        );
        cleanup(&s_path);
        cleanup(&c_path);
    }

    #[test]
    fn merge_preview_count_matches_apply_for_sanitize_colliding_types() {
        // Preview and apply must dedup category types on the SAME (display_safe-sanitized) value,
        // or plan.new_categories drifts from report.categories_added. Two accepted source assets
        // whose types differ only by a zero-width char both sanitize to "Acme_": the preview must
        // show ONE new asset category and apply must add ONE (not 2 previewed vs 1 applied).
        let s_path = tmp_path("merge-div-src");
        let mut s = OpenVault::create(s_path.clone(), b"s1", b"s2", fast()).unwrap();
        let mut a1 = records::AssetLiability::new().unwrap();
        a1.id = "a1".into();
        a1.asset_type = "Acme\u{200b}".into(); // ZERO WIDTH SPACE
        a1.updated_at = 100;
        let mut a2 = records::AssetLiability::new().unwrap();
        a2.id = "a2".into();
        a2.asset_type = "Acme\u{200c}".into(); // ZERO WIDTH NON-JOINER -> also "Acme_"
        a2.updated_at = 100;
        s.vault.assets.push(a1);
        s.vault.assets.push(a2);
        s.save().unwrap();
        let source = OpenVault::open_read_only(s_path.clone(), b"s1", b"s2").unwrap();

        let c_path = tmp_path("merge-div-cur");
        let mut c = OpenVault::create(c_path.clone(), b"c1", b"c2", fast()).unwrap();
        let plan = c.plan_merge_from(&source).unwrap();
        let previewed_asset_cats = plan.new_categories.iter().filter(|l| l.contains("asset type")).count();
        assert_eq!(previewed_asset_cats, 1, "two collapse to one previewed category");
        let report = c.apply_merge_from(&source).unwrap();
        assert_eq!(
            previewed_asset_cats, report.categories_added,
            "previewed new-category count must equal what apply added (no preview/apply drift)"
        );
        cleanup(&s_path);
        cleanup(&c_path);
    }

    #[test]
    fn merge_preview_sanitizes_untrusted_source_record_labels() {
        // A crafted SOURCE vault must not inject bidi/zero-width characters into the merge
        // preview label the user authorizes (terminal/TUI/GUI spoofing). The label is cleaned
        // at the source in plan_collection, so neither the CLI nor the TUI renderer is spoofable.
        let s_path = tmp_path("merge-spoof-src");
        let mut s = OpenVault::create(s_path.clone(), b"s1", b"s2", fast()).unwrap();
        let mut a = acct_with("spoof", "alice", "pw", 100);
        a.title = "invoice\u{202e}fdp.exe".into(); // U+202E RIGHT-TO-LEFT OVERRIDE
        a.account_type = "Bank\u{202e}x".into(); // untrusted category type, also spoofed
        s.vault.accounts.push(a);
        s.save().unwrap();
        let source = OpenVault::open_read_only(s_path.clone(), b"s1", b"s2").unwrap();

        let c_path = tmp_path("merge-spoof-cur");
        let c = OpenVault::create(c_path.clone(), b"c1", b"c2", fast()).unwrap();
        let plan = c.plan_merge_from(&source).unwrap();
        let r = plan.records.iter().find(|r| r.id == "spoof").expect("the source account is previewed");
        assert!(
            !r.label.contains('\u{202e}'),
            "the bidi-override char must be stripped from the preview label, got {:?}",
            r.label
        );
        assert!(r.label.contains('_'), "the spoof char is replaced with '_', got {:?}", r.label);
        // The new-category preview strings (sibling text on the same approval screen, derived
        // from the same untrusted source) must be sanitized too.
        assert!(
            !plan.new_categories.iter().any(|c| c.contains('\u{202e}')),
            "preview category strings must be sanitized: {:?}",
            plan.new_categories
        );
        assert!(
            plan.new_categories.iter().any(|c| c.contains("Bank_x")),
            "the spoofed account type appears sanitized in the preview: {:?}",
            plan.new_categories
        );
        cleanup(&s_path);
        cleanup(&c_path);
    }

    #[test]
    fn merge_ignores_older_or_equal_and_current_only_records() {
        let s_path = tmp_path("merge-old-src");
        let mut s = OpenVault::create(s_path.clone(), b"s1", b"s2", fast()).unwrap();
        s.vault.accounts.push(acct_with("a", "x", "src-older", 100)); // older than current
        s.vault.accounts.push(acct_with("b", "x", "src-equal", 500)); // equal to current
        s.save().unwrap();

        let c_path = tmp_path("merge-old-cur");
        let mut c = OpenVault::create(c_path.clone(), b"c1", b"c2", fast()).unwrap();
        c.vault.accounts.push(acct_with("a", "x", "cur-newer", 300));
        c.vault.accounts.push(acct_with("b", "x", "cur-equal", 500));
        c.save().unwrap();

        let source = OpenVault::open_read_only(s_path.clone(), b"s1", b"s2").unwrap();
        let plan = c.plan_merge_from(&source).unwrap();
        assert!(plan.is_empty(), "neither older nor equal source records are pulled");
        let report = c.apply_merge_from(&source).unwrap();
        assert_eq!((report.records_added, report.records_updated), (0, 0));
        // Current values untouched.
        assert_eq!(c.vault.accounts.iter().find(|a| a.id == "a").unwrap().password, "cur-newer");
        assert_eq!(c.vault.accounts.iter().find(|a| a.id == "b").unwrap().password, "cur-equal");
        cleanup(&s_path);
        cleanup(&c_path);
    }

    #[test]
    fn merge_apply_refused_when_read_only() {
        let s_path = tmp_path("merge-ro-src");
        let mut s = OpenVault::create(s_path.clone(), b"s1", b"s2", fast()).unwrap();
        s.vault.accounts.push(acct_with("z", "x", "p", 100));
        s.save().unwrap();
        let c_path = tmp_path("merge-ro-cur");
        OpenVault::create(c_path.clone(), b"c1", b"c2", fast()).unwrap();

        let source = OpenVault::open_read_only(s_path.clone(), b"s1", b"s2").unwrap();
        let mut c_ro = OpenVault::open_read_only(c_path.clone(), b"c1", b"c2").unwrap();
        // Planning is allowed read-only (it mutates nothing)...
        assert_eq!(c_ro.plan_merge_from(&source).unwrap().new_count(), 1);
        // ...but applying is refused.
        assert!(matches!(c_ro.apply_merge_from(&source), Err(VaultError::ReadOnly)));
        cleanup(&s_path);
        cleanup(&c_path);
    }

    #[test]
    fn merge_skips_record_referencing_locally_tombstoned_doc() {
        // SOURCE has a general document with an attached blob.
        let s_path = tmp_path("merge-tomb-src");
        let mut s = OpenVault::create(s_path.clone(), b"s1", b"s2", fast()).unwrap();
        let doc = write_src("tomb-doc", b"deed-bytes");
        let blob_id = s.add_document("general-documents/deed", "deed.pdf", &doc).unwrap();
        let mut gd = records::GeneralDocument::new().unwrap();
        gd.id = "gd-tomb".into();
        gd.title = "Deed".into();
        gd.file = Some(blob_id.clone());
        gd.updated_at = 100;
        s.vault.general_documents.push(gd);
        s.save().unwrap();

        // First merge into CURRENT: the doc + blob arrive.
        let c_path = tmp_path("merge-tomb-cur");
        let mut c = OpenVault::create(c_path.clone(), b"c1", b"c2", fast()).unwrap();
        {
            let source = OpenVault::open_read_only(s_path.clone(), b"s1", b"s2").unwrap();
            c.apply_merge_from(&source).unwrap();
        }
        assert!(c.has_document(&blob_id));

        // In CURRENT: unlink the record and delete (tombstone) the blob.
        c.vault.general_documents.clear();
        c.save().unwrap();
        c.remove_document(&blob_id).unwrap();
        assert!(c.vault.deleted_docs.contains(&blob_id), "blob is now tombstoned locally");

        // SOURCE bumps the record so recency would re-select it.
        s.vault.general_documents[0].updated_at = 500;
        s.save().unwrap();

        // The re-selected record references a locally-tombstoned doc → blocked, not applied.
        let source = OpenVault::open_read_only(s_path.clone(), b"s1", b"s2").unwrap();
        let plan = c.plan_merge_from(&source).unwrap();
        assert!(plan.records.is_empty(), "record blocked by the tombstoned dependency");
        assert_eq!(plan.skipped.len(), 1);
        assert!(plan.skipped[0].reason.contains("deleted"), "reason explains the block: {:?}", plan.skipped[0].reason);

        let report = c.apply_merge_from(&source).unwrap();
        assert_eq!(report.records_added, 0);
        assert_eq!(report.records_skipped, 1);
        // The tombstone is intact (nothing resurrected), and the vault still reopens.
        assert!(c.vault.deleted_docs.contains(&blob_id));
        drop(c);
        OpenVault::open(c_path.clone(), b"c1", b"c2").unwrap();
        cleanup(&s_path);
        cleanup(&c_path);
    }

    #[test]
    fn merge_rejects_source_with_unsafe_vault_id() {
        // A crafted source whose (attacker-controlled) vault.id carries a bidi/control char
        // must be refused before it can reach the preview or this vault's audit log.
        let s_path = tmp_path("merge-badid-src");
        let mut s = OpenVault::create(s_path.clone(), b"s1", b"s2", fast()).unwrap();
        s.vault.accounts.push(acct_with("x", "u", "p", 5));
        s.save().unwrap();

        let c_path = tmp_path("merge-badid-cur");
        let c = OpenVault::create(c_path.clone(), b"c1", b"c2", fast()).unwrap();

        let mut source = OpenVault::open_read_only(s_path.clone(), b"s1", b"s2").unwrap();
        // Tamper with the in-memory source id (a real crafted vault could carry this).
        source.vault.id = "ab\u{202e}cd".into();
        let err = c.plan_merge_from(&source).unwrap_err();
        assert!(matches!(err, VaultError::Storage(StorageError::Corrupt(_))), "got {err:?}");
        cleanup(&s_path);
        cleanup(&c_path);
    }

    #[test]
    fn merge_reconciles_category_types_into_config_lists() {
        // SOURCE: an account with a NOVEL type+subtype and an asset with a NOVEL type — none
        // present in the destination's editable category lists.
        let s_path = tmp_path("merge-cats-src");
        let mut s = OpenVault::create(s_path.clone(), b"s1", b"s2", fast()).unwrap();
        let mut a = sample_account("alice", "pw");
        a.id = "acct-x".into();
        a.title = "X".into();
        a.owner = "o".into();
        a.account_type = "Brokerage".into();
        a.account_subtype = "Margin".into();
        a.updated_at = 9;
        s.vault.accounts.push(a);
        let mut asset = records::AssetLiability::new().unwrap();
        asset.id = "asset-x".into();
        asset.asset_type = "Crypto".into();
        asset.updated_at = 9;
        s.vault.assets.push(asset);
        s.save().unwrap();

        let c_path = tmp_path("merge-cats-cur");
        let mut c = OpenVault::create(c_path.clone(), b"c1", b"c2", fast()).unwrap();
        // Sanity: the destination's lists do NOT have these types yet.
        assert!(!c.categories().account_type_names().iter().any(|t| t == "Brokerage"));
        assert!(!c.categories().asset.iter().any(|t| t == "Crypto"));

        let source = OpenVault::open_read_only(s_path.clone(), b"s1", b"s2").unwrap();
        // The plan previews the new types that will be added.
        let plan = c.plan_merge_from(&source).unwrap();
        assert_eq!(plan.new_categories.len(), 3, "account type + subtype + asset type: {:?}", plan.new_categories);

        let report = c.apply_merge_from(&source).unwrap();
        assert_eq!(report.categories_added, 3);
        // The types now appear in the editable Config lists + the subtype is under its type.
        assert!(c.categories().account_type_names().iter().any(|t| t == "Brokerage"));
        assert!(c.categories().subtypes_for("Brokerage").iter().any(|s| s == "Margin"));
        assert!(c.categories().asset.iter().any(|t| t == "Crypto"));
        // Idempotent: a re-merge adds nothing more.
        assert!(c.plan_merge_from(&source).unwrap().new_categories.is_empty());
        cleanup(&s_path);
        cleanup(&c_path);
    }

    #[test]
    fn sync_types_from_records_backfills_missing_category_types() {
        let path = tmp_path("sync-types");
        let mut v = OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();
        // Records carrying types NOT in the editable lists (as if from an older import/merge).
        let mut acct = sample_account("u", "p");
        acct.account_type = "Brokerage".into();
        acct.account_subtype = "Margin".into();
        v.vault.accounts.push(acct);
        let mut asset = records::AssetLiability::new().unwrap();
        asset.asset_type = "Crypto".into();
        v.vault.assets.push(asset);
        // A blank type contributes nothing.
        let mut blank = records::AssetLiability::new().unwrap();
        blank.asset_type = "   ".into();
        v.vault.assets.push(blank);
        v.save().unwrap();

        let added = v.sync_types_from_records().unwrap();
        assert_eq!(added, 3, "account type + subtype + asset type");
        assert!(v.categories().account_type_names().iter().any(|t| t == "Brokerage"));
        assert!(v.categories().subtypes_for("Brokerage").iter().any(|s| s == "Margin"));
        assert!(v.categories().asset.iter().any(|t| t == "Crypto"));
        // Idempotent: a second sync adds nothing and writes nothing new.
        assert_eq!(v.sync_types_from_records().unwrap(), 0);

        // Read-only handles refuse.
        drop(v);
        let mut ro = OpenVault::open_read_only(path.clone(), b"a", b"b").unwrap();
        assert!(matches!(ro.sync_types_from_records(), Err(VaultError::ReadOnly)));
        cleanup(&path);
    }

    #[test]
    fn sync_types_from_records_sanitizes_spoofed_category_types() {
        // A record's type field can be UNTRUSTED (delivered via merge/import). sync runs
        // automatically on every writable open, so it must NOT re-inject a raw bidi/zero-width
        // spoofed type into the category list — it must sanitize identically to apply_merge_from.
        let path = tmp_path("sync-spoof");
        let mut v = OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();
        let mut a = records::AssetLiability::new().unwrap();
        a.asset_type = "Bank\u{202e}x".into(); // RIGHT-TO-LEFT OVERRIDE mid-string
        v.vault.assets.push(a);
        let mut acct = sample_account("u", "p");
        acct.account_type = "Cre\u{200b}dit".into(); // ZERO WIDTH SPACE
        v.vault.accounts.push(acct);
        v.sync_types_from_records().unwrap();
        let san_asset = records::display_safe("Bank\u{202e}x");
        let san_acct = records::display_safe("Cre\u{200b}dit");
        assert!(v.vault.categories.asset.iter().any(|x| x.as_str() == san_asset));
        assert!(v.vault.categories.account.iter().any(|x| x.name == san_acct));
        assert!(
            !v.vault.categories.asset.iter().any(|x| x.as_str().contains('\u{202e}')),
            "raw bidi-spoofed asset type must NOT be synced"
        );
        assert!(
            !v.vault.categories.account.iter().any(|x| x.name.contains('\u{200b}')),
            "raw zero-width-spoofed account type must NOT be synced"
        );
        cleanup(&path);
    }

    #[test]
    fn type_usage_helpers_count_live_records_and_sync_never_deletes() {
        let path = tmp_path("type-usage");
        let mut v = OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();
        // Configured entries that NO record uses (as if added then their records deleted).
        v.add_account_type("Unused Bank").unwrap();
        v.add_account_subtype("Unused Bank", "GhostSub").unwrap();
        v.add_asset_type("Unused Asset").unwrap();
        // Records using OTHER types not yet in the lists.
        for u in ["u1", "u2"] {
            let mut a = sample_account(u, "p");
            a.account_type = "Used Bank".into();
            a.account_subtype = "Checking".into();
            v.vault.accounts.push(a);
        }
        let mut asset = records::AssetLiability::new().unwrap();
        asset.asset_type = "Used Asset".into();
        v.vault.assets.push(asset);
        v.save().unwrap();

        // Usage counts reflect live records (case-insensitive); unused entries report 0.
        assert_eq!(v.account_type_usage("Used Bank"), 2);
        assert_eq!(v.account_type_usage("used bank"), 2, "case-insensitive");
        assert_eq!(v.account_subtype_usage("Used Bank", "Checking"), 2);
        assert_eq!(v.asset_type_usage("Used Asset"), 1);
        assert_eq!(v.account_type_usage("Unused Bank"), 0);
        assert_eq!(v.account_subtype_usage("Unused Bank", "GhostSub"), 0);
        assert_eq!(v.asset_type_usage("Unused Asset"), 0);

        // Auto-sync is ADDITIVE: it adds the record-derived types and keeps the unused ones.
        let before_accounts = v.categories().account_type_names();
        let before_assets = v.categories().asset.clone();
        let added = v.sync_types_from_records().unwrap();
        assert_eq!(added, 3, "Used Bank + Checking + Used Asset");
        let after_accounts = v.categories().account_type_names();
        let after_assets = v.categories().asset.clone();
        for t in &before_accounts {
            assert!(after_accounts.contains(t), "sync kept pre-existing account type {t}");
        }
        for t in &before_assets {
            assert!(after_assets.contains(t), "sync kept pre-existing asset type {t}");
        }
        assert!(after_accounts.iter().any(|t| t == "Unused Bank"), "unused type survives sync");
        assert!(after_assets.iter().any(|t| t == "Unused Asset"), "unused asset type survives sync");
        assert!(
            v.categories().subtypes_for("Unused Bank").iter().any(|s| s == "GhostSub"),
            "unused subtype survives sync"
        );
        cleanup(&path);
    }

    #[test]
    fn type_usage_matches_whitespace_padded_record_values() {
        // A record carrying a whitespace-padded type (legacy/imported data) must still count
        // as "in use" of the TRIMMED configured type — otherwise a just-synced type would be
        // mislabeled "unused" and wrongly deletable. usage/sync/remove must agree on the key.
        let path = tmp_path("type-usage-trim");
        let mut v = OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();
        let mut acct = sample_account("u", "p");
        acct.account_type = " Brokerage ".into();
        acct.account_subtype = " Margin ".into();
        v.vault.accounts.push(acct);
        let mut asset = records::AssetLiability::new().unwrap();
        asset.asset_type = " Crypto ".into();
        v.vault.assets.push(asset);
        v.save().unwrap();

        // Sync inserts the TRIMMED entries.
        assert_eq!(v.sync_types_from_records().unwrap(), 3);
        // The trimmed entries are reported IN USE (not "unused"), despite the padded records.
        assert_eq!(v.asset_type_usage("Crypto"), 1);
        assert_eq!(v.account_type_usage("Brokerage"), 1);
        assert_eq!(v.account_subtype_usage("Brokerage", "Margin"), 1);
        // And deletion is correctly refused as in-use rather than silently orphaning the record.
        assert!(matches!(v.remove_asset_type("Crypto"), Ok(CategoryRemoval::InUse(1))));
        assert!(matches!(v.remove_account_subtype("Brokerage", "Margin"), Ok(CategoryRemoval::InUse(1))));
        cleanup(&path);
    }

    /// Build a (source, current) pair where the source has a NEWER general-document record
    /// (same id "gd") referencing a fresh blob, and the current has an OLDER `gd` with no
    /// document. Returns the two vault.pmv paths. Used by the ENOSPC merge tests.
    #[cfg(feature = "fault-injection")]
    fn merge_pair(tag: &str) -> (PathBuf, PathBuf) {
        let s_path = tmp_path(&format!("{tag}-src"));
        {
            let mut s = OpenVault::create(s_path.clone(), b"s1", b"s2", fast()).unwrap();
            let f = write_src(tag, b"document-bytes");
            let blob = s.add_document("general-documents/x", "x.pdf", &f).unwrap();
            let mut gd = records::GeneralDocument::new().unwrap();
            gd.id = "gd".into();
            gd.updated_at = 2000;
            gd.file = Some(blob);
            s.vault.general_documents.push(gd);
            s.save().unwrap();
            fs::remove_file(&f).ok();
        }
        let c_path = tmp_path(&format!("{tag}-cur"));
        {
            let mut c = OpenVault::create(c_path.clone(), b"c1", b"c2", fast()).unwrap();
            let mut gd = records::GeneralDocument::new().unwrap();
            gd.id = "gd".into();
            gd.updated_at = 1000;
            gd.file = None;
            c.vault.general_documents.push(gd);
            c.save().unwrap();
        }
        (s_path, c_path)
    }

    #[cfg(feature = "fault-injection")]
    #[test]
    fn enospc_during_merge_blob_copy_leaves_current_unchanged_and_unpoisoned() {
        let (s_path, c_path) = merge_pair("enospc-merge-blob");
        let source = OpenVault::open_read_only(s_path.clone(), b"s1", b"s2").unwrap();
        let mut c = OpenVault::open(c_path.clone(), b"c1", b"c2").unwrap();
        // The merge must copy the source's blob — make that copy hit a full disk.
        crate::fault::fail_at("volume.write", 1);
        let err = c.apply_merge_from(&source).unwrap_err();
        crate::fault::clear();
        assert!(matches!(err, VaultError::Storage(_)), "blob copy fails cleanly: {err:?}");
        // Phase 1 failed before any record mutation: in-memory record is still the old one,
        // and the handle is NOT poisoned (nothing was committed) — a normal save still works.
        assert_eq!(c.vault.general_documents.iter().find(|g| g.id == "gd").unwrap().updated_at, 1000);
        c.save().expect("handle still writable (not poisoned)");
        drop(c);
        // On disk the older record stands and the vault reopens.
        let re = OpenVault::open(c_path.clone(), b"c1", b"c2").unwrap();
        assert_eq!(re.vault.general_documents.iter().find(|g| g.id == "gd").unwrap().updated_at, 1000);
        cleanup(&s_path);
        cleanup(&c_path);
    }

    #[cfg(feature = "fault-injection")]
    #[test]
    fn enospc_during_merge_save_poisons_handle_and_does_not_persist() {
        let (s_path, c_path) = merge_pair("enospc-merge-save");
        let source = OpenVault::open_read_only(s_path.clone(), b"s1", b"s2").unwrap();
        let mut c = OpenVault::open(c_path.clone(), b"c1", b"c2").unwrap();
        // The blob copy succeeds; the FINAL vault.pmv save hits a full disk.
        crate::fault::fail_at("vault.write", 1);
        let err = c.apply_merge_from(&source).unwrap_err();
        crate::fault::clear();
        assert!(matches!(err, VaultError::Io(_)), "the final save fails: {err:?}");
        // The handle is POISONED so the diverged in-memory (merged) state can never be
        // re-flushed by a later unrelated save (the #0/#3 fix).
        assert!(matches!(c.save(), Err(VaultError::ReadOnly)), "handle poisoned after a failed merge save");
        drop(c);
        // The merge did NOT take on disk (the save failed): the older record stands, and the
        // vault reopens cleanly (the copied blob is a harmless unreferenced orphan).
        let re = OpenVault::open(c_path.clone(), b"c1", b"c2").unwrap();
        assert_eq!(re.vault.general_documents.iter().find(|g| g.id == "gd").unwrap().updated_at, 1000, "merge not persisted");
        cleanup(&s_path);
        cleanup(&c_path);
    }
}
