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

// Sanity bounds for KDF parameters read from an untrusted file header, validated
// *before* the (expensive, memory-hard) key derivation runs (DoS guard).
const MAX_M_COST: u32 = 1 << 20; // 1 GiB, in KiB
const MAX_T_COST: u32 = 64;
const MAX_P_COST: u32 = 16;

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

/// An OS advisory lock on `<dir>/pass-mgr.lock`, held for the lifetime of a
/// writable [`OpenVault`]. The lock is taken on the open file handle, so the
/// kernel releases it when the handle closes — no stale lock file to clean up.
struct WriteLock {
    _file: fs::File,
}

impl WriteLock {
    /// Acquire the single-writer lock for `dir`. Errors with
    /// [`VaultError::Locked`] if another writable session already holds it.
    // `Self` is shorthand for the type being impl'd (here `WriteLock`).
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
        let dir = parent_dir(&path); // `&path` lends the path without giving it away
        fs::create_dir_all(&dir)?;
        harden_dir(&dir);
        // fsync the new vault directory's own entry into its parent, so a power loss
        // right after the first save can't lose the directory that holds vault.pmv.
        sync_parent_dir(&dir);
        // Take the single-writer lock before writing anything into the directory.
        let write_lock = Some(WriteLock::acquire(&dir)?);
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
        // vault.json — pretty for human inspection; the buffer wipes on drop.
        let vault_json = Zeroizing::new(serde_json::to_vec_pretty(&vault)?);
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
        let mut p = 0u32;
        loop {
            let man_path = man_dir.join(format!("manifest.{p}.json"));
            if !man_path.exists() {
                break; // partitions are contiguous from 0
            }
            let entries: Vec<ManifestEntry> = serde_json::from_slice(&read_capped(&man_path, storage::MAX_MANIFEST_SIZE)?)?;
            let vol_dir = vol_root.join(format!("vol.{p}"));
            for e in &entries {
                // The mirror is untrusted input: the blob is read from
                // `vol.<p>/<id>`, so a crafted id containing a path separator or
                // `..` would traverse out of the mirror. Require a plain filename.
                if !is_safe_blob_id(&e.id) {
                    return Err(VaultError::Storage(StorageError::Corrupt(format!("unsafe document id in mirror: {:?}", e.id))));
                }
                // Size-capped + symlink-rejected read (no OOM, no /dev/zero or
                // arbitrary-file read through a planted symlink).
                let bytes = Zeroizing::new(read_capped(&vol_dir.join(&e.id), MAX_DOC_SIZE)?);
                store.put(&e.id, &e.path, &bytes, e.uploaded_at, &key)?;
            }
            p += 1;
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
        let prev = if rotate_ring && depth > 0 { read_capped_vault(&self.path).ok() } else { None };

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
        // `self.storage.ids()` yields only manifest-referenced (live) blobs, so the
        // dead frames left by updates/deletes are dropped here — this is exactly
        // what makes the rewrite double as a volume compaction.
        let mut new_store =
            VolumeStore::open(&staging, write_key, &self.vault.id, self.vault.settings.volume_max_size)?;
        let ids: Vec<String> = self.storage.ids().map(|s| s.to_string()).collect();
        for id in &ids {
            let bytes = self.storage.read(id, &self.key)?; // decrypt under the CURRENT key
            let (path, uploaded_at) = self
                .storage
                .entry(id)
                .map(|e| (e.path.clone(), e.uploaded_at))
                .unwrap_or_default();
            new_store.put(id, &path, &bytes, uploaded_at, write_key)?; // encrypt under the staged key
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

    /// Set the per-partition volume-size cap (bytes, clamped to >= 1). Updates the
    /// saved settings and the live store so the change governs **future**
    /// placement this session, then persists. Existing partitions are untouched.
    pub fn set_volume_max_size(&mut self, bytes: u64) -> Result<(), VaultError> {
        if self.read_only {
            return Err(VaultError::ReadOnly);
        }
        let bytes = bytes.max(1); // shadow `bytes` with a clamped copy (floor of 1)
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
    // `&str` is a borrowed string slice (read-only view); `String` is owned. The
    // `Option<String>` return is `Some(path)` if the id exists, else `None`.
    pub fn doc_path(&self, file_id: &str) -> Option<String> {
        // `.map(|e| e.path.clone())` transforms a `Some(entry)` into `Some(owned_path)`,
        // leaving `None` as `None`. We `.clone()` because `e` is only a borrow.
        self.storage.entry(file_id).map(|e| e.path.clone())
    }

    /// Whether a document id is present in the store.
    pub fn has_document(&self, file_id: &str) -> bool {
        self.storage.contains(file_id)
    }

    // --- Category lists (stored in the vault) --------------------------------

    // Returns a *borrow* (`&TypeLists`) into the vault rather than a copy: the
    // caller may read the category lists but the data stays owned by the vault.
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
pub(crate) fn virtual_path(location: &str, filename: &str) -> String {
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
    !id.is_empty() && id != "." && id != ".." && !id.contains(['/', '\\', '\0'])
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

/// Doc ids referenced by any record (Trust&Will `file`, Asset `statement`).
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

    // Pre-read the candidate bytes (size-capped, small). CRITICAL: the live header is
    // NOT a trusted key-derivation source — a corruption confined to its salt/params
    // would defeat recovery even with a perfect mirror. Derive the key from each
    // DISTINCT *candidate* salt. All same-epoch copies share one salt, so this is ~1
    // Argon2 in practice (and a wrong password still costs ~1, not N), while a
    // candidate whose own header is damaged is covered by trying the next salt.
    // Pair each blob with its SOURCE PATH. `filter_map` drops unreadable candidates,
    // so a bare index into `candidates` would desync (e.g. an unreadable mirror would
    // make a generation-recovery falsely report as a lossless "mirror" recovery). The
    // paired path keeps the mirror-vs-generation label honest.
    let blobs: Vec<(&PathBuf, Vec<u8>)> = candidates.iter().filter_map(|c| read_capped_vault(c).ok().map(|b| (c, b))).collect();
    let mirror = mirror_path(path);
    let mut tried_salts: Vec<[u8; SALT_LEN]> = Vec::new();
    for (_, src) in &blobs {
        let Ok(header) = Header::parse(src) else { continue };
        if tried_salts.contains(&header.salt) {
            continue; // already derived a key for this salt
        }
        tried_salts.push(header.salt);
        let Ok(key) = crypto::derive_key_chained(pw1, pw2, &header.salt, &header.params) else { continue };
        // Try this key against every candidate (mirror first, then generations).
        for (cand_path, raw) in &blobs {
            if let Ok((vault, hdr)) = decode_vault_with_key(raw, &key) {
                // The mirror is normally the same generation as the lost primary, but
                // a crash *between* the primary commit and the (best-effort) mirror
                // write can leave the mirror one generation stale — so we do NOT
                // promise "no data lost", only that it is usually the latest. A
                // generation is definitely older (a surfaced rollback). Either way the
                // user should re-save and refresh backups.
                let notice = if **cand_path == mirror {
                    "The main vault file was unreadable and was recovered from its mirror copy \
                     (normally the latest state — but if a save was interrupted before the \
                     mirror was written, the most recent change may be missing). Re-save, and \
                     refresh your off-device backups.".to_string()
                } else {
                    "The main vault file AND its mirror were unreadable; recovered from an \
                     earlier generation — your most recent change(s) may be lost. Re-save, \
                     and refresh your off-device backups.".to_string()
                };
                return Ok((vault, hdr, key, Some(notice)));
            }
        }
    }
    // No copy decrypted under any candidate-derived key — wrong password, or every
    // copy is also corrupt. Return the live file's original error.
    Err(primary_err)
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
/// (primary/mirror/bak temps) in the vault dir and `.manifest*.tmp` in `manifest/`.
/// Best-effort, writable opens only. The temps are encrypted (no plaintext leak), but
/// sweeping keeps the directory tidy and avoids old-key temps lingering after a rekey.
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
fn write_vault_file(
    path: &Path,
    vault: &Vault,
    key: &Key,
    salt: &[u8; SALT_LEN],
    params: KdfParams,
) -> Result<(), VaultError> {
    // Serialize the vault to JSON bytes (wiped on drop), pick a fresh random nonce,
    // and build the header. `*salt` dereferences the `&[u8; N]` borrow to copy the
    // array by value into the new `Header`.
    let plaintext = Zeroizing::new(serde_json::to_vec(vault)?);
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
    Ok(())
}

/// Replace `live` with `staged` (a directory) if `staged` still exists.
fn replace_dir(live: &Path, staged: &Path) -> Result<(), VaultError> {
    if !staged.exists() {
        return Ok(());
    }
    let old = sibling_old(live); // a temporary ".<name>.old" path next to `live`
    let _ = fs::remove_dir_all(&old); // clear any leftover from a prior crash (best-effort)
    if live.exists() {
        fs::rename(live, &old)?; // move the current dir aside...
    }
    fs::rename(staged, live)?; // ...then move the staged dir into its place
    let _ = fs::remove_dir_all(&old); // drop the old copy (best-effort; harmless if it lingers)
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
    // Don't snapshot a tree mid-rekey: the volume/manifest may be the new key while
    // vault.pmv is still the old one, yielding an unopenable backup. Finish (or
    // discard) the pending rekey by opening with --write first.
    if src_dir.join(REKEY_DIR).exists() {
        return Err(VaultError::RekeyPending);
    }
    // Refuse a symlinked destination directory: an attacker who can write the vault
    // dir could otherwise point the backup into the very tree we are reading, or at
    // arbitrary files the user can write. `symlink_metadata` inspects the link
    // itself (does not follow it). The CLI also validates the dest is outside the
    // vault dir; this is defense-in-depth at the library boundary so every caller is
    // covered. (A non-existent dest is fine — it is created below as a real dir.)
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
    // The initial `.rekey` check is a TOCTOU: a concurrent writer may have STARTED a
    // rekey during the copy window above, so the snapshot could mix an old vault.pmv
    // with partially-swapped volume/manifest dirs. If `.rekey` appeared, discard the
    // partial backup and ask the caller to retry. Best-effort — readers are not
    // lock-isolated from a concurrent writer (§9.16); a rekey that both started and
    // finished within the window is the rare residual case.
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
        if from.is_dir() {
            copy_dir(&from, &to)?; // recurse into subdirectories
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
pub fn write_new_bytes(path: &Path, data: &[u8]) -> Result<(), VaultError> {
    let mut f = create_new_0600(path)?;
    harden_file(path)?;
    // `.and_then(|()| f.sync_all())` chains the fsync onto the write: it runs only
    // if `write_all` returned `Ok(())`, and the whole expression is `Err` if either
    // step failed. On failure: close the file, delete the partial output, return.
    if let Err(e) = f.write_all(data).and_then(|()| f.sync_all()) {
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
        // lossless mirror recovery — the notice must warn of a possible rollback.
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
            notice.contains("earlier generation") || notice.contains("may be lost"),
            "must report a rollback, got: {notice:?}"
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
        fs::write(&stale_primary, b"leaked encrypted temp").unwrap();
        fs::write(&stale_mirror, b"leaked encrypted temp").unwrap();
        {
            let _ = OpenVault::open(path.clone(), b"a", b"b").unwrap(); // writable open sweeps
        }
        assert!(!stale_primary.exists(), "stale primary .tmp swept on writable open");
        assert!(!stale_mirror.exists(), "stale mirror .tmp swept on writable open");
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
        assert!(Header::parse(&header_bytes(MAX_M_COST, MAX_T_COST, MAX_P_COST)).is_ok());
        // One step outside each bound: rejected (kills the `||` and comparison mutants).
        for h in [
            header_bytes(7, 1, 1),
            header_bytes(MAX_M_COST + 1, 1, 1),
            header_bytes(8, 0, 1),
            header_bytes(8, MAX_T_COST + 1, 1),
            header_bytes(8, 1, 0),
            header_bytes(8, 1, MAX_P_COST + 1),
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
}
