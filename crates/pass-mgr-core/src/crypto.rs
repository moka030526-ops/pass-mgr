//! Cryptographic core for pass-mgr.
//!
//! Design:
//! - Master password -> 32-byte key via **Argon2id** (memory-hard KDF) with a
//!   random per-vault salt. KDF parameters are stored in the vault header so the
//!   file stays self-describing and we can raise the cost over time.
//! - Vault bytes are encrypted with **XChaCha20-Poly1305** (AEAD). The 24-byte
//!   nonce is random per write; the **entire vault header — magic, version,
//!   Argon2 parameters, salt, AND the nonce — is fed in as associated data**, so
//!   any tampering with it (a cost-parameter downgrade, a swapped salt, a flipped
//!   nonce) is detected by the Poly1305 tag on decrypt. To make that possible the
//!   nonce is generated first and authenticated via [`encrypt_with_nonce`].
//! - The derived [`Key`] zeroizes its bytes on drop.
//!
//! Rust-reader orientation (this file assumes you may not know Rust):
//! - `//!` at the top of a file is a *module-level doc comment* describing the
//!   whole module; `///` documents the item immediately below it; `//` is an
//!   ordinary inline comment. None of these affect runtime behavior.
//! - Functions return `Result<T, E>` (either an `Ok(T)` value or an `Err(E)`).
//!   The `?` operator after such a call means "if it's an error, stop and
//!   return that error from this function; otherwise unwrap the success value."
//! - `&[u8]` is a *borrowed* read-only view of a byte buffer (a "slice"); the
//!   caller still owns the data, we just look at it. `&` = shared/borrowed.
//! - Secret material is wiped from memory when it goes out of scope (`zeroize`),
//!   which is why several types and locals exist purely to control cleanup.

// `use` brings names from other crates (libraries) into scope, like imports.
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    // `Key as ChaChaKey` renames the imported `Key` so it won't clash with our
    // own `Key` type defined below.
    Key as ChaChaKey, XChaCha20Poly1305, XNonce,
};
// `thiserror` auto-generates boilerplate for our error enum (see below).
use thiserror::Error;
// `Zeroize` is a trait providing `.zeroize()` to overwrite secret bytes with 0.
use zeroize::Zeroize;

// `pub const` = a public, compile-time constant. `usize` is the platform's
// unsigned integer type used for sizes/lengths.
pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 24;
pub const KEY_LEN: usize = 32;

// An `enum` is a type that is exactly one of a fixed set of variants — here, the
// kinds of failure this module can produce. `#[derive(...)]` auto-generates trait
// implementations: `Error` (via thiserror, using the `#[error("...")]` strings as
// the human-readable message) and `Debug` (a developer-facing printout).
#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("invalid Argon2 parameters")]
    KdfParams,
    #[error("key derivation failed")]
    KdfDerive,
    #[error("encryption failed")]
    Encrypt,
    #[error("decryption failed — wrong password or corrupted vault")]
    Decrypt,
    #[error("OS random source failed: {0}")]
    Random(String),
    #[error("nonce must be {NONCE_LEN} bytes, got {0}")]
    BadNonce(usize),
}

/// Tunable Argon2id cost parameters. Stored in the vault header so an existing
/// vault always decrypts with the parameters it was written with.
// A `struct` groups named fields into one value (like a record/class with no
// methods of its own here). Derived traits: `Debug` (printable for diagnostics),
// `Clone`+`Copy` (this value is small/plain, so it is duplicated by simple
// bitwise copy on assignment instead of being "moved"), `PartialEq`+`Eq`
// (enables `==` comparison between two `KdfParams`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    /// Memory cost in KiB.
    pub m_cost: u32,
    /// Iterations (time cost).
    pub t_cost: u32,
    /// Degree of parallelism (lanes).
    pub p_cost: u32,
}

// `impl Trait for Type` implements an interface (`trait`) for a type. `Default`
// is the standard trait for "the default value of this type", obtained via
// `KdfParams::default()`. `Self` inside the block is shorthand for `KdfParams`.
impl Default for KdfParams {
    /// OWASP-aligned defaults: 64 MiB, 3 passes, 1 lane. Interactive-friendly on
    /// a laptop while staying expensive for offline cracking.
    fn default() -> Self {
        KdfParams {
            m_cost: 64 * 1024,
            t_cost: 3,
            p_cost: 1,
        }
    }
}

impl KdfParams {
    /// Memory-cost floor (KiB).
    pub const MIN_M_COST: u32 = 8;
    /// Memory-cost ceiling (KiB) = **512 MiB**. The params live in the header and
    /// must be used to DERIVE the key *before* the AEAD tag can reject a tampered
    /// header, so an attacker who rewrites the header (or plants a redundancy
    /// candidate) can force this much memory-hard work per open. The ceiling is set
    /// well below "OOM the process" so a maxed header is a clean error, not a kill —
    /// while staying 8× above the 64 MiB default. (Was 1 GiB; lowered per audit.)
    pub const MAX_M_COST: u32 = 512 * 1024;
    /// Iteration (time-cost) ceiling. Far above the default of 3.
    pub const MAX_T_COST: u32 = 16;
    /// Parallelism (lanes) ceiling.
    pub const MAX_P_COST: u32 = 16;

    /// Reject parameters outside the sane bounds above. Called on BOTH the read path
    /// (`Header::parse`, a pre-derivation DoS guard) AND the write paths
    /// (`create`/`import_tree`) so a vault can never be WRITTEN with params the reader
    /// would later refuse — which would otherwise make it permanently unopenable.
    pub fn validate(&self) -> Result<(), CryptoError> {
        if self.m_cost < Self::MIN_M_COST
            || self.m_cost > Self::MAX_M_COST
            || self.t_cost < 1
            || self.t_cost > Self::MAX_T_COST
            || self.p_cost < 1
            || self.p_cost > Self::MAX_P_COST
        {
            return Err(CryptoError::KdfParams);
        }
        Ok(())
    }
}

/// A derived symmetric key. The key bytes live on the heap and their page(s)
/// are **memory-locked** (`mlock` on Unix, `VirtualLock` on Windows) so the OS
/// will not page them to swap, where a plaintext copy could survive on disk
/// (see `docs/DESIGN.md` §9.6). The bytes are wiped, then unlocked, on drop.
pub struct Key {
    // `Box<T>` is an owning pointer to a heap-allocated `T`; here the `T` is a
    // fixed-size array of 32 bytes (`[u8; KEY_LEN]`). Heap allocation gives the
    // key a stable address we can memory-lock.
    bytes: Box<[u8; KEY_LEN]>,
    /// Held for its lifetime; unlocks the page(s) when dropped. `None` if the OS
    /// refused the lock (then the key is still usable, just not swap-protected).
    // `Option<T>` is either `Some(value)` or `None` (Rust's null-free "maybe").
    // The leading `_` in `_lock` tells the compiler we never read this field; we
    // keep it only so its cleanup (unlocking the page) runs when `Key` is dropped.
    // Gated behind the `mlock` feature; absent in the mobile build (no swap budget).
    #[cfg(feature = "mlock")]
    _lock: Option<region::LockGuard>,
}

// Methods of `Key`. `fn` with no `pub` keyword is private to this module.
impl Key {
    // Takes ownership of a 32-byte array (it is *moved* in) and wraps it in a Key.
    fn new(bytes: [u8; KEY_LEN]) -> Key {
        // Move the array onto the heap behind a `Box`.
        let boxed = Box::new(bytes);
        // Pin the page(s) holding the key. Best-effort: a failure (e.g. a tight
        // RLIMIT_MEMLOCK) leaves the key working but unprotected from swap.
        // `region::lock(...)` returns a `Result`; `.ok()` converts it to an
        // `Option` (discarding the error), so a failed lock just yields `None`.
        // Gated behind `mlock`: in the mobile build there is no lock to take (the
        // OS grants apps no mlock budget), so the field and this call disappear.
        #[cfg(feature = "mlock")]
        let _lock = region::lock(boxed.as_ref().as_ptr(), KEY_LEN).ok();
        // Construct and return the struct (last expression with no `;` is the
        // return value in Rust).
        Key {
            bytes: boxed,
            #[cfg(feature = "mlock")]
            _lock,
        }
    }

    // `&self` = a shared (read-only) borrow of this Key; the method can read the
    // key but cannot modify or take ownership of it. Builds the AEAD cipher object.
    fn cipher(&self) -> XChaCha20Poly1305 {
        // `from_slice` reinterprets our 32 bytes as the cipher's key type.
        let key = ChaChaKey::from_slice(self.bytes.as_ref());
        XChaCha20Poly1305::new(key)
    }

    /// The raw 32 key bytes. Crate-private: only used to seed the second pass of
    /// the chained two-password derivation (see [`derive_key_chained`]). `k1`
    /// itself is zeroized when dropped at the end of that function.
    // `pub(crate)` = visible anywhere in this crate (this program) but not to
    // outside code. Returns `&[u8]`: a borrowed view of the bytes — the caller
    // gets to *look* at the key without copying or owning it.
    pub(crate) fn as_bytes(&self) -> &[u8] {
        self.bytes.as_ref()
    }
}

// `Drop` is the destructor trait: `drop` runs automatically when a `Key` value
// goes out of scope. We use it to wipe the secret. Fields are dropped after this
// body in declaration order, so `bytes` is wiped here, then `_lock` unlocks.
impl Drop for Key {
    // `&mut self` = an exclusive (mutable) borrow, required because we overwrite
    // the bytes. You cannot call this directly; the compiler inserts the call.
    fn drop(&mut self) {
        // Wipe before the lock guard drops (which unlocks the page).
        //
        // NOTE: mutation testing flags this `drop` body as an un-killed mutant
        // (replacing it with a no-op still passes the suite). That is an inherent
        // limit, not a gap: confirming a destructor wiped its bytes means reading
        // memory after the value is gone, which is use-after-free — undefined
        // behavior, and impossible here since the crate is `#![forbid(unsafe_code)]`.
        // The behavior is exercised (keys are dropped throughout the tests) and the
        // zeroize call is a well-reviewed one-liner; see DESIGN §9.6.
        // `self.bytes[..]` takes the whole array as a slice; `.zeroize()` (from
        // the Zeroize trait) overwrites every byte with 0 and resists the
        // compiler optimizing the wipe away.
        self.bytes[..].zeroize();
    }
}

/// Fill a fresh `[u8; N]` from the operating-system CSPRNG.
// `<const N: usize>` is a *const generic*: the caller picks the array length `N`
// at the call site (e.g. `random_bytes::<24>()`), and one function serves all
// sizes. Returns `Result`, since the OS random source can theoretically fail.
pub fn random_bytes<const N: usize>() -> Result<[u8; N], CryptoError> {
    // `mut` marks `buf` as mutable so `getrandom::fill` can write into it.
    let mut buf = [0u8; N];
    // `&mut buf` lends the buffer out mutably to be filled. `.map_err(...)`
    // converts any error into our `CryptoError` type; the `|e| ...` is a closure
    // (an inline anonymous function taking the error `e`). The trailing `?` then
    // returns early on error. If we reach the next line, the fill succeeded.
    getrandom::fill(&mut buf).map_err(|e| CryptoError::Random(e.to_string()))?;
    Ok(buf)
}

/// Derive the vault key from a master password + salt under the given parameters.
// All three parameters are borrowed (`&`): this function reads them but does not
// take ownership, so the caller keeps and reuses its password/salt/params.
pub fn derive_key(
    password: &[u8],
    salt: &[u8],
    params: &KdfParams,
) -> Result<Key, CryptoError> {
    let argon = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        // `Some(KEY_LEN)` requests a 32-byte output. `Params::new(...)` returns a
        // `Result`; `.map_err(|_| ...)?` discards the original error (the `_`
        // ignores it), substitutes our `KdfParams` error, and `?` returns early
        // if construction failed.
        Params::new(params.m_cost, params.t_cost, params.p_cost, Some(KEY_LEN))
            .map_err(|_| CryptoError::KdfParams)?,
    );
    // A mutable local buffer for Argon2 to write the derived key into.
    let mut key = [0u8; KEY_LEN];
    argon
        // `&mut key` lends the buffer mutably so it can be filled in place.
        .hash_password_into(password, salt, &mut key)
        .map_err(|_| CryptoError::KdfDerive)?;
    // `key` is `Copy`, so the bytes copied into `Key` leave a copy in this local
    // buffer too; wipe it explicitly (the copy inside `Key` is what we return).
    let derived = Key::new(key);
    key.zeroize();
    Ok(derived)
}

/// Derive the vault key from **two** passwords entered sequentially (req. 9).
///
/// The derivation is chained so both secrets are required and neither can be
/// verified independently of the other:
/// ```text
///   k1  = Argon2id(pw1, salt1, params)   // 32 bytes
///   key = Argon2id(pw2, salt = k1, params)
/// ```
/// `k1` is dropped (and thus zeroized) when this function returns. `salt1` is
/// the random per-vault salt stored in the file header. See `docs/DESIGN.md`
/// §5.2 for the security rationale and caveats.
pub fn derive_key_chained(
    pw1: &[u8],
    pw2: &[u8],
    salt1: &[u8],
    params: &KdfParams,
) -> Result<Key, CryptoError> {
    // First pass; `?` returns early if it fails. `k1` is a `Key`, so it will be
    // automatically wiped (its `Drop`) when this function returns.
    let k1 = derive_key(pw1, salt1, params)?;
    // k1's 32 bytes (>= Argon2's 8-byte minimum) become the salt of the 2nd pass.
    // No `;` and no `return`: this expression's result is what the function returns.
    derive_key(pw2, k1.as_bytes(), params)
}

/// Encrypt `plaintext` with a freshly generated nonce, binding `aad` into the
/// authentication tag. Returns `(nonce, ciphertext)`. Used for the document
/// archive, whose nonce is stored alongside the ciphertext and bound implicitly
/// (the AAD there is the vault-instance id).
// `&Key` borrows the key (no copy of the secret is made). The return type is a
// `Result` wrapping a *tuple* `(nonce, ciphertext)`: the fixed-size nonce array
// plus a `Vec<u8>` (a growable, heap-allocated byte vector — the ciphertext).
pub fn encrypt(
    key: &Key,
    plaintext: &[u8],
    aad: &[u8],
) -> Result<([u8; NONCE_LEN], Vec<u8>), CryptoError> {
    let nonce_bytes = random_bytes::<NONCE_LEN>()?;
    // `.map(|ct| ...)` transforms the `Ok` value: the closure receives the
    // ciphertext `ct` and pairs it with the nonce. On error, `map` passes the
    // error through unchanged.
    encrypt_with_nonce(key, &nonce_bytes, plaintext, aad).map(|ct| (nonce_bytes, ct))
}

/// Encrypt `plaintext` under a **caller-supplied** nonce, binding `aad` into the
/// authentication tag. This lets the caller place the nonce into the header and
/// then authenticate that whole header (nonce included) as `aad` — closing any
/// gap for an undetected nonce/salt/parameter swap. The caller must supply a
/// fresh, unique nonce per encryption (we always pass a random one).
// `nonce: &[u8; NONCE_LEN]` is a borrow of an exactly-24-byte array, so the wrong
// length is impossible at compile time (unlike `decrypt` below, which takes a
// runtime-sized slice and must check the length itself).
pub fn encrypt_with_nonce(
    key: &Key,
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let xnonce = XNonce::from_slice(nonce);
    key.cipher()
        // `Payload { msg, aad }` bundles the plaintext with the associated data
        // that gets authenticated (but not encrypted).
        .encrypt(xnonce, Payload { msg: plaintext, aad })
        .map_err(|_| CryptoError::Encrypt)
}

/// Decrypt `ciphertext`, verifying the tag against `aad`. Returns the plaintext
/// or [`CryptoError::Decrypt`] for a wrong password / corrupted or tampered file.
// Here `nonce: &[u8]` is a runtime-sized slice (length not known at compile
// time), so we validate it before use.
pub fn decrypt(
    key: &Key,
    nonce: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    // Explicit guard: reject a wrong-length nonce with a clear error instead of
    // panicking in `from_slice`. `return Err(...)` exits the function early.
    if nonce.len() != NONCE_LEN {
        return Err(CryptoError::BadNonce(nonce.len()));
    }
    // Shadowing: rebind the name `nonce` to the cipher's nonce type. The original
    // `&[u8]` is no longer reachable; the new binding reuses the name.
    let nonce = XNonce::from_slice(nonce);
    key.cipher()
        // Verifies the Poly1305 tag over ciphertext+aad; any mismatch (wrong
        // password, tampering) becomes `CryptoError::Decrypt`.
        .decrypt(nonce, Payload { msg: ciphertext, aad })
        .map_err(|_| CryptoError::Decrypt)
}

// `#[cfg(test)]` is *conditional compilation*: this whole `tests` module is only
// compiled when running the test suite, never in the shipped binary. Inside:
// - `#[test]` marks a function as a test the runner executes.
// - `use super::*;` imports everything from the parent module (this file).
// - `b"..."` is a byte-string literal (`&[u8]`), not text.
// - `.unwrap()` extracts the `Ok`/`Some` value but *panics* (aborts the test) if
//   it's an `Err`/`None`. Fine in tests: a panic = a failed test, and these
//   inputs are known-good.
// - `assert!(cond)` fails the test if `cond` is false; `assert_eq!`/`assert_ne!`
//   check equality/inequality; `matches!(x, Pattern)` is true if `x` matches the
//   given enum pattern.
#[cfg(test)]
mod tests {
    use super::*;

    // Cheap params so the test suite stays fast; production uses the defaults.
    fn fast() -> KdfParams {
        KdfParams { m_cost: 256, t_cost: 1, p_cost: 1 }
    }

    #[test]
    fn round_trip() {
        let key = derive_key(b"correct horse", b"sixteen-byte-slt", &fast()).unwrap();
        let aad = b"header-bytes";
        let (nonce, ct) = encrypt(&key, b"top secret", aad).unwrap();
        let pt = decrypt(&key, &nonce, &ct, aad).unwrap();
        assert_eq!(pt, b"top secret");
    }

    #[test]
    fn wrong_password_fails() {
        let salt = b"sixteen-byte-slt";
        let good = derive_key(b"right", salt, &fast()).unwrap();
        let bad = derive_key(b"wrong", salt, &fast()).unwrap();
        let (nonce, ct) = encrypt(&good, b"secret", b"aad").unwrap();
        assert!(matches!(
            decrypt(&bad, &nonce, &ct, b"aad"),
            Err(CryptoError::Decrypt)
        ));
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let key = derive_key(b"pw", b"sixteen-byte-slt", &fast()).unwrap();
        let (nonce, mut ct) = encrypt(&key, b"secret", b"aad").unwrap();
        ct[0] ^= 0xff;
        assert!(decrypt(&key, &nonce, &ct, b"aad").is_err());
    }

    #[test]
    fn encrypt_with_nonce_round_trips_and_binds_nonce() {
        let key = derive_key(b"pw", b"sixteen-byte-slt", &fast()).unwrap();
        let nonce = [7u8; NONCE_LEN];
        let aad = b"full-header-bytes";
        let ct = encrypt_with_nonce(&key, &nonce, b"secret", aad).unwrap();
        assert_eq!(decrypt(&key, &nonce, &ct, aad).unwrap(), b"secret");
        // A different nonce (or different aad) must not verify.
        assert!(decrypt(&key, &[9u8; NONCE_LEN], &ct, aad).is_err());
        assert!(decrypt(&key, &nonce, &ct, b"other-header").is_err());
    }

    #[test]
    fn tampered_aad_fails() {
        // Changing the header (aad) must invalidate the tag.
        let key = derive_key(b"pw", b"sixteen-byte-slt", &fast()).unwrap();
        let (nonce, ct) = encrypt(&key, b"secret", b"header-v1").unwrap();
        assert!(decrypt(&key, &nonce, &ct, b"header-v2").is_err());
    }

    #[test]
    fn derivation_is_deterministic() {
        let a = derive_key(b"pw", b"sixteen-byte-slt", &fast()).unwrap();
        let b = derive_key(b"pw", b"sixteen-byte-slt", &fast()).unwrap();
        assert_eq!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn random_bytes_differ() {
        let a = random_bytes::<NONCE_LEN>().unwrap();
        let b = random_bytes::<NONCE_LEN>().unwrap();
        assert_ne!(a, b, "two random nonces should not collide");
    }

    #[test]
    fn chained_round_trip() {
        let salt = b"sixteen-byte-slt";
        let key = derive_key_chained(b"first", b"second", salt, &fast()).unwrap();
        let (nonce, ct) = encrypt(&key, b"two-pw secret", b"aad").unwrap();
        let pt = decrypt(&key, &nonce, &ct, b"aad").unwrap();
        assert_eq!(pt, b"two-pw secret");
    }

    #[test]
    fn chained_requires_both_passwords() {
        let salt = b"sixteen-byte-slt";
        let good = derive_key_chained(b"first", b"second", salt, &fast()).unwrap();
        // Either password wrong -> different key.
        let bad_pw1 = derive_key_chained(b"FIRST", b"second", salt, &fast()).unwrap();
        let bad_pw2 = derive_key_chained(b"first", b"SECOND", salt, &fast()).unwrap();
        assert_ne!(good.as_bytes(), bad_pw1.as_bytes());
        assert_ne!(good.as_bytes(), bad_pw2.as_bytes());
    }

    #[test]
    fn chained_is_order_sensitive() {
        // Swapping the two passwords must yield a different key.
        let salt = b"sixteen-byte-slt";
        let ab = derive_key_chained(b"alpha", b"beta", salt, &fast()).unwrap();
        let ba = derive_key_chained(b"beta", b"alpha", salt, &fast()).unwrap();
        assert_ne!(ab.as_bytes(), ba.as_bytes());
    }

    #[test]
    fn chained_is_deterministic() {
        let salt = b"sixteen-byte-slt";
        let a = derive_key_chained(b"x", b"y", salt, &fast()).unwrap();
        let b = derive_key_chained(b"x", b"y", salt, &fast()).unwrap();
        assert_eq!(a.as_bytes(), b.as_bytes());
    }
}
