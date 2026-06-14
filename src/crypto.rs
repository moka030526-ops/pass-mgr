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

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    Key as ChaChaKey, XChaCha20Poly1305, XNonce,
};
use thiserror::Error;
use zeroize::Zeroize;

pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 24;
pub const KEY_LEN: usize = 32;

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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    /// Memory cost in KiB.
    pub m_cost: u32,
    /// Iterations (time cost).
    pub t_cost: u32,
    /// Degree of parallelism (lanes).
    pub p_cost: u32,
}

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

/// A derived symmetric key. The key bytes live on the heap and their page(s)
/// are **memory-locked** (`mlock` on Unix, `VirtualLock` on Windows) so the OS
/// will not page them to swap, where a plaintext copy could survive on disk
/// (see `docs/DESIGN.md` §9.6). The bytes are wiped, then unlocked, on drop.
pub struct Key {
    bytes: Box<[u8; KEY_LEN]>,
    /// Held for its lifetime; unlocks the page(s) when dropped. `None` if the OS
    /// refused the lock (then the key is still usable, just not swap-protected).
    _lock: Option<region::LockGuard>,
}

impl Key {
    fn new(bytes: [u8; KEY_LEN]) -> Key {
        let boxed = Box::new(bytes);
        // Pin the page(s) holding the key. Best-effort: a failure (e.g. a tight
        // RLIMIT_MEMLOCK) leaves the key working but unprotected from swap.
        let lock = region::lock(boxed.as_ref().as_ptr(), KEY_LEN).ok();
        Key { bytes: boxed, _lock: lock }
    }

    fn cipher(&self) -> XChaCha20Poly1305 {
        let key = ChaChaKey::from_slice(self.bytes.as_ref());
        XChaCha20Poly1305::new(key)
    }

    /// The raw 32 key bytes. Crate-private: only used to seed the second pass of
    /// the chained two-password derivation (see [`derive_key_chained`]). `k1`
    /// itself is zeroized when dropped at the end of that function.
    pub(crate) fn as_bytes(&self) -> &[u8] {
        self.bytes.as_ref()
    }
}

impl Drop for Key {
    fn drop(&mut self) {
        // Wipe before the lock guard drops (which unlocks the page).
        self.bytes[..].zeroize();
    }
}

/// Fill a fresh `[u8; N]` from the operating-system CSPRNG.
pub fn random_bytes<const N: usize>() -> Result<[u8; N], CryptoError> {
    let mut buf = [0u8; N];
    getrandom::fill(&mut buf).map_err(|e| CryptoError::Random(e.to_string()))?;
    Ok(buf)
}

/// Derive the vault key from a master password + salt under the given parameters.
pub fn derive_key(
    password: &[u8],
    salt: &[u8],
    params: &KdfParams,
) -> Result<Key, CryptoError> {
    let argon = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(params.m_cost, params.t_cost, params.p_cost, Some(KEY_LEN))
            .map_err(|_| CryptoError::KdfParams)?,
    );
    let mut key = [0u8; KEY_LEN];
    argon
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
    let k1 = derive_key(pw1, salt1, params)?;
    // k1's 32 bytes (>= Argon2's 8-byte minimum) become the salt of the 2nd pass.
    derive_key(pw2, k1.as_bytes(), params)
}

/// Encrypt `plaintext` with a freshly generated nonce, binding `aad` into the
/// authentication tag. Returns `(nonce, ciphertext)`. Used for the document
/// archive, whose nonce is stored alongside the ciphertext and bound implicitly
/// (the AAD there is the vault-instance id).
pub fn encrypt(
    key: &Key,
    plaintext: &[u8],
    aad: &[u8],
) -> Result<([u8; NONCE_LEN], Vec<u8>), CryptoError> {
    let nonce_bytes = random_bytes::<NONCE_LEN>()?;
    encrypt_with_nonce(key, &nonce_bytes, plaintext, aad).map(|ct| (nonce_bytes, ct))
}

/// Encrypt `plaintext` under a **caller-supplied** nonce, binding `aad` into the
/// authentication tag. This lets the caller place the nonce into the header and
/// then authenticate that whole header (nonce included) as `aad` — closing any
/// gap for an undetected nonce/salt/parameter swap. The caller must supply a
/// fresh, unique nonce per encryption (we always pass a random one).
pub fn encrypt_with_nonce(
    key: &Key,
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let xnonce = XNonce::from_slice(nonce);
    key.cipher()
        .encrypt(xnonce, Payload { msg: plaintext, aad })
        .map_err(|_| CryptoError::Encrypt)
}

/// Decrypt `ciphertext`, verifying the tag against `aad`. Returns the plaintext
/// or [`CryptoError::Decrypt`] for a wrong password / corrupted or tampered file.
pub fn decrypt(
    key: &Key,
    nonce: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if nonce.len() != NONCE_LEN {
        return Err(CryptoError::BadNonce(nonce.len()));
    }
    let nonce = XNonce::from_slice(nonce);
    key.cipher()
        .decrypt(nonce, Payload { msg: ciphertext, aad })
        .map_err(|_| CryptoError::Decrypt)
}

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
