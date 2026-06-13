//! Built-in password generator.
//!
//! Uses the OS CSPRNG (via [`crate::crypto::random_bytes`]) with rejection
//! sampling so character selection has no modulo bias. When the requested
//! length allows, at least one character from every enabled class is
//! guaranteed, then the result is shuffled.

use crate::crypto::{random_bytes, CryptoError};

const LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &[u8] = b"0123456789";
// Deliberately excludes quotes/backslash/space to stay shell- and form-safe.
const SYMBOLS: &[u8] = b"!@#$%^&*()-_=+[]{};:,.<>?/";

#[derive(Debug, Clone, Copy)]
pub struct GenOptions {
    pub length: usize,
    pub lowercase: bool,
    pub uppercase: bool,
    pub digits: bool,
    pub symbols: bool,
}

impl Default for GenOptions {
    fn default() -> Self {
        GenOptions {
            length: 20,
            lowercase: true,
            uppercase: true,
            digits: true,
            symbols: true,
        }
    }
}

impl GenOptions {
    fn classes(&self) -> Vec<&'static [u8]> {
        let mut v = Vec::new();
        if self.lowercase {
            v.push(LOWER);
        }
        if self.uppercase {
            v.push(UPPER);
        }
        if self.digits {
            v.push(DIGITS);
        }
        if self.symbols {
            v.push(SYMBOLS);
        }
        v
    }
}

#[derive(Debug, thiserror::Error)]
pub enum GenError {
    #[error("at least one character class must be enabled")]
    NoClasses,
    #[error("length must be greater than zero")]
    ZeroLength,
    #[error(transparent)]
    Random(#[from] CryptoError),
}

/// Draw a uniformly-distributed index in `0..n` from the OS CSPRNG using
/// rejection sampling (no modulo bias). Panics only if `n == 0`.
fn uniform(n: usize) -> Result<usize, CryptoError> {
    debug_assert!(n > 0);
    let n = n as u64;
    // Largest multiple of n that fits in u32's range; reject anything above it.
    let zone = ((u64::from(u32::MAX) + 1) / n) * n;
    loop {
        let r = u64::from(u32::from_le_bytes(random_bytes::<4>()?));
        if r < zone {
            return Ok((r % n) as usize);
        }
    }
}

/// Generate a password according to `opts`.
pub fn generate(opts: &GenOptions) -> Result<String, GenError> {
    if opts.length == 0 {
        return Err(GenError::ZeroLength);
    }
    let classes = opts.classes();
    if classes.is_empty() {
        return Err(GenError::NoClasses);
    }

    let mut out: Vec<u8> = Vec::with_capacity(opts.length);

    // Guarantee one char from each class when there's room.
    if opts.length >= classes.len() {
        for class in &classes {
            out.push(class[uniform(class.len())?]);
        }
    }

    // Fill the remainder from the union of all enabled characters.
    let pool: Vec<u8> = classes.iter().flat_map(|c| c.iter().copied()).collect();
    while out.len() < opts.length {
        out.push(pool[uniform(pool.len())?]);
    }

    // Fisher-Yates shuffle so guaranteed chars aren't stuck at the front.
    for i in (1..out.len()).rev() {
        let j = uniform(i + 1)?;
        out.swap(i, j);
    }

    // All bytes are ASCII from the constant tables, so this is always valid UTF-8.
    Ok(String::from_utf8(out).expect("charset is ASCII"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn respects_length() {
        let opts = GenOptions { length: 32, ..Default::default() };
        assert_eq!(generate(&opts).unwrap().len(), 32);
    }

    #[test]
    fn only_selected_classes() {
        let opts = GenOptions {
            length: 64,
            lowercase: false,
            uppercase: false,
            digits: true,
            symbols: false,
        };
        let pw = generate(&opts).unwrap();
        assert!(pw.bytes().all(|b| b.is_ascii_digit()));
    }

    #[test]
    fn guarantees_each_class_when_room() {
        let opts = GenOptions { length: 8, ..Default::default() };
        let pw = generate(&opts).unwrap();
        assert!(pw.bytes().any(|b| b.is_ascii_lowercase()));
        assert!(pw.bytes().any(|b| b.is_ascii_uppercase()));
        assert!(pw.bytes().any(|b| b.is_ascii_digit()));
        assert!(pw.bytes().any(|b| SYMBOLS.contains(&b)));
    }

    #[test]
    fn rejects_no_classes() {
        let opts = GenOptions {
            length: 10,
            lowercase: false,
            uppercase: false,
            digits: false,
            symbols: false,
        };
        assert!(matches!(generate(&opts), Err(GenError::NoClasses)));
    }

    #[test]
    fn rejects_zero_length() {
        let opts = GenOptions { length: 0, ..Default::default() };
        assert!(matches!(generate(&opts), Err(GenError::ZeroLength)));
    }

    #[test]
    fn uniform_in_range() {
        for _ in 0..1000 {
            assert!(uniform(7).unwrap() < 7);
        }
    }
}
