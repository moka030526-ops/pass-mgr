//! Built-in password generator.
//!
//! Uses the OS CSPRNG (via [`crate::crypto::random_bytes`]) with rejection
//! sampling so character selection has no modulo bias. When the requested
//! length allows, at least one character from every enabled class is
//! guaranteed, then the result is shuffled.
//!
//! Rust orientation for non-Rust readers:
//! - `//!` lines are *module-level* documentation (they describe this whole
//!   file); `///` documents the item that immediately follows it; `//` is an
//!   ordinary inline comment.
//! - A "CSPRNG" is a cryptographically secure random number generator.
//! - "Rejection sampling" / "modulo bias": naively doing `random % n` makes
//!   some indices slightly more likely than others. We discard out-of-range
//!   draws instead so every index is equally likely (see `uniform` below).

// `use` brings names into scope (like an import). The `{a, b}` form imports
// two items from the same module: `random_bytes` (a function) and `CryptoError`
// (an error type) from this crate's `crypto` module. `crate::` means "rooted at
// this project", not an external dependency.
use crate::crypto::{random_bytes, CryptoError};

// `const` is a compile-time constant. `&[u8]` is a "byte slice": a read-only
// view (shared borrow, the `&`) into a sequence of bytes (`u8` = unsigned 8-bit).
// The `b"..."` prefix makes a byte-string literal (raw bytes, not a text String).
// These four tables are the allowed characters per category.
const LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &[u8] = b"0123456789";
// Deliberately excludes quotes/backslash/space to stay shell- and form-safe.
const SYMBOLS: &[u8] = b"!@#$%^&*()-_=+[]{};:,.<>?/";

// `#[derive(...)]` auto-generates standard method implementations for this type:
//   Debug -> can be printed for debugging; Clone -> can be duplicated explicitly;
//   Copy  -> cheap to copy implicitly (so passing it around does NOT "move"/
//             consume the original). A type may be Copy only if all its fields are.
// `pub struct` declares a public record type (a bundle of named fields).
// `usize` is an unsigned integer sized for the platform (used for lengths/indices).
#[derive(Debug, Clone, Copy)]
pub struct GenOptions {
    pub length: usize,
    pub lowercase: bool,
    pub uppercase: bool,
    pub digits: bool,
    pub symbols: bool,
}

// `impl Trait for Type` provides an implementation of a trait (an interface)
// for a type. `Default` is the standard trait for "give me a sensible default
// value"; implementing it lets callers write `GenOptions::default()` and use the
// `..Default::default()` shorthand (seen in the tests). `Self` is shorthand for
// the type being implemented (here `GenOptions`).
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

// An inherent `impl` block adds methods directly to the type (not via a trait).
impl GenOptions {
    // `&self` is a shared (read-only) borrow of the GenOptions instance: the
    // method can read its fields but not modify or consume it. The return type
    // `Vec<&'static [u8]>` is a growable list (`Vec`) of byte slices; `'static`
    // is a lifetime meaning "lives for the entire program", true here because the
    // slices point at the `const` tables above, which never go away.
    fn classes(&self) -> Vec<&'static [u8]> {
        // `let mut v` declares a mutable variable; without `mut` it'd be
        // read-only. `Vec::new()` makes an empty list.
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
        // A trailing expression with no semicolon is the return value (Rust has
        // implicit returns). This hands the assembled list back to the caller.
        v
    }
}

// An `enum` is a "tagged union": a value that is exactly one of several named
// variants. This is the error type returned when generation fails.
// `thiserror::Error` is a derive macro (from the `thiserror` crate) that builds
// the boilerplate to make this a proper error type; the `#[error("...")]`
// attributes define each variant's human-readable message.
#[derive(Debug, thiserror::Error)]
pub enum GenError {
    // No character class was enabled.
    #[error("at least one character class must be enabled")]
    NoClasses,
    // Requested length was zero.
    #[error("length must be greater than zero")]
    ZeroLength,
    // Wraps an underlying CryptoError. `#[from]` auto-generates a conversion so a
    // `CryptoError` turns into this variant automatically — that is what lets the
    // `?` operator (used later) propagate randomness failures with no extra code.
    // `transparent` means this variant reuses the inner error's message verbatim.
    #[error(transparent)]
    Random(#[from] CryptoError),
}

/// Draw a uniformly-distributed index in `0..n` from the OS CSPRNG using
/// rejection sampling (no modulo bias). Panics only if `n == 0`.
//
// Return type `Result<usize, CryptoError>`: a value that is either `Ok(index)`
// on success or `Err(CryptoError)` on failure. Callers must handle both — Rust
// has no silent failure here. `0..n` is the half-open range 0,1,...,n-1.
fn uniform(n: usize) -> Result<usize, CryptoError> {
    // `debug_assert!` checks a condition only in debug builds; it documents the
    // precondition (n must be > 0) and would panic if violated during testing.
    debug_assert!(n > 0);
    // Shadowing: re-declare `n` with the same name but a new type (`u64`, a
    // 64-bit unsigned int). `as u64` is an explicit numeric cast. The old
    // `usize` `n` is now hidden for the rest of the function.
    let n = n as u64;
    // Largest multiple of n that fits in u32's range; reject anything above it.
    // Drawing only from [0, zone) and then taking `% n` is exactly uniform,
    // because that interval contains a whole number of n-sized blocks.
    let zone = ((u64::from(u32::MAX) + 1) / n) * n;
    // `loop { ... }` repeats forever until something inside returns/breaks.
    loop {
        // Read 4 fresh random bytes. `random_bytes::<4>()` uses a const generic
        // (`<4>`) to request a fixed-size 4-byte array; the trailing `?` is the
        // try operator: if the call returned `Err`, `?` returns that error from
        // `uniform` immediately, otherwise it unwraps the `Ok` value.
        // `from_le_bytes` interprets the 4 bytes as a little-endian u32, then
        // `u64::from(...)` widens it to u64 so the comparison/modulo below fit.
        let r = u64::from(u32::from_le_bytes(random_bytes::<4>()?));
        if r < zone {
            // In range: take modulo n to get the index, cast back to usize, and
            // return success. `Ok(...)` wraps it in the success variant of Result.
            return Ok((r % n) as usize);
        }
        // Otherwise r was in the rejected tail; loop and draw again.
    }
}

/// Generate a password according to `opts`.
//
// `opts: &GenOptions` is taken by shared borrow (`&`): we only read the options,
// so we don't need to own or copy them. Returns `Ok(String)` (an owned, growable,
// UTF-8 text string) on success or `Err(GenError)` on failure.
pub fn generate(opts: &GenOptions) -> Result<String, GenError> {
    if opts.length == 0 {
        // `return Err(...)` exits early with the error variant of Result.
        return Err(GenError::ZeroLength);
    }
    let classes = opts.classes();
    if classes.is_empty() {
        return Err(GenError::NoClasses);
    }

    // Mutable byte buffer we'll build the password into. `Vec::with_capacity`
    // pre-allocates room for `opts.length` bytes (an optimization; it can still
    // grow). Type annotation `Vec<u8>` makes the element type explicit.
    let mut out: Vec<u8> = Vec::with_capacity(opts.length);

    // Guarantee one char from each class when there's room.
    if opts.length >= classes.len() {
        // `for class in &classes` iterates over borrowed elements (`&` so we don't
        // consume the list). `class.len()` is the table size; `uniform(...)?`
        // picks a random index (propagating any RNG error via `?`); `class[idx]`
        // indexes into the slice; `out.push(...)` appends that byte to the buffer.
        for class in &classes {
            out.push(class[uniform(class.len())?]);
        }
    }

    // Fill the remainder from the union of all enabled characters.
    // Iterator chain: `.iter()` walks the list of slices; `.flat_map(|c| ...)`
    // applies a closure (the `|c| ...` anonymous function) to each slice `c` and
    // flattens the results into one stream; `c.iter().copied()` yields each byte
    // by value (copying the `u8` out of the borrowed slice); `.collect()` gathers
    // the whole stream into a new `Vec<u8>` (the target type guides what we build).
    let pool: Vec<u8> = classes.iter().flat_map(|c| c.iter().copied()).collect();
    // Keep appending random characters from the combined pool until we reach the
    // requested length. `out.len()` is the current count.
    while out.len() < opts.length {
        out.push(pool[uniform(pool.len())?]);
    }

    // Fisher-Yates shuffle so guaranteed chars aren't stuck at the front.
    // `(1..out.len())` is the range 1..len-1; `.rev()` walks it high-to-low.
    for i in (1..out.len()).rev() {
        let j = uniform(i + 1)?;
        // `swap` exchanges the bytes at positions i and j in place.
        out.swap(i, j);
    }

    // All bytes are ASCII from the constant tables, so this is always valid UTF-8.
    // `String::from_utf8(out)` validates the bytes and returns a Result; `.expect`
    // unwraps the Ok value and would panic with this message if the bytes were
    // somehow not valid UTF-8. It is safe here because every byte came from the
    // ASCII-only constant tables, so the failure branch is unreachable in practice.
    Ok(String::from_utf8(out).expect("charset is ASCII"))
}

// `#[cfg(test)]` is conditional compilation: this `mod tests` module is only
// compiled when running tests (via `cargo test`), so it adds nothing to the
// shipped binary. `mod` declares a nested module.
#[cfg(test)]
mod tests {
    // `use super::*;` imports everything from the parent module (this file), so
    // the tests can call `generate`, `uniform`, `GenOptions`, etc. directly.
    use super::*;

    // `#[test]` marks a function as a unit test the test runner will execute.
    #[test]
    fn respects_length() {
        // `..Default::default()` is "struct update syntax": set `length` to 32 and
        // fill every other field from GenOptions::default().
        let opts = GenOptions { length: 32, ..Default::default() };
        // `.unwrap()` extracts the Ok value of the Result and panics (failing the
        // test) if it's an Err — acceptable in tests where we expect success.
        // `assert_eq!` fails the test unless the two arguments are equal.
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
        // `pw.bytes()` iterates over the password's bytes; `.all(|b| ...)` returns
        // true only if the closure holds for every byte. `assert!` fails the test
        // if its condition is false.
        assert!(pw.bytes().all(|b| b.is_ascii_digit()));
    }

    #[test]
    fn guarantees_each_class_when_room() {
        let opts = GenOptions { length: 8, ..Default::default() };
        let pw = generate(&opts).unwrap();
        // `.any(|b| ...)` is the mirror of `.all`: true if at least one byte
        // satisfies the closure. `SYMBOLS.contains(&b)` checks membership; `&b`
        // passes a borrow of the byte because `contains` expects a reference.
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
        // `matches!(value, Pattern)` is true if `value` fits the given pattern
        // here, that the Result is the Err variant carrying GenError::NoClasses.
        assert!(matches!(generate(&opts), Err(GenError::NoClasses)));
    }

    #[test]
    fn rejects_zero_length() {
        let opts = GenOptions { length: 0, ..Default::default() };
        assert!(matches!(generate(&opts), Err(GenError::ZeroLength)));
    }

    #[test]
    fn uniform_in_range() {
        // `for _ in 0..1000` repeats 1000 times; `_` is a throwaway loop variable
        // (we don't use the counter).
        for _ in 0..1000 {
            assert!(uniform(7).unwrap() < 7);
        }
    }

    #[test]
    fn uniform_covers_the_whole_range() {
        // Over many draws every index in 0..n must appear. This rejects a sampler
        // that collapses to a constant (e.g. always 0 or 1) or grossly biases the
        // output away from part of the range.
        let n = 6;
        // `[false; 6]` is a fixed-size array of 6 booleans, all initialized false.
        let mut seen = [false; 6];
        for _ in 0..3000 {
            // Mark each drawn index as seen.
            seen[uniform(n).unwrap()] = true;
        }
        // `|&s| s` is a closure that destructures the borrowed bool `&s` into the
        // value `s`; the trailing string is the message shown if the assert fails.
        assert!(seen.iter().all(|&s| s), "uniform must reach every index in 0..n");
    }

    #[test]
    fn generate_has_high_character_diversity() {
        // A correct generator drawing from all four classes produces many distinct
        // characters; a constant-index sampler would collapse to only a handful.
        let opts = GenOptions { length: 64, ..Default::default() };
        let pw = generate(&opts).unwrap();
        // `.collect()` into a `BTreeSet<u8>` (an ordered set) automatically
        // de-duplicates the bytes, so `distinct.len()` is the number of unique
        // characters. The target type on the left tells `collect` what to build.
        let distinct: std::collections::BTreeSet<u8> = pw.bytes().collect();
        assert!(distinct.len() >= 16, "expected diverse output, got {} distinct", distinct.len());
    }
}
