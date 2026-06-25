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
use zeroize::Zeroizing;

// `const` is a compile-time constant. `&[u8]` is a "byte slice": a read-only
// view (shared borrow, the `&`) into a sequence of bytes (`u8` = unsigned 8-bit).
// The `b"..."` prefix makes a byte-string literal (raw bytes, not a text String).
// These four tables are the allowed characters per category.
const LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &[u8] = b"0123456789";
// Deliberately excludes quotes/backslash/space to stay shell- and form-safe.
const SYMBOLS: &[u8] = b"!@#$%^&*()-_=+[]{};:,.<>?/";

// Upper bound on a generated password's length. Any real password is far shorter;
// this just stops a programmatic caller (the public `GenOptions.length` field has
// no inherent ceiling) from requesting a multi-gigabyte allocation.
const MAX_LENGTH: usize = 4096;

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
    // Requested length was absurdly large (would allocate gigabytes for no sane
    // reason). Guards the public `GenOptions.length` field against a programmatic
    // caller passing a huge value.
    #[error("length must be at most {MAX_LENGTH}")]
    TooLong,
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
    // Largest multiple of n that fits in a 64-bit draw; reject anything above it.
    // Drawing only from [0, zone) and then taking `% n` is exactly uniform, because
    // that interval contains a whole number of n-sized blocks. The zone math is done
    // in u128 so `span` (2^64) does not overflow and so `zone` stays > 0 for EVERY
    // n in 1..=u64::MAX — a 64-bit draw never lets the accept zone collapse to 0
    // (which, with a 32-bit draw, made `uniform` spin forever for n > 2^32).
    let span = u128::from(u64::MAX) + 1; // 2^64
    let zone = (span / u128::from(n)) * u128::from(n);
    // `loop { ... }` repeats until an in-range draw returns.
    loop {
        // Read 8 fresh random bytes as a little-endian u64. The trailing `?` is the
        // try operator: on `Err` it returns that error from `uniform` immediately.
        let r = u64::from_le_bytes(random_bytes::<8>()?);
        if u128::from(r) < zone {
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
    if opts.length > MAX_LENGTH {
        return Err(GenError::TooLong);
    }
    let classes = opts.classes();
    if classes.is_empty() {
        return Err(GenError::NoClasses);
    }

    // Mutable byte buffer we'll build the cleartext password into, wrapped in
    // `Zeroizing` so it is WIPED on drop. This matters on the error paths below: any
    // `?` that returns an RNG failure mid-build drops `out` while it already holds a
    // PARTIAL plaintext password — without `Zeroizing` those bytes would be freed to
    // the allocator un-wiped (stranding a secret in freed heap, which the rest of the
    // codebase forbids). Pre-sized to `opts.length` so the pushes never reallocate
    // (a realloc would orphan an un-wiped copy of the partial password).
    let mut out = Zeroizing::new(Vec::<u8>::with_capacity(opts.length));

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
    // Move the bytes OUT of the zeroizing buffer into the returned String (the success
    // path's intended secret, which the caller stores in a ZeroizeOnDrop record field).
    // `mem::take` leaves `out` holding an empty Vec, so its drop wipes nothing extra.
    Ok(String::from_utf8(std::mem::take(&mut *out)).expect("charset is ASCII"))
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
    fn rejects_overlong_length() {
        // A programmatic caller asking for an absurd length is refused with a clean
        // error, not served a multi-gigabyte allocation.
        let opts = GenOptions { length: usize::MAX, ..Default::default() };
        assert!(matches!(generate(&opts), Err(GenError::TooLong)));
    }

    // Regression: with a 32-bit draw the rejection zone collapsed to 0 for any
    // n > 2^32, so `uniform` spun forever. A 64-bit draw must return promptly. Gated
    // to 64-bit targets, where `usize` can actually exceed 2^32.
    #[cfg(target_pointer_width = "64")]
    #[test]
    fn uniform_terminates_for_n_above_2_pow_32() {
        let n: usize = (1usize << 33) + 1; // > 2^32
        assert!(uniform(n).unwrap() < n);
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

    use proptest::prelude::*;
    proptest! {
        /// `uniform(n)` is always in `[0, n)` and never panics, for any `n >= 1`.
        #[test]
        fn prop_uniform_in_range(n in 1usize..=2_000_000) {
            let r = uniform(n).unwrap();
            prop_assert!(r < n, "uniform({n}) = {r} out of range");
        }

        /// `generate` produces exactly the requested length using ONLY characters
        /// from the enabled classes (and never panics).
        #[test]
        fn prop_generate_length_and_charset(
            length in 1usize..=128,
            lowercase in any::<bool>(),
            uppercase in any::<bool>(),
            digits in any::<bool>(),
            symbols in any::<bool>(),
        ) {
            prop_assume!(lowercase || uppercase || digits || symbols); // need >=1 class
            let opts = GenOptions { length, lowercase, uppercase, digits, symbols };
            let pw = generate(&opts).unwrap();
            prop_assert_eq!(pw.len(), length, "exact requested length (ASCII, 1 byte/char)");
            for c in pw.bytes() {
                let ok = (lowercase && LOWER.contains(&c))
                    || (uppercase && UPPER.contains(&c))
                    || (digits && DIGITS.contains(&c))
                    || (symbols && SYMBOLS.contains(&c));
                prop_assert!(ok, "byte {c} is not from any enabled class");
            }
        }
    }


    // --- mutation-testing kill-tests (round 7: cargo-mutants survivor closure) ---
    #[test]
    fn mut_generate_accepts_exactly_max_length() {
        // Boundary: length == MAX_LENGTH must be ACCEPTED (the guard is strict `>`).
        // Mutating `>` to `>=` (line 171) would reject this exact value with TooLong,
        // so the unwrap below would panic and the length assertion would never pass.
        let opts = GenOptions { length: MAX_LENGTH, ..Default::default() };
        let pw = generate(&opts).unwrap();
        assert_eq!(pw.len(), MAX_LENGTH);
        // And one past the cap is still refused, pinning the cap location itself.
        let over = GenOptions { length: MAX_LENGTH + 1, ..Default::default() };
        assert!(matches!(generate(&over), Err(GenError::TooLong)));
    }

    #[test]
    fn mut_generate_shuffle_uses_inclusive_swap_partner() {
        // Pins the Fisher-Yates index `uniform(i + 1)` (line 211) against the
        // `i * 1` mutation. With length 2 and only lower+upper enabled, the
        // pre-shuffle buffer is exactly [lower, upper] (classes() pushes LOWER then
        // UPPER). The only shuffle step is i == 1: real code draws uniform(2) -> j in
        // {0,1}, so when j == 1 there is NO swap and index 0 stays lowercase. The
        // `* 1` mutation draws uniform(1) -> j == 0 always, forcing swap(1,0) every
        // time, so index 0 would ALWAYS be uppercase. Observing a lowercase at index
        // 0 even once distinguishes the two (false-negative prob ~ 2^-256).
        let opts = GenOptions {
            length: 2,
            lowercase: true,
            uppercase: true,
            digits: false,
            symbols: false,
        };
        let mut saw_lower_at_0 = false;
        let mut saw_upper_at_0 = false;
        for _ in 0..256 {
            let pw = generate(&opts).unwrap();
            let b0 = pw.as_bytes()[0];
            if b0.is_ascii_lowercase() {
                saw_lower_at_0 = true;
            }
            if b0.is_ascii_uppercase() {
                saw_upper_at_0 = true;
            }
        }
        // Real code yields both outcomes (~50/50); the `* 1` mutant never leaves a
        // lowercase at index 0, so this fails under the mutation.
        assert!(saw_lower_at_0, "index 0 must sometimes stay lowercase (uniform(i+1), not uniform(i))");
        assert!(saw_upper_at_0, "index 0 must sometimes be uppercase too (sanity)");
    }
}
