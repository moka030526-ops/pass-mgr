#![no_main]
//! Fuzz the document virtual-path helpers with arbitrary attacker-controlled
//! strings (the user controls the subfolder + filename). For ANY input these
//! invariants must hold — a violation panics and libFuzzer flags it:
//!   - doc_slug: ASCII [a-z0-9-] only, no spaces, no leading/trailing '-', <=40,
//!     and never empty (falls back).
//!   - doc_filename: no '/'/'\\'/control/whitespace, no leading/trailing '.', <=120
//!     bytes, and never empty.
//!   - doc_upload_dir: keeps the trusted root/timestamp prefix, contains no space,
//!     no "/./" or "/../" traversal, and no empty path component.
use libfuzzer_sys::fuzz_target;
use pass_mgr_core::records::{doc_filename, doc_slug, doc_upload_dir};

fuzz_target!(|data: &[u8]| {
    // The full byte string is the attacker-controlled input (subfolder / filename).
    let s = String::from_utf8_lossy(data);

    let slug = doc_slug(&s, "fb");
    assert!(!slug.is_empty(), "slug never empty");
    assert!(slug.len() <= 40, "slug bounded: {slug:?}");
    assert!(!slug.starts_with('-') && !slug.ends_with('-'), "no edge dash: {slug:?}");
    assert!(
        slug.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'),
        "slug charset: {slug:?}"
    );

    let fname = doc_filename(&s);
    assert!(!fname.is_empty(), "filename never empty");
    assert!(fname.len() <= 120, "filename bounded: {fname:?}");
    assert!(
        !fname.chars().any(|c| c == '/' || c == '\\' || c.is_control() || c.is_whitespace()),
        "filename has no separator/control/whitespace: {fname:?}"
    );
    assert!(!fname.starts_with('.') && !fname.ends_with('.'), "no edge dot: {fname:?}");

    // Full upload directory with a trusted root/timestamp prefix + the attacker subfolder.
    let dir = doc_upload_dir("taxes/2024", "20240102-030405", &s);
    assert!(dir.starts_with("taxes/2024/20240102-030405"), "prefix preserved: {dir:?}");
    assert!(!dir.contains(' '), "no space in dir: {dir:?}");
    assert!(!dir.contains("/../") && !dir.contains("/./") && !dir.ends_with("/.."), "no traversal: {dir:?}");
    for comp in dir.split('/') {
        assert!(!comp.is_empty(), "no empty path component: {dir:?}");
    }
});
