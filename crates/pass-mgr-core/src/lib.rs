//! pass-mgr-core — the security-critical, headless core of the standalone,
//! offline, two-password encrypted **estate vault**.
//!
//! This crate holds the whole vault implementation: the data model
//! ([`records`]), the partitioned crash-safe on-disk format ([`storage`]), the
//! key derivation + authenticated encryption ([`crypto`]), the editable
//! category lists ([`types`]), the random password generator ([`password`]),
//! and the [`vault::OpenVault`] API that ties them together.
//!
//! It has **no UI and no desktop/OS front-end dependencies** (no egui, ratatui,
//! arboard, or directories), so the exact same audited code is reused unchanged
//! behind the desktop binaries (the `pass-mgr` crate) and the mobile FFI (the
//! `pass-mgr-ffi` crate). The fuzz targets under `fuzz/` link against it
//! directly to hammer the untrusted-input parsers.
//!
//! The crate contains **no `unsafe` code** (enforced crate-wide below); the only
//! privileged operation — locking the derived key's pages out of swap — goes
//! through the `region` crate's safe API.
//!
//! (Rust note for non-Rust readers: lines beginning with `//!` are *inner doc
//! comments* — documentation attached to the enclosing item, here the whole
//! crate/file. `///` would document the single item that follows it, and `//`
//! is an ordinary line comment. None of these are executable code.)

// A crate-level attribute. `#![...]` (with the `!`) applies to the *whole file*;
// `forbid` is the strictest lint level — it makes any use of the `unsafe`
// keyword anywhere in this crate a hard compile error that cannot be locally
// overridden. For a security tool this guarantees memory-safety checks are
// never bypassed.
#![forbid(unsafe_code)]

// Module declarations. In Rust a `mod NAME;` line pulls in the contents of a
// sibling file (`src/NAME.rs`) as a submodule of this crate. `pub` makes the
// module part of the crate's public API, so the desktop front-ends, the mobile
// FFI wrapper, and the fuzz targets can all reach into them. Items inside a
// module are private by default unless they too are marked `pub`.
pub mod crypto; // security-critical: key derivation + authenticated encryption
pub mod fault; // crash-safety fault-injection hooks (no-op without the feature)
pub mod password; // random password generator
pub mod records; // the secret records stored in the vault
pub mod storage; // the partitioned, crash-safe on-disk storage engine
pub mod types; // editable category lists / shared data types
pub mod vault; // ties crypto + storage + records into the OpenVault API
