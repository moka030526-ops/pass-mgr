//! pass-mgr — a standalone, offline, two-password encrypted **estate vault**.
//!
//! This library crate holds the whole implementation. The `pass-mgr` binary
//! ([`src/main.rs`]) is a thin CLI on top of it, and the fuzz targets under
//! `fuzz/` link against it directly to hammer the untrusted-input parsers.
//!
//! The security-critical core is [`crypto`] + [`vault`] + [`records`]; [`types`]
//! holds the editable category lists, [`password`] the random generator, and
//! [`gui`]/[`ui`] the two interchangeable front-ends (both drive the same
//! [`vault::OpenVault`] API).
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
// sibling file (`src/NAME.rs`) or directory (`src/NAME/mod.rs`) as a submodule
// of this crate — this is how the codebase is split across files. `pub` makes
// the module part of the crate's public API, so the `pass-mgr` binary, the
// other front-end, and the fuzz targets can all reach into them. Items inside a
// module are private by default unless they too are marked `pub`.
pub mod crypto; // security-critical: key derivation + authenticated encryption
pub mod fault; // crash-safety fault-injection hooks (no-op without the feature)
pub mod gui; // graphical front-end (drives the same vault API as `ui`)
pub mod launch; // vault-path/flag resolution shared by the console + windowed binaries
pub mod password; // random password generator
pub mod records; // the secret records stored in the vault
pub mod single_instance; // GUI single-instance guard (coalesces repeated launches)
pub mod storage; // the partitioned, crash-safe on-disk storage engine
pub mod types; // editable category lists / shared data types
pub mod ui; // text/terminal front-end (interchangeable with `gui`)
pub mod vault; // ties crypto + storage + records into the OpenVault API
