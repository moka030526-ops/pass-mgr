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
#![forbid(unsafe_code)]

pub mod crypto;
pub mod gui;
pub mod password;
pub mod records;
pub mod storage;
pub mod types;
pub mod ui;
pub mod vault;
