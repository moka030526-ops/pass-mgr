# pass-mgr — Implementation Document

_Last updated: 2026-06-13_

This document describes how the code is structured and the concrete steps to
build the application from the current foundation. Read `DESIGN.md` first for the
"why"; this is the "how".

## 1. Current state of the tree

```
src/
├── crypto.rs      DONE   Argon2id KDF + XChaCha20-Poly1305 AEAD, tested
├── password.rs    DONE   Bias-free random password generator, tested
├── vault.rs       PARTIAL data model + file format (single-password, Unix-only)
└── main.rs        STUB   "Hello, world!"
```

What is missing relative to the requirements:

- Two-password chained KDF (req. 9) — `crypto.rs` + `vault.rs`.
- `kind` / `description` / `history` fields and `Vault.types` / `audit` /
  `last_opened_at` (req. 2, 3, 4, 5, 6) — `vault.rs`.
- Cross-platform file permissions (Windows + Linux) — `vault.rs`.
- The entire TUI (req. 2, 10, 12 surfaced to the user) — new `ui.rs` + `main.rs`.

## 2. Module plan

```
src/
├── crypto.rs   crypto primitives + derive_key_chained()
├── password.rs (unchanged) generator
├── vault.rs    data model, file format, open/create/save, history helpers
├── ui.rs       ratatui screens, input handling, app state machine
└── main.rs     CLI arg for vault path, terminal setup/teardown, run loop
```

No `unsafe`. Each module stays under a few hundred lines.

## 3. Step-by-step build

### Step 1 — Chained two-password KDF (`crypto.rs`)

Add a function that performs the chained derivation from `DESIGN.md` §5.2:

```rust
/// Derive the vault key from TWO passwords (entered sequentially) and one salt.
/// k1 = Argon2id(pw1, salt1); key = Argon2id(pw2, salt = k1).
pub fn derive_key_chained(
    pw1: &[u8],
    pw2: &[u8],
    salt1: &[u8],
    params: &KdfParams,
) -> Result<Key, CryptoError> {
    let k1 = derive_key(pw1, salt1, params)?;     // existing fn, 32-byte output
    // k1's bytes are used as the salt for the second pass, then dropped (zeroized).
    let key = derive_key(pw2, k1.as_bytes(), params)?;
    Ok(key)
}
```

- Expose a read-only `Key::as_bytes(&self) -> &[u8]` (kept crate-private) so the
  intermediate key can seed the second derivation. `k1` is dropped (and thus
  zeroized) at the end of the function.
- Argon2's salt must be ≥ 8 bytes; `k1` is 32 bytes, so this is valid.
- Keep the single-password `derive_key` — the chained function is built on top of
  it and the existing unit tests still cover the primitive.
- Add tests: both passwords required; swapping pw1/pw2 yields a different key;
  determinism for the same inputs.

### Step 2 — Extend the data model (`vault.rs`)

Add fields (all `#[serde(default)]` for forward-compatibility):

```rust
pub struct Change { pub at: i64, pub action: String, pub detail: String }

pub struct Entry {
    pub id: String,
    pub title: String,
    pub kind: String,          // custom type (req. 2)
    pub description: String,   // (req. 3)
    pub username: String,
    pub password: String,
    pub url: String,
    pub created_at: i64,
    pub updated_at: i64,
    pub history: Vec<Change>,  // (req. 4, 5)
}

pub struct Vault {
    pub version: u8,
    pub last_opened_at: i64,   // (req. 6)
    pub types: Vec<String>,    // known custom types (req. 2)
    pub audit: Vec<Change>,    // vault-level log (req. 4)
    pub entries: Vec<Entry>,
}
```

History helpers:

- `Entry::record(action, detail)` pushes a `Change { at: now, .. }`.
- `Vault::upsert` computes a field-level diff against the existing entry and
  records one `Change` per changed field (password recorded as
  `"password updated"` only — never the old value, per `DESIGN.md` §9.4).
- `Vault::remove` pushes a `"deleted"` `Change` to `Vault.audit`.
- `Vault::register_type(kind)` adds unseen types to `Vault.types`.

### Step 3 — Wire two passwords into open/create (`vault.rs`)

- Bump `FORMAT_VERSION` to `2`.
- `OpenVault::create(path, pw1, pw2, params)` and
  `OpenVault::open(path, pw1, pw2)` call `derive_key_chained`.
- On successful `open`, set `vault.last_opened_at = now` **after** reading the
  previous value (so the UI can display the prior access time), then it is saved
  back on the next write.
- `change_password(pw1, pw2)` re-derives with a fresh `salt1`.

### Step 4 — Cross-platform file handling (Windows + Linux)

The current `vault.rs` imports `std::os::unix::fs::{OpenOptionsExt,
PermissionsExt}` unconditionally — this **fails to compile on Windows**. Fix by
isolating permission tightening behind `cfg` and keeping the cross-platform write
path identical:

```rust
// Common path: write tmp, fsync, rename. No platform-specific calls here.

#[cfg(unix)]
fn harden_file(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut p = std::fs::metadata(path)?.permissions();
    p.set_mode(0o600);
    std::fs::set_permissions(path, p)
}

#[cfg(windows)]
fn harden_file(_path: &Path) -> std::io::Result<()> {
    // NTFS inherits the user-profile ACL, which is already per-user private.
    // No portable std API to set a restrictive DACL; rely on inherited ACLs.
    // (Optional future: tighten via the `windows` crate.)
    Ok(())
}
```

- Replace the `.mode(0o600)` builder call (Unix-only `OpenOptionsExt`) with a
  plain `OpenOptions`, then call `harden_file` after creating the temp file.
- Do the same for the parent-directory `0700` logic behind `#[cfg(unix)]`.
- The path itself comes from the `directories` crate
  (`ProjectDirs::from(...).data_dir()`), which already returns the correct
  per-OS location (`%APPDATA%` on Windows, `~/.local/share` on Linux).
- See `DESIGN.md` §9 note added below: on Windows, file privacy relies on the
  inherited user-profile ACL rather than an explicit mode bit.

### Step 5 — TUI (`ui.rs` + `main.rs`)

State machine (`enum Screen { Unlock, Create, List, Detail, Edit }`) over a
single `App` struct holding the `OpenVault`, current filter, search text, and
selection.

- **Unlock/Create:** two masked password prompts in sequence (req. 9). Create
  flow confirms each. After unlock, show "Last opened: <ts>" (req. 6).
- **List:** top = filter chips (`All` + one per `Vault.types`) + search box;
  middle = filtered/sorted entries; bottom = key hints. Filtering combines the
  selected type with the text query.
- **Detail:** all fields, masked password with reveal toggle (`r`) and copy
  (`c`) via `arboard`; a history pane (`h`) listing timestamped `Change`s.
- **Edit:** form over the fields incl. a `kind` field (free text; new values get
  registered as types). A `g` action calls `password::generate` to fill the
  password field (req. 12). Saving runs `Vault::upsert` (records history) then
  `OpenVault::save`.

`main.rs`: parse an optional vault-path argument (default from `directories`),
enter the alternate screen / raw mode, run the event loop, and **always** restore
the terminal on exit (including panics — install a panic hook that disables raw
mode first).

### Step 6 — Tests & checks

- Unit tests per module (crypto chaining, history diff, type registration,
  filter logic) — keep the UI thin and logic in testable functions.
- `cargo test` on Linux.
- `cargo build` / `cargo check --target x86_64-pc-windows-gnu` (or CI on a
  Windows runner) to confirm portability (§4).

## 4. Cross-platform notes (req: compile on Windows + Linux)

| Concern | Linux | Windows |
|---------|-------|---------|
| Vault location | `~/.local/share/pass-mgr/` (`directories`) | `%APPDATA%\pass-mgr\` (`directories`) |
| File privacy | explicit `0600` / dir `0700` | inherited per-user NTFS ACL (no portable std mode bit) — see `DESIGN.md` §9 |
| Terminal | ratatio + crossterm backend (default) | same — crossterm supports Windows consoles |
| Line endings / paths | `PathBuf`, no hardcoded separators | `PathBuf`, no hardcoded separators |
| `unsafe` / FFI | none | none |

All dependencies (`argon2`, `chacha20poly1305`, `getrandom`, `arboard`,
`ratatui`/`crossterm`, `directories`, `zeroize`) support both targets. The only
non-portable code today is the Unix permission handling in `vault.rs`, addressed
in Step 4 via `#[cfg(...)]`.

## 5. Definition of done

- `cargo build` and `cargo test` pass on Linux.
- `cargo build` passes targeting Windows (cross-compile or CI).
- All 13 brief requirements + the cross-platform requirement are demonstrably
  met (see `DESIGN.md` §2 traceability table).
- No `unsafe`, no network crates, every secret-bearing buffer zeroized.
