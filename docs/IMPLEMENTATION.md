# pass-mgr — Implementation Document

_Last updated: 2026-06-14_

How the code is structured, as built. Read `DESIGN.md` first for the "why"; this
is the "how" and the "where". No `unsafe`, no networking crates.

## 1. Module map

```
src/
├── crypto.rs    Argon2id chained two-password KDF + XChaCha20-Poly1305 AEAD;
│                the derived Key lives in mlock'd heap pages (swap mitigation).
├── records.rs   The data model: 5 record types, Change/history, the Record
│                trait + generic upsert/remove, the Volume manifest, the Vault.
│                Shared helpers: unix_now, random_id, civil_from_unix.
├── vault.rs     On-disk file format (header + AEAD JSON) and the encrypted
│                document archive (<vault>.vol); OpenVault open/create/save/
│                export/change_password, document add/read/export/remove, backup.
├── types.rs     External, editable category lists: flat Asset/Liability types
│                and hierarchical Account types (AccountType{name, subtypes}).
├── password.rs  Bias-free random password generator (OS CSPRNG, rejection
│                sampling, class guarantees, Fisher–Yates shuffle).
├── gui.rs       egui/eframe graphical UI (default). Tabs + Config screen.
├── ui.rs        ratatui terminal UI (`--tui`). Field-based edit forms.
└── main.rs      CLI dispatch, vault-path selection, terminal setup/teardown,
                 no-echo password reader; decrypt / extract / backup commands.
```

The security-critical core is `crypto.rs` + `vault.rs` + `records.rs`; both
front-ends drive the **same** `OpenVault` API, so all crypto/data logic is shared.

## 2. Data model (`records.rs`)

Five record types, one per UI tab, each with `id` (128-bit hex), `created_at`,
`updated_at`, and an append-only `history: Vec<Change>`:

| Tab | Type | Key fields |
|-----|------|-----------|
| Instructions | `Instruction` | title, description |
| Trust and Will | `TrustWill` | document, usage, `file` (doc id) |
| Assets and Liabilities | `AssetLiability` | kind (Asset/Liability), description, owner, beneficiary, approx_value, as_of_date, institution, type, url, review, `statement` (doc id) |
| Accounts | `Account` | account_type, account_subtype, owner, username, password, url, description, review |
| Real Estate | `RealEstate` | address, ownership, taxes, hoa, income/financing/payment account |

- Shared insert/edit/history logic is the **`Record` trait** + generic
  `upsert`/`remove` (records.rs). Each type supplies only its field-level `diff`
  and a `label`. `upsert` preserves `id`/`created_at` and appends the diff to
  history; `remove` logs a deletion to the vault audit log.
- All types derive `Zeroize`/`ZeroizeOnDrop`, so decrypted secrets (incl. the
  password history and document bytes held in memory) are wiped on drop.
- `Vault` owns the five `Vec`s plus a `Volume` manifest, `version`, a write
  `generation` counter, `last_opened_at`, and the vault-level `audit` log.

## 3. File format & document volume (`vault.rs`)

- **Vault file** (`vault.pmv`): a 61-byte plaintext header (magic `PMVAULT\0`,
  format version 3, Argon2 params, salt, nonce) followed by the
  XChaCha20-Poly1305 ciphertext of the JSON `Vault`. The first 37 header bytes
  (everything but the nonce) are the AEAD associated data. KDF params are
  range-checked on parse (DoS guard). Saves are atomic: write a unique hidden
  temp file with `create_new`+0600, fsync, rename, fsync the directory; the write
  `generation` is bumped each save.
- **Document archive** (`vault.pmv.vol`): a *single* encrypted container holding
  all uploaded document bytes (`nonce ‖ ciphertext`), decrypted as a unit on
  open. Bound to the vault via `volume.id` in the AEAD AAD; on open, every
  manifest-referenced id must be present (rejects a stale/swapped `.vol`).
  `parse_archive` is fully bounds-checked. Deleting a record or detaching a
  document reclaims its blob; attaching persists the record→doc link immediately.
- **Backup** (`backup()`): copies the encrypted vault + `.vol` into a directory
  as a collision-safe, timestamped (`-YYYYMMDD-HHMMSS`) pair. No decryption.
- Cross-platform file hardening (`harden_file`/`harden_dir`/`write_new_*`,
  `pub(crate)` and reused by `main.rs`): 0600/0700 on Unix; on Windows it relies
  on the inherited per-user `%APPDATA%` ACL.

## 4. Cryptography (`crypto.rs`)

- **KDF:** Argon2id, 64 MiB / 3 / 1 defaults. Two passwords are chained:
  `k1 = Argon2id(pw1, salt1)`, `key = Argon2id(pw2, k1)`. Both required; order
  matters; neither verifiable independently.
- **AEAD:** XChaCha20-Poly1305, fresh 24-byte random nonce per write.
- **Key memory:** the derived `Key` is a boxed `[u8;32]` whose page(s) are
  `mlock`/`VirtualLock`'d (the `region` crate) so the key is not paged to swap;
  wiped then unlocked on drop. Transient stack copies are zeroized.

## 5. Type lists (`types.rs`)

`TypeLists::load(writable)` reads `<data_dir>/types/{asset_types,account_types}.json`,
seeding defaults when missing **only in a writable session** (a read-only launch
uses the defaults in memory and writes nothing — honoring the §4.4 guarantee) and
**never clobbering** a user-edited file.
Account types are hierarchical (`AccountType { name, subtypes }`) and the loader
accepts a legacy flat `["..."]` array for back-compat. `add_asset_type`,
`add_account_type`, `add_account_subtype` mutate and persist; the Config screen
drives these. The Account subtype dropdown/filter is dependent on the chosen type.

## 6. UIs

Both share the four-screen shape (Auth / browse list / edit / Config). The GUI
(`gui.rs`) uses egui with a deferred-action pattern (side effects applied after
the render closures to keep `self` borrows disjoint). The TUI (`ui.rs`) builds
each edit form as a flat `Vec<Field>` and rebuilds the typed record by field
index in `commit_edit_record`. Selection resolves **by id** so filtered lists
never edit the wrong record. Accounts filter by type/subtype/owner/review;
Assets by review. Clipboard copies are cleared on exit; the write `generation`
is shown on unlock so a rollback is noticeable.

## 7. CLI (`main.rs`)

```
pass-mgr [VAULT]              graphical UI (READ-ONLY by default)
pass-mgr --write [VAULT]      writable (allow create/edit/delete/upload)
pass-mgr --tui [VAULT]        terminal UI (add --write to edit)
pass-mgr decrypt [VAULT]      print the decrypted vault JSON (secrets!) to stdout
pass-mgr extract [VAULT] DIR  decrypt all documents into DIR (path-sanitized)
pass-mgr backup [VAULT] DIR   copy the encrypted vault + archive into DIR
```

`--write`/`--tui` are parsed as position-independent flags. **Read-only is the
default** and is enforced authoritatively in `OpenVault` (`open_read_only` +
`read_only` guards on every mutator; nothing is written on a read-only open),
with the UIs hiding write controls and showing a read-only badge (`DESIGN.md`
§4.4). `decrypt`/`extract`/`backup` are read operations and ignore `--write`.

`extract` sanitizes manifest paths (`safe_relative_path`: no `..`/absolute/drive/
backslash) so it can't escape `DIR`, writes via the hardened `write_new_bytes`,
and creates dirs 0700. The no-echo password reader uses crossterm raw mode on a
TTY and falls back to a piped line otherwise.

## 8. Build, test, coverage

```bash
cargo build --release                         # GUI default; --tui for terminal
cargo test                                    # unit + integration tests
cargo clippy                                  # lints (kept clean)
cargo check --target x86_64-pc-windows-gnu    # Windows portability
cargo llvm-cov --summary-only                 # coverage (if cargo-llvm-cov installed)
```

Tests cover the core thoroughly (crypto, records, vault, types, password) plus
the front-end logic by driving the TUI state machine through key events and the
GUI's deferred methods directly, and rendering every TUI screen to a ratatui
`TestBackend`. The egui rendering itself is not unit-tested (needs a GUI harness).

## 9. Cross-platform notes

| Concern | Linux | Windows |
|---------|-------|---------|
| Data dir | `~/.local/share/pass-mgr/` | `%APPDATA%\pass-mgr\` (via `directories`) |
| File privacy | explicit `0600` / `0700` | inherited per-user NTFS ACL (`DESIGN.md` §9.9) |
| Key swap-lock | `mlock` | `VirtualLock` (both via `region`) |
| Portable `.exe` | n/a | `.cargo/config.toml` static-CRT for MSVC |

## 10. Definition of done

- `cargo build`, `cargo test`, `cargo clippy` clean on Linux; Windows
  cross-compile checks pass.
- All brief requirements + the later features (estate tabs, subtypes, review
  flags + filters, config screen, backup, extract, swap mitigation) met (see
  `DESIGN.md` §2).
- No `unsafe`, no network crates, secrets zeroized, key memory-locked.
