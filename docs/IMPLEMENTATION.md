# pass-mgr — Implementation Document

_Last updated: 2026-06-14_

How the code is structured, as built. Read `DESIGN.md` first for the "why"; this
is the "how" and the "where". No `unsafe`, no networking crates.

## 1. Module map

```
src/
├── lib.rs       Library crate root (`pass_mgr`): re-exports the modules below
│                and sets `#![forbid(unsafe_code)]` crate-wide. The binary and
│                the fuzz targets both build on this library.
├── crypto.rs    Argon2id chained two-password KDF + XChaCha20-Poly1305 AEAD;
│                the derived Key lives in mlock'd heap pages (swap mitigation).
├── records.rs   The data model: 5 record types, Change/history, the Record
│                trait + generic upsert/remove, the Vault (which embeds the
│                category lists and a `settings` block; the id→location map lives
│                in the manifests, not here).
│                Shared helpers: unix_now, random_id, civil_from_unix.
├── storage.rs   The partitioned document engine (format v4): Manifest/
│                ManifestEntry/VolumeStore; frame encode/decode + bounds-checked
│                parsers, atomic manifest commits, lazy open/read, partition
│                selection, the ordered crash-safe commit protocol, and
│                scan-rebuild of a lost manifest. `pub mod fuzz` exposes the
│                parsers to the fuzz targets.
├── vault.rs     The vault file (header + AEAD JSON) and orchestration over
│                `storage`: OpenVault open/create/save/export/change_password
│                (staged full re-encryption), document add/read/export/remove,
│                the single-writer lockfile, the in-vault category + volume-size
│                mutators, and backup.
├── types.rs     The editable category lists (flat Asset/Liability types and
│                hierarchical Account types, AccountType{name, subtypes}). Pure
│                in-memory data; **persisted inside the vault**, not on disk.
├── password.rs  Bias-free random password generator (OS CSPRNG, rejection
│                sampling, class guarantees, Fisher–Yates shuffle).
├── fault.rs     Crash-safety fault-injection hook (`point`). A zero-cost no-op
│                unless the `fault-injection` feature is on; then it can return
│                ENOSPC (full-disk tests) or abort (force-kill tests) at a named
│                commit step. Compiled out of release builds.
├── gui.rs       egui/eframe graphical UI (default). Tabs + Config screen.
├── ui.rs        ratatui terminal UI (`--tui`). Field-based edit forms.
└── main.rs      Binary crate: CLI dispatch (`--write`/`--tui`/`--part`), vault-
                 directory selection, terminal setup/teardown, no-echo password
                 reader; decrypt / manifest / extract / backup commands.
```

The crate is split into a **library** (`lib.rs` → `pass_mgr`) holding the whole
implementation and a thin **binary** (`main.rs`). The split lets the fuzz targets
under `fuzz/` link the parsers directly. The security-critical core is `crypto.rs`
+ `storage.rs` + `vault.rs` + `records.rs`; both front-ends drive the **same** `OpenVault` API,
so all crypto/data logic is shared. There is no `unsafe` anywhere in the crate
(`#![forbid(unsafe_code)]`); even the key page-locking uses the `region` crate's
safe API.

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

The `Vault` also embeds the `categories` (`TypeLists`) used by the dropdowns, so
the editable type lists travel with the encrypted vault (see §5).

- Shared insert/edit/history logic is the **`Record` trait** + generic
  `upsert`/`remove` (records.rs). Each type supplies only its field-level `diff`
  and a `label`. `upsert` preserves `id`/`created_at` and appends the diff to
  history; `remove` logs a deletion to the vault audit log.
- All types derive `Zeroize`/`ZeroizeOnDrop`, so decrypted secrets (incl. the
  password history and document bytes held in memory) are wiped on drop.
- `Vault` owns the five `Vec`s plus `categories` (`TypeLists`), a `settings`
  block (`volume_max_size`), an `id` (binds the volumes/manifests to this vault),
  `version`, a write `generation` counter, `last_opened_at`, and the vault-level
  `audit` log. The document index is **not** here — it lives in the per-partition
  manifests; records hold only doc-id references.

## 3. File format & document store (`vault.rs` + `storage.rs`)

The vault is a **directory** (`mypath/vault.pmv` + `manifest/` + `volume/` +
`pass-mgr.lock`); see `DESIGN.md` §6 for the byte layouts.

- **Vault file** (`vault.pmv`): a 61-byte plaintext header (magic `PMVAULT\0`,
  format version 4, Argon2 params, salt, nonce) followed by the
  XChaCha20-Poly1305 ciphertext of the JSON `Vault`. The **entire 61-byte header
  — including the nonce — is the AEAD associated data**: `save` generates the
  nonce first, writes it into the header, and passes the whole header to
  `crypto::encrypt_with_nonce`, so a downgrade of the Argon2 params or a swap of
  the salt/nonce can't go undetected (verified by `header_tampering_is_detected`).
  KDF params are range-checked, and `vault.pmv` is size-capped, on parse (DoS
  guard). Saves are atomic: write a unique hidden temp file with `create_new`+0600,
  fsync, rename, fsync the directory; the write `generation` is bumped each save.
- **Document store** (`storage.rs`): per-partition `volume/vol.<N>` of append-only
  frames `[u32 len][nonce][ct]` (ct over `[id_len][id][path_len][path][bytes]`,
  AAD = `vault_id ‖ partition`), indexed by encrypted `manifest/manifest.<N>`.
  - **Commit protocol** (`put`): append+fsync the frame, fsync the volume dir,
    then atomically swap the manifest (temp→fsync→rename→fsync dir) — the storage
    commit point. The manifest `end_offset` is authoritative, so a torn trailing
    frame is ignored. A lost/corrupt manifest is rebuilt by scanning its volume.
  - **Lazy + bounded:** `open` decrypts only the manifests; `read` opens one
    volume and one frame, verifying the frame's authenticated id/path against the
    manifest (rejects a relocated/substituted frame). All length fields are
    bounds-checked; per-doc/per-manifest sizes are capped.
  - **Partitioning:** `volume_max_size` (vault `settings`, default 256 MiB)
    governs placement of new docs; updates stay in the original partition. No
    compaction in v1 (reclaimed blobs linger as garbage).
  - **Lifecycle:** attaching persists the record→doc link immediately; remove/
    detach/delete persist the unlinked vault **first**, then reclaim the blob, so
    a crash leaves at most a harmless orphan, never a dangling reference.
- **Password change** (`change_password`): full re-encryption under a fresh
  key+salt, staged in `.rekey/` (`vault.pmv` + `manifest/` + `volume/` + `READY`),
  committed by roll-forward (volumes, then manifests, then `vault.pmv` last), and
  recovered on the next open if interrupted. Poisons the live handle if a partial
  commit fails.
- **Single-writer lock:** a writable open/create takes an OS advisory lock on
  `pass-mgr.lock` (`File::try_lock`, released on process exit); a second writable
  instance gets `VaultError::Locked`. Read-only opens skip it.
- **Backup** (`backup()`): copies the whole encrypted tree into a collision-safe,
  timestamped subdir (refuses a half-committed rekey). No decryption.
- **Plaintext round-trip** (`export_tree`/`import_tree`, DESIGN.md §6.3):
  `export_tree` decrypts the whole vault into `out/vault.json` +
  `manifest/manifest.<N>.json` + `volume/vol.<N>/<id>` (reusing the decrypt +
  store-read paths; 0600/`create_new`; refuses a pending rekey). `import_tree`
  rebuilds a new encrypted vault from such a mirror under new passwords, reusing
  `VolumeStore::put` + `write_vault_file` then the normal open path; it treats the
  mirror as untrusted (validates the version and rejects a blob id that isn't a
  safe filename — `is_safe_blob_id` — so a crafted mirror can't traverse out).
- Cross-platform file hardening (`harden_file`/`harden_dir`/`write_new_*`):
  0600/0700 on Unix; on Windows it relies on the inherited per-user `%APPDATA%` ACL.

## 4. Cryptography (`crypto.rs`)

- **KDF:** Argon2id, 64 MiB / 3 / 1 defaults. Two passwords are chained:
  `k1 = Argon2id(pw1, salt1)`, `key = Argon2id(pw2, k1)`. Both required; order
  matters; neither verifiable independently.
- **AEAD:** XChaCha20-Poly1305, fresh 24-byte random nonce per write. Every path
  uses `encrypt_with_nonce` with an explicit nonce and explicit associated data:
  the vault binds its **whole 61-byte header**, each volume frame and each
  manifest bind `PREFIX ‖ vault_id ‖ partition`. The 24-byte XChaCha nonce space
  makes random-nonce collision negligible (tested for uniqueness across writes).
- **Key memory:** the derived `Key` is a boxed `[u8;32]` whose page(s) are
  `mlock`/`VirtualLock`'d (the `region` crate) so the key is not paged to swap;
  wiped then unlocked on drop. Transient stack copies are zeroized.

## 5. Type lists (`types.rs`)

`TypeLists` is pure in-memory data (a flat `asset: Vec<String>` and hierarchical
`account: Vec<AccountType{name, subtypes}>`) **stored inside the vault** — it is a
field of `Vault` (`#[serde(default = "TypeLists::with_defaults")]`, and
`#[zeroize(skip)]` since category names are not secrets). A new vault is seeded
with `with_defaults()`; a vault that predates the field falls back to those
defaults on load. There are **no external files** — nothing to read at startup
and nothing unencrypted to leak.

The Config-screen edits go through `OpenVault::add_asset_type` /
`add_account_type` / `add_account_subtype`, which mutate `vault.categories` and
`save()` the encrypted vault (refused when read-only). The mutators in `types.rs`
themselves only touch memory and report whether anything changed. The Account
subtype dropdown/filter is dependent on the chosen type.

## 6. UIs

Both share the four-screen shape (Auth / browse list / edit / Config). The GUI
(`gui.rs`) uses egui with a deferred-action pattern (side effects applied after
the render closures to keep `self` borrows disjoint). The TUI (`ui.rs`) builds
each edit form as a flat `Vec<Field>` and rebuilds the typed record by field
index in `commit_edit_record`. Selection resolves **by id** so filtered lists
never edit the wrong record. Accounts filter by type/subtype/owner/review;
Assets by review. A copied password is auto-cleared from the clipboard after 15s
(a deadline the event loop polls for) and again on exit; the write `generation`
is shown on unlock so a rollback is noticeable. Both UIs validate a document's
virtual path against `storage::MAX_PATH_LEN` (256 bytes) before attaching — the
GUI disables the Attach button with an inline error, the TUI rejects the upload
key — and the Config screen (write mode only) edits the volume-size setting via
`OpenVault::set_volume_max_size` (which updates the live store cap and persists).
Change-password runs through the Auth screen into `OpenVault::change_password`.

## 7. CLI (`main.rs`)

The positional argument is the vault **directory** (default per-user data dir).

```
pass-mgr [DIR]                    graphical UI (READ-ONLY by default)
pass-mgr --write [DIR]            writable (allow create/edit/delete/upload)
pass-mgr --tui [DIR]             terminal UI (add --write to edit)
pass-mgr decrypt [DIR]           print the decrypted vault JSON (secrets!) to stdout
pass-mgr manifest [DIR] [--part N]   print the document index: one partition or all
pass-mgr extract [DIR] OUT [--part N]   decrypt documents into OUT: one volume or all
pass-mgr backup [DIR] DEST       copy the whole encrypted vault tree into DEST
pass-mgr export-tree [DIR] OUT   decrypt the whole vault into a plaintext mirror
pass-mgr import-tree SRC [DIR]   build a new encrypted vault from a plaintext mirror
```

`--write`/`--tui` are position-independent flags. **Read-only is the default**,
enforced authoritatively in `OpenVault` (`open_read_only` + `read_only` guards on
every mutator; nothing is written, and no lock is taken, on a read-only open),
with the UIs hiding write controls and showing a read-only badge (`DESIGN.md`
§4.4). A writable open takes the single-writer lock; a second writable instance
fails fast with `VaultError::Locked`.

`--part N` / `--part=N` (parsed by `extract_part_flag`) selects one partition for
`manifest`/`extract`; it is rejected on other commands. `extract` sanitizes the
manifest paths (`safe_relative_path`: no `..`/absolute/drive/backslash, drops
Windows reserved names + trailing dots) so it can't escape `OUT`, writes via the
hardened `write_new_bytes` (0600), and creates dirs 0700. `decrypt`/`manifest`/
`extract`/`backup` are read operations (refuse a half-committed rekey). The
no-echo password reader uses crossterm raw mode on a TTY and falls back to a piped
line otherwise.

## 8. Build, test, coverage

```bash
cargo build --release                         # GUI default; --tui for terminal
cargo test                                    # unit + property tests (proptest)
cargo clippy --all-targets -- -D warnings     # lints (kept clean)
cargo check --target x86_64-pc-windows-gnu    # Windows portability
cargo test --features fault-injection         # + the crash / full-disk tests
cargo +nightly fuzz build                     # build the fuzz targets
cargo +nightly fuzz run parse_frame           # fuzz a parser (also parse_manifest/
                                              #   scan_volume/parse_header)
cargo mutants --file src/storage.rs ...       # mutation testing (see below)
```

**Crash-safety / fault injection (`--features fault-injection`).** The `fault`
module instruments every commit step (volume append, manifest write+rename, vault
write+rename, the rekey roll-forward). Two test layers exercise it: *in-process*
ENOSPC injection asserts that a full disk at any step fails cleanly and leaves the
prior state intact and recoverable (the failed op vanishes; a torn tail past
`end_offset` is ignored; a half-staged rekey is discarded); and `tests/
crash_recovery.rs` *spawns the real binary* (the hidden `__crashop` subcommand)
and aborts it (`std::process::abort` — no `Drop`/flush, like SIGKILL/power-loss)
after the volume append, after the manifest commit, during the vault save, and
mid-rekey, then reopens and asserts recovery (document intact, lock released,
rekey rolled forward). See DESIGN.md §12 for the matrix.

Tests cover the core thoroughly (crypto, storage, vault, records, types,
password): per-operation crash-injection and the full rekey roll-forward matrix,
per-blob/per-manifest AAD binding and frame-substitution rejection, nonce
uniqueness, the partition/`end_offset` arithmetic, and `proptest` suites for the
parsers and path normalization. Front-end logic is driven through the TUI key
handler and the GUI's deferred methods directly, with every TUI screen rendered to
a ratatui `TestBackend`; egui rendering itself is not unit-tested (needs a GUI
harness). The untrusted-input parsers (`parse_header`, `parse_frame`,
`parse_manifest`, `scan_volume`) have `cargo-fuzz` targets.

**Mutation testing (§13.6).** `cargo mutants` over the security-critical files is
run periodically; surviving mutants are triaged. Killed: the `Header::parse`
bounds, the partition-scan recovery, the frame plausibility checks, and the date
math. Documented surviving classes (a killing test would be tautological, flaky,
or impossible): `Key::drop`'s zeroize (not observable without UB-adjacent memory
inspection); `password::uniform`'s rejection-zone arithmetic (bias-only — output
range/coverage are preserved; the genuinely-broken variants are caught via
*timeout*); the DoS-guard size *constants* (value not behavior); and the
fsync/fuzz-wrapper helpers (durability isn't in-process observable; fuzz wrappers
are exercised by the fuzz binaries, which discard the parsed result).

## 9. Cross-platform notes

| Concern | Linux | Windows |
|---------|-------|---------|
| Data dir | `~/.local/share/pass-mgr/` | `%APPDATA%\pass-mgr\` (via `directories`) |
| File privacy | explicit `0600` / `0700` | inherited per-user NTFS ACL (`DESIGN.md` §9.9) |
| Key swap-lock | `mlock` | `VirtualLock` (both via `region`) |
| Portable `.exe` | n/a | `.cargo/config.toml` static-CRT for MSVC |

## 10. Format-v4 redesign — as built

The partitioned store (§3) replaced the earlier single-`.vol` archive. The work
landed in phases (see `git log` and `PLAN.md` "Execution progress"): the storage
engine (`storage.rs`) and its wiring into `vault.rs` (directory layout,
`FORMAT_VERSION = 4`, staged `change_password`); the exhaustive rekey
crash-injection tests; the CLI `--part` selectivity and the single-writer
lockfile; the UI path-limit enforcement and volume-size config; the verification
pass (refreshed fuzz targets, `proptest`, storage AAD/bounds/nonce/corruption
tests, mutation triage); and finally two **max-depth multi-agent reviews** (a
bug-hunt and a security review, each *find → adversarial-verify → critic →
synthesize*) whose every confirmed finding was fixed and re-verified before this
doc was updated. The notable review fixes: per-frame id/path verification on read,
the volume-dir fsync ordering, persist-before-reclaim in the delete/detach paths,
the `vault.pmv` size cap, and the `append_frame` symlink refusal. The residual
limitations (at-rest rollback, the Argon2-cost open DoS, single-active-session
concurrency) are documented in `DESIGN.md` §9.12/§9.13/§9.16.

## 11. Definition of done

- `cargo build`, `cargo test`, `cargo clippy` clean on Linux; Windows
  cross-compile checks pass.
- All brief requirements + the later features (estate tabs, subtypes, review
  flags + filters, config screen, backup, extract, swap mitigation) met (see
  `DESIGN.md` §2).
- No `unsafe`, no network crates, secrets zeroized, key memory-locked.
