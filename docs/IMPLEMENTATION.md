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
│                trait + generic upsert/remove, the Volume manifest, the Vault
│                (which now also embeds the category lists).
│                Shared helpers: unix_now, random_id, civil_from_unix.
├── vault.rs     On-disk file format (header + AEAD JSON) and the encrypted
│                document archive (<vault>.vol); OpenVault open/create/save/
│                export/change_password, document add/read/export/remove, the
│                in-vault category mutators, and backup.
├── types.rs     The editable category lists (flat Asset/Liability types and
│                hierarchical Account types, AccountType{name, subtypes}). Pure
│                in-memory data; **persisted inside the vault**, not on disk.
├── password.rs  Bias-free random password generator (OS CSPRNG, rejection
│                sampling, class guarantees, Fisher–Yates shuffle).
├── gui.rs       egui/eframe graphical UI (default). Tabs + Config screen.
├── ui.rs        ratatui terminal UI (`--tui`). Field-based edit forms.
└── main.rs      Binary crate: CLI dispatch (incl. the `--vol` flag), vault-path
                 selection, terminal setup/teardown, no-echo password reader;
                 decrypt / extract / backup commands.
```

The crate is split into a **library** (`lib.rs` → `pass_mgr`) holding the whole
implementation and a thin **binary** (`main.rs`). The split lets the fuzz targets
under `fuzz/` link the parsers directly. The security-critical core is `crypto.rs`
+ `vault.rs` + `records.rs`; both front-ends drive the **same** `OpenVault` API,
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
- `Vault` owns the five `Vec`s plus a `Volume` manifest, `version`, a write
  `generation` counter, `last_opened_at`, and the vault-level `audit` log.

## 3. File format & document volume (`vault.rs`)

> **Being replaced (format v4).** The single-`.vol` document store below is
> superseded by a partitioned, lazily-loaded, crash-safe volume + manifest engine
> (new `storage.rs`), specified in [`PLAN.md`](PLAN.md) and summarized in
> `DESIGN.md` §11. The description here is the current (v3) as-built until that
> lands; the planned module changes are in §10 below.

- **Vault file** (`vault.pmv`): a 61-byte plaintext header (magic `PMVAULT\0`,
  format version 3, Argon2 params, salt, nonce) followed by the
  XChaCha20-Poly1305 ciphertext of the JSON `Vault`. The **entire 61-byte header
  — including the nonce — is the AEAD associated data**: `save` generates the
  nonce first, writes it into the header, and passes the whole header to
  `crypto::encrypt_with_nonce`, so a downgrade of the Argon2 params or a swap of
  the salt/nonce can't go undetected (verified by `header_tampering_is_detected`).
  KDF params are range-checked on parse (DoS guard). Saves are atomic: write a
  unique hidden temp file with `create_new`+0600, fsync, rename, fsync the
  directory; the write `generation` is bumped each save.
- **Document archive** (`vault.pmv.vol` by default): a *single* encrypted
  container holding all uploaded document bytes (`nonce ‖ ciphertext`), decrypted
  as a unit on open. Bound to the vault via `volume.id` in the AEAD AAD; on open,
  every manifest-referenced id must be present (rejects a stale/swapped `.vol`).
  `parse_archive` is fully bounds-checked. Deleting a record or detaching a
  document reclaims its blob; attaching persists the record→doc link immediately.
  The archive path can be overridden (the `--vol` flag): `OpenVault` resolves and
  stores it once (`archive_path`), defaulting to `<vault>.vol`.
- **Resource limits:** the whole archive is read and decrypted in memory, so an
  upload over 64 MiB, or a total archive over 1 GiB, is refused with
  `VaultError::TooLarge` — checked against the file's reported size *before* it is
  read, so a hostile/corrupt `.vol` can't drive an unbounded allocation.
- **Backup** (`backup()`): copies the encrypted vault + `.vol` into a directory
  as a collision-safe, timestamped (`-YYYYMMDD-HHMMSS`) pair. No decryption.
- Cross-platform file hardening (`harden_file`/`harden_dir`/`write_new_*`,
  `pub(crate)` and reused by `main.rs`): 0600/0700 on Unix; on Windows it relies
  on the inherited per-user `%APPDATA%` ACL.

## 4. Cryptography (`crypto.rs`)

- **KDF:** Argon2id, 64 MiB / 3 / 1 defaults. Two passwords are chained:
  `k1 = Argon2id(pw1, salt1)`, `key = Argon2id(pw2, k1)`. Both required; order
  matters; neither verifiable independently.
- **AEAD:** XChaCha20-Poly1305, fresh 24-byte random nonce per write. The vault
  path uses `encrypt_with_nonce` so the nonce can be placed in the header and the
  **whole header authenticated as associated data** (`encrypt` — which picks its
  own nonce — is kept for the document archive, whose AAD is the `volume.id`).
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
is shown on unlock so a rollback is noticeable.

## 7. CLI (`main.rs`)

```
pass-mgr [VAULT]              graphical UI (READ-ONLY by default)
pass-mgr --write [VAULT]      writable (allow create/edit/delete/upload)
pass-mgr --tui [VAULT]        terminal UI (add --write to edit)
pass-mgr --vol PATH ...       use PATH as the document archive (default <vault>.vol)
pass-mgr decrypt [VAULT]      print the decrypted vault JSON (secrets!) to stdout
pass-mgr extract [VAULT] DIR  decrypt all documents into DIR (path-sanitized)
pass-mgr backup [VAULT] DIR   copy the encrypted vault + archive into DIR
```

`--vol`/`--volume` (with a following path, or `--vol=PATH`) is a position-
independent flag threaded into `OpenVault::open_with` / `create_with` and into
`export_documents` / `backup`. It overrides the default `<vault>.vol` archive
location for the UI, `extract`, and `backup` (it is irrelevant to `decrypt`,
which never touches the archive).

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

## 10. Planned redesign — partitioned storage (format v4)

Not yet built; authoritative spec in [`PLAN.md`](PLAN.md), design in `DESIGN.md`
§11. Planned module changes:

- **New `storage.rs`** — the partitioned engine: `Manifest`/`ManifestEntry`,
  `VolumeStore`; frame encode/decode, atomic manifest writes, lazy open/read,
  partition selection, the ordered crash-safe commit protocol, scan-rebuild, and
  the rekey staging/roll-forward.
- **`records.rs`** — drop the `Volume`/`volume` field from `Vault`; add
  `settings { volume_max_size }`; records keep doc-id refs (the id→location map
  moves to the manifests).
- **`vault.rs`** — `OpenVault` orchestrates `vault.pmv` + `storage`; `open` loads
  only manifests; document ops go through `storage`; `change_password` runs full
  re-encryption (stage + `READY` + roll-forward); `FORMAT_VERSION = 4`; an
  advisory single-writer lockfile; only harden dirs the app creates.
- **`main.rs`** — directory-based path; remove `--vol`; `decrypt` (vault),
  `manifest [--part N]` (one/all), `extract [--part N]` (one/all volumes); backup
  the whole tree.
- **`ui.rs`/`gui.rs`** — 256-byte path-limit enforcement, volume-size config,
  lighter theme, and the §11-folded security-review UI fixes.

Verification gate: the full §13 test catalog (incl. a fault-injection harness for
crash-safety), fuzzing the new parsers, mutation testing, then **two max-depth
multi-agent reviews** (bug hunt + security) with every confirmed finding fixed
before this doc is updated to as-built.

## 11. Definition of done

- `cargo build`, `cargo test`, `cargo clippy` clean on Linux; Windows
  cross-compile checks pass.
- All brief requirements + the later features (estate tabs, subtypes, review
  flags + filters, config screen, backup, extract, swap mitigation) met (see
  `DESIGN.md` §2).
- No `unsafe`, no network crates, secrets zeroized, key memory-locked.
