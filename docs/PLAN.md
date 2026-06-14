# pass-mgr — Execution Plan: Partitioned Volumes + Manifests (format v4)

_Status: APPROVED FOR EXECUTION (not yet implemented). Authoritative spec for the
storage-layer redesign. Author/owner: Michael. Created 2026-06-14._

This plan supersedes the single-`<vault>.vol` document store with a partitioned,
lazily-loaded, crash-safe volume + manifest design. It is written so it can be
executed in a later session step-by-step (§12).

---

## 0. Locked decisions

1. **Record fields:** keep the additions — Assets have `beneficiary`, `url`,
   `review`; Accounts have `account_subtype`, `review`. (Field list otherwise as
   in the spec: Instructions, Trust&Will, Assets/Liabilities, Accounts, Real Estate.)
2. **Category type lists** stay **inside the encrypted vault** (no external files).
3. **No compaction in v1.** Updates/deletes leave dead blobs as garbage in the
   volume; a separate crash-safe `compact` maintenance command is future work.
4. **Password change = full re-encryption** under a fresh key (Option A), done
   crash-safely (§7). No long-lived data-encryption key.
5. **CLI must decrypt all volumes** (extract every document across all
   partitions) — see §8.
6. **Format version → 4.** Pre-release: no auto-migration; v3 vaults are not
   read (a clear "unsupported version / please recreate" error).
7. **One key for everything.** The two-password chained Argon2id key encrypts the
   vault, every manifest, and every blob (each with its own nonce + AAD).

---

## 1. On-disk layout

The user supplies **only** a directory, `mypath`. All names below are fixed.

```
mypath/
├── vault.pmv              encrypted JSON vault (records, categories, settings, audit)
├── pass-mgr.lock          advisory single-writer lockfile (see §10)
├── manifest/
│   ├── manifest.0         encrypted manifest for partition 0
│   ├── manifest.1         ...
└── volume/
    ├── vol.0              append-only, per-blob-encrypted document log, partition 0
    ├── vol.1              ...
```

- The `--vol` flag is **removed** (the archive location is now fixed inside
  `mypath/volume/`).
- `pass-mgr DIR` opens the directory; if `vault.pmv` is absent and `--write` is
  given, a new vault directory is initialised.

---

## 2. File formats

### 2.1 Vault file `vault.pmv` (unchanged scheme, version 4)
61-byte plaintext header (magic `PMVAULT\0`, version=4, Argon2 m/t/p, salt, nonce);
**entire header is the AEAD associated data** (already implemented). Ciphertext =
XChaCha20-Poly1305 of the JSON `Vault`. The `Vault` JSON now holds:
- `version`, `generation`, `last_opened_at`, `audit`
- the five record collections (with all current fields)
- `categories` (the `TypeLists`)
- `settings { volume_max_size: u64 }` (configurable, default 256 MiB)
- Records reference documents by **doc-id only** (`TrustWill.file`,
  `AssetLiability.statement`). The **id → location** mapping lives in the
  manifests, not the vault (single source of truth for placement).
- The old `Volume` manifest field is **removed** from the vault.

### 2.2 Manifest `manifest.<N>` (encrypted, atomically written)
`nonce ‖ ciphertext`, AAD = `"PMVAULT-MANIFEST-v1" | vault_id | partition_N`.
Plaintext (JSON or length-prefixed) =
```
{ seq: u64,                 // monotonically increasing per partition
  end_offset: u64,          // committed valid length of vol.N (append point)
  entries: [ { id, virtual_path, size, blob_offset, blob_len, uploaded_at } ] }
```
Only **live** entries are listed; bytes in `[0, end_offset)` not covered by a live
entry are garbage (no compaction in v1). `end_offset` is authoritative for "where
valid data ends" regardless of any torn trailing bytes.

### 2.3 Volume `vol.<N>` (append-only, per-blob encrypted, self-describing)
A sequence of frames:
```
[u32 frame_len][nonce(24)][ciphertext]
```
- `frame_len` = length of `nonce ‖ ciphertext`.
- `ciphertext` = XChaCha20-Poly1305 of `serialize(doc_id, virtual_path, doc_bytes)`,
  AAD = `"PMVAULT-VOL-v1" | vault_id | partition_N | doc_id | virtual_path`.
- The id/path are **inside** the encrypted payload too, so the manifest can be
  **rebuilt by scanning the volume** (§3 recovery).
- A truncated/garbled trailing frame (len overruns EOF, or tag fails) marks the
  end of valid data; it is ignored and overwritten by the next append.
- `data_len`/offsets are bounds-checked (`<= isize::MAX`) so 32-bit `usize` casts
  can't wrap (review gap).

---

## 3. Crash-safety model — the commit protocol

Everything hinges on **ordered, individually-atomic writes** plus the rule that
the vault is the final source of truth.

**Add / update document** `D = (id I, path P, bytes B)` into partition `N`:
1. Seek `vol.N` to `manifest[N].end_offset` (truncating any torn tail), write the
   frame, **fsync(vol.N)**.
2. Write `manifest.N'` = entries + new entry, `end_offset += frame`, `seq += 1`,
   **atomically** (temp in `manifest/` → fsync → rename → fsync dir).
   ← *volume-layer commit point.*
3. Write `vault.pmv` atomically with the record→id link. ← *final commit point.*

**Delete:** remove the entry from `manifest.N` (atomic), then update `vault.pmv`.
Blob stays as garbage.

**Recovery on open:**
- Decrypt all manifests; per partition, treat `end_offset` as the valid extent
  (ignore bytes beyond it).
- Verify every doc-id referenced by a record exists in some manifest. Because the
  manifest commits **before** the vault, the only crash windows are:
  - blob appended but manifest not committed → blob beyond `end_offset` → ignored;
  - manifest committed but vault not → manifest entry not referenced by any record
    → harmless garbage.
  Either way the **last fully-committed state is intact** — at worst the in-flight
  update is lost. No partial/corrupt state is ever visible.
- If a manifest file is unreadable/bit-rotted, **rebuild it** by scanning its
  volume frame-by-frame (each frame self-describes id/path) up to the last
  decryptable frame.

This guarantees: *at all times consistent; on any crash/power loss, recover to at
least the state prior to the last update.*

---

## 4. Partitioning

- **Active partition** = highest-numbered partition with `end_offset <
  volume_max_size`.
- **New document:** if `active.end_offset + frame > volume_max_size`, create
  `vol.N+1` + `manifest.N+1` (write the empty manifest first, atomically), then
  append there.
- **Update of an existing document:** append the new version to the **same
  partition that holds the original** (locality requirement), updating that
  entry's offset/len; the old frame becomes garbage. Updates may push a partition
  slightly past the cap (the cap governs *new-document* placement only).
- `volume_max_size` is stored in the vault `settings`; default **256 MiB**;
  editable on the Config screen; changing it affects only future placement.

---

## 5. Lazy loading & lifecycle

- **On open:** decrypt `vault.pmv` + all manifests only. Build an in-memory index
  `id → (partition, offset, len, path, size)`. **Volumes are not opened.**
- **Read a document:** open `vol.<part>` read-only, seek, read one frame, decrypt,
  return bytes; close (small optional LRU of handles, **flushed and closed when
  idle**).
- **Write:** open `vol.<part>` append, write frame, fsync, close.

---

## 6. Path length limit

- Virtual path = `normalize(location) + "/" + filename`, limited to **256 bytes**.
- Enforced in three places: the core (`add_document` → `VaultError::PathTooLong`),
  the **GUI** (validate before attach; show error, block the button), and the
  **TUI** (reject on the upload key). Tests assert all three reject > 256.

---

## 7. Password change — full re-encryption (Option A), crash-safe

Goal: rotating the passwords produces a brand-new encryption under a fresh
key+salt, while a crash at any point leaves either the **old** vault fully
working or the **new** one fully working — never a mix.

Protocol ("stage + READY marker + roll-forward"):
1. Derive `new_key` from the new (pw1,pw2) + a fresh salt.
2. Stage a complete new tree in `mypath/.rekey/` (`vault.pmv`, `manifest/`,
   `volume/`), re-encrypting the vault, every manifest, and every blob under
   `new_key` (fresh nonces). fsync every file and the staging dirs.
3. Write `mypath/.rekey/READY` (fsync) — marks staging complete & valid.
4. **Commit by roll-forward:** move staged `volume/` and `manifest/` into place,
   then `vault.pmv` **last**; fsync dirs; remove `.rekey/`.

Recovery on open:
- `.rekey/` present **with** `READY` → a rekey was interrupted mid-commit →
  **finish the roll-forward** (idempotent), then remove `.rekey/`. New passwords.
- `.rekey/` present **without** `READY` → staging was incomplete → **discard**
  `.rekey/`; the live (old-key) tree is intact. Old passwords still work.
- No `.rekey/` → normal open.

The old data is never destroyed until the new tree is fully staged and marked
ready, so there is always one complete, openable generation.

> Cost note: rotation rewrites all volume data, so on a multi-GB vault it takes
> time proportional to the data. Accepted (estate vaults rotate rarely; this buys
> true "rotate to recover from a leaked password" semantics).

---

## 8. CLI / UX

Path is now a **directory**:
```
pass-mgr [DIR]                      graphical UI (READ-ONLY by default)
pass-mgr --write [DIR]              editable
pass-mgr --tui [DIR]               terminal UI
pass-mgr decrypt [DIR]             print the decrypted VAULT JSON to stdout
pass-mgr manifest [DIR] [--part N] print decrypted manifest(s): partition N, or ALL (default)
pass-mgr extract  [DIR] OUTDIR [--part N]
                                   decrypt documents to OUTDIR: ALL partitions
                                   (default) or only partition N
pass-mgr backup   [DIR] DESTDIR    copy the whole consistent tree (timestamped)
pass-mgr --help
```
Command-line decryption facilities (all read-only, no file mutation):
- **Vault** — `decrypt` prints the decrypted `vault.pmv` JSON (records,
  categories, settings, audit). *(the "same for vault" requirement.)*
- **Manifests** — `manifest` decrypts and prints the document index. With
  `--part N` it decrypts **only that one manifest**; with no flag it decrypts
  **all** manifests. *(the "specific manifest or all" requirement.)*
- **Volumes / documents** — `extract` is the "decrypt all volumes" facility: with
  no flag it iterates **every** manifest → every partition → every document,
  decrypting all volumes into OUTDIR (virtual tree reconstructed, path-sanitized);
  with `--part N` it decrypts **only that one volume/partition**.

Notes:
- `--vol` is removed. `backup` copies `vault.pmv` + `manifest/` + `volume/` as a
  consistent set (no decryption).
- Config screen gains the **volume-size** setting (write mode only).
- **Colors:** lighten the GUI theme (brighter panels/background).

---

## 9. Code / module changes

- **`records.rs`**: remove the `Volume`/`volume` field from `Vault`; add
  `settings: VaultSettings { volume_max_size }`. Records keep doc-id refs.
- **New `storage.rs`**: the partitioned engine — `Manifest`, `ManifestEntry`,
  `VolumeStore`: frame encode/decode, atomic manifest write, lazy open/read,
  partition selection, the §3 commit protocol, scan-rebuild, and the §7 rekey
  staging/roll-forward.
- **`vault.rs` / `OpenVault`**: orchestrates `vault.pmv` + `storage`; `open`
  loads manifests; `add/remove/read/export_document` go through `storage`;
  `change_password` runs the rekey protocol; `backup` copies the tree; bump
  `FORMAT_VERSION = 4`; only-harden-dirs-we-create (review finding).
- **`crypto.rs`**: reuse `encrypt_with_nonce`; distinct AAD builders for vault /
  manifest / blob.
- **`main.rs`**: directory path; remove `--vol`; `extract` across all partitions;
  optional create-time volume-size; advisory lockfile.
- **`ui.rs` / `gui.rs`**: 256-byte path enforcement; volume-size config control;
  lighten theme; remove single-vol assumptions; the review's UI fixes (§11).

---

## 10. Concurrency (review gap)

Add an advisory **lockfile** `mypath/pass-mgr.lock` taken on a writable open
(O_EXCL or OS advisory lock); a second `--write` instance fails fast with a clear
message. Read-only opens do not take the lock.

---

## 11. Security-review findings folded in (13 confirmed: all LOW/INFO)

**Superseded by this redesign:** archive-size-overhead lock-out (×2); virtual-dir
entries never reclaimed (no `Volume.directories` anymore); single-`.vol` size
checks.

**Fix during the redesign (or Phase 1):**
- Only `chmod 0700` directories the app **creates**, never a pre-existing
  user-chosen dir. *(vault.rs)*
- Wrap GUI/TUI **password buffers and clipboard copies in `Zeroizing`** so master
  passwords don't linger in freed heap. *(gui.rs, ui.rs — 3 items)*
- Gate the **`fuzz` module behind a `fuzzing` feature** so it isn't in the normal
  public API. *(vault.rs)*
- `safe_relative_path`: also neutralize **Windows reserved device names** and
  trailing dots/spaces. *(main.rs)*
- `arboard` with **`default-features = false`** (drop the unused image stack).
- Regenerate **`Cargo.lock`** (drop stale phf/rand entries).
- UI subtype fixes: egui filter omitting free-text subtypes; edit form can't
  re-select an out-of-list subtype; TUI doesn't reconstrain subtype on type
  change; form re-saves a removed category. *(gui.rs, ui.rs — 4 items)*
- Bounds-check `data_len <= isize::MAX` (32-bit `usize` safety).

**Other gaps to cover:** multi-process access (§10 lockfile); `getrandom` failure
surfaced clearly; cross-check DESIGN/IMPLEMENTATION after build; re-examine
Windows `harden_*` paths and `region` lock behavior.

---

## 12. Execution phases (ordered)

- **Phase 1 — quick wins (redesign-independent):** password/clipboard `Zeroizing`,
  `arboard` feature, `safe_relative_path` Windows hardening, UI subtype fixes,
  lighten theme, regenerate `Cargo.lock`. Commit.
- **Phase 2 — storage engine (`storage.rs`):** manifest + volume formats, the §3
  commit protocol, lazy load, partitioning, scan-rebuild. Unit + crash-injection
  tests (no UI wiring yet).
- **Phase 3 — vault integration:** `OpenVault` over `storage`; directory layout;
  `settings`; remove `Volume`; `FORMAT_VERSION = 4`; lockfile.
- **Phase 4 — rekey protocol (§7):** full re-encryption, stage + READY +
  roll-forward; crash tests.
- **Phase 5 — CLI:** directory path, remove `--vol`, `extract` across all
  partitions, `backup` tree, volume-size option.
- **Phase 6 — UI:** path-limit enforcement, volume-size config, wiring, theme.
- **Phase 7 — verification (testing, §13):** the full automated test catalog,
  fuzzing, and mutation testing.
- **Phase 8 — maximum-depth reviews (§14):** a max-depth bug-hunt code review and
  a max-depth security review (multi-agent workflows), then fix every confirmed
  finding and re-verify. Update DESIGN/IMPLEMENTATION to as-built only after this.

---

## 13. Testing (exhaustive — crash-safety is the priority)

The bar: **every commit-protocol step, every recovery path, every parser, and
every enforced limit has a dedicated test**, plus property-based and fault-
injection coverage. Target: line coverage ≥ 85% on `storage.rs`/`vault.rs`/
`crypto.rs`, and a *behavioral* guarantee (below) that survives mutation testing.

### 13.1 Crash-safety / fault injection (highest priority)
Build a **fault-injection harness**: a trait wrapping the file ops
(append/fsync/atomic-rename/dir-fsync) that can be told to **fail or "lose power"
after the Kth syscall**. Drive a workload through it crashing at every step, then
reopen with the real backend and assert recovery.

| Scenario | Expected after reopen |
|---|---|
| Crash after volume append, before manifest commit | blob beyond `end_offset` ignored; prior state intact; next append reuses the space |
| Crash during manifest temp-write (before rename) | old manifest still authoritative; no corrupt manifest ever observed |
| Crash after manifest rename, before dir fsync | manifest present (rename is atomic); consistent |
| Crash after manifest commit, before vault write | manifest entry = harmless garbage; vault unchanged; prior state intact |
| Crash during vault temp-write / before rename | old vault authoritative |
| Torn / partial trailing frame in a volume | ignored as end-of-valid-data; overwritten on next append |
| Multiple torn frames / random trailing garbage | `end_offset` from manifest is honored; data intact |
| Corrupt or zero-length manifest file | rebuilt by scanning the volume; all committed blobs recovered |
| Corrupt volume frame mid-file (bit flip) | tag fails closed; rebuild stops at last good frame; no panic |
| Rekey interrupted, `READY` present (each sub-step) | roll-forward to new key; new passwords open; no data loss |
| Rekey interrupted, `READY` absent (each sub-step) | staging discarded; old passwords still open the intact old tree |
| **Randomized crash fuzz** | for N random workloads × random crash points, reopen always yields a consistent state equal to *some* committed prefix (never partial/corrupt) |

### 13.2 Storage engine unit tests
- Manifest encode/decode round-trip; AAD binding (wrong partition/vault-id → fail).
- Volume frame encode/decode round-trip; self-describing id/path recoverable.
- `end_offset` accounting across add/update/delete.
- Partition selection: fills to `volume_max_size` → rolls to `vol.N+1`; update
  lands in the **same** partition as the original; new doc in the active one.
- Lazy load: open touches only manifests (assert volumes unopened via the harness);
  read opens+closes the right volume; idle flush/close.
- `data_len`/offset bounds (`> isize::MAX` rejected; no `usize` wrap).

### 13.3 Crypto / format
- Re-run and extend the header-AAD tamper tests; per-blob and per-manifest AAD
  tamper tests (flip vault-id/partition/path → decrypt fails).
- Nonce uniqueness across many writes; wrong key/password fails closed.
- Rekey: after change_password, old key fails everywhere, new key opens vault +
  every manifest + every blob.

### 13.4 Property-based (add `proptest` dev-dependency)
- Round-trip: `parse(serialize(x)) == x` for manifests and frames over arbitrary
  inputs.
- Invariant: arbitrary sequences of add/update/delete leave the index, manifests,
  and referenced blobs mutually consistent; every referenced doc is readable.
- Path normalization/limit is idempotent and never yields an escaping path.

### 13.5 Fuzzing (extend `fuzz/`)
- Existing: `parse_header`, `parse_archive`.
- New targets: `parse_manifest` (decrypted manifest bytes), `parse_frame`
  (volume frame), and `scan_volume` (rebuild path over arbitrary bytes).
- Invariant: never panic / OOM / hang; only `Ok`/`Err`. Run in CI for a fixed
  budget; keep a seed corpus + any regression crashes.

### 13.6 Mutation testing
- `cargo mutants` on `storage.rs`, `vault.rs`, `crypto.rs`, `records.rs`,
  `types.rs`, `password.rs`. Triage every survivor; add a killing test or a
  documented `// reason` skip. (Records boilerplate may be scoped out for time.)

### 13.7 Path-limit enforcement
- 256-byte virtual path rejected in **core** (`PathTooLong`), **GUI** (button
  blocked + error), and **TUI** (upload key rejected); boundary cases (255/256/257,
  multibyte UTF-8, deep `location` + long filename).

### 13.8 CLI
- `decrypt` prints vault JSON, mutates nothing.
- `manifest` with `--part N` (one) and without (all); bad N errors cleanly.
- `extract` all partitions vs `--part N`; multi-partition tree reconstructed;
  path sanitization (incl. Windows reserved names, traversal) holds.
- `backup` copies a consistent tree; the backup re-opens with the same passwords.
- Two concurrent `--write` opens → second fails fast (lockfile).

### 13.9 UI (both front-ends)
- TUI: key-driven harness + `TestBackend` render of every screen; read-only keys
  inert; field-index mapping correctness; selection-by-id under filters edits the
  right record; subtype reconstrained on type change; path-limit rejection.
- GUI: deferred-action methods directly; read-only gating; subtype filter
  includes free-text; out-of-list subtype re-selectable; volume-size config;
  clipboard auto-clear; password buffers are `Zeroizing`.

### 13.10 Cross-platform & regression
- `cargo check --target x86_64-pc-windows-gnu`; Windows `harden_*`/path paths
  exercised where possible.
- A regression test per **security-review finding** in §11 so none recurs.

---

## 14. Maximum-depth reviews (mandatory gates, after Phase 7)

Two independent multi-agent reviews (`Workflow`), each: **parallel reviewers per
dimension → every finding adversarially verified by ≥2 skeptics (default-to-
refuted) → completeness critic → synthesis**. Every *confirmed* finding is fixed
and re-verified before the docs are marked as-built.

### 14.1 Maximum-depth code review (bug hunt)
Dimensions: crash-safety/commit-ordering correctness; the rekey roll-forward state
machine; partition-selection and `end_offset` arithmetic; frame/manifest parser
bounds & integer casts; lazy-open lifecycle (leaked/again-opened handles, double
-fsync, fd exhaustion); error-path rollback; data-model logic (upsert/remove/diff,
doc-id↔manifest consistency); UI state machines; concurrency/lockfile races;
panics/`unwrap`/indexing on any input. Goal: find correctness bugs, not just
security ones.

### 14.2 Maximum-depth security review
Dimensions: KDF & full-rekey key handling; AEAD/AAD binding for vault, manifests,
and blobs (any unauthenticated field? cross-partition/cross-vault confusion?);
nonce management at scale (collision risk across many blobs/rekeys); secret
zeroization across the new buffers and the staging tree; path traversal &
`extract` sanitization; filesystem TOCTOU/symlink on the new dirs and the rekey
swap; resource limits (volume size, frame size, manifest size — DoS); supply
chain (`cargo audit`/`cargo deny`); the threat-model boundary. Adversary model:
holds the files and/or a crafted vault/manifest/volume; does **not** hold the
passwords; host-compromise-while-unlocked out of scope.

> A prior deep security review of the *pre-redesign* code returned 13 confirmed
> findings — all LOW/INFO, no critical/high — folded into §11. These §14 reviews
> re-run at full depth against the **new** storage layer.
