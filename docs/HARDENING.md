# Hardening Report

_Adversarial security review, mutation testing, fuzzing, and supply-chain audit of
the estate-vault codebase (workspace: `pass-mgr-core`, `pass-mgr-desktop`,
`pass-mgr-ffi`, and the Compose Multiplatform `mobile/` viewer)._

> **Scope and honesty.** This report describes the assurance work performed and the
> defects it found and fixed. It is **not** a proof that the code is bug-free — no
> such proof exists for software of this size. What it does establish is that several
> independent, adversarial techniques were pointed at the code, the defects they
> surfaced were fixed, and the result is reproducible from the commands in the
> appendix. The cryptographic trust base is unchanged: the security of a vault still
> rests on the two passwords and on the audited [`RustCrypto`](https://github.com/RustCrypto)
> primitives, not on any code added during this pass.

## 1. Summary

| Layer | Result |
| --- | --- |
| Adversarial security review (7 rounds incl. a 152- and a 159-agent deep hunt, an overnight 3-phase autonomous sweep, a dynamic-verification round, and a full-crate mutation round) | **36 real defects found and fixed** (F-1…F-15 + round-4 R-1…R-14 + round-5 A-1…A-8 + round-6 B-1…B-2; 7 HIGH total, the rest MED/LOW); candidate findings in §3.2 investigated and refuted |
| Mutation testing (`cargo-mutants`) | round-7 **whole-crate** run: **1629 mutants → 107 survived → 37 kill-tests** close the meaningful ones (suite 226→263); the rest are accepted residual (fault-injection scaffolding, fuzz entries, the un-killable `Key::drop`, proven equivalent mutants, unobservable fsync side-effects) — see §3.1g |
| Fuzzing (`cargo-fuzz`, 5 targets incl. `doc_paths`) | **≈183 M cumulative + ~67 M round-6, 0 crashes** |
| Supply-chain (`cargo-audit` + `cargo-deny`) | **0 advisories across 595 deps; bans/licenses/sources clean** (re-confirmed round 5) |
| Lints (`cargo clippy -D warnings`, all targets/features) | **clean** |
| Test suite | **core 263 · ffi 32 · compat 4 · desktop 75 + 20 — all green** (incl. an exhaustive every-byte vault-tamper matrix; debug + `--release`; `--no-default-features` swaps the single-writer test for the no-op-lock test) |

The cryptographic envelope was never broken: across seven rounds no finding lets an
attacker read a vault they could not already open. The fixes harden secret hygiene
(plaintext password lifetime / display / clipboard auto-clear / momentary reveal),
open-time DoS resistance, untrusted-import path safety (incl. a symlink-TOCTOU
arbitrary-file read), deletion durability, **rekey crash-durability**, backup
integrity, FFI **and desktop** no-oracle parity, iOS clipboard/snapshot parity, and a
destructive-CLI footgun — see §3.1 / §3.1b / §3.1c / §3.1d / §3.1e / §3.1f / §3.1g.
Rounds 6–7 added a **dynamic-verification** layer (fuzzing, an exhaustive every-byte
tamper matrix, and full-crate mutation testing) on top of the static review.

## 2. Assurance layers applied

1. **Adversarial security review** — re-read the new attack surface (Real Estate
   portal credentials, Taxes filing documents, the multi-document folder helpers, the
   UniFFI boundary, and the mobile viewer) specifically looking for ways to *break* it:
   secret leakage, oracles, path traversal, DoS, downgrade, and TOCTOU.
2. **Mutation testing** — `cargo-mutants --in-diff` against the new-code diff to find
   logic that no test actually pins down (mutants that survive = untested behaviour).
3. **Fuzzing** — `cargo-fuzz` targets over the byte-level parsers (vault header,
   volume frame, partition manifest, whole-volume scan) where untrusted input is decoded.
4. **Supply-chain** — `cargo-audit` against the RustSec advisory DB over the full
   dependency tree, including the new mobile/FFI dependencies.
5. **Lints** — `clippy -D warnings` across all targets and all features.

## 3. Security review findings

### 3.1 Confirmed and fixed

#### F-1 (Low) — Real Estate portal password buffers reallocated on each keystroke

* **Where:** `crates/pass-mgr-desktop/src/gui.rs`, Real Estate edit tab.
* **What:** The three portal password edit buffers (`property_mgmt_password`,
  `insurance_password`, `hoa_password`) started empty and grew as the user typed.
  Each `String` growth reallocates, and the old backing buffer is freed **without
  zeroization**, scattering plaintext password fragments across freed heap that may
  persist until overwritten (and can reach swap or a core dump).
* **Why it matters:** Same class of leak the Accounts password field already mitigates.
  Low severity: requires local memory access and only yields *fragments*, but it is a
  gratuitous secret-lifetime extension.
* **Fix:** Pre-`reserve(128)` the three buffers (mirroring the existing Accounts-field
  mitigation) so normal typing never grows — and therefore never reallocates and
  leaks — them.

#### F-2 (Medium) — Mobile clipboard auto-clear timer died with the field

* **Where:** `mobile/composeApp/src/commonMain/kotlin/com/passmgr/App.kt`.
* **What:** Copying a password to the clipboard scheduled a 15-second auto-clear from a
  `LaunchedEffect` **scoped to the password-field composable**. Navigating away from the
  detail screen (or locking the vault) before the timer fired *cancelled* the effect,
  so the clipboard was never cleared — the password sat on the system clipboard
  indefinitely, readable by any app or by paste-history.
* **Why it matters:** The clipboard is a shared, cross-app surface; on mobile it is one
  of the most realistic password-exfiltration paths. Medium severity.
* **Fix:** Lifted the auto-clear to a single **App-scoped** `LaunchedEffect` keyed on a
  monotonic `clipboardToken`, so the 15-second clear survives navigation; and the
  clipboard is **wiped immediately on lock**. Threaded a single `onCopy` callback
  through `VaultScreen → DetailScreen → PasswordField`, removing the per-field timer.

### 3.1b Second round — a follow-up adversarial bug hunt over the feature surface

A second multi-agent hunt (6 finders × 3 skeptics per finding, default-refute) over the
least-audited code found two more **confirmed HIGH** defects (one false positive was
filtered out). Both are fixed, with a sweep confirming neither pattern recurs elsewhere.

#### F-3 (High) — TUI Ctrl+Y / Ctrl+G acted on the *first* password field, not the focused one

* **Where:** `crates/pass-mgr-desktop/src/ui.rs` (edit-key handler).
* **What:** Copy-password (`Ctrl+Y`) and generate-password (`Ctrl+G`) located the field
  with `fields.iter().find(|f| matches!(f.kind, Password))` — the **first** password
  field, ignoring the focused field. Harmless on Accounts (one password), but the Real
  Estate tab has **three** portal password fields (Property Mgmt / Insurance / HOA). So
  `Ctrl+Y` while editing the Insurance or HOA login **copied the Property Mgmt password**
  to the OS clipboard (wrong secret, cross-portal leak), and `Ctrl+G` always regenerated —
  i.e. silently overwrote — the Property Mgmt password, so the other two could never be
  generated from the keyboard.
* **Why it matters:** A real secret reaches the OS clipboard / a different secret is
  destroyed, both on a documented on-screen keybinding. High.
* **Fix:** New `target_password_index(fields, focus)` helper — prefer the focused field
  when it is a password, else fall back to the first. Both handlers use it. The egui GUI
  was already correct (each portal has its own per-field copy button). Regression test
  `copy_generate_target_the_focused_password_field`.

#### F-4 (High) — Android config change discarded the clipboard auto-clear timer

* **Where:** `mobile/.../App.kt` + `androidMain/AndroidManifest.xml`.
* **What:** Even after F-2 lifted the auto-clear to App scope, `clipboardToken` lived in
  plain `remember` and the timer in a `LaunchedEffect`. The activity declared no
  `configChanges`, so a routine config change (rotation, dark/light toggle, locale, font
  or display size, split-screen) **recreates the activity**, discarding the `remember`
  state and cancelling the wipe coroutine — leaving the copied password on the clipboard
  with no timer to clear it.
* **Why it matters:** Same clipboard-exfiltration surface as F-2, re-opened by an everyday
  UI event. High.
* **Fix:** `clipboardToken` is now `rememberSaveable` (survives recreation → the fresh
  composition re-arms the wipe; reset to 0 after wiping / on lock), **and** the activity
  declares `android:configChanges` for the common triggers so it is not recreated for them
  in the first place. (The unlock password fields stay on plain `remember` by design —
  persisting a typed password into the saved-state bundle would itself be a leak.)

### 3.1c Third round — 152-agent deep hunt (9 lenses → 3-skeptic verify → critic → round 2)

The deepest pass yet: 9 parallel finder lenses (crypto, I/O & crash safety, untrusted
parsers, path traversal, FFI memory, secret hygiene, logic/UI, concurrency, supply chain),
each finding adversarially verified by 3 independent skeptics (default-refute, survives only
on ≥2 confirmations), then a completeness critic + a targeted second round. **28 findings
survived verification; deduplicated to 14 root causes.** A separate dynamic pass corroborated
the static review: extended fuzzing (~183 M execs across all five parsers, 0 crashes) and a
fresh `cargo audit` + `cargo deny` (clean). One HIGH and all confirmed MED/LOW items below are
fixed; the synthesizer's flagged false-positives are listed in §3.2.

| # | Sev | Fix |
| --- | --- | --- |
| F-5 | **High** | **Password history shown in cleartext, bypassing the reveal/mask toggle.** The history pane rendered `Change.detail` verbatim — `password: "old" -> "new"` — even with the field masked. New `records::display_detail` masks any password-field history line (`<hidden> -> <hidden>`, field name kept) in BOTH UIs; you cannot copy from history, so values are never needed there. |
| F-6 | Med | **Redundancy recovery buffered every candidate at once** (up to ~11 × 256 MiB → open-time OOM). `decrypt_with_redundancy` is now two-pass: a header-only salt scan, then one candidate buffer in memory at a time (`read_header_of` + bounded loop). |
| F-7 | Med | **`backup()` copied the live tree with no write lock** → a concurrent rekey could yield an unopenable backup. It now holds `WriteLock` for the whole snapshot (fails `Locked` rather than risk corruption). |
| F-8 | Med | **`is_safe_blob_id` allowed Windows ADS / drive-relative / device-name ids** on untrusted-mirror import. Tightened to an ASCII-hex allowlist (real ids are 32-hex), which also rejects `:`, device names, dots/spaces, control bytes. Untrusted `ManifestEntry.path` is now control-byte-validated too (`is_safe_doc_path`). |
| F-9 | Med | **CLI value-flags (`--backup`/`--history-before`) could swallow the vault-dir positional**, silently retargeting destructive `compact` onto the default vault. New `compact_target` refuses the implicit default when a value-flag is present, and the resolved target is echoed before any prompt. |
| F-10 | Med | **Clipboard not marked sensitive.** Linux now sets arboard's `exclude_from_history` hint (shared `copy_secret_to_clipboard`); Android marks the clip `EXTRA_IS_SENSITIVE` and the activity sets `FLAG_SECURE` (no plaintext in the 13+ paste preview, screenshots, or recents). |
| F-11 | Low→Med | **KDF param ceiling too high (pre-auth OOM) + write path didn't validate.** Bounds moved onto `KdfParams::validate()` (m_cost ceiling 1 GiB → 512 MiB, t_cost 64 → 16), now called on BOTH `Header::parse` (read) and `create`/`import_tree` (write) so a vault can't be written that the reader would refuse. |
| F-12 | Low | **FFI `open_vault` left passwords un-zeroized on a panic-unwind.** pw1/pw2 are now bound in `Zeroizing` on entry (wiped on every exit). The crate disclosure is also expanded to be honest that the UniFFI record DTOs / RustBuffer can't be zeroize-on-drop. |
| F-13 | Low | **Keep-visible-on-save ignored the review-only and username-search filters** → a just-saved account vanished. Both now relaxed for the saved record (GUI + TUI). |
| F-14 | Low | **`copy_dir` (backup) followed source symlinks** (`is_dir`/`fs::copy` dereference). Now uses `read_dir` file-type and refuses symlink entries. |
| F-15 | Low | **Single-instance lock degraded to unguarded on a planted symlink** (ELOOP). `acquire_in` now removes the junk entry and retries once. |
| — | Low | **CI/policy hardening:** `overflow-checks = true` in `[profile.release]` (fail-closed on overflow), `wildcards = "deny"` (+ `allow-wildcard-paths`) in `deny.toml`, a release-mode test job, and `cargo deny` + the `doc_paths` fuzzer made standing CI checks. |

### 3.1d Fourth round — 159-agent HARDCORE hunt (bypass-the-fixes + 12 lenses → exploit-PoC → 3-skeptic verify → loop)

The meanest pass yet: a dedicated **bypass phase** attacking the round-3 fixes, then 12 deeper lenses (FFI-focused) where every candidate had to ship a concrete PoC that an exploit-validation agent traced line-by-line before three skeptics voted (default-refute, "not-already-fixed" + "gain over the dir-write baseline" required). **20 findings survived → 14 root causes**, all exploit-validated. The honest verdict was "the codebase is hardened, but here are real, non-obvious wins." All confirmed items fixed:

| # | Sev | Fix |
| --- | --- | --- |
| R-1 | **High** | **`import_tree` symlink TOCTOU.** `read_capped` stat-checked for a symlink, then `read_bounded` did a separate `File::open` that FOLLOWS links — a winnable race laundering an arbitrary file (e.g. `/etc/shadow`) into the importer's vault. `read_bounded` now opens with `O_NOFOLLOW` (unix), closing the race at the open (matching `append_frame`). |
| R-2 | **High** | **Deleted-document resurrection made permanent.** A lazy delete left the frame; a manifest-loss rebuild re-admitted it and `compact` baked it in. Added an authenticated **deletion tombstone** (`Vault::deleted_docs`, `serde(default)`): `remove_document` records the id; the doc readers suppress a resurrected frame; `staged_rewrite` drops tombstoned frames and clears the set. (Compatible with the deliberate "compaction never silently drops a not-yet-reclaimed orphan" guarantee — it keys on `remove_document`, not on record-references.) |
| R-3 | Med | **FFI correct-password oracle.** `ArchiveMismatch` had a distinct variant reachable only AFTER a correct-password decrypt, so it discriminated correct vs wrong passwords. Folded into `WrongPasswordOrCorrupt`; variant removed. |
| R-4 | Med | **`backup()` followed a symlinked source `vault.pmv`** (F-14 only guarded `copy_dir`). The snapshot now rejects a symlink at the source file. |
| R-5 | Med | **Unicode bidi/zero-width bypass** of `is_safe_doc_path`/`doc_filename` (`is_control` is Cc-only). New `is_spoofy_format_char` rejects U+200B–200F / 202A–202E / 2060 / 2066–2069 / FEFF (RLO label spoofing). |
| R-8 | Med | **Volume-truncation version rollback.** A mirror listing one id twice left two frames for it (the rollback precondition). `import_tree` now rejects duplicate ids across the whole mirror. |
| R-9 | regression | **In-app Backup self-deadlocked** on the session's own `WriteLock` (my F-7). Added `OpenVault::backup` that reuses the held lock (read-only opens acquire one); the free `backup` keeps acquiring for the CLI. GUI/TUI call the method. |
| R-11 | Low | **`is_safe_blob_id` accepted UPPERCASE hex** → case-insensitive-FS export collision. Now lowercase-hex only. |
| R-12 | Low | **`recovery_notice` false "data lost" alarm** after a rekey/compact `bak1` (which is current-gen). Reworded to the honest "the most recent change may be missing" for both mirror and bak recoveries. |
| R-6/R-13/R-14 | Med/Low | **iOS parity** (committed source; build-verify on a Mac): `copySecret` → `UIPasteboard.setItems` with `LocalOnly`+15 s expiry (no Universal-Clipboard broadcast); SwiftUI `scenePhase` opaque overlay (no app-switcher snapshot of secrets); real per-file `FileProtectionType.complete` + removed the no-op `NSFileProtectionComplete` Info.plist key. |
| R-7 | Low | **egui secret residue — ACCEPTED RESIDUAL (documented).** Stock `TextEdit` keeps un-zeroized undo snapshots and a revealed field's built-in Ctrl+C bypasses the clipboard hint. Both need local process-memory / clipboard-history access. A full fix needs a custom password widget + interactive GUI verification; mitigations in place (hardened 📋 copy button, `ZeroizeOnDrop`, reveal re-masks on tab switch). |

Dropped as non-security: `extract --part` swallowed-positional footgun (operator-only, needs the operator's own passwords; `cli_extract` already echoes the target).

### 3.1e Fifth round — overnight autonomous multi-agent audit (bugs → security → deep bugs)

A three-phase sweep: a bug hunt (correctness/panics/data-loss), then a security hunt
(crypto, oracle/timing, untrusted input + supply chain, secret leakage), then a deeper
bug hunt (crash-recovery/concurrency state machines, degenerate-data/panic fuzz-by-reason,
desktop cross-frame state). Each phase fanned out parallel analysis agents; every finding
was verified against the source before fixing. The codebase held up well — most lenses came
back clean or by-design — but the deep crash-safety pass found a real **HIGH** durability
bug, and the secret-hygiene pass found a real **HIGH** clipboard leak (the round-4 R-7
"accepted residual", now actually fixed). All confirmed items fixed:

| # | Sev | Fix |
| --- | --- | --- |
| A-1 | **High** | **Rekey commit was not crash-durable.** `commit_rekey` renamed `volume/` → `manifest/` → `vault.pmv` then fsync'd the parent dir only ONCE at the end; `replace_dir`/`replace_path` fsync'd nothing. On a power loss the rename metadata can reach disk out of program order, leaving a **new-key `vault.pmv` durable while `volume/`+`manifest/` are still old-key** — an unopenable vault the roll-forward can't repair (the abort-based crash tests don't model page-cache loss, so they missed it). Fixed: `replace_dir`/`replace_path` now `sync_parent_dir` after each rename, so new-volume-durable-before-new-manifest-before-new-vault is enforced. |
| A-2 | **High** | **Built-in Ctrl+C/cut of a secret field never auto-cleared.** A focused password (account, RE portal, **or the master-password unlock/create/change fields**) copied via the OS Ctrl+C / cut / context-menu was rerouted through the hardened (history-excluded) clipboard path, but — unlike the 📋 button — never armed the 15 s auto-clear or the on-exit wipe, so it lingered on the clipboard indefinitely. (This is round-4 **R-7**, previously accepted as residual.) Fixed: `secret_text_edit` surfaces the intercepted secret to the caller, which routes it through `copy_to_clipboard` (hardened copy **+** armed clear), unifying it with the button path; the auth screen arms it too. |
| A-3 | Med | **Desktop unlock correct-password oracle.** The GUI/TUI showed a distinct message for `ArchiveMismatch`/`Json`/`Storage` — failures reachable ONLY after a successful (correct-password) decrypt — vs the generic `Crypto` (wrong password), so a dir-write attacker who pre-broke the archive could tell when a guessed password was right. (Same class the FFI closed as R-3.) Fixed: all correct-password-reachable failures collapse to one "wrong password or corrupted/unreadable vault" message; password-INDEPENDENT structural errors (bad magic/version/truncated/params/too-large, not-found, locked, rekey-pending) keep their specific, useful messages. |
| A-4 | Med | **`tick_clipboard` masked a save failure.** The 15 s auto-clear set `status = "Clipboard cleared."` unconditionally, so an idle-repaint wipe could silently overwrite a `"Save failed: …"` the user hadn't seen (both front-ends). Fixed: only replace a blank or the prior `"Copied …"` notice. |
| A-5 | Low | **`import_tree` symlink guard covered only the leaf.** `read_capped`/`read_bounded` apply `O_NOFOLLOW` to the final component, so a symlinked intermediate `manifest/`, `volume/`, or `vol.<p>/` in an untrusted mirror could still redirect reads outside it (id is hex-constrained, so exfiltration is limited, but it broke the symlink-guard invariant). Fixed: new `reject_symlink_dir` on every intermediate mirror directory. |
| A-6 | Low | **`export_tree` didn't validate the blob id it uses as a filename.** The import side enforces `is_safe_blob_id`; export joined `e.id` into the output path without it. Fixed: the same lowercase-hex allowlist on the write side (symmetry; closes the gap if any future path ever admits a stray id). |
| A-7 | Low | **Grouped-tree expand-state key collisions.** The GUI salted each `CollapsingHeader` id with a `/`-joined label path and the TUI keyed `acct_expanded` with a `\x1f`-joined string, so two distinct group paths could collide (owner `"a/b"` vs owner `"a"` + type `"b"`) and share expand state. Fixed: the GUI hashes the label-stack **slice** and the TUI keys on a `Vec<String>` label stack — collision-free. |
| A-8 | Low | **Unchecked `u64` arithmetic in `storage.rs`** (`end_offset` add, partition-fit add, `space_stats` sums). Not attacker-reachable (values are post-AEAD), but inconsistent with the module's `checked_add` discipline and would PANIC (DoS) rather than wrap under `overflow-checks = true`. Fixed: `saturating_add`, matching the rest of the module. |

**Dynamic corroboration:** `cargo audit` (0 advisories, 0 yanked) and `cargo deny check` (advisories/bans/licenses/sources ok) re-run clean; no networking crate in the tree. The cryptographic core was re-verified end-to-end (fresh random nonce on every encrypt/save/frame, fresh salt per KDF, whole-header AAD, vault-id+partition-bound frame AAD, genuine two-password Argon2id chaining, `Zeroizing`/`mlock` key handling, CSPRNG-only randomness, params validated on both read and write, constant-time AEAD tag check) — no change needed.

### 3.1f Sixth round — dynamic verification (mutation testing + fuzzing + exhaustive tamper) + fix re-audit

Where rounds 1–5 were *static* multi-agent review, this round moved to **dynamic verification** — executing adversarial inputs rather than reasoning about them — plus an adversarial re-audit of the round-5 fixes (new code is where regressions hide). Tools actually run, not just cited:

- **Mutation testing** (`cargo-mutants` 27.1) over this session's security-core diff: **44 mutants → 4 missed, 38 caught, 2 unviable**. The 4 survivors were ALL the `+` operators in `trim_all_records`'s seven-term sum — behaviour no test pinned because the test left most tabs at count 0. Killed by strengthening the test to put one dirty record in **every** collection: the expected total (7) then changes under any `+`→`-`/`*` mutation of any term, so all four arithmetic survivors are pinned by construction (confirmed by a targeted `cargo-mutants` re-run over `trim_all_records`). The round-5 fsync, symlink-guard, export-validation, `saturating_add`, and tree changes were all already caught.
- **Fuzzing** (`cargo-fuzz`, libFuzzer+ASan) — a fresh run of all five parser targets (`parse_header`, `parse_frame`, `parse_manifest`, `scan_volume`, `doc_paths`): **~67 M executions this session, 0 crashes / panics / leaks / OOMs** (atop the ~183 M cumulative).
- **Exhaustive tamper matrix** (new test `every_single_byte_flip_of_a_valid_vault_is_rejected_without_panic`): flips both the low and high bit of **every byte** of a valid `vault.pmv` and asserts `OpenVault::open` fails closed over the WHOLE path (parse → KDF → AEAD → JSON → referenced⊆stored) — never a panic, never a silent accept. This generalises the prior 3-offset header-tamper test to the entire file (header-as-AAD + ciphertext + Poly1305 tag).

Two real fixes landed from the re-audit; the round-5 fixes themselves were confirmed regression-free.

| # | Sev | Fix |
| --- | --- | --- |
| B-1 | Med | **`reveal_all` / `re_reveal_all` were sticky across tab switches.** The per-record `reveal_pw` is re-masked on every tab change, but the two screen-level "reveal all" toggles were not — so a reveal-all left on in one tab silently persisted into a later visit, exposing every password to a bystander (it stayed scoped per screen, so not a cross-tab leak — just a stale sticky reveal). Both UIs now clear all three reveal toggles on tab switch (GUI `ui_top_bar`; TUI a new `switch_tab` helper routing every tab-change key). |
| B-2 | Low | **`staged_rewrite` silently defaulted a doc's path on an index/manifest desync.** `entry(id).map(...).unwrap_or_default()` would, if the in-memory index and on-disk manifest ever disagreed, re-encrypt a document into the compacted/rekeyed store with an EMPTY path and `uploaded_at = 0` — silent metadata corruption with no error. Currently unreachable (`reindex` keeps them in sync), but now **fails closed** with a `Corrupt` error instead of defaulting, so a future desync can't bake in bad metadata. |

### 3.1g Seventh round — full-crate mutation testing & survivor closure

A **whole-crate** `cargo-mutants` run over `pass-mgr-core` (not just a diff): **1629
mutants → 107 survived** (behaviour no test pinned). A 9-agent workflow authored
**37 targeted kill-tests** (one cluster per function; each test crafted to fail under
its specific mutation and pass on real code, most verified by the authoring agent
applying the mutation via `sed` and re-running). The core suite went **226 → 262**,
all green, clippy clean. The kill-tests close the meaningful survivors:

| Area | Survivors killed |
| --- | --- |
| `password` | `generate` length-cap boundary; Fisher-Yates inclusive swap partner (`uniform(i+1)`). |
| `records` | `acct_match` exact-filter semantics (`==`/`\|\|`); `history_stats` cutoff (`<` vs `<=`); `parse_ymd_utc` year-range guard; `doc_filename` length boundary. |
| `storage` | exact size-cap constants; `put` doc-size cap; `load_manifest` truncation/oversize bounds; `VolumeStore::open` corrupt-manifest rebuild-vs-propagate guards; `read_frame_at` EOF/overrun/plausibility bounds; `write_atomic` temp-in-dir; blob mode 0600. |
| `vault` | KDF-bound + `MAX_*` constants; `import_tree` vault-id length/empty/charset boundary; `add_document` size cap; accessors (`redundancy`/`opened_generation`/`previous_access`/`export` return real values, not constants); `read_bounded`/`read_file_capped`/`read_capped_vault` cap + `NotFound` guard; `save_internal` heal; `staged_rewrite` empty-store; `backup_snapshot` collision counter; `harden_file`/`harden_dir` perms (0600/0700). |

**Confirmation method.** A full single-pass *re-run* to re-verify all 1629 is
impractical in this environment (background tasks are wall-clock-limited to ~15–20 min;
a full run needs hours — the heavier post-fix suite makes it worse). The kills were
instead confirmed by three independent means: (1) a partial re-run fully processed
`crypto`/`password`/`records` and showed **every** targeted survivor there now caught
(only the accepted-residual below remained); (2) the authoring agents machine-verified
storage/vault kills by applying each mutation; (3) a **function-scoped** re-run over the
targeted storage/vault functions reported **0 MISSED**.

**Accepted residual survivors (deliberately not killed — documented, not gaps):**

- **Fault-injection scaffolding** (`fault.rs`, 15): only exercised by the crash-recovery
  tests under `--features fault-injection`; the default-feature mutation run can't reach
  them. (A separate `--features fault-injection` mutation pass would cover them.)
- **Fuzz entry points** (4): `storage::fuzz::{manifest,frame,scan_volume}`,
  `vault::fuzz::header` — `#[doc(hidden)]` harnesses exercised by `cargo-fuzz`, not unit
  tests.
- **`Key::drop` destructor** (1): zeroize-on-drop can't be observed by a safe test
  (reading the freed bytes would be UB) — inherently un-killable (also noted in §4).
- **Proven equivalent mutants** (5): `uniform` (line 145 `+`→`-`/`*`, line 152 `<`→`<=`)
  — `zone` is always a whole multiple of `n`, so the mutation only shifts the
  *unobservable* rejection rate by ≤2 draws in 2⁶⁴ and never biases the output;
  `doc_filename` (lines 314/316 `>`→`>=`) — produces byte-identical output at the
  boundary. No black-box test can distinguish these from the original.
- **Unobservable side-effects / edge fallbacks** (~18): `sync_dir`/`sync_parent_dir`→()
  (an `fsync` leaves no test-observable trace), the `!parent.is_empty()` "use `.`"
  guards in `parent_dir`/`with_suffix`/`sibling_old`/`sibling_tmp` (only the
  bare-filename edge), `rand_suffix`→constant (temp-suffix uniqueness isn't
  deterministically testable), and `compaction_detail`→const string (a cosmetic status
  message).
The three "follow-up candidates" were then each resolved (one killed, two shown to be
non-gaps on closer inspection):

- `sweep_stale_temps` (`&&`→`||`) — **killed** by `mut_sweep_stale_temps_needs_prefix_and_tmp_suffix`
  (verified: a file matching only one clause — an unrelated `*.tmp`, or a non-`.tmp`
  `.vault.pmv.*` sibling — must survive the sweep; the test fails under `||`).
- `WriteLock::acquire` → `Default` — **not a gap**: the survivor is at the
  `#[cfg(not(feature = "single-writer-lock"))]` *no-op* stub, which the default-feature
  run doesn't compile (a cfg-phantom), and which equals `Default::default()` for the
  field-less mobile `WriteLock` anyway. The real `flock` `acquire` had no survivors.
- `write_vault_file` (`delete !` on the `!parent.is_empty()` guard) — **equivalent
  mutant**: every caller (`create` at line 312, plus `save`/rekey on an already-open
  vault dir) pre-creates the parent directory, so `write_vault_file`'s own
  `create_dir_all` is redundant defense-in-depth and the guard can't change behaviour.

### 3.2 Investigated and refuted (no change needed)

| # | Hypothesis | Why it does not hold |
| --- | --- | --- |
| R-1 | Wrong-password timing/error oracle | AEAD verification is constant-time; any failure (bad password, tampered header, truncation) returns the same generic open error — no distinguishing signal. |
| R-2 | Path traversal via document/portal filenames | Document bytes live in a partitioned, index-addressed encrypted volume — never written to attacker-controlled paths. Export sanitizes the suggested name. |
| R-3 | Crypto coverage gaps | KDF chaining, AAD/header binding, nonce uniqueness, and version handling are each pinned by tests; no untested branch found. |
| R-4 | DoS via a crafted vault/volume | Header and manifest sizes are bounded and validated before allocation; oversized/short/garbage inputs are rejected, not trusted. |
| R-5 | Header/AAD tamper accepted | Every header byte participates as AEAD AAD; flipping any byte fails authentication (test-confirmed). |
| R-6 | Cross-record document leakage | `referenced_doc_ids` are per-record; the volume index does not alias chunks across records. |
| R-7 | Residual unzeroized secrets elsewhere | Key material and password buffers use `Zeroizing`; F-1 was the only remaining growth-realloc gap on the new surface. |
| R-8 | Single-writer lock TOCTOU | The advisory `flock` is correct for the stated *single-instance-on-one-host* threat model; it is not claimed to defend against a multi-host shared filesystem, and that limitation is documented. |
| R-9 | FFI `count()` truncates `usize` → `u32` | Unreachable: needs >4.29 B in-memory records in a single-user offline vault. Cosmetic; left as-is. |
| R-10 | `scan_volume` (manifest-loss rebuild) adopts an uncommitted trailing frame that a normal reopen would roll back | Concerns only a single *unacknowledged* write after a compound double-fault; standard durability semantics, no integrity/secret/oracle impact. |
| R-11 | Mobile 15 s clipboard wipe clobbers unrelated content copied meanwhile | WONTFIX: unconditionally wiping is the *secure* default for a password auto-clear; the proposed read-compare-then-clear weakens the guarantee and triggers OS clipboard-access prompts. |
| R-12 | `ArchiveMismatch`/`RekeyPending` mildly distinguish "password correct but store tampered" from "wrong password" | Reaching either REQUIRES the correct passwords, so it grants no brute-force/oracle capability; left as an intentional, documented post-decrypt state. (Round 5 nonetheless folded the desktop `ArchiveMismatch`/`Json`/`Storage` unlock messages into the generic one — see A-3 — for parity with the FFI.) |
| A-9 | Password history stores cleartext before/after values (masked only at display) | Accepted design (full audit trail). `Change` is `ZeroizeOnDrop`; both UIs mask any `*password` line via `display_detail`; values can't be copied/revealed from history. Caveat recorded: a *future* secret field whose name does not end in `password` would bypass `detail_is_secret` — redact at `track`-time if such a field is ever added. |
| A-10 | `remove_document` tombstone not single-fault durable | A crash between `storage.remove` (durable) and the caller's `vault.save()` drops the tombstone; only a SECOND fault (later manifest-loss rebuild) could then resurrect the frame. Narrow double-fault; the caller-saves contract is deliberate (batch deletes). Documented rather than restructured. |
| A-11 | `rotate_generations` could lose the newest backup on a failed `bak1` write | Re-examined: the current shift-then-write order NEVER destroys an existing generation — a failed `bak1` write only fails to ADD the just-rotated-out primary, which the next save re-rings. The "write bak1 first" alternative would be the actual bug (it overwrites `bak1` before shifting). Left as-is. |
| A-12 | Redundancy recovery runs up to ~4× Argon2 on a failed open when copies exist (co-located timing signal) | Bounded by `MAX_RECOVERY_SALTS`; leaks only "redundancy is on + primary didn't decrypt", NOT password correctness (the extra work fires for any failing password equally). Accepted for the offline local threat model. |
| A-13 | CLI prints distinct `VaultError` messages (wrong-password vs corrupt) | The CLI is a local diagnostic surface (`verify`/`manifest` exist *to* report structural state) and CLI access already implies file access; the no-oracle property is enforced where it matters — the FFI (R-3) and now the desktop unlock (A-3). Left verbose by design. |
| A-14 | `account_tree` group build is O(N²) in distinct group count | Linear `child_mut` scan; ~165 ms only at 8 000 *distinct* owners (far past estate scale; the GUI rebuilds it per frame only when grouped). Not worth a `HashMap` index at realistic sizes. |
| A-15 | egui revealed-field galley / cross-platform clipboard-history residues | Platform-inherent: a revealed password is laid into egui's font galley cache (not zeroizable without patching egui), and the `exclude_from_history` clipboard hint is best-effort on macOS/Windows. Mitigations in place; documented as residual. |
| B-3 | TUI redundancy field accepts an unbounded number (GUI offers a 0–5 combo) | Not a bug: `set_redundancy` clamps to `MAX_REDUNDANCY` (10) and the success line re-reads the applied value, so no false success and no oversized ring — just a cosmetic GUI/TUI input asymmetry. Left as-is. |
| B-4 | Redundancy ring shows two equal-generation slots right after a rekey/compact | After a rekey, `cleanup_redundancy` wipes the old-key baks and `refresh_redundancy_copies` writes mirror+bak1 at the same (current) generation; the next save then leaves `bak1 == bak2` for one cycle. No data loss and no wrong recovery (the duplicate copies are byte-identical, and "newest valid wins" still holds) — only the "strictly descending" ring invariant is briefly non-strict and effective depth is one less for that cycle. Cosmetic; the strict invariant proptest covers only the save-only path. |
| B-5 | `recovery_notice` can't tell a stale (one-generation-behind) mirror from a current one | By design: the lost primary is unreadable, so the recovered copy can't be compared against it. The notice already hedges ("the most recent change may be missing") and never claims "no data lost"; `opened_generation`/`previous_access` surface the recovered generation for the user to notice a rollback. |
| B-6 | The four `unreachable!()` arms for `CategoryRemoval::HasSubtypes` on asset-types/subtypes (GUI+TUI) | Kept: asset types and subtypes structurally have no children, so the core never returns `HasSubtypes` for them — the arms are correct fail-loud defensive code that a test would catch if a future core change violated the contract, preferable to silently swallowing it. |

## 4. Mutation testing

`cargo-mutants --in-diff` was run over the whole new-code diff (the merged Taxes /
Real Estate / mobile / FFI work) — 194 mutants. A surviving mutant marks behaviour no
test actually constrains. Adding the tests below moved the result from **106 missed /
54 caught** to **50 missed / 110 caught / 34 unviable** — **56 survivors killed**.

### 4.1 Security-critical surface (`core` + `ffi`) — clean

The crates where the security logic lives have **no real survivors left**:

* **2 FFI survivors killed** with new tests in `crates/pass-mgr-ffi/src/lib.rs`:
  * `previous_access_is_a_real_timestamp_not_a_constant` — `previous_access()` returns the
    stored access time, not a hard-coded constant.
  * `recovery_notice_is_some_after_mirror_recovery` — corrupt the primary copy of a
    redundant vault, open it through the FFI, and assert a recovery notice surfaces.
* **1 remaining `core` survivor (`vault.rs:282`) is a `cfg` phantom, not a coverage gap.**
  It is the *no-op* `WriteLock::acquire` — the `#[cfg(not(feature = "single-writer-lock"))]`
  stand-in for the read-only mobile build. cargo-mutants does not evaluate `cfg`, so in
  the default (feature-**on**) tree it mutated dead code: the mutated fn is never compiled,
  every test passes, and it is reported "missed." When the feature is **off** and the fn
  *is* compiled, the mutant (`-> Ok(Default::default())`) is **unviable** — `WriteLock` is
  an empty struct with no `Default`. Unkillable by construction. The *compiled* `acquire`
  (the real `flock`, `vault.rs:253`) is pinned by `single_writer_lock_blocks_second_writable_open`.
  We also **`cfg`-gated** that test (it asserted `Locked`, only true with the feature on — a
  latent failure under `--no-default-features`) and added `no_op_lock_allows_a_second_writable_open`
  for the feature-off path, so both lock configurations now have real coverage.

### 4.2 Desktop UI surface (`gui.rs` + `ui.rs`) — bulk killed, remainder accepted

The merged feature UI had a large untested cluster. **12 new desktop tests** were added,
killing 56 of the ~106 survivors by exercising the real logic:

* `parse_doc_index` (1-based→0-based parsing, range/whitespace/non-numeric);
* `Tab::title` (correct, non-empty, unique);
* Real Estate and Taxes **edit screens rendered to a `TestBackend`** with content
  assertions (kills the draw-fn→`()` mutants in the TUI);
* full **attach → export → remove** document round-trips for both Taxes and Real Estate,
  in **both** the TUI (`ui.rs`) and GUI (`gui.rs`) handlers, plus out-of-range and
  missing-input rejection, and record-selection-by-id under multiple records.

The **50 remaining survivors are all in the thin desktop UI** — by design the front-ends
"touch no security-critical code" (DESIGN §7); they drive the audited core, which is
separately and fully tested. They fall into three accepted classes:

1. **egui rendering fns** (`tab_realestate`, `tab_taxes`, `portal_section`, `ui_top_bar`,
   `App::ui`) mutated to `()` — egui is immediate-mode and has no `TestBackend`-equivalent
   render-assertion harness, so a no-op draw cannot be caught the way the ratatui ones are.
2. **keyboard / render dispatch** (`handle_edit_key` key matching, `draw_edit` field-type
   comparisons) — exercised functionally but not pinned at the per-branch level.
3. **status-message arithmetic and boundary edges** in the doc handlers (e.g. `n+1`
   display math, exact `MAX_PATH_LEN` boundary) — cosmetic/off-by-one in user-facing
   strings, not data-affecting.

No surviving mutant lets bad data reach disk or weakens the crypto envelope; the
data-affecting handler logic (what gets attached, exported, removed, persisted) is pinned.

FFI tests 29 → **31**; desktop lib tests 35 → **47**; core gained the no-op-lock test; all green.

## 5. Fuzzing

All four `cargo-fuzz` targets — the untrusted-input decoders — were run for a bounded
budget (≈90 s each) with libFuzzer:

| Target | Decodes | Executions | Result |
| --- | --- | --- | --- |
| `parse_header` | the 61-byte vault header (KDF params, salts, nonces) | 48,471,113 | no crash |
| `parse_frame` | a single `[len][nonce][ciphertext]` volume frame | 18,240,317 | no crash |
| `parse_manifest` | an encrypted partition manifest | 8,059,217 | no crash |
| `scan_volume` | a whole volume scanned frame-by-frame | 6,804,180 | no crash |

**≈81.6 M executions, zero crashes, zero panics, zero leaks**, no entries written to
`fuzz/artifacts/`. Arbitrary bytes into any parser yield `Err`, never a panic, over-read,
or unbounded allocation — consistent with the bounds-checked, size-capped design and the
`#![forbid(unsafe_code)]` core. (The CI `fuzz-smoke` job runs a shorter 30 s pass of each
target on every push; longer campaigns are worthwhile in a nightly/scheduled job.)

## 6. Supply-chain audit

`cargo audit` was run against the RustSec advisory database (1134 advisories) over the
**entire** dependency tree — 595 crates, including the new mobile/UniFFI/JNA chain.

* **Result: 0 vulnerabilities, 0 warnings.** No yanked crates, no unmaintained-crate
  advisories triggering on the resolved versions.
* The audited tree includes the cryptographic primitives (`chacha20poly1305`,
  `argon2`), the UniFFI scaffolding, and the desktop UI stack (`ratatui` → `strum`).

Beyond the enforced `clippy -D warnings` gate, a **pedantic + nursery** clippy scan was
run over the workspace as a stricter-lint assessment. It surfaced only stylistic
suggestions and a handful of bounds-checked truncating casts (`cast_possible_truncation`)
in the parsers — no new defects, consistent with the fuzzing result. These pedantic
groups are intentionally **not** added to the enforced gate (they are noisy and would
bury the signal); the default `-D warnings` gate stays.

Recommendation: add `cargo-deny` (not yet installed) for license/source-ban policy on top
of advisory scanning, and schedule a periodic `cargo audit` so a newly-published advisory
against an already-shipped version is caught between releases.

## 7. Residual risk & recommendations

* **Trust base unchanged.** Vault confidentiality rests on the two passwords and on the
  RustCrypto primitives. This pass did not (and cannot) change that.
* **Mobile is a read-only viewer.** It never writes vaults, so it inherits the desktop
  format guarantees but adds a clipboard surface (now mitigated, F-2) and a JNA/FFI
  boundary. The FFI build disables `mlock`/`single-writer-lock` by design (mobile
  sandboxes provide the process isolation those features target on desktop).
* **Recommended next steps:** run the fuzz targets for a longer wall-clock budget in CI;
  add `cargo-deny` for license/ban policy on top of `cargo-audit`; consider a periodic
  scheduled `cargo-audit` so advisory regressions are caught between releases.

## Appendix — reproduce

```sh
# Lints (all targets, all features)
cargo clippy --workspace --all-targets --all-features -- -D warnings

# Full test suite
cargo test --workspace

# Mutation testing on the new-code diff (the diff must match the working tree)
git diff <base>..HEAD > /tmp/new.diff   # <base> = the pre-feature-merge commit
cargo mutants --in-diff /tmp/new.diff
# The lone remaining "missed" is the no-op acquire's #[cfg(not(...))] line (§4); confirm
# both lock configurations are actually covered:
cargo test -p pass-mgr-core single_writer                       # feature on  (default)
cargo test -p pass-mgr-core --no-default-features no_op_lock    # feature off (mobile)

# Fuzzing (nightly toolchain) — targets: parse_header, parse_frame, parse_manifest, scan_volume
cargo +nightly fuzz run parse_header  -- -max_total_time=90
cargo +nightly fuzz run scan_volume   -- -max_total_time=90

# Supply-chain
cargo audit
```
