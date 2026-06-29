# Deep Audit (Round 3) — 2026-06-29

A third pass, run immediately after round 2 (`AUDIT_2026-06-29_round2.md`). Its primary
goal was **verification**: adversarially try to *break* the round-2 fixes (M1/L1/L2/L3 and
the new URL/username copy feature) and find regressions or incompleteness in the
just-committed code — plus a set of deeper lenses the first two rounds under-covered.

**Threat model:** unchanged (see round 2). A LOCAL encrypted vault; in scope: file theft,
crafted inputs, local processes, clipboard, and **silent data-loss/corruption** (the
owner's #1 priority); out of scope: a same-privilege attacker with the vault unlocked in
RAM.

**Result: the round-2 fixes are confirmed structurally sound — no destructive
regressions.** Verification surfaced **3 Low** issues: two are *incompleteness* in round
2's own L1/L2 error-path code, one is a pre-existing forward-secrecy hardening gap. **All
three are fixed in this commit**, each with a regression test. No Critical/High/Medium.

---

## Methodology

**Empirical pass.**

| Tool | Scope | Result |
|------|-------|--------|
| `cargo test --workspace` | every crate | **all green** (incl. the 3 new regression tests) |
| `cargo fuzz` | `merge_from` (deep, Argon2-bound) + `doc_paths` | **0 crashes** — 353 and 1.24M executions |
| `cargo mutants` | the 6 functions changed in round 2 (`save_internal`, `unique_export_path`, `rotate_generations`, `prune_generations_above`, `open_inner`, `decrypt_with_redundancy`) | **22 caught / 4 unviable / 3 missed** (88% of viable). The 3 missed are equivalent/optimization-only mutants in pre-existing code (e.g. a salt-dedup fast-path where recovery still succeeds via the fallback pass) — not defects |
| Build matrix | musl-static minimal CLI; full GUI; aarch64-android `cargo check` (core+ffi) | **all clean** (windows-gnu skipped: host lacks `mingw dlltool`; android *compiles* — the earlier failure was host-linker-vs-NDK config, not code) |

**Static / verification pass.** A multi-agent workflow ran **5 adversarial self-reviews**
(one per round-2 change, each agent tasked with *breaking* it) plus **6 deeper lenses**
(redundancy×rekey/compaction interaction, export→import round-trip integrity, the GUI
deferred-action patterns, unicode/encoding/locale, the feature/build matrix, and the FFI
mobile boundary), then a completeness critic that spawned 4 more targeted hunts. Every
candidate was **independently verified by 3 skeptical agents** (correctness-trace,
exploit/repro, scope/false-positive), surviving only on a 2-of-3 majority. 29 agents.

---

## Findings

| ID | Severity | Title | Status |
|----|----------|-------|--------|
| F1 | Low (regression) | `warn_partial_plaintext` could implicate the user's pre-existing files in its "securely delete" advice | **Fixed** |
| F2 | Low (regression) | A ~255-byte filename made the cosmetic `documents/` copy `ENAMETOOLONG`-abort the whole export, truncating the authoritative mirror | **Fixed** |
| F3 | Low (pre-existing) | A partial `cleanup_redundancy` failure on rekey could strand an old-key vault copy with no compensating sweep | **Fixed** |

### F1 (Low, regression in round-2 L1) — warning could name the user's own files

**What.** The L1 partial-plaintext warning inferred "this run wrote partial files" from
`read_dir(out_dir).next().is_some()`. That premise only holds for an empty/new output dir;
none of the three export paths enforced emptiness. If the user exported into a directory
that already held their own files and the very first hardened write failed (e.g. a
pre-existing `vault.json` → `O_EXCL` `EEXIST`, or `ENOSPC`), nothing of this run landed yet
the warning told them to securely delete the *whole directory* — risking destruction of
unrelated data (user-mediated, against the non-destructive priority).

**Fix.** Snapshot the directory's top-level entries **before** the export; on failure, warn
only about the entries that *appeared since* (every export write creates a new top-level
entry: `vault.json`, `manifest/`, `volume/`, `documents/`, `csv/`, or a per-doc subtree),
naming each, and explicitly stating pre-existing files were not written by this run. Stays
silent when nothing new landed. Test: `partial_plaintext_warning_attributes_only_new_entries`.

### F2 (Low, regression in round-2 L2) — a long filename aborted the authoritative export

**What.** A single ~255-byte filename component is legally storable (only the *total*
virtual path is capped at 256). In `export_tree`, two documents sharing such a name collide
in the cosmetic `documents/` tree; the disambiguating `_N`/`_<id>` suffix pushes the
component past `NAME_MAX` (255) → `create_new` fails `ENAMETOOLONG` → the `?` aborted the
*entire* export mid-walk, leaving later partitions' authoritative `volume/`+`manifest`
unwritten and all CSVs skipped — an incomplete, non-round-trippable mirror. (Round-2's L2
`_<id>` fallback actually made the basename *longer*.)

**Fix.** The `documents/` human-tree copy is explicitly cosmetic (`import_tree` reads only
the id-keyed `volume/`+`manifest`). It is now **best-effort**: a new `write_human_tree_copy`
helper performs the symlink-guarded write, and `export_tree` discards its `Result` — any
failure (over-long name, symlink rejection, `ENOSPC`) skips just that one viewing copy and
the authoritative mirror always completes. The document remains fully recoverable from
`volume/`. Test: `export_tree_completes_when_a_cosmetic_human_copy_name_is_too_long`
(two 255-byte-named docs → export succeeds → both round-trip via `import_tree`).

### F3 (Low, pre-existing) — old-key redundancy copy could survive a rekey

**What.** After a password change, `commit_rekey` swaps in the new-key tree and calls
`cleanup_redundancy` (best-effort `let _ = remove_file(...)`) to delete the now-stale
old-key mirror/`bak`s, then removes the staging dir. If an individual `remove_file` failed
transiently (e.g. an immutable flag, EIO, a read-only remount) while the staging unlink
succeeded, an old-key `bak` could persist with **no compensating sweep** — a full pre-rekey
vault copy still decryptable under the *old* passwords, defeating part of the forward
secrecy a password change implies. Contrived trigger, confidentiality-at-rest only (no data
loss; the leftover binds the old salt so it is unusable for recovery under the new key).

**Fix.** A new `sweep_foreign_epoch_copies`, run on every writable open, removes any
redundancy copy whose header salt differs from the live primary's salt. The salt changes
only on rekey and is authenticated, so a salt-mismatch is exactly a cross-epoch (old-key)
leftover. This is provably **recovery-safe**: recovery only ever uses a copy that decodes
under the current password (i.e. the current salt), so a foreign-salt copy is never a
recovery source — deleting it removes only dead old-key ciphertext. (A cheaper, more precise
signal than re-deriving a key per candidate: at open time we hold the key for the current
salt, not the password, so a header-salt comparison is both correct and free of extra
Argon2 work.) Test: `open_sweeps_old_key_redundancy_leftover_after_a_failed_rekey_cleanup`.

---

## Confirmed sound (the round-2 fixes held up)

The adversarial self-reviews and 3-skeptic verification confirmed: M1's
`rotate_ring=false` open-time refresh introduces no generation/recovery regression (no code
depends on `bak.generation == primary.generation - 1`; recovery selects by decryptability,
not generation arithmetic); the L3 `presize_secret` correctly zeroizes the old buffer, is
applied to every secret push and no non-secret one, and handles backspace/reset; and the
copy-button feature's timer cancellation can never leave a real password un-wiped (a plain
copy always overwrites the clipboard first, and only one deferred copy action can fire per
frame). Export/extract remain read-only on the source vault; failures are reported honestly.
