# Deep Audit (Round 2) — 2026-06-29

A second, deeper bug hunt + security review run **after** the first-pass audit
(`AUDIT_2026-06-29.md`) had converged dry. This round adds an **empirical** layer (run
the tools, don't just read) on top of a broader multi-agent static review, and it
re-examines the areas the first pass weighted less: the GUI/TUI state machines, the FFI
boundary, the clipboard lifecycle, and the newest code (the `export-tree` plaintext
mirror, `migrate-doc-paths`, and merge).

**Threat model (unchanged from round 1).** A LOCAL encrypted password/asset/document
vault. In scope: theft of the on-disk vault files (confidentiality + tamper/rollback
detection), a crafted vault / other-vault / document / CSV fed to
open/merge/extract/export/migrate, malicious filenames/paths/ids/content, other local
processes/users, clipboard secret leakage, and **silent data-loss / corruption** (the
owner's stated #1 requirement: additive, non-destructive, no silent loss). Out of scope:
an attacker already running as the user with the vault unlocked in RAM (egregious
zeroization gaps are still noted as Low).

**Result: no Critical or High.** One Medium (a data-retention correctness bug in the
opt-in redundancy ring) and three Low (a non-atomic plaintext export, a pathological
export abort, and a TUI secret-buffer reallocation). **All four are fixed in this commit**,
each with a regression test or a precise guard. The encrypted-at-rest core — atomic
temp+rename writes, AEAD verification + place-binding, redundancy commit ordering,
symlink/`O_EXCL` write hardening, and tombstone-aware export — held up across every lens.

---

## Methodology

**Empirical pass (new this round).**

| Tool | Scope | Result |
|------|-------|--------|
| `cargo test --workspace` | every crate | **all green** |
| `cargo fuzz` (nightly libFuzzer) | all 6 targets: `parse_header`, `parse_frame`, `parse_manifest`, `scan_volume`, `doc_paths`, `merge_from` | **0 crashes / panics / OOMs** — 2.38M, 1.61M, 11.6K, 2.23M, 500K, and 204 (deep, Argon2-bound) executions respectively |
| `cargo mutants` | `merge.rs` + `csv.rs`, lib tests | baseline passed; **16/80 mutants tested before a 25-min cap — all 16 caught, 0 survived** (the rest were not reached because an uncaught mutant re-runs the slow exhaustive tests; the tested subset shows clean mutation coverage on the two most data-loss-prone modules) |

**Static pass.** A multi-agent workflow ran **16 diverse finder lenses** (crypto
correctness, storage atomicity, parser robustness, path/filename sanitization, merge
data-loss, migrate idempotency, CSV/export injection, secret-memory hygiene, clipboard
lifecycle, GUI logic, TUI logic, FFI boundary, concurrency/locking, fail-open error
handling, business-logic correctness, and a prior-fix regression re-check). Every
candidate finding was then **independently verified by 3 skeptical agents** with distinct
lenses (correctness, exploitability/repro, scope/false-positive), each defaulting to
"not a real bug" unless it could concretely confirm both a trigger and a bad outcome; a
finding survived only on a **2-of-3 majority**. A completeness critic then proposed a
second, targeted round, which was verified the same way. 48 agents; 2 of the 4 confirmed
findings came from the second (critic-driven) round.

---

## Findings

| ID | Severity | Title | Status |
|----|----------|-------|--------|
| M1 | Medium | Every writable open rotates the redundancy ring, eroding the advertised "prior generations / undo last save" depth | **Fixed** |
| L1 | Low | `export_tree` / `extract` are non-atomic: a mid-walk error strands partial cleartext with no shred warning | **Fixed** |
| L2 | Low | `export_tree` aborts when >10000 documents collide on one virtual path (`O_EXCL` `EEXIST`), stranding plaintext | **Fixed** |
| L3 | Low | TUI password field reallocates mid-typing, stranding plaintext fragments in freed un-zeroized heap | **Fixed** |

---

### M1 (Medium) — A no-edit open consumed a redundancy generation slot

**Where:** `crates/pass-mgr-core/src/vault.rs` — `open_inner` auto-save, `save_internal`,
`rotate_generations`.

**What.** On every writable open, `open_inner` refreshes `last_opened_at` and called
`save_internal(rotate_ring = recovery_notice.is_none())` — i.e. `rotate_ring = true` on a
normal open. Because the refresh changes the serialized bytes, that auto-save was a
genuine save that rotated the redundancy ring (dropping the oldest `bak{N}`, shifting the
rest, ringing the outgoing primary into `bak1`). With `redundancy = N`, a handful of
routine no-edit opens overwrote every retained generation with copies of the current
state, silently eroding the "keep N prior generations / undo last save" depth the feature
advertises (`gui.rs`).

**Impact.** No *live* record or document is ever lost (the primary + same-generation
mirror always hold the current good state, and corruption-recovery — the feature's primary
purpose — still works), but the **older-snapshot / undo capability** the user opted into
is broken. Held at **Medium** (above Low: a real non-destructive-guarantee breach on an
advertised feature; below High: bounded to historical rollback depth, and `redundancy`
defaults to off).

**Fix.** The open-time refresh now passes `rotate_ring = false` (the path the heal case
already used). It updates the primary + mirror and prunes any slots above the configured
depth, but **never rotates the ring** — a metadata-only touch cannot consume a generation
slot. A genuine `save()` (an actual edit) still rotates via `rotate_ring = true`.
Regression test: `no_edit_reopen_preserves_prior_generations` (re-opens a healthy
redundancy vault 3× with no edits and asserts the prior generations are byte-for-content
unchanged).

### L1 (Low) — Partial cleartext left with no warning when a plaintext export fails

**Where:** `crates/pass-mgr-core/src/vault.rs` (`export_tree`);
`crates/pass-mgr-desktop/src/main.rs` (`cli_export_tree`, `cli_extract`).

**What.** `export_tree` (and the `extract` loop) write **unencrypted** files
incrementally with no transactional wrapper. A failure after the first file — `ENOSPC`, a
bit-rotted frame failing AEAD at `store.read`, a rejected blob id, a symlinked
intermediate dir — returns `Err` while everything already written stays on disk at `0600`.
The CLI propagated the raw error via `?`, so a user who sees a *failure* reasonably
assumes nothing was written and may walk away leaving plaintext secrets behind.

**Impact.** Low: the source vault is only **read** (no source-side loss/corruption); the
failure is reported honestly (not as false success); the output is cleartext **by design**
into a user-chosen directory the CLI banners as UNENCRYPTED; files are `0600`/dirs `0700`,
owned by the invoking user. The only genuine gap was the missing post-error shred warning.

**Fix.** Both `cli_export_tree` and `cli_extract` now catch the error and, **only when the
output directory is non-empty** (so a clean first-write failure — which the hardened
writer already unlinks — stays silent), print a loud warning that PARTIAL unencrypted
files remain and must be securely deleted (`shred -u` / `srm -r`) before discarding.

### L2 (Low) — `export_tree` aborted on >10000 same-path documents

**Where:** `crates/pass-mgr-core/src/vault.rs` — `unique_export_path`, and its
`export_tree` call site.

**What.** The human `documents/` tree maps every document sharing a folder+basename to the
same path; `unique_export_path` disambiguates with `_1..=9999` suffixes and, when
exhausted, returned the **original colliding path**. The next `O_EXCL` create then failed
with `EEXIST` and aborted the whole export mid-walk (compounding L1 by stranding the
already-written plaintext). The trigger is pathological (>10000 documents with an
identical original filename in one folder; real vaults use timestamped filenames).

**Fix.** `unique_export_path` gained an optional guaranteed-unique fallback token. The
`export_tree` call passes the document **id** (unique, in scope), so on exhaustion it falls
back to `<stem>_<id><ext>` instead of the colliding path — the cosmetic human-tree copy
can never `EEXIST`-abort the export. The two non-export-tree callers pass `None` (unchanged
behavior). The authoritative round-trip copy is the id-keyed `volume/` blob, written first.

### L3 (Low) — TUI password buffer reallocation stranded plaintext fragments

**Where:** `crates/pass-mgr-desktop/src/ui.rs` — `Field::password`, and the keystroke
handlers for edit-form fields, the auth/master-password fields, and the merge source
passwords.

**What.** A TUI password `Field` was presized to `len + 128` **once** at construction, but
the keystroke handler did a bare `value.push(c)` with no re-presize. Typing past the
headroom reallocated the `String`, copying the partially-typed cleartext into a new buffer
and freeing the **old** buffer **without zeroizing** it — exactly the leak the
construction-time presize comment claimed to prevent. `ZeroizeOnDrop` only wipes the final
live buffer, not the abandoned copies. The egui GUI already avoided this by calling
`presize_secret` every frame; the TUI had no equivalent.

**Impact.** Low (defense-in-depth): a plaintext fragment lingers in freed, un-mlock'd heap
and could reach swap or a core dump. Recovery needs capabilities adjacent to the
out-of-scope same-privilege RAM attacker.

**Fix.** Added a TUI `presize_secret` helper (mirroring the GUI's: move into a roomier
buffer, zeroize the original, swap — never a bare `reserve`, which would itself realloc)
and call it before **every** secret `push`: the edit-form password fields, the
auth/master-password fields, and `merge_pw1`/`merge_pw2`. The invariant
(`capacity ≥ len + 128`) now holds continuously. Unit test:
`presize_secret_keeps_headroom_and_content`.

---

## Areas examined and found clean

Crypto (Argon2 params/salt/nonce derivation, AEAD AAD place-binding, fail-closed decrypt,
constant-time paths, recovery-salt DoS bound); storage atomicity & crash/rekey
roll-forward; the hand-rolled frame/header/manifest parsers (re-fuzzed, 0 findings);
path/id sanitization & symlink write-guards (the round-1 fixes verified intact); merge
one-way-additive data-loss invariants; `migrate-doc-paths` idempotency; CSV anti-formula
neutralization & per-tab/export-tree output; the FFI boundary (panic strategy, error
mapping); concurrency / single-writer lock; and a regression re-check of all round-1
fixes. No new issues survived verification in any of these.
