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
| Adversarial security review (3 rounds incl. a 152-agent deep hunt) | **15 real defects found and fixed** (F-1…F-15: 1 HIGH this round + 4 earlier HIGH, the rest MED/LOW); candidate findings in §3.2 investigated and refuted |
| Mutation testing (`cargo-mutants --in-diff`, 194 mutants) | **56 survivors killed** (106→50 missed); `core`/`ffi` clean (only a `cfg` phantom); the 50 remaining are all in the thin desktop UI (rendering / keyboard / cosmetic) — see §4 |
| Fuzzing (`cargo-fuzz`, 5 targets incl. `doc_paths`) | **≈183 M executions, 0 crashes** (latest extended run) |
| Supply-chain (`cargo-audit` + `cargo-deny`) | **0 advisories across 595 deps; bans/licenses/sources clean** |
| Lints (`cargo clippy -D warnings`, all targets/features) | **clean** |
| Test suite | **core 212 · ffi 31 · compat 4 · desktop 61 + 20 · crash-recovery 18 — all green** (debug + `--release`; `--no-default-features` swaps the single-writer test for the no-op-lock test) |

The cryptographic envelope was never broken: no finding lets an attacker read a vault
they could not already open. The fixes harden secret hygiene (plaintext password
lifetime / display), open-time DoS resistance, untrusted-import path safety, backup
integrity, and a destructive-CLI footgun — see §3.1/§3.1b/§3.1c.

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
| R-12 | `ArchiveMismatch`/`RekeyPending` mildly distinguish "password correct but store tampered" from "wrong password" | Reaching either REQUIRES the correct passwords, so it grants no brute-force/oracle capability; left as an intentional, documented post-decrypt state. |

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
