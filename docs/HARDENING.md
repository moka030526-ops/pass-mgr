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
| Adversarial security review | **2 real defects found and fixed**; 8 candidate findings investigated and refuted |
| Mutation testing (`cargo-mutants`, new code) | 2 real survivors **killed** with new tests; the 1 remaining is a `cfg` phantom (dead code in the compiled config), not a coverage gap |
| Fuzzing (`cargo-fuzz`, 4 targets) | **≈81.6 M executions, 0 crashes** |
| Supply-chain (`cargo-audit`) | **0 advisories across 595 deps** |
| Lints (`cargo clippy -D warnings`, all targets/features) | **clean** |
| Test suite | **core 192 · ffi 31 · compat 4 · desktop 35 + 19 · crash-recovery 18 — all green** (`--no-default-features` swaps the single-writer test for the no-op-lock test) |

Both confirmed defects were **secret-hygiene** issues (plaintext password lifetime),
not breaks of the cryptographic envelope. Neither lets an attacker read a vault they
could not already open; both narrow the window in which a local attacker with memory
or clipboard access could recover a password.

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

## 4. Mutation testing

`cargo-mutants` was run over the new-code diff (`--in-diff`). Surviving mutants mark
behaviour that the test suite does not actually constrain.

* **3 survivors** were reported on the FFI surface and the write-lock path.
* **2 killed** with new FFI tests in `crates/pass-mgr-ffi/src/lib.rs`:
  * `previous_access_is_a_real_timestamp_not_a_constant` — pins that `previous_access()`
    returns the stored access time, not a hard-coded constant (kills a mutant that
    replaced the body with a fixed value).
  * `recovery_notice_is_some_after_mirror_recovery` — creates a redundant vault, corrupts
    the primary copy, opens it through the FFI, and asserts a recovery notice surfaces
    (kills a mutant that always returned "no notice").
* **1 survivor** at `vault.rs:282` is a **`cfg` phantom, not a coverage gap.** That line
  is the body of the *no-op* `WriteLock::acquire` — the
  `#[cfg(not(feature = "single-writer-lock"))]` stand-in used by the read-only mobile
  build. cargo-mutants parses source text without evaluating `cfg`, so in the default
  (feature-**on**) tree it compiles it mutated this dead code: the mutated function is
  never compiled, every test still passes, and the mutant is reported "missed." When the
  feature is **off** and the function *is* compiled, the specific mutant
  (`-> Ok(Default::default())`) is **unviable** — `WriteLock` is an empty struct with no
  `Default` impl. Either way it is unkillable by construction. The *compiled* `acquire`
  (the real `flock`, `vault.rs:253`) is pinned by `single_writer_lock_blocks_second_writable_open`.
  To close the loop we additionally **`cfg`-gated** that test (it asserted `Locked`, which
  only holds with the feature on — a latent failure under `--no-default-features`) and
  added `no_op_lock_allows_a_second_writable_open` for the feature-off path, so both lock
  configurations now have real, passing coverage.

FFI tests went from 29 → **31**; core gained the no-op-lock test; all green.

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
