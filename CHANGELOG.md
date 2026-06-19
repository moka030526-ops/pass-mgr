# Changelog

All notable changes to **pass-mgr** (the offline, two-password encrypted estate
vault) are recorded here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project aims to follow [Semantic Versioning](https://semver.org/).

The full, per-finding security write-up for the hardening work below lives in
[`docs/HARDENING.md`](docs/HARDENING.md); the design rationale is in
[`docs/DESIGN.md`](docs/DESIGN.md).

## [Unreleased]

These changes are committed but **not yet tagged** — the workspace crates are still
at `0.1.0`. When cutting the release, rename this section to the chosen version +
date and bump the crate versions to match.

### Added

- **Mobile apps.** Native Android and iOS apps (Compose Multiplatform UI over the
  audited core via a UniFFI/Gobley FFI). Read-only viewer surface: open with the two
  passwords, browse the tabs, view a record, read its history. The Android APK builds
  in CI; iOS builds on a Mac (see `mobile/iosApp/IOS_SECURITY_VERIFY.md`).
- **Taxes tab** — tax filings keyed by year, each with a per-year document folder.
- **Real Estate tab** — property records with management/insurance/HOA portal logins,
  financing balance, free-text comments, and multiple attached documents.
- **General Documents tab** — standalone titled documents, on a uniform document
  path layout (`<root>/<auto-group>/<compact-utc>/[subfolder]/<filename>`) shared by
  every document-bearing tab, with a single, consistent attach/export widget.
- **Accounts enhancements:**
  - **Title** field (shown in the list as `Title - Account Type - Username`, with its
    own filter and new-entry prefill).
  - **Mandatory title and owner** — an account cannot be saved without both (enforced
    in the GUI and TUI; see `account_required_field_error`).
  - **Grouped tree view** — toggle the list into an `owner → type → subtype → title`
    tree (empty grouping levels are skipped, no "(none)" buckets).
  - **Closed as of** date field.
  - **Faceted (cross-filtering) filters** — type/subtype/owner/title each narrow to
    the values still valid under the other active filters, auto-clearing stale picks.
  - **Reveal-all** toggle on the Accounts screen (overrides per-record reveal).
  - **Keep-visible-on-save** — editing a filtered field moves the active filter to the
    saved value (incl. the review-only and username-search filters) so the entry never
    silently vanishes.
  - **New-from-filter** — clicking *New* under active filters pre-populates the form.
  - **Trim all fields** — every Account field is left/right-trimmed on save, plus a
    one-off bulk-trim action over the whole vault (history-recorded).
- **Config: delete an unused category** — asset types, account types, and account
  subtypes can be deleted from Config, **only when no live record uses them** (history
  mentions never block); an account type with subtypes must have those removed first.
- **Packaging & platform:** Windows GUI-subsystem binary (no console window on
  launch); desktop shortcuts with locked/unlocked vault icons; packaging docs.
- **CI / tooling:** GitHub Actions verification suite (clippy `-D warnings`, tests,
  fault-injection crash/full-disk recovery, Windows cross-compile, parser fuzz smoke,
  Android APK); `cargo-deny` supply-chain policy and the `doc_paths` fuzzer as standing
  checks; a release-mode test job.

### Changed

- **Cargo workspace split** into `pass-mgr-core` (audited, `#![forbid(unsafe_code)]`),
  `pass-mgr-desktop` (GUI/TUI/CLI), and `pass-mgr-ffi` (the only `unsafe`-permitting
  crate, for the UniFFI scaffolding).
- **Feature-gated** `mlock` and the single-writer file lock — on for desktop, off for
  the mobile build (which serializes access in-process).
- **Release profile** now sets `overflow-checks = true` (fail-closed on integer
  overflow) in addition to `strip`.
- New fields are additive (`#[serde(default)]`); the on-disk **format stays v4** and
  older vaults open unchanged.
- **Read-only mode is now fully non-editable.** A read-only session previously let you
  type into a record's form fields (the edits were silently discarded on close); the
  forms are now a true view — every data field is disabled. Only the color theme can be
  changed; backup and document export (both read-only-safe) remain available.

### Security

Four rounds of adversarial multi-agent audit (including a 152-agent and a 159-agent
hunt) fixed **26 confirmed defects**; none broke the cryptographic envelope (no
finding lets an attacker read a vault they could not already open). Highlights:

- **Untrusted-import path safety** — `import_tree` symlink **TOCTOU** that could
  launder an arbitrary file (e.g. `/etc/shadow`) into the vault is closed with
  `O_NOFOLLOW`; blob ids restricted to a lowercase-hex allowlist (rejects Windows
  ADS/drive-relative/device-name escapes and case-insensitive-FS collisions);
  document paths reject control bytes **and** Unicode bidi/zero-width spoofing;
  duplicate ids in a mirror are rejected (closes a version-rollback vector).
- **Deletion durability** — a deleted document could be resurrected by a manifest-loss
  rebuild and made permanent by compaction; an authenticated deletion **tombstone**
  now keeps deletes deleted.
- **No-oracle contract (FFI)** — every open failure (wrong password, any corruption,
  the post-decrypt `ArchiveMismatch`, the pre-decrypt size-cap `TooLarge`) collapses to
  one `WrongPasswordOrCorrupt` variant, so the read-only mobile surface is never a
  correct-password oracle.
- **Open-time DoS resistance** — bounded distinct-salt key derivations and lazy
  one-buffer-at-a-time redundancy recovery; KDF cost ceiling lowered (1 GiB → 512 MiB
  memory) and validated on **both** the read and write paths so a vault can't be
  written that won't reopen, and a tampered header can't force a multi-GiB allocation.
- **Secret hygiene** — password **history** values are masked in the UI; clipboard
  copies are flagged sensitive on every platform (Linux `exclude_from_history`,
  Android `EXTRA_IS_SENSITIVE` + `FLAG_SECURE`, iOS `UIPasteboard` local-only + expiry,
  scene-phase snapshot overlay, real file Data Protection); the egui password fields no
  longer retain secret snapshots in the undo buffer or bypass the clipboard hint on
  copy; FFI password buffers are wiped even on a panic-unwind.
- **Backup integrity** — backups run under the single-writer lock (no corrupt snapshot
  under a concurrent rekey) and refuse symlinked source/destination.
- **CLI safety** — a value-flag could swallow the vault-dir positional and retarget a
  destructive `compact` onto the default vault; the resolved target is now validated
  and echoed.
- **Tooling assurance** — extended fuzzing (~183 M executions across five parser
  targets, 0 crashes), mutation testing (≈99–100 % kill rate on the changed security
  code), AddressSanitizer clean on the FFI, and `cargo-audit` + `cargo-deny` clean.

### Fixed

- **Regression:** the in-app *Backup* button self-deadlocked on the session's own
  write lock; it now reuses the held lock (`OpenVault::backup`).
- The redundancy-recovery notice no longer cries "data may be lost" when the recovered
  copy is actually the current generation.
- `"Saved." / "Deleted."` status messages are gated on the write actually reaching
  disk (no false success on a full disk / read-only handle).

## [0.1.0] — initial baseline

The foundational offline estate vault:

- **Crypto:** two required passwords → chained **Argon2id** key derivation →
  **XChaCha20-Poly1305** AEAD, with the entire file header (magic, version, KDF
  params, salt, nonce) authenticated as associated data. Wrong password and a
  corrupt/tampered vault fail closed and indistinguishably (no oracle); secret
  material is zeroized and (on desktop) memory-locked.
- **Front-ends:** desktop **GUI** (egui) and **TUI** (ratatui) over one shared vault
  API, plus a **CLI** (`compact`, `backup`, `extract`, `export-tree`, `import-tree`,
  `verify`).
- **Storage:** records and a **partitioned encrypted document store** inside a single
  vault directory; **crash-safe** atomic writes (temp → fsync → rename → dir-fsync)
  with manifest-rebuild recovery, and optional in-place redundancy (mirror + prior
  generations) with a generation counter for rollback detection.
- Read-only by default (mutations require `--write`); editable category type lists
  stored inside the encrypted vault.
