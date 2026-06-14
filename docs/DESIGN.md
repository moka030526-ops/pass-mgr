# pass-mgr — Design Document

_Last updated: 2026-06-13_

## 1. Purpose

`pass-mgr` is a **standalone, offline** password manager. It stores credentials
in a single, strongly-encrypted file on the local disk. It never opens a network
socket and has no remote sync, telemetry, or update mechanism. The whole point is
that the secrets never leave the machine.

The code is deliberately small and readable so that a single person can audit the
entire security-critical path in one sitting.

## 2. Requirements traceability

Each numbered requirement from the brief maps to a concrete design element.

| # | Requirement | Where it lives |
|---|-------------|----------------|
| 1 | Standalone, no internet | No network crates in `Cargo.toml`; verified by dependency audit (§8) |
| 2 | Filter screen + custom types | `Entry.kind` (freeform), filter bar in TUI (`ui.rs`) |
| 3 | Description, username, password, URL | `Entry` fields |
| 4 | Each change logged with timestamp | `Entry.history: Vec<Change>` + `Vault.audit` |
| 5 | History maintained | Per-entry `history` retained on every edit |
| 6 | Last access maintained | `Vault.last_opened_at`, surfaced on unlock |
| 7 | Highest encryption level | Argon2id + XChaCha20-Poly1305 (§5) |
| 8 | Encrypted JSON file | JSON plaintext, AEAD-encrypted on disk (§6) |
| 9 | Two passwords, set sequentially | Chained KDF (§5.2) |
| 10 | Intuitive interface | Ratatui TUI, single-screen list + detail (§7) |
| 11 | File identifiable | `PMVAULT\0` magic + self-describing header (§6) |
| 12 | Random password generator | `password.rs`, bias-free CSPRNG sampling |
| 13 | Simple to review | ~5 small modules, no `unsafe`, heavily commented, unit-tested |
| + | Compiles on Windows + Linux | Portable std + `#[cfg]`-gated permissions (§9.9), `directories` for paths |

## 3. Technology choices

- **Language:** Rust (edition 2024). Memory safety without a GC; `zeroize`
  support for wiping secrets.
- **Interface:** two interchangeable front-ends over the same vault API —
  a [`ratatui`](https://crates.io/crates/ratatui) terminal UI (`ui.rs`, good for
  SSH/headless) and an [`egui`/`eframe`](https://crates.io/crates/eframe)
  graphical UI (`gui.rs`, the default). Both compile into the single standalone
  binary; neither uses a browser, Electron, or the network. The GUI is the
  default; `--tui` selects the terminal UI.
- **KDF:** `argon2` (Argon2id).
- **Cipher:** `chacha20poly1305` (XChaCha20-Poly1305 AEAD).
- **Clipboard:** `arboard`, for copying a password without displaying it.
- **Randomness:** `getrandom` (OS CSPRNG).
- **Serialization:** `serde` + `serde_json`.
- **Secret hygiene:** `zeroize` to wipe keys and decrypted buffers.

There is intentionally **no async runtime and no networking crate**. This is a
load-bearing design decision, not an omission (req. 1).

## 4. Data model

The model lives in `records.rs` and serializes to JSON. The app is a five-tab
estate vault: each tab is a `Vec` of one record type. Every record shares an
`id` (128-bit random hex, stable across edits), `created_at`/`updated_at`, and an
append-only `history: Vec<Change>` (req. 4, 5). The shared insert/edit/diff logic
is the `Record` trait + generic `upsert`/`remove`.

```text
Vault
├── version: u8                  // schema version (currently 3)
├── last_opened_at: i64          // set on each successful unlock (req. 6)
├── instructions:  Vec<Instruction>   // Tab 1: title, description
├── trust_wills:   Vec<TrustWill>     // Tab 2: document, usage, file (doc id)
├── assets:        Vec<AssetLiability>// Tab 3: kind, description, owner, value, date,
│                                     //         institution, type, statement (doc id)
├── accounts:      Vec<Account>       // Tab 4: account_type, owner, username, password, url, description
├── real_estate:   Vec<RealEstate>    // Tab 5: address, ownership, taxes, hoa, income/financing/payment account
├── volume: Volume               // document-archive manifest (metadata only)
└── audit: Vec<Change>           // vault-level log: created, password changed, deletions, uploads

Volume                            // metadata for the encrypted document archive
├── directories: Vec<String>     // virtual directory tree (e.g. "/statements/2026")
├── files: Vec<VolumeFile>       // {id, location, filename, size, uploaded_at, source}
└── uploads: Vec<Change>         // upload history: location / date / file (req)

Change
├── at: i64                      // unix-seconds timestamp
├── action: String               // "created" | "updated" | "deleted" | "uploaded" | ...
└── detail: String               // human-readable summary, e.g. "username: alice -> bob"
```

The `kind`/`asset_type`/`account_type` dropdown values come from external,
editable JSON lists in the data dir (`types/asset_types.json`,
`types/account_types.json`), auto-created with defaults (req. 2).

### 4.1 History semantics (req. 4 & 5)

- **Append-only.** A `Change` is pushed to a record's history on every mutation.
  We never rewrite or drop earlier entries, so the audit trail is tamper-evident
  _within_ the (already integrity-protected) vault.
- The `detail` string records **field-name + before/after** for every changed
  field, **including the password** (e.g. `password: "old" -> "new"`). This
  makes the history a complete record and allows recovering a previous password.
  The security trade-off — the vault retains old passwords forever — is accepted
  here and noted in §9.4.
- Deletions are recorded in the **vault-level** `audit` log (the entry itself is
  gone, so it cannot hold its own tombstone).

### 4.2 Category types (req. 2)

The Asset/Liability "type" and the Account "account type" are chosen from
dropdowns populated by external JSON lists (`types/asset_types.json`,
`types/account_types.json`) created with sensible defaults on first run and
editable by the user. They are stored unencrypted (category names only).

### 4.3 Encrypted document volume

Statements, wills, and other documents are uploaded into a **single encrypted
archive** file `<vault>.vol`, decrypted as one unit on unlock and re-encrypted
as one unit on change (an "encrypted zip"):

- The archive holds the document bytes keyed by a random file id, encrypted with
  the same vault key (XChaCha20-Poly1305, fresh random nonce per write). On disk:
  `nonce ‖ ciphertext`.
- **Identity binding:** the AEAD associated data is a fixed tag plus the vault's
  random `volume.id`, so a `.vol` from a different vault (or a swapped one) fails
  authentication. On open, a **consistency check** also requires every document
  referenced by the manifest to be present in the archive, rejecting a stale or
  rolled-back `.vol` that is missing newer documents.
- **Lifecycle:** deleting a record or detaching a document **reclaims** its blob
  from the archive (and logs the removal), so "deleted" documents do not linger.
  Attaching immediately persists the record→document link, so no orphan is left.
- The vault JSON's `Volume` holds only metadata (vault id, virtual location,
  filename, size, upload time/source) and the upload/removal history.
- The archive plaintext is a length-prefixed binary frame
  (`[count][id_len][id][data_len][data]…`); parsing is fully bounds-checked so a
  crafted/corrupted archive fails closed rather than panicking or over-allocating.
- Whole archive is held decrypted in memory while the vault is open (acceptable
  for the standalone, single-user use case; see §9).

## 5. Cryptography

### 5.1 Primitives

- **KDF:** Argon2id, OWASP-aligned defaults — 64 MiB memory, 3 passes, 1 lane,
  32-byte output. Parameters are stored in the file header so the vault stays
  self-describing and the cost can be raised later without breaking old files.
- **AEAD:** XChaCha20-Poly1305. 24-byte random nonce per write (large enough that
  random nonces won't collide in practice). The header bytes *excluding the
  nonce* (magic + version + KDF parameters + salt — the first 37 bytes) are fed
  in as **associated data**, so any tampering with the version, KDF parameters,
  or salt is detected on decrypt. The nonce itself is not part of the AAD because
  it is already bound as the cipher's nonce input — altering it makes the
  authentication tag fail regardless.

### 5.2 Two-password chained derivation (req. 9)

The two passwords are entered **sequentially** at the unlock screen. The final
encryption key is derived by chaining two Argon2id passes:

```text
k1   = Argon2id(password1, salt1, params)     // 32 bytes
key  = Argon2id(password2, salt = k1, params) // 32 bytes, used for AEAD
```

- `salt1` is a random 16-byte value stored in the header.
- The **output of the first derivation becomes the salt of the second.** This is
  what makes the two passwords sequential by construction: you cannot compute
  `key` without first knowing `password1` (to get the salt) _and_ `password2`.
- Both passwords are required; neither alone is sufficient, and there is no way
  to verify `password1` independently of `password2` (the only oracle is a
  successful AEAD decrypt of the whole vault).
- Cost: two Argon2id evaluations per unlock (~2× the single-password time). This
  is acceptable for an interactive unlock and doubles the work an attacker must
  do per guess.

> Caveat: chaining does **not** make brute force quadratically harder — an
> attacker still guesses `(pw1, pw2)` pairs and pays two KDF evaluations per
> guess. The security benefit is "two independent secrets, both required," plus
> doubled per-guess cost. See §9.1.

### 5.3 Key lifetime

- The derived `Key` is wrapped in a `ZeroizeOnDrop` newtype; its bytes are wiped
  when the unlocked vault is dropped (lock / quit).
- Decrypted plaintext buffers are explicitly `zeroize()`d after use.
- `k1` (the intermediate key) is also zeroized after the second derivation.

## 6. On-disk file format (req. 8, 11)

All integers little-endian. The header is plaintext (so the file is
self-identifying and self-describing); the body is ciphertext.

```text
offset  len  field
0       8    magic            b"PMVAULT\0"            (req. 11 — identifiable)
8       1    format version   currently 2
9       4    Argon2 m_cost (KiB)
13      4    Argon2 t_cost
17      4    Argon2 p_cost
21      16   salt1            (first-pass KDF salt)
37      24   nonce            (XChaCha20-Poly1305)
61      ..   ciphertext       AEAD(JSON vault), header[0..61] as associated data
```

- The first 37 header bytes (everything except the nonce) are the AEAD
  associated data, so the magic/version/params/salt are authenticated even
  though they are not secret. The nonce is bound implicitly as the cipher nonce.
- **Atomic writes:** the vault is written to a uniquely-named, hidden temp file
  (`.<name>.<random>.tmp`) created with `create_new`/`O_EXCL` so a pre-planted
  symlink at a predictable path cannot be followed, `fsync`'d, then renamed over
  the real file; the parent directory is then `fsync`'d so the rename is durable.
  A crash mid-write cannot corrupt an existing vault, and a failed write removes
  the temp file.
- **File permissions:** on Unix the temp file is created with mode `0600`
  *atomically* (no world-readable window) and the parent directory is `0700`.
- **Untrusted-input bounds:** KDF parameters read from the file header are
  range-checked before the memory-hard derivation runs, so a crafted header
  cannot force a huge Argon2 allocation (DoS).

> Note: format version bumps from 1 → 2 because the two-password scheme and the
> richer schema (types/history/last_opened_at) change both the header meaning and
> the JSON shape. Version 1 files (if any exist from early prototyping) are not
> auto-migrated; see §9.5.

## 7. User interface (req. 10)

The app ships **two front-ends** that share the same `OpenVault` API and the
same four-screen state machine (Auth / List / Detail / Edit), so all crypto and
data-model logic is common:

- **Graphical (`gui.rs`, default)** — `egui`/`eframe`, immediate-mode, on-screen
  buttons. Needs a desktop (X11/Wayland).
- **Terminal (`ui.rs`, `--tui`)** — `ratatui`, keyboard-driven, works over SSH.

Because the security-critical modules (`crypto.rs`, `vault.rs`, `password.rs`)
are UI-independent, adding the GUI changed no crypto and required no schema
change. The terminal UI has three screens beyond Auth:

1. **Unlock / Create.** Prompts for password 1, then password 2 (masked). On a
   missing file, switches to a create flow that asks for each password twice to
   confirm. Shows "Last opened: <timestamp>" after a successful unlock (req. 6).
2. **List.** A filter bar (`All` + type chips) and a search box at the top, the
   entry list in the middle, key hints at the bottom. Typing filters live.
3. **Detail / Edit.** Shows all fields; password masked with a reveal toggle and
   a "copy to clipboard" action. An edit form writes a `Change` to history on
   save. A "History" pane lists timestamped changes for the entry (req. 4, 5).

Key bindings are shown on-screen at all times (intuitive, discoverable). No
mouse required.

### 7.1 Clipboard caveat

Copying a password uses the OS clipboard via `arboard`. The clipboard is shared
with every app and may be synced by the OS. We mitigate by offering a "clear
clipboard" action, but cannot guarantee the OS hasn't already captured it. See
§9.3.

## 8. Threat model

**In scope (defended):**

- **Theft of the vault file at rest.** Without both passwords, the file is
  indistinguishable from random beyond its plaintext header. Argon2id makes
  offline guessing expensive.
- **Tampering with the file** (flipping bits, editing the header). Detected by
  the AEAD tag; decrypt fails closed.
- **Wrong password.** Fails closed with a generic error; no partial decrypt.

**Out of scope (cannot defend, by design or by platform):**

- **A compromised host.** Malware, a keylogger, or a root user on the same
  machine can capture passwords as you type or read process memory. No userland
  password manager can defend against this.
- **Cold-boot / swap / hibernation.** Keys live in RAM while unlocked and may be
  paged to disk by the OS. We zeroize on drop but cannot prevent the OS from
  having swapped earlier.
- **Shoulder-surfing / screen capture** of revealed passwords.
- **Rubber-hose / coercion.** Both passwords can be extracted from the user.

## 9. Security caveats & known limitations

### 9.1 Two passwords ≠ exponential security
Chained derivation requires both secrets but does **not** multiply entropy
multiplicatively against brute force in the way users may assume. If `pw1` is
weak (e.g. a 4-digit PIN), it adds little. Guidance: treat the pair as one strong
secret; use a long, high-entropy phrase for at least one of them.

### 9.2 No password verification before full decrypt
There is intentionally no separate "password check" value. The only way to know
the passwords are right is a successful AEAD decrypt. This is good for security
(no independent oracle for `pw1`) but means error messages are necessarily
generic ("wrong password or corrupted vault").

### 9.3 Clipboard exposure
See §7.1. Copying a password places it on the shared system clipboard. Other
applications, clipboard managers, and OS-level cloud-clipboard sync can read it
while it is there. Both front-ends now clear the clipboard on exit (best-effort),
which bounds exposure to the session; a timed auto-clear is a possible future
enhancement.

### 9.4 History stores old passwords
By request, the per-entry history records the full before/after value of every
field, **including passwords**. This gives a complete, recoverable change log,
but means the vault permanently retains every previous password for an entry.
The mitigations are that (a) the whole vault is encrypted under both passwords at
rest, and (b) history lives only inside the vault. The risk is that a previously
leaked/rotated password remains readable to anyone who can already open the
vault. If you rotate a password specifically because it leaked, be aware the old
value is still stored in that entry's history.

### 9.5 No automatic format migration
Format v1 prototype files are not auto-upgraded to v2. If a v1 file exists, the
app reports an unsupported-version error rather than risk a lossy migration. A
one-shot migration tool can be added if needed.

### 9.6 Memory-safety of secrets is best-effort
Secrets are zeroized on drop throughout: the derived keys and the intermediate
KDF key (`crypto.rs`), the decrypted plaintext buffers (`Zeroizing`), the whole
decrypted data model (`Entry`/`Change`/`Vault` are `ZeroizeOnDrop`), and the
password-input buffers in the TUI, GUI, and CLI. Residual risk remains: Rust may
move `String`/`Vec` contents during reallocation (leaving un-wiped copies of an
in-progress buffer), and the OS may swap memory to disk. Zeroization reduces but
does not eliminate residual-secret risk, and none of it defends a compromised
host (out of scope, §8).

### 9.7 No rate limiting / lockout
The app does not lock out after repeated failed unlocks (it is a local file; an
attacker with the file can attack it offline regardless). The defense is Argon2id
cost, not attempt limiting.

### 9.8 Single-file, single-user
No concurrent access control. Two instances opening the same vault and saving
can lose each other's writes (last-writer-wins). Intended for single-user,
single-instance use.

### 9.9 Windows file privacy is weaker than Linux
On Linux the vault file is created `0600` and its directory `0700`, so other
local users cannot read it. Windows has no portable standard-library equivalent
of Unix mode bits; we rely on the **inherited per-user NTFS ACL** of
`%APPDATA%`, which is private to the user profile by default but is not
explicitly hardened by the app. On a shared Windows machine with a permissive
parent ACL, the file could be more exposed than on Linux. The encryption (both
passwords required) remains the primary defense regardless of platform.

### 9.10 The CLI `decrypt` prints all secrets in plaintext
`pass-mgr decrypt [VAULT]` writes the entire decrypted vault as JSON to stdout,
including every password (and the password history). This is intentional — it is
an export/recovery escape hatch — but it means secrets can land in your terminal
scrollback, shell history (if redirected), or a file. The command prompts for
both passwords (read without echo on a TTY) and never modifies the vault file.
Treat its output as highly sensitive; pipe it somewhere safe rather than letting
it sit on screen.

### 9.11 Crash mid-write does not corrupt the vault
Saves are atomic: the new vault is written to a uniquely-named temp file,
`fsync`'d, renamed over the real file, and then the parent directory is `fsync`'d
(on Unix) so the rename is durable. A crash *before* the rename leaves the
original vault intact (and the failed write removes its temp file); the rename
itself is atomic, so a crash during it yields either the complete old file or the
complete new one — never a half-written vault. On platforms without directory
fsync a hard power loss could still lose the last save (never corrupt the file).
Any truncated/garbled file is additionally caught by the AEAD tag on open (fails
closed). See §6.

### 9.12 Whole-snapshot rollback is out of scope
The document archive is bound to its vault (`volume.id` in the AEAD AAD) and an
on-open check rejects a `.vol` that is *inconsistent* with the vault manifest
(missing referenced documents) — so an attacker can't swap in another vault's
archive or a stale archive that drops newer documents. What no at-rest scheme
can prevent without an external trusted counter is an attacker restoring a
**matched older pair** of `vault.pmv` + `vault.pmv.vol` (a full, self-consistent
snapshot): that simply looks like the vault as it was at that time. This is the
same inherent limitation that applies to the main vault file on its own.

## 10. Non-goals

- Browser integration / autofill.
- Cloud sync, multi-device, sharing.
- Mobile clients.
- Plugin system.

These are deliberately excluded to keep the attack surface and the codebase
small (req. 1, 13).
