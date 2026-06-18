# pass-mgr — Design Document

_Last updated: 2026-06-15. Format version 4 (partitioned document store)._

## 1. Purpose

`pass-mgr` is a **standalone, offline, two-password encrypted estate vault**. It
keeps the things a family needs to settle an estate — account credentials, asset
and liability records, real-estate details, trust/will documents, and free-text
instructions — in one strongly-encrypted location on the local disk, together
with the scanned documents that back them up.

Three properties define it:

- **Offline by construction.** It never opens a network socket and has no remote
  sync, telemetry, auto-update, or cloud anything. There is no async runtime and
  no networking crate in the dependency tree (a load-bearing decision, not an
  omission — see §3, req. 1). The secrets never leave the machine.
- **Two passwords, both required.** The encryption key is derived by chaining two
  Argon2id passes over two independently-entered passwords (§5.2), so the vault
  can be split across two trustees and neither half alone can open it.
- **Auditable.** The code is deliberately small (a handful of modules, no
  `unsafe`, heavily commented, extensively tested) so one person can read the
  entire security-critical path — KDF, AEAD, the on-disk format, and the crash-
  safety protocol — in a single sitting. That reviewability *is* a security
  feature (req. 13).

The intended user is non-technical (someone organising their own estate, or an
executor opening it later); the intended reviewer is a security-conscious
engineer auditing what they run. This document is the "why"; `IMPLEMENTATION.md`
is the "how" and the "where".

## 2. Requirements traceability

Each numbered requirement from the brief maps to a concrete design element.

| # | Requirement | Where it lives |
|---|-------------|----------------|
| 1 | Standalone, no internet | No network/async crates in `Cargo.toml`; offline by construction (§3) |
| 2 | Filter screens + custom category types | Per-tab filters (account type/subtype/owner/review; asset review); editable `categories` stored in-vault (§4.2, §4.3) |
| 3 | Rich records (accounts, assets, real estate, trust/will, instructions, taxes, general documents) | Seven record types, one per tab (§4.1) |
| 4 | Each change logged with timestamp | Per-record `history: Vec<Change>` + vault-level `audit` (§4.2) |
| 5 | History maintained | Append-only `history` retained on every edit; field-level diffs (§4.2); trimmable on demand via `compact --json` (§11.1) |
| 6 | Last access maintained | `Vault.last_opened_at` + a monotonic `generation`, surfaced on unlock (§4.2) |
| 7 | Highest encryption level | Argon2id KDF + XChaCha20-Poly1305 AEAD, per-blob (§5) |
| 8 | Encrypted JSON | JSON vault + JSON manifests, all AEAD-encrypted on disk (§6) |
| 9 | Two passwords, set sequentially | Chained Argon2id derivation (§5.2) |
| 10 | Intuitive interface | Two interchangeable front-ends (egui GUI default, ratatui TUI) over one API (§7) |
| 11 | File identifiable | `PMVAULT\0` magic + self-describing header; fixed directory layout (§6) |
| 12 | Random password generator | `password.rs`, bias-free rejection sampling over the OS CSPRNG (§5, §7) |
| 13 | Simple to review | Small modules, no `unsafe` (crate-wide `#![forbid]`), commented, unit/property/fuzz/mutation-tested |
| 14 | Attach supporting documents | Partitioned, per-blob-encrypted, crash-safe document store (§4.3, §6, §11) |
| 15 | Survive crashes / power loss | Ordered per-operation commit + recovery; staged crash-safe rekey (§6.4, §11) |
| + | Compiles on Windows + Linux | Portable `std` + `#[cfg]`-gated permissions (§9.9), `directories` for paths |

## 3. Technology choices

- **Language:** Rust (edition 2024). Memory safety without a garbage collector —
  no use-after-free or buffer overflow in safe code, which matters for a program
  that parses attacker-controlled files. The crate sets `#![forbid(unsafe_code)]`
  crate-wide, so there is *no* `unsafe` anywhere (even the page-locking goes
  through a safe wrapper, see below). `zeroize` integrates cleanly for wiping
  secrets on drop.
- **Interface:** two interchangeable front-ends over the same vault API —
  a [`ratatui`](https://crates.io/crates/ratatui) terminal UI (`ui.rs`, good for
  SSH/headless) and an [`egui`/`eframe`](https://crates.io/crates/eframe)
  graphical UI (`gui.rs`, the default). Both compile into the single standalone
  binary; neither uses a browser, Electron, or the network. Keeping all crypto
  and storage behind one `OpenVault` API means the (larger, less-audited) UI code
  is *not* security-critical and can't reach around the core. `--tui` selects the
  terminal UI.
- **KDF:** `argon2` (Argon2id) — the current best-practice memory-hard password
  hash (PHC winner, OWASP-recommended). Memory-hardness is what makes offline
  guessing expensive on GPUs/ASICs. Chosen over PBKDF2/bcrypt for that reason.
- **Cipher:** `chacha20poly1305` (XChaCha20-Poly1305 AEAD). AEAD gives
  confidentiality *and* integrity in one primitive (encrypt-then-MAC built in), so
  tampering is detected on decrypt. The **X**ChaCha variant has a 192-bit (24-byte)
  nonce, large enough that **random** nonces effectively never collide — which lets
  every write pick a fresh random nonce with no counter state to corrupt. Chosen
  over AES-GCM to avoid AES-GCM's smaller nonce (reuse is catastrophic) and its
  reliance on hardware AES for constant-time safety.
- **Clipboard:** `arboard` (default features disabled — the image stack is not
  pulled in), for copying a password without displaying it; auto-cleared (§7.1).
- **Randomness:** `getrandom` (the OS CSPRNG) for salts, nonces, ids, and the
  password generator — no userspace PRNG to seed or mis-seed.
- **Serialization:** `serde` + `serde_json`. JSON keeps the plaintext
  human-inspectable (it round-trips through `export-tree`, §6.3) and the parser is
  mature and fuzzed upstream.
- **Secret hygiene:** `zeroize` to wipe keys and decrypted buffers on drop;
  `region` to memory-lock (`mlock`/`VirtualLock`) the derived key's pages so they
  are not paged to swap (best-effort, §9.6).

There is intentionally **no async runtime and no networking crate** — verified by
`cargo audit`/dependency review and by the absence of `tokio`/`reqwest`/etc. in
`Cargo.lock`. This is a load-bearing design decision, not an omission (req. 1):
nothing in the process can open a socket, so secrets cannot exfiltrate even if a
dependency tried.

## 4. Data model

The model lives in `records.rs` and serializes to JSON. The app is a seven-tab
estate vault: each tab is a `Vec` of one record type. Every record shares an
`id` (128-bit random hex, stable across edits), `created_at`/`updated_at`, and an
append-only `history: Vec<Change>` (req. 4, 5). The shared insert/edit/diff logic
is the `Record` trait + generic `upsert`/`remove`.

```text
Vault
├── version: u8                  // schema version (currently 4)
├── id: String                   // random; binds this vault's manifests + volumes
├── last_opened_at: i64          // set on each successful unlock (req. 6)
├── generation: u64              // monotonic write counter (rollback hint, §9.12)
├── instructions:  Vec<Instruction>   // Tab 1: title, description
├── trust_wills:   Vec<TrustWill>     // Tab 2: document, usage, file (doc id)
├── assets:        Vec<AssetLiability>// Tab 3: kind, description, owner, value, date,
│                                     //         institution, type, statement (doc id)
├── accounts:      Vec<Account>       // Tab 4: account_type, owner, username, password, url, description
├── real_estate:   Vec<RealEstate>    // Tab 5: address, ownership, taxes, hoa, income/financing/payment account,
│                                     //   financing_balance, 3 portal logins (mgmt/insurance/HOA: url+username+password),
│                                     //   comments, documents (doc ids; folder real-estate/<address>/)
├── tax_filings:   Vec<TaxFiling>     // Tab 6: year, notes, documents (doc ids)
├── general_documents: Vec<GeneralDocument> // Tab 7: title, description, file (one doc id)
├── categories: TypeLists        // the editable dropdown lists (in-vault, §5/§4.2)
├── settings: VaultSettings      // { volume_max_size, redundancy }  (Config screen, §4.3)
└── audit: Vec<Change>           // vault-level log: created, password changed, deletions, uploads

// The Taxes/General-Documents collections and the new Real Estate fields were all
// added as #[serde(default)] fields, so the on-disk schema version stays 4 and a
// vault written before them still loads (a missing field decodes to its default).
//
// Document storage uses one uniform virtual-path layout across every document tab
// (§4.3): <root>/<auto-group>/<timestamp>/[subfolder]/<filename>, where <root> is
// the tab (taxes, real-estate, general-documents, trust-will, assets), <auto-group>
// is the record's identifying field (year / address / title / document / desc),
// <timestamp> is the upload time (YYYYMMDD-HHMMSS UTC), and the user controls only
// the optional <subfolder> and the <filename>. Each component is slugged/capped.

Change
├── at: i64                      // unix-seconds timestamp
├── action: String               // "created" | "updated" | "deleted" | "uploaded" | ...
└── detail: String               // human-readable summary, e.g. "username: alice -> bob"
```

The document index (`{id, path, size, offset, length}` per blob) is **not** in the
vault JSON — it lives in the per-partition manifests (§4.3, §11); records hold
only the doc-id references. The `kind`/`asset_type`/`account_type` dropdown values
come from `categories`, which is stored **inside the encrypted vault** (§4.2,
§5) — there are no external configuration files.

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
dropdowns populated by the vault's `categories` (`TypeLists`), seeded with
sensible defaults on creation and editable from the Config screen. They live
**inside the encrypted vault** (not in external files), so they travel with it
and leak nothing at rest (§5, §4.4).

### 4.3 Encrypted document store (partitioned, format v4)

Statements, wills, and other documents live in a **partitioned, lazily-loaded,
crash-safe** store under the vault directory — `mypath/volume/vol.<N>` (the blob
data) indexed by `mypath/manifest/manifest.<N>` (the encrypted index). The full
design is in **§11**; the essentials:

- **Per-blob encryption.** Each document is one **self-describing frame**
  `[u32 len][nonce(24)][ciphertext]` appended to a volume, where the ciphertext
  covers `[id_len][id][path_len][path][bytes]` and the AEAD associated data is
  `PREFIX ‖ vault_id ‖ partition`. Per-blob encryption (vs one big archive) is
  what lets the store grow without bound and read one document without decrypting
  the rest.
- **Identity binding.** A frame authenticates only under its vault's id and its
  partition, so a volume/manifest from another vault (or a wrong partition) fails
  the tag. The id and path *inside* the authenticated plaintext are verified
  against the manifest entry on every read, so a relocated/substituted (but
  individually authentic) frame from the same partition cannot be served under the
  wrong identity. An open-time check additionally requires every document a record
  references to be present (rejects a store missing referenced docs).
- **Lifecycle.** Attaching persists the record→document link immediately.
  Removing/detaching/deleting **persists the unlinked vault first, then** reclaims
  the blob (drops its manifest entry), so a crash in between leaves at most a
  harmless orphan, never a dangling reference. A reclaimed blob's bytes linger in
  the volume as garbage until the `compact` command (§11.1) rewrites the volume
  keeping only live blobs.
- **In-memory footprint.** Only the (small) manifests are decrypted on open;
  volume bytes are read on demand, one frame at a time — the whole document set is
  never held in memory at once.
- **Uniform virtual-path layout.** Every document tab files its uploads under one
  scheme — `<root>/<auto-group>/<timestamp>/[subfolder]/<filename>` — where `<root>`
  is the tab (`taxes`, `real-estate`, `general-documents`, `trust-will`, `assets`),
  `<auto-group>` is the record's identifying field (filing year, property address,
  document title, …, so a record's documents cluster together), `<timestamp>` is the
  upload instant (`YYYYMMDD-HHMMSS` UTC, making each upload's path unique), and the
  user supplies only the optional `<subfolder>` and the `<filename>`. The auto-group
  and subfolder are slugged (lowercased, ASCII-alphanumeric, `-`-separated, capped at
  40) and the filename is sanitized (separators/control chars neutralized, capped at
  120) — so no user input can inject extra path levels or `..` traversal, and the
  built path stays within `MAX_PATH_LEN`. The virtual path is authenticated inside
  the frame (it is part of the AEAD plaintext and checked against the manifest), so
  it is integrity-protected like the bytes. These helpers live in `records.rs`
  (`doc_slug`, `compact_utc`, `doc_upload_dir`, `doc_filename`, and the per-tab
  `*_doc_location` prefixes) and are shared verbatim by the GUI and TUI.

### 4.4 Read-only by default

Both UIs open the vault **read-only** unless `--write` is passed. Read-only is
enforced in two layers:

- **Core (authoritative):** `OpenVault::open_read_only` sets a `read_only` flag;
  every mutating method (`save`, `change_password`, `add_document`,
  `remove_document`, and the category mutators `add_asset_type` /
  `add_account_type` / `add_account_subtype`) returns `VaultError::ReadOnly`, and
  the open path writes nothing to disk (not even the refreshed
  `last_opened_at`/generation) and takes no single-writer lock. So a read-only
  session is guaranteed not to modify `vault.pmv` or the document store.
- **UI:** the front-ends hide write controls (New/Save/Delete/attach/detach/
  generate/change-password/type-add) and show a `🔒 READ-ONLY` badge; reads
  (browse, reveal, copy, export, backup) remain available.

Because the category lists now live **inside the vault** (not in external files),
a read-only session writes **nothing** to disk at all — there are no auxiliary
config files to seed.

Creating a vault is itself a write, so first-run creation requires `--write`.

## 5. Cryptography

### 5.1 Primitives

- **KDF:** Argon2id, OWASP-aligned defaults — 64 MiB memory, 3 passes, 1 lane,
  32-byte output. Parameters are stored in the file header so the vault stays
  self-describing and the cost can be raised later without breaking old files.
- **AEAD:** XChaCha20-Poly1305. 24-byte random nonce per write (large enough that
  random nonces won't collide in practice). The **entire 61-byte header** — magic,
  version, all three Argon2 parameters, salt, **and the nonce** — is fed in as
  **associated data**, so every header field is bound under the Poly1305 tag.
  Tampering with any of it (a cost-parameter *downgrade*, a *swapped salt*, a
  *flipped nonce*) is detected on decrypt. To bind the nonce, the nonce is
  generated first, written into the header, and the whole header is passed as AAD
  to `encrypt_with_nonce` (rather than letting the cipher pick the nonce after the
  AAD is fixed). This is belt-and-suspenders: the params/salt already influence
  the derived key and the nonce is already the cipher nonce, but authenticating
  them explicitly closes any room for an undetected downgrade/swap and makes the
  property auditable. See §5.4 and the `header_tampering_is_detected` test.

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

### 5.4 Encryption scheme — end-to-end methodology

Putting §5.1–§5.3 together, this is exactly what happens to your data.

**Creating / saving the vault**

1. On create, generate a random 16-byte `salt1` and a random vault `id` (which
   binds this vault's manifests and volume frames in their AAD).
2. Derive the key from the two passwords (chained Argon2id, §5.2):
   `k1 = Argon2id(pw1, salt1)`, `key = Argon2id(pw2, salt = k1)`.
3. Serialize the whole vault (records, history, document manifest, **and the
   category lists**) to JSON.
4. Generate a fresh random 24-byte nonce and write it into the header.
5. AEAD-encrypt the JSON: `ct = XChaCha20-Poly1305(key, nonce, plaintext,
   aad = full 61-byte header)`. The header (magic, version, Argon2 params, salt,
   nonce) is the associated data, so it is authenticated but not encrypted.
6. Write `header ‖ ct` atomically (temp file + `fsync` + rename + dir `fsync`).

**Opening the vault**

1. Parse and range-check the header (reject absurd Argon2 params before doing any
   memory-hard work — a DoS guard).
2. Re-derive `key` from the two passwords + the header's salt/params.
3. AEAD-decrypt, verifying the Poly1305 tag over `(full header, ciphertext)`. A
   wrong password, a corrupted body, or **any** altered header field fails here —
   there is no separate password check, so the tag is the single source of truth.

**Documents** are encrypted per-blob into the partitioned store (`volume/vol.<N>`,
indexed by `manifest/manifest.<N>`) under the same `key`, each frame's AAD binding
`vault_id ‖ partition` so a foreign/swapped/cross-partition frame or manifest is
rejected; the authenticated id/path inside each frame are checked against the
manifest on read, and an open-time referenced⊆stored check rejects a store missing
referenced documents (§4.3, §11, §9.12).

**Methodology / rationale.** Standard, well-reviewed primitives only (Argon2id,
XChaCha20-Poly1305) from audited Rust crates; no home-grown crypto and no
`unsafe`. Encrypt-then-MAC is provided by the AEAD construction itself. The file
is self-describing (params in the header) so cost can be raised over time without
breaking old vaults. Secrets are memory-locked (§9.6) and zeroized on drop.

**Weaknesses / limits of the scheme** (details in §9):

- **Password-grade security.** The vault is only as strong as the two passwords.
  Argon2id makes guessing expensive but cannot save weak passwords; chaining does
  **not** make brute force quadratic (§5.2 caveat, §9.1).
- **No password verifier.** The only way to know a password is right is a full
  AEAD decrypt; conversely there is no rate-limiting/lockout against an attacker
  who has the file and guesses offline (§9.2, §9.7).
- **History retains old passwords** in the (encrypted) vault by design (§9.4).
- **Confidentiality, not anti-forensics.** The plaintext header leaks that this
  is a pass-mgr vault and its KDF cost; file size leaks the rough data volume.
- **At-rest only.** Once unlocked, the key and plaintext live in process memory;
  a compromised host (malware, keylogger, debugger, cold-boot) defeats every
  in-process measure (§9.14). Memory zeroization/locking is best-effort (§9.6).
- **Rollback of a matched older tree** (`vault.pmv` + `manifest/` + `volume/`, or
  an individual partition) can't be detected at rest without an external trusted
  counter (§9.12).
- **Nonce reuse** would be catastrophic for any stream cipher; here nonces are
  random per write, and the 24-byte XChaCha nonce space makes collision
  negligible — but this relies on the OS CSPRNG being sound.

### 5.5 How this compares to BitLocker, Office/Excel passwords, and encrypted disks

It is worth being precise about where `pass-mgr` sits relative to the encryption
people already know, because the systems solve *different* problems and the
honest comparison is "complementary, not competing." `pass-mgr` is **application-
level, file-scoped, authenticated encryption that you actively unlock and that
re-locks** — it protects one small estate vault even while you are logged in and
even from other programs running as you. Full-disk encryption (FDE) —
**BitLocker**, **LUKS/dm-crypt**, **FileVault**, **VeraCrypt** — instead protects
a *whole volume at rest*: it is transparent once the machine is booted and the
volume mounted, so it defends against a stolen or powered-off disk but does
**nothing** to stop a logged-in attacker, malware, or another app from reading
your files. **Office/Excel password protection** is the closest analogue (one
encrypted document opened on demand), but it is the weakest of the group.

Three axes matter most:

| | KDF (offline-guessing cost) | Cipher / integrity | Scope & escrow |
|---|---|---|---|
| **pass-mgr** | **Argon2id**, memory-hard (64 MiB), chained over **two** required passwords | **XChaCha20-Poly1305 AEAD** — authenticated; tampering fails closed | one file-set; **no escrow/recovery, no backdoor** |
| **BitLocker** | volume key **sealed to the TPM** (+ optional PIN); not a memory-hard passphrase hash. 48-digit recovery key = 128-bit random | **AES-XTS** — confidentiality only, **no authentication** (malleable; tamper not detected) | whole volume; recovery key is often **escrowed** to AD/Azure/Microsoft account |
| **LUKS2** | **Argon2id** (comparable to pass-mgr) | AES-XTS — **no authentication** by default (dm-integrity is separate) | whole volume; multiple key slots (any one unlocks) |
| **FileVault / VeraCrypt** | **PBKDF2**, many iterations (fast on GPUs relative to Argon2id) | AES-XTS — no authentication | whole volume; FileVault offers a recovery-key escrow |
| **Excel / Office (.xlsx, 2013+)** | **iterated SHA-512** (e.g. ~100 k spins) — *not* memory-hard, fast to crack on GPUs; older `.xls` RC4 is trivially broken, and "protect sheet/workbook" is just a removable flag, not encryption | AES-CBC + an HMAC integrity check (agile encryption) | one document; no escrow |

The upshot: pass-mgr's **key-derivation hardness matches the strongest of these
(LUKS2's Argon2id)** and is far stronger than Excel's fast SHA-512 or FileVault/
VeraCrypt's PBKDF2 against an attacker who has the file and guesses offline.
Its **authentication is stronger than every disk encryptor's**: AES-XTS used by
BitLocker/LUKS/FileVault/VeraCrypt provides confidentiality but is *malleable* and
detects neither bit-flips nor swaps, whereas pass-mgr's AEAD (and its per-frame
`vault_id ‖ partition ‖ id` binding, §4.3) makes any tampering fail closed. It is
also **escrow-free with no recovery path** — unlike BitLocker's commonly-escrowed
recovery key, losing both pass-mgr passwords means the data is gone (intentional
for a two-trustee estate vault; a footgun if you simply forget). And its
**two-passwords-both-required** design is unusual: BitLocker can require TPM+PIN
(an AND, but bound to one machine's hardware), LUKS exposes multiple slots that
each unlock independently (an OR), and Excel takes a single password.

What pass-mgr deliberately gives up: FDE's *transparent, whole-disk* coverage (it
protects only its own vault, not your `/home` or temp files), and BitLocker's
hardware-bound, anti-hammering TPM and enterprise recovery. So the recommended
posture is to run pass-mgr **on top of** an encrypted disk: FDE protects
everything at rest and ties the key to the machine/TPM; pass-mgr adds a second,
independently-keyed, authenticated, app-isolated layer for the estate secrets
that stays locked while you work and that no other process — or a future you who
only remembers one password — can open without both secrets.

## 6. On-disk file format (req. 8, 11)

The vault is a **directory** `mypath/` holding three things:

```text
mypath/vault.pmv          encrypted JSON vault (header + AEAD ciphertext)
mypath/manifest/manifest.<N>  encrypted per-partition document index
mypath/volume/vol.<N>         append-only, per-blob-encrypted document frames
mypath/pass-mgr.lock          single-writer advisory lock (empty; writable opens only)
```

### 6.1 `vault.pmv`

All integers little-endian. The header is plaintext (so the file is
self-identifying and self-describing); the body is ciphertext.

```text
offset  len  field
0       8    magic            b"PMVAULT\0"            (req. 11 — identifiable)
8       1    format version   currently 4
9       4    Argon2 m_cost (KiB)
13      4    Argon2 t_cost
17      4    Argon2 p_cost
21      16   salt1            (first-pass KDF salt)
37      24   nonce            (XChaCha20-Poly1305)
61      ..   ciphertext       AEAD(JSON vault), full 61-byte header as assoc. data
```

### 6.2 Manifests and volumes

- A **volume** `vol.<N>` is a sequence of frames `[u32 frame_len][nonce(24)][ct]`
  where `ct = AEAD(key, nonce, plaintext, aad = "PMVAULT-VOLUME-v1\0" ‖ vault_id ‖
  N)` and `plaintext = [u32 id_len][id][u32 path_len][path][doc_bytes]`. Frames are
  append-only; the manifest's `end_offset` is the authoritative end of valid data,
  so a torn trailing frame from a crash is ignored and overwritten.
- A **manifest** `manifest.<N>` is `nonce(24) ‖ ct` where `ct = AEAD(key, nonce,
  JSON, aad = "PMVAULT-MANIFEST-v1\0" ‖ vault_id ‖ N)` and the JSON is
  `{seq, end_offset, entries: [{id, path, size, offset, length, uploaded_at}]}`.
  Manifests are written atomically (temp → fsync → rename → dir fsync). A
  lost/corrupt manifest is rebuilt by scanning its self-describing volume.

- The **entire 61-byte header** (magic, version, params, salt, nonce) is the AEAD
  associated data, so every field is authenticated under the Poly1305 tag even
  though none of it is secret — a cost-parameter downgrade, a swapped salt, or a
  flipped nonce all fail the tag on open (§5.1, §5.4).
- **Atomic writes:** the vault is written to a uniquely-named, hidden temp file
  (`.<name>.<random>.tmp`) created with `create_new`/`O_EXCL` so a pre-planted
  symlink at a predictable path cannot be followed, `fsync`'d, then renamed over
  the real file; the parent directory is then `fsync`'d so the rename is durable.
  A crash mid-write cannot corrupt an existing vault, and a failed write removes
  the temp file.
- **File permissions:** on Unix every vault file (`vault.pmv`, manifests,
  volumes, and the lock file) is `0600` and the directories `0700`; temp files are
  created `0600` *atomically* (no world-readable window). Volume appends additionally
  open with **`O_NOFOLLOW`** (Unix), so the kernel atomically refuses if the volume
  path's final component is a symlink — closing the check-then-open race a bare
  pre-check leaves; a `symlink_metadata` pre-check is kept only as a fast early
  error. The `backup` destination directory is likewise refused if it is a symlink.
- **Untrusted-input bounds:** KDF parameters read from the file header are
  range-checked before the memory-hard derivation runs, and `vault.pmv`, each
  manifest, and each document are size-capped before being read, so a crafted file
  cannot force a huge allocation (DoS) — see §9.13.

> Note: the current format is **version 4** (the partitioned document store of
> §4.3/§11, with the category lists and a `settings` block embedded in the vault
> JSON). Earlier versions are not auto-migrated; an unsupported version is reported
> rather than risk a lossy migration (see §9.5). The full 61-byte header is the
> vault AAD; manifests and volume frames each bind `vault_id ‖ partition` in their
> own AAD.

### 6.3 Plaintext mirror — full decrypt / import round-trip

Two CLI commands form a **lossless round-trip** between the encrypted vault and a
fully-decrypted directory that *mirrors its structure* (distinct from `extract`,
which writes a human-readable virtual tree and is one-way):

```
pass-mgr export-tree [DIR] OUTDIR    # decrypt the whole vault into a plaintext mirror
pass-mgr import-tree  SRCDIR [DIR]   # build a NEW encrypted vault from a mirror
```

**Mirror layout** (everything decrypted, names mirroring the encrypted tree):

```text
OUTDIR/vault.json                 # the decrypted Vault (records, categories,
                                  #   settings, audit, id, version, generation)
OUTDIR/manifest/manifest.<N>.json # the decrypted manifest of partition N
                                  #   (entries: {id, path, size, uploaded_at, ...})
OUTDIR/volume/vol.<N>/<id>        # each document's raw decrypted bytes, by id,
                                  #   grouped by the partition it lived in
```

`export-tree` decrypts the vault once (one Argon2 derivation), then walks every
partition writing the three kinds of file; it refuses a half-committed rekey
(`RekeyPending`) so the mirror is always self-consistent.

`import-tree` reverses it: read `vault.json` (preserving the records, categories,
settings, and vault `id`), then re-encrypt every document from the mirror — using
its manifest entry for the virtual `path`/`uploaded_at` and the `vol.<N>/<id>`
bytes for content — into a brand-new encrypted vault under **two new passwords**
(fresh salt, fresh per-blob nonces). Documents are re-placed by the current
`volume_max_size`, so the imported partition layout reflects the imported
`settings`, not necessarily the source's. It refuses to overwrite an existing
vault.

**No duplicated crypto.** Both commands are thin orchestration over the same
primitives used everywhere else: `export-tree` reuses the decrypt path and the
`VolumeStore` read accessors; `import-tree` reuses `VolumeStore::open` +
`put` (the exact per-blob re-encryption a password change already performs) +
the atomic vault writer, then hands back a normal `OpenVault` via the standard
open path (which re-validates and runs the referenced⊆stored consistency check).

**Uses.** Disaster recovery and migration (rotate to a clean vault, or move to a
new machine, via a human-inspectable intermediate), format introspection, and
re-keying by full rebuild. Because the mirror is **plaintext on disk**, it
carries the same warning as `decrypt`/`extract`: write it only to encrypted or
ephemeral storage and delete it promptly (§9.10, §9.17).

## 7. User interface (req. 10)

The app ships **two interchangeable front-ends** that drive the **same**
`OpenVault` API and the same screen shape (Auth → browse → edit, plus a Config
screen), so every line of crypto, storage, and data-model logic is shared and
UI-independent. Adding or changing a front-end touches no security-critical code.

- **Graphical (`gui.rs`, the default)** — `egui`/`eframe`, immediate-mode,
  on-screen buttons and tabs. Needs a desktop (X11/Wayland).
- **Terminal (`ui.rs`, `--tui`)** — `ratatui`, keyboard-driven, works over SSH /
  headless. Key bindings are shown on-screen at all times; no mouse required.

The desktop front-ends present the estate vault as **seven tabs**, one per record
type — Instructions, Trust & Will, Assets & Liabilities, Accounts, Real Estate,
Taxes, and General Documents — over four screens. (The read-only mobile viewer, §8,
currently exposes the first five record types.) The four screens are:

1. **Auth (unlock / create).** Prompts for password 1, then password 2 (masked).
   On a missing vault it switches to a create flow that asks for each password
   twice to confirm. After unlock it shows the last-opened time and the write
   `generation` (req. 6; a jump backwards in generation hints at a rollback,
   §9.12). The same screen drives **change-password** (re-key), which calls
   `OpenVault::change_password`.
2. **Browse.** The selected tab's records as a list, with per-tab **filters**
   (Accounts by type/subtype/owner/"needs review"; Assets by "needs review")
   driven by the in-vault category lists, plus a free-text **username search** on
   the Accounts tab (case-insensitive substring; the GUI has a search box, the TUI
   enters it with `/`). Selection resolves **by record id**, so a filtered or
   searched list never edits the wrong record.
3. **Edit.** All fields of one record; passwords masked with a reveal toggle and
   a clipboard copy that auto-clears (§7.1). Saving appends a field-level `Change`
   to the record's history (req. 4, 5), shown in a History pane. Document-bearing
   tabs can **attach / detach / replace / export** supporting documents: Trust &
   Will and Assets hold a single document each, while Real Estate and Taxes hold a
   **folder of multiple documents** (`real_estate/<id>/…`, `taxes/<year>/…`) tracked
   per record by `referenced_doc_ids`. The attach path enforces the 256-byte
   virtual-path limit (the GUI disables the button with an inline error, the TUI
   rejects the upload key) and persists the record→document link before reclaiming
   any old blob (crash-safe ordering, §11).
4. **Config (write mode only).** Edit the category lists (asset types, account
   types + subtypes) and the **volume size** (`volume_max_size`), and run a
   `backup`. All edits persist into the encrypted vault — there are no external
   config files.

Read-only is the default and is enforced in the core (§4.4), with the UIs hiding
write controls and showing a read-only badge.

### 7.1 Clipboard caveat

Copying a password uses the OS clipboard via `arboard`. The clipboard is shared
with every app and may be synced by the OS. We mitigate by offering a "clear
clipboard" action, but cannot guarantee the OS hasn't already captured it. See
§9.3.

## 8. Threat model

**Adversary.** Someone who can read and/or write the on-disk vault *directory*
(`vault.pmv`, `manifest/`, `volume/`) and may supply a crafted vault/manifest/
volume, but who does **not** know the two passwords. The machine is assumed
trustworthy *while the vault is unlocked* (host compromise is out of scope, below).

**In scope (defended):**

- **Theft of the files at rest.** Without both passwords, every encrypted unit is
  indistinguishable from random beyond the plaintext header. Argon2id makes
  offline guessing expensive, and the header KDF parameters are size-bounded so a
  crafted header can't force an unbounded Argon2 allocation (§9.13).
- **Tampering / forgery.** Every unit is AEAD-authenticated and *bound to its
  place*: the vault to its full header, each manifest and each volume frame to
  `vault_id ‖ partition`, and each frame's id/path checked against the manifest on
  read (§4.3). So bit-flips, a swapped salt/nonce/param, a frame moved
  across partitions, a manifest/volume from another vault, or a relabelled
  document all fail the tag or the id check — decrypt fails closed.
- **Crafted-input safety.** The hand-rolled frame/manifest parsers are fully
  bounds-checked, size-capped, and fuzzed; arbitrary bytes yield `Err`, never a
  panic, over-read, or OOM (§6.4, §9.13).
- **Crash / power loss.** An interrupted write (including a password change)
  recovers to a fully-committed state — never a partial or mixed one (§11).
- **Wrong password.** Fails closed with a generic error; no partial decrypt and
  no independent oracle for either password (§9.2).
- **Accidental local exposure.** 0600/0700 permissions, swap-locked keys, and a
  read-only default reduce *incidental* leakage to other local accounts or to disk.

**Out of scope (cannot defend, by design or by platform):**

- **A compromised host.** Malware, a keylogger, a debugger, or a root user on the
  same machine can capture passwords as you type or read process memory while the
  vault is unlocked. No userland password manager can defend against this.
- **Cold-boot / swap / hibernation.** Keys live in RAM while unlocked and may have
  been paged to disk earlier; zeroize/`mlock` are best-effort (§9.6).
- **Rollback to authentic older state.** An attacker who can write the files can
  restore an earlier, self-consistent snapshot (whole tree, a partition, or a
  truncated volume); defeating this needs an external trusted counter (§9.12).
- **Destruction.** Anyone who can write the directory can also delete it; the
  format protects confidentiality/integrity, not availability.
- **Shoulder-surfing / screen capture** of revealed passwords.
- **Rubber-hose / coercion.** Both passwords can be extracted from the user.
- **Plaintext the user exports.** `decrypt`/`extract`/`export-tree` deliberately
  write secrets in the clear; protecting that output is the user's job (§9.10,
  §9.17).

### 8.1 Mobile viewer and the FFI boundary

The Compose Multiplatform app (`mobile/`) is a **read-only viewer** that drives the
same audited core through a UniFFI boundary (`crates/pass-mgr-ffi`). It widens the
attack surface in three specific, bounded ways:

- **It never writes vaults.** It calls only the open/read path, so it inherits every
  at-rest confidentiality and integrity guarantee above and adds no new write or
  recovery code to audit. It does **not** take the single-writer lock and does not
  mutate the document volume.
- **The clipboard.** Copying a credential on mobile crosses into a shared, cross-app
  surface. The viewer clears the clipboard automatically 15 s after a copy and
  immediately on lock; the auto-clear is owned at app scope so it survives navigation
  (hardening finding F-2, see `docs/HARDENING.md`). The §9.3 caveat — the OS may have
  captured the value before the clear — still applies.
- **Feature gates are off on mobile.** The FFI crate builds the core with
  `default-features = false`, so the desktop-only `mlock` (swap-locking key pages) and
  `single-writer-lock` (advisory `flock`) features are **not** compiled in. On mobile
  the OS process sandbox provides the isolation those features target on a shared
  desktop, and `mlockall`-style locking is neither portable nor useful inside an app
  sandbox. The cryptographic core is otherwise identical.

The FFI crate (`pass-mgr-ffi`) is the **only** crate permitted `unsafe`, confined to
the generated UniFFI scaffolding; `pass-mgr-core` keeps `#![forbid(unsafe_code)]`.

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
while it is there. To bound the window, both front-ends now **auto-clear the
clipboard 15 seconds after a copy** (the GUI schedules a repaint at the deadline;
the TUI polls its event loop) **and again on exit** (best-effort). This shrinks
but does not eliminate exposure: a clipboard manager or cloud-sync that captures
the value within those 15 seconds keeps its own copy.

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
decrypted data model (records/`Change`/`Vault` are `ZeroizeOnDrop`, and the
in-memory document archive holds `Zeroizing` bytes), and the password-input
buffers in the TUI, GUI, and CLI.

**Swap mitigation.** The derived encryption key — the highest-value secret, since
it decrypts the whole vault — is held in heap pages that are **memory-locked**
(`mlock` on Unix, `VirtualLock` on Windows, via the `region` crate), so the OS
will not page it out to swap where a plaintext copy could persist on disk across
reboots. The lock is released and the bytes wiped on drop.

Residual risk remains and is *not* fully mitigated: the decrypted records, the
document archive, and password-input buffers are **not** page-locked (a blanket
`mlockall(MCL_FUTURE)` would cover them but makes later allocations fail under
the default `RLIMIT_MEMLOCK` and would destabilize the GUI). Those can still be
swapped. Rust may also move `String`/`Vec` contents during reallocation, leaving
un-wiped copies. For full protection of all secrets at rest in swap, use an
**encrypted swap device/file** (or disable swap). None of this defends a
compromised host (out of scope, §8).

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
closed). See §6, the full crash-safety treatment in §12, and the corruption
taxonomy (crash vs. media bit-rot vs. tampering, with per-case recovery) in §12.7.

### 9.12 Rollback of authentic at-rest state is out of scope
Every encrypted unit is authenticated and bound to its vault and partition: the
vault to its header, each manifest and each volume frame to `vault_id ‖ partition`
(and each frame's id/path are checked against the manifest on read, §4.3). So an
attacker holding the files cannot **forge** content, swap in another vault's
files, move a frame across partitions, or relabel a document — all fail the tag
or the id/path check.

What no purely-at-rest scheme can prevent **without an external trusted counter**
is an attacker restoring older-but-authentic state that the user once wrote:

- Replacing the whole tree (`vault.pmv` + `manifest/` + `volume/`), or a single
  partition's matched `manifest.<N>` + `vol.<N>`, with an earlier self-consistent
  version — it simply looks like the vault as it was then.
- Deleting a `manifest.<N>`: it is rebuilt by scanning `vol.<N>` (recovery for a
  genuinely lost manifest), which also re-indexes documents that had been
  *deleted* (a delete drops only the manifest entry; the blob lingers until a
  `compact` rewrite removes it, §4.3/§11.1), effectively undoing those not-yet-
  compacted deletes. Running `compact --volume` physically drops those frames and
  closes this window for them.
- Truncating a `vol.<N>` to an earlier `end_offset` to drop recently-appended
  frames.

The open-time consistency check is one-directional (every *referenced* document
must be *present*); it deliberately permits unreferenced/garbage blobs, so it does
not detect a dropped record pointer or a rolled-back unreferenced document. The
write-generation counter (bumped on every save, including a rekey) lets a user who
records it out-of-band notice a rollback, but the format itself does not enforce
monotonicity. This is the same inherent limitation that applies to any single
encrypted file at rest; defending it requires an external trusted store
(a TPM counter, a remote witness) which is out of scope for an offline vault.

### 9.13 Resource limits (DoS guards)
A crafted or corrupt file must not be able to exhaust memory before it is
authenticated. Sizes are checked against the file's reported length *before* the
read, and an exceed returns `VaultError::TooLarge` / `StorageError::TooLarge`:

- **Per document:** 64 MiB (`MAX_DOC_SIZE`).
- **Per manifest:** 256 MiB (`MAX_MANIFEST_SIZE`) — generous; manifests are a
  small index.
- **`vault.pmv`:** 256 MiB (`MAX_VAULT_SIZE`) before the wholesale read+decrypt.
- **Volume frames:** the frame-length prefix is range-checked (`>= nonce`, `<=
  MAX_DOC_SIZE + overhead`) and bounds-checked against the file before any
  allocation, so a corrupt length can neither over-read nor over-allocate.

Documents and volumes are read one frame at a time, so the whole document set is
never held in memory at once. One bounded cost remains by design: the Argon2id
parameters live in the (authenticated-but-not-secret) header and must run *before*
any password check (§9.2), so opening an attacker-supplied vault with a maxed-out
cost header (`m_cost` up to 1 GiB, `t_cost`/`p_cost` at their ceilings, run twice
for the chained derivation, §5.2) can burn memory/CPU. The parameters are bounded
(`MAX_M_COST`/`MAX_T_COST`/`MAX_P_COST` in `vault.rs`) so the cost is finite, and
the user chooses which vault to open; lower the ceilings if you only ever open
your own vaults. Adjust any of these constants for genuinely larger needs.

### 9.14 Trust boundary — host compromise is out of scope
pass-mgr protects data **at rest** and assumes the machine is trustworthy *while
the vault is open*. It does **not** defend against a compromised host: malware
running as your user, a kernel keylogger, screen capture/scraping while records
are revealed, a debugger attached to the process, or a cold-boot/DMA attack
against RAM can all read secrets regardless of any in-process measure. The swap
mitigation (§9.6), zeroize-on-drop, and read-only default reduce *incidental*
leakage (to disk, to other local accounts via file modes, to accidental writes),
not an attacker with code execution in your session. Keep the host patched, the
disk full-disk-encrypted, and the vault closed when unattended.

### 9.15 Distributing the binary — integrity is the user's responsibility
The build is reproducible from source, but the project does not ship a signed
binary. The build produces **two** executables on Windows — `pass-mgr-gui.exe` (the
windowed app end users run, §13.3) and `pass-mgr.exe` (the console/CLI build) — and
recipients should verify whichever they run: publish a SHA-256 checksum alongside
each (`sha256sum target/release/pass-mgr*` on Linux, `Get-FileHash` on Windows) and,
ideally, **code-sign** the Windows `.exe`s with your own Authenticode certificate
(`signtool sign /fd SHA256 /a pass-mgr-gui.exe`, and likewise `pass-mgr.exe`) so
SmartScreen and AV trust them. Without that, a tampered download cannot be
distinguished from a genuine one.

### 9.16 Concurrency is single-writer, best-effort for readers
A writable open takes an OS advisory lock on `mypath/pass-mgr.lock` (via
`File::try_lock`, released automatically when the process exits — no stale lock to
clear), so a second writable instance fails fast with `VaultError::Locked`.
Read-only opens and the CLI read facilities (`decrypt`/`manifest`/`extract`) do
**not** take the lock — multiple readers are fine — but they are therefore **not
isolated** from a writer running *concurrently in the same instant*: a backup or
extract taken while another session is mid-write can observe a per-operation
in-between state. The read paths and `backup` do refuse a half-committed password
change (`RekeyPending`), and each individual write is atomic, so the exposure is a
narrow same-moment race, not corruption. The intended model is single-user,
single-active-session; don't back up or extract while actively editing in another
window.

The lock is compiled in behind the **`single-writer-lock`** Cargo feature (default-on
for the desktop build, alongside the **`mlock`** key-page locking feature of §9.6).
Both are switched **off** in the mobile FFI build, which is read-only and relies on the
OS app sandbox instead (§8.1); a desktop build with `--no-default-features` likewise
drops them, trading the writer-collision guard for portability.

### 9.17 Plaintext export writes secrets to disk
`export-tree` (§6.3) — like `decrypt` and `extract` — writes **unencrypted** data
to disk: the full vault JSON (every password, in the clear), the document index,
and every document's bytes. That is the whole point of the command, but it
recreates exactly the exposure the vault exists to prevent. Treat any mirror as
radioactive: write it only to an encrypted volume (LUKS/BitLocker/FileVault) or a
tmpfs/ramdisk, re-encrypt it with `import-tree` promptly, and securely delete the
plaintext when done. The mirror has no integrity binding once on disk — anyone who
can edit it can change what `import-tree` will encrypt.

### 9.18 A password change does not re-encrypt existing backups

`change_password` is a **full re-encryption** of the *live* vault: it derives a new
key from the new passwords + a fresh salt and stages a complete new-key tree
(`vault.pmv` + `manifest/` + `volume/`), then atomically swaps it in (§12.3). It can
only rewrite the files in the live vault directory. A `backup` (§11) is an
independent encrypted copy elsewhere, so the rekey **never touches it** — there is no
"re-encrypt all my backups" operation, and there cannot be (backups may be offline or
on detached media).

Consequently each backup is a self-contained snapshot frozen at the passwords in
effect when it was taken: a backup made **before** the change opens only with the
**old** passwords; one made **after** opens with the new ones. The vault `id` is
preserved across a rekey, so an old backup and the new live vault share an id, but
their files are not interchangeable — each part is bound to its key by the AEAD, so an
old-key `volume/`/`manifest/`/`vault.pmv` fails authentication under the new key.

The security consequence: **a password change is not revocation.** If you rotate the
passwords because the old ones may have leaked, anyone holding an **old backup and the
old passwords can still read it** — the same reason the per-record password *history*
retains old secrets (§9.4). So after a password change: make a **fresh** backup (a
plain change does *not* auto-back-up, unlike `compact`, §11.1), and if the rotation
was due to compromise, **securely destroy the old backups** (or accept they remain
readable with the old passwords). Restoring an old backup is just using it as the
vault directory and opening it with *its* passwords; it is a complete consistent tree,
but an older **generation**, so the unlock screen flags the rollback (§9.12) and any
changes made after that backup are not in it. (`backup` refuses to run mid-rekey —
`RekeyPending` — so it never snapshots a half-re-encrypted tree, and it does not copy
the opt-in in-place redundancy files §12.8, since a backup *is* the off-device
redundancy.)

## 10. Non-goals

- Browser integration / autofill.
- Cloud sync, multi-device, sharing.
- A **writable** mobile client. (A read-only mobile *viewer* over the same core now
  exists, §8.1; editing/creating vaults remains desktop-only.)
- Plugin system.

These are deliberately excluded to keep the attack surface and the codebase
small (req. 1, 13).

## 11. Partitioned document storage (format v4 — as built)

_Status: **implemented** (`src/storage.rs` + `src/vault.rs`). The single-`.vol`
store of earlier prototypes is replaced by this partitioned design. Execution
history, the full test plan, and the review gates are in [`PLAN.md`](PLAN.md)._

The document store is partitioned so it can grow without bound, load lazily, and
survive crashes.

**Layout.** The user supplies only a directory `mypath`; all names are fixed:
`mypath/vault.pmv`, `mypath/manifest/manifest.<N>`, `mypath/volume/vol.<N>`. The
`--vol` flag is removed.

**Volumes** are append-only logs of **individually-encrypted, self-describing
frames** (`[len][nonce][ciphertext]`, with the doc-id and virtual path both inside
the ciphertext and bound in the AAD). Per-blob encryption is what enables lazy,
partial reads of large volumes. **Each partition has its own encrypted manifest**
listing `{id, virtual_path, size, offset, len}` plus a `seq` and the committed
`end_offset`; manifests are written atomically (temp → fsync → rename → dir fsync).

**Crash-safety (the core).** A write commits in a fixed order — append+fsync the
blob, then atomically swap the manifest (volume-layer commit), then atomically
write the vault (final commit). The vault is authoritative; anything in a
manifest/volume not referenced by the vault is reclaimable garbage; a torn
trailing frame past `end_offset` is ignored. So **any crash/power loss recovers to
at least the state prior to the last update, and no partial/corrupt state is ever
visible.** A lost/corrupt manifest is **rebuilt by scanning** its self-describing
volume.

**Lazy load.** On open, only the (small) manifests are decrypted into an index;
volumes are opened on demand and flushed/closed when idle.

**Partitioning.** A configurable `volume_max_size` (default 256 MiB, stored in the
vault) governs placement of *new* documents; exceeding it starts a new partition.
Updates append to the **same** partition as the original. The dead blobs that
updates and deletes leave behind are reclaimed on demand by `compact` (§11.1).

**Password change** re-encrypts **everything** under a fresh key (full
re-encryption, not a wrapped data-key), staged in `mypath/.rekey/` with a `READY`
marker and committed by roll-forward, so a crash mid-rotation leaves either the
old or the new tree fully working — never a mix. Rationale for full re-encryption
over an envelope/data-key scheme (rotation must defend against a leaked *old*
password) is in `PLAN.md` §7.

### 11.1 Compaction (`compact`)

The append-only volume never shrinks on its own: an update appends a new frame and
drops the old manifest entry; a delete drops the entry. The old frames remain as
**garbage** in `[0, end_offset)`. Separately, every record carries an append-only
per-edit `history` log that grows monotonically. The CLI `compact` command reclaims
both, individually or together (`pass-mgr compact [DIR] --volume --json …`):

- **Volume compaction (`--volume`)** rewrites the document store keeping only the
  **live** blobs (those still referenced by a manifest entry), dropping every dead
  frame. It is implemented as a **same-key re-key**: it reuses the exact
  stage→`READY`→roll-forward machinery of a password change (§12.3), re-encrypting
  each live document with a fresh nonce into `.rekey/` and swapping the new tree in
  atomically. Documents may be re-packed into fewer partitions, so **partition
  numbers are not stable across a compaction or rekey** (records reference document
  *ids*, never partitions, so this is invisible to the data model). The
  write-generation is bumped, exactly as a rekey does.
- **History compaction (`--json`)** trims each record's `history`: either entries
  older than a `--history-before YYYY-MM-DD` cutoff (UTC; entries on/after the date
  are kept) or all of them (`--history-all`). The vault-level `audit` log is
  **always preserved**, and a `compacted` event is appended to it. JSON-only
  compaction needs no volume work — it is an in-memory trim followed by the normal
  atomic `vault.pmv` save.

**Safety.** Compaction is power-loss-safe by construction (it reuses the rekey
commit, §12.3) but it is **irreversible** — trimmed history and reclaimed bytes are
gone. The command therefore **backs up the encrypted tree first** by default (to a
sibling `<dir>-backups/` directory; `--backup DEST` overrides, `--no-backup` opts
out), and offers `--dry-run` to report what would be reclaimed without writing.

**Threat-model note.** A volume compaction can visibly shrink `vol.<N>` at rest,
which signals to an at-rest observer that data was deleted — a filesystem-level
metadata leak the never-shrinking v1 volume avoided. This is consistent with the
already-accepted at-rest limitations (§8, §9.12); it leaks *that* data was removed,
never *what*. Conversely, compaction **physically removes** the deleted-but-lingering
frames, which closes the "delete a `manifest.<N>` to resurrect deletes" window
(§9.12) for those frames.

**CLI** gains directory-based decryption facilities: `decrypt` (vault JSON),
`manifest [--part N]` (one or all manifests), and `extract [--part N]` (decrypt one
or all volumes' documents). See `PLAN.md` §8.

## 12. Crash-safety and recovery (req. 15)

This is the property the vault treats as non-negotiable: **after any abrupt
failure, reopening yields a consistent, openable vault equal to some committed
state, losing at most the single in-flight operation — never a corrupt or
unopenable vault, and never silent loss of older committed data.**

### 12.1 Failure modes considered

| Mode | What it does to the disk |
|---|---|
| **Force-kill (`SIGKILL`)** | Process dies instantly: no `Drop`, no destructors, no buffered flush. Bytes already `write()`-en may be in the OS page cache but not on the platter; an in-progress `write()` can be half-applied. |
| **Full disk (`ENOSPC`)** | A `write`/`set_len`/`fsync`/`rename` returns an error *mid-operation*; later steps don't run; partial bytes may be on disk. The code must clean up and propagate the error, leaving prior state intact. |
| **Power loss** | Everything not `fsync`'d is lost — *including directory entries* for newly-created or renamed files whose parent directory wasn't `fsync`'d. An `fsync`'d file is durable; a `rename` is atomic but only durable once its directory is `fsync`'d. |
| **Forced shutdown** | Power loss combined with the process being killed — the union of the above. |

### 12.2 The commit primitives

Two atomic primitives underlie everything:

- **Atomic file replace** (`write_atomic`, used for manifests and `vault.pmv`):
  write a uniquely-named hidden temp with `create_new`/`O_EXCL` (mode `0600`),
  `fsync` it, `rename` over the target, then `fsync` the directory. A crash before
  the rename leaves the original untouched and removes the temp; the rename is
  atomic (old-or-new, never half); the directory `fsync` makes it durable. An
  `ENOSPC` during the temp write removes the temp and returns the error.
- **Durable append** (`append_frame`, used for volume frames): open the volume,
  `write` the frame at the committed `end_offset`, `set_len` to drop any torn
  tail, `fsync` the file, then `fsync` the volume *directory* (so a first-ever
  `vol.<N>` entry is durable before anything references it). The open uses
  **`O_NOFOLLOW`** so a symlink planted at the volume path (even in the race window
  after the pre-check) is refused atomically by the kernel rather than followed.

### 12.3 Per-operation commit order and recovery

**Add / update a document (`storage::put`).**
1. `append_frame` the encrypted frame at `end_offset`; fsync file + dir.
2. `write_atomic` the partition manifest (its new `end_offset` now *includes* the
   frame) — the storage commit point.
3. Update the in-memory index (only after the on-disk commit succeeds).

Recovery: the manifest's `end_offset` is authoritative. A crash/`ENOSPC` after
step 1 but before step 2 leaves the frame as a torn tail *beyond* the committed
`end_offset` — invisible on reopen and overwritten by the next append. A crash
during step 2 leaves the old manifest authoritative (atomic replace). Either way
the document either fully exists or doesn't; nothing in between, no corruption.

**Delete (`storage::remove`)** is a single `write_atomic` of the manifest with the
entry dropped — atomic, so it either happened or didn't. (The blob lingers as
garbage until a `compact --volume` rewrite, §11.1.)

**Save the vault (`vault::save` / `write_vault_file`)** is a single atomic replace
of `vault.pmv`. The vault is the **final commit point**: a document blob/manifest
committed in `storage::put` but not yet referenced by a saved vault is harmless
garbage. So even a crash *between* a document commit and the vault save leaves a
consistent vault (it just doesn't reference the new doc yet).

**UI document lifecycle.** Attach commits the blob *then* links + saves the vault
(a crash before the save leaves an unreferenced orphan — harmless). Delete /
detach / replace **save the unlinked vault first, then reclaim the blob** — so a
crash in between leaves an orphan, never a dangling reference (which would be
`ArchiveMismatch` on open). See §11.

**Password change (`change_password`)** is the only multi-file commit, handled by
**stage + READY + roll-forward**:
1. Stage a complete new-key tree in `mypath/.rekey/` (`vault.pmv`, `manifest/`,
   `volume/`), re-encrypting every blob; fsync the files and dirs.
2. Write the `.rekey/READY` marker (fsync) — the staging is now complete & valid.
3. **Commit by roll-forward:** move `volume/`, then `manifest/`, then `vault.pmv`
   **last**; fsync; remove `.rekey/`.

On the next open, `recover_pending_rekey` runs *before* anything else:
`.rekey/` with `READY` → finish the (idempotent) roll-forward → the new passwords
open it; `.rekey/` without `READY` → discard it → the old passwords still open the
intact old tree. A crash mid-commit therefore always lands on one whole tree,
never a mix. If `commit_rekey` fails *in-process* (e.g. `ENOSPC` on a rename), the
live handle is **poisoned** (made read-only) so it cannot write the new key over a
half-moved tree; the next open completes the roll-forward.

**Compaction (`compact --volume`)** is the same multi-file commit as a password
change — it shares one `staged_rewrite` helper, the same `.rekey/` staging,
`READY` marker, roll-forward order (`volume/` → `manifest/` → `vault.pmv`), the
same `rekey.after_volume`/`after_manifest`/`after_vault` fault points, and the same
handle-poisoning on a partial commit — differing only in that it **keeps the
current key** instead of deriving a new one. Recovery is therefore identical and
needs no new code: a crash before `READY` discards the staging (the *un*compacted
vault stands); a crash after it rolls forward to the compacted vault. The one extra
case compaction introduces — *every* document deleted, so the staged store has zero
partitions — is handled by materializing empty staged `volume/`+`manifest/` dirs so
the commit still swaps the garbage dirs out. History-only compaction (`--json`
without `--volume`) is just an in-memory trim plus the single atomic `vault.pmv`
save above, so it inherits that step's crash-safety directly.

### 12.4 What "minimal corruption" means here

The unit of possible loss is **one operation**: a crash can lose the document
add/update/delete or the vault save that was in flight, and nothing older. There
is no scenario in which a committed earlier record, document, or the whole vault
becomes unreadable due to a crash — corruption is contained to the torn tail of a
volume (ignored by `end_offset`) or an abandoned temp/`.rekey` (discarded on
open). A lost or bit-rotted manifest is *rebuilt* by scanning its self-describing
volume, so even losing an entire manifest is recoverable.

### 12.5 How this is verified

Crash-safety is tested at four levels (see `IMPLEMENTATION.md`):

- **Direct on-disk state** — reproduce the exact bytes a crash would leave (torn
  tails, truncated/garbage manifests, half-staged `.rekey` with/without `READY`,
  each roll-forward sub-step) and assert recovery on reopen.
- **In-process fault injection** — a feature-gated hook makes a chosen
  `write`/`fsync`/`rename` return `ENOSPC`, asserting the operation fails cleanly
  and the prior state stays intact and openable.
- **Subprocess abort** — a child process performs a real operation and is aborted
  at a chosen commit point (a feature-gated crash point), modelling a true
  force-kill / power loss against the real code path; the parent then reopens and
  asserts full recovery. Crash points cover the storage commit (`volume.write`,
  `put.after_append`, `put.after_commit`, `atomic.*`), the vault commit
  (`vault.write`, `vault.rename`), the rekey/compaction roll-forward
  (`rekey.after_volume`/`after_manifest`/`after_vault`), **and the in-place
  redundancy writes** (`redundancy.rotate`, `redundancy.bak`, `redundancy.mirror`,
  `redundancy.refresh`) — the last group asserts that a crash in any best-effort
  redundancy copy, which always runs *after* the authoritative primary commit,
  leaves the vault openable from the primary with committed data intact and no
  recovery needed (`tests/crash_recovery.rs`, redundancy enabled).
- **Real power loss (`dm-flakey`)** — the abort tests above kill the *process*, but
  the OS still flushes its page cache afterward, so a **missing `fsync` is invisible
  to them** (and to mutation testing — removing an `fsync` changes no in-process
  behaviour). `tests/dmflakey_powerloss.sh` closes that gap: it puts the vault on an
  ext4 filesystem over a Linux device-mapper `dm-flakey` device, runs each operation
  (crashed at the commit points above), then simulates a power cut by reloading the
  device with the `drop_writes` feature and unmounting — so the page cache is flushed
  but **the device discards everything that was not fsync'd**. On remount the vault
  must still open with the committed document intact; a missing/incorrect `fsync`
  would surface here as lost data. It needs root (it manages a loop + dm device), so
  it is a **manual** harness, not part of `cargo test`. Property-based tests
  (`proptest`) additionally fuzz the redundancy-ring invariants, the calendar math,
  and the password generator over random inputs.
- **Data-race check (ThreadSanitizer)** — the app has exactly one cross-thread
  hand-off: the detached focus accept loop (§13) touching the `egui::Context` the
  main thread also renders from. An `#[ignore]`d reproducer
  (`single_instance::tests::focus_accept_thread_is_race_free`) starts the *real*
  accept thread on a live `Context` and drives it with concurrent raise-to-front
  pings while the main thread pokes the same `Context`. Run once under nightly
  ThreadSanitizer (`RUSTFLAGS=-Zsanitizer=thread cargo +nightly test -Zbuild-std
  --target x86_64-unknown-linux-gnu --lib … -- --ignored`, with the whole dependency
  tree and `std` instrumented): **no data races reported**. This is the expected
  result — the crate is `#![forbid(unsafe_code)]` and the only shared object is a
  `Sync` type used through its safe API — but the run confirms it empirically rather
  than by argument.

> Residual platform caveat: durability ultimately depends on the OS and hardware
> honoring `fsync`. On a filesystem/mount that ignores barriers, or hardware with
> a lying write cache, a power loss can still lose the last fsync'd write — that is
> below the application's control (and below what even the `dm-flakey` harness can
> see, since it trusts the device to honor the writes it does *not* drop). The format
> never *corrupts*; at worst it loses the most recent operation. See §9.11.

### 12.6 What a half-finished write looks like on disk (vault vs. volume)

A natural worry is: *"if I'm writing and it fails midway, is there now a
half-written file?"* The answer differs by what is being written, and in neither
case is the live data left partially overwritten.

- **Writing the vault (`vault.pmv`) — never modified in place.** The vault is not
  edited where it sits; `write_vault_file` re-encrypts the *whole* vault to a new,
  uniquely-named temp file, fsyncs it, and only then `rename`s it over `vault.pmv`
  (then fsyncs the directory). So a failure *during the write* lands entirely in
  the throwaway temp — `vault.pmv` is still the previous, complete file — and a
  failure *during the rename* is atomic (you get the whole old file or the whole
  new file, never a spliced one). There is **no "partial bytes in the middle of
  `vault.pmv`" state**; the worst case is that the save didn't happen. (And a
  truncated/garbled file would still fail the AEAD tag on open, i.e. fail closed,
  rather than load corrupt data.)
- **Writing a document — a torn frame at the *end* of the volume, ignored.** A
  document is appended to the end of `vol.<N>` at the committed `end_offset`,
  fsynced, and only then is the manifest (which records the new `end_offset`)
  committed by the same atomic temp+rename. A failure mid-append leaves a
  partial/torn frame *beyond* the old `end_offset`, but the manifest still records
  the old value, which is authoritative: on reopen everything past `end_offset` is
  ignored, and the next append seeks back to `end_offset` and `set_len`s the file,
  physically discarding the tail. So the document is simply *not added*; nothing
  earlier in the volume is touched. If the manifest itself is lost or corrupt, it
  is rebuilt by scanning the volume up to the last *fully decryptable* frame.

In both cases the rule from §12.4 holds: at most the single in-flight operation is
lost, the existing data is intact, and the vault reopens cleanly. The `vault.pmv`
is also the final commit point, so a document fully committed to its volume +
manifest but not yet referenced by a saved vault is just harmless unreferenced
garbage — not a dangling reference.

### 12.7 Potential corruptions: taxonomy, detection, and recovery

§12.1–12.6 cover **crash-induced** damage (power loss, force-kill, `ENOSPC`),
which is always bounded to the in-flight operation and is self-healing on reopen.
But "corruption" can also come from two other sources, and it is worth being
explicit about all three and what each means in practice:

1. **Crash-induced** (the in-flight write was interrupted). Covered by §12.1–12.6:
   recovers to the last committed state, losing at most the one operation.
2. **At-rest / media corruption** (bit-rot, a bad sector, a failing disk, a
   truncated or garbled file from an interrupted *copy* to a USB stick). Unrelated
   to any pass-mgr operation; this section is mainly about these.
3. **Deliberate tampering by someone without the two passwords.** *Recovering* from
   this is out of scope as a goal (an attacker with write access to the files can
   always delete or roll them back — see §8 and §9.12), but the cryptography still
   **detects** it: every read is authenticated, so tampering surfaces as an error,
   never as plausible-but-wrong data.

**The fail-closed principle.** Every byte the vault hands back has passed an AEAD
(XChaCha20-Poly1305) tag check: `vault.pmv` as a whole, each partition manifest,
and each document frame are individually authenticated, with the vault `id` +
partition bound in as associated data (§5.4, §6.2). A wrong password, a flipped
bit, a truncation, or a substituted file therefore all produce the **same**
outcome — an explicit "won't decrypt / corrupted" error — rather than silently
decrypting to garbage or to the wrong record. The format never returns
plausible-but-wrong plaintext. And the recovery scanner that rebuilds a lost
manifest is itself fully bounds-checked (lengths capped before allocation, all
offset arithmetic via `checked_add`), so even a maliciously-corrupt volume cannot
panic it or drive an out-of-bounds read or an unbounded allocation.

**What each kind of damage does, and how it is handled:**

| Where the damage is | How it is detected | Automatic recovery | If not recoverable in place |
|---|---|---|---|
| Torn frame at the **end** of a volume (crash mid-append) | manifest `end_offset` is authoritative | ignored on reopen; physically dropped by the next append's `set_len` | — |
| A whole **manifest** lost or undecryptable, its volume intact | manifest fails to decrypt/parse, or the file is absent | **rebuilt** by scanning the self-describing volume up to the last good frame (`rebuild_manifest`/`scan_volume`) | — |
| A **transient I/O error** reading a *present, valid* manifest | error class distinguished from corruption (`Io`/`TooLarge` ≠ `Corrupt`/`Crypto`/`Json`) | none needed — the error **propagates** instead of forcing a lossy scan (see §13.2.2); reopen/retry | — (transient) |
| A single **document frame** bit-rotted | AEAD tag fails (and the frame's id/path are checked against the manifest) — but only when *that document is read* | the vault still **opens**; every other document still reads fine; only that one read errors | restore that document from a backup |
| **`vault.pmv`** truncated or bit-rotted | header parse and/or the AEAD tag fail on open → fail closed | none — it is a single small AEAD file with **no in-place redundancy** by design | **restore `vault.pmv` from a backup** |
| A record references a document **id that is absent** from the store | presence check at open | none — open **refuses** with `ArchiveMismatch` rather than silently dropping the reference | restore the store (or that document) from a backup |
| Frame parser fed **corrupt lengths/offsets** (e.g. from a damaged volume during a rebuild) | bounds + `checked_add` guards | rejected as `Corrupt` — no panic, no over-read, no unbounded allocation | — |
| A manifest/volume from a **different vault** dropped in | AAD binds the vault `id` + partition → AEAD fails | won't decrypt | restore the matching tree from a backup |

**What genuinely requires a backup.** Self-healing covers a lost/garbled
*manifest* (rebuilt from its volume) and any crash. It does **not** cover physical
loss of authenticated *data*: a damaged `vault.pmv`, a bit-rotted document frame,
or a missing piece of the store. By default there is no parity/duplicate-block
scheme for `vault.pmv` — it is a small file, and the intended redundancy is an
ordinary external backup (`backup`, §11 / README), which is a full encrypted copy
needing the same two passwords. An **opt-in** in-place redundancy for `vault.pmv`
(a same-generation mirror plus retained prior generations) is available for the
narrow at-rest bit-rot case — see §12.8 — but it too is a *complement* to backups,
not a replacement. The write-generation counter shown at open lets a user *notice* a
rollback to an older authentic state (§9.12) but is detection, not redundancy.
Individual documents in an otherwise-healthy vault can also be salvaged one at a time
with `export-document` / `extract` from any readable copy.

### 12.8 Optional in-place redundancy for `vault.pmv`

`vault.pmv` is the one piece with no automatic recovery: a lost/garbled *manifest*
rebuilds from its volume and a bad *document frame* costs only that document, but a
damaged vault file (the records index) otherwise needs a backup (§12.7). For users
who want a same-disk safety net against **localized bit-rot / a single bad sector**,
an **opt-in** in-place redundancy is available. It is **off by default**, and it is
emphatically **not a substitute for off-device backups** — it does nothing for
whole-disk failure, deletion, theft, ransomware, or directory loss, which remain
backup territory. Two mechanisms work together (one setting enables both):

- A **same-generation mirror** (`vault.pmv.mirror`): a second, independent
  encryption of the *current* vault written on every save. It recovers the **exact
  latest** state if the live file bit-rots — no data loss.
- **Retained prior generations** (`vault.pmv.bak1` … `vault.pmv.bakN`, newest =
  `bak1`): the last *N* committed vault files. They cover the case where the live
  file *and* its mirror are both unreadable, and double as an "undo the last save /
  recover from a bad edit" feature. Recovery from a generation is a **rollback** —
  the most recent save(s) are lost — so it is the second line after the mirror.

**The setting.** `VaultSettings.redundancy: u32`, stored (encrypted) inside the
vault, `#[serde(default)] = 0`. `0` = off (a single `vault.pmv`, exactly as before);
`N ≥ 1` = write a mirror and keep `N` prior generations (capped at `MAX_REDUNDANCY`).
Configurable in both UIs' Config screen. Because the value lives in the vault it
governs **writing** only; the **read/recovery** path always uses any redundant copies
that happen to exist, independent of the current setting.

**Save sequence (depth `N > 0`), all crash-safe.** The live `vault.pmv` commit point
is unchanged; redundancy is layered around it as strictly best-effort work that can
never corrupt or block the real save, and **the ring is mutated only AFTER the new
primary has committed**, so a *failed* save never disturbs it:

1. **Capture** the outgoing generation's bytes (a size-capped read of the current
   `vault.pmv`) — without touching the ring yet.
2. **Write the primary** `vault.pmv` with the existing atomic temp→fsync→rename→
   fsync-dir path (§12.2). This is the sole authoritative commit; if it fails (e.g.
   `ENOSPC`) the whole save fails, the live file is untouched, AND the ring is
   untouched (not yet rotated).
3. **Ring** the captured generation: drop `bakN`, shift `bak{k}→bak{k+1}`, write the
   captured bytes as `bak1` **atomically and symlink-safely** (an O_EXCL temp →
   rename — the rename *replaces* any symlink planted at `bak1` instead of following
   it; a plain `fs::copy` would redirect the encrypted write + 0600 chmod through such
   a symlink), then **prune** any slot beyond `depth` (so lowering the depth never
   orphans old generations on disk).
4. **Write the mirror** `vault.pmv.mirror` (its own fresh nonce). Best-effort: a
   mirror failure does not fail the save (the primary already committed).

When `N = 0`, steps 1/3/4 are skipped and any leftover copies are removed, so
disabling the feature also stops leaving old encrypted secrets on disk. Crash
analysis: a crash before step 2 changes nothing; step 2 is atomic (old-or-new); a
crash during step 3/4 leaves at most an odd/partial `bak*`/mirror (harmless — each
copy is AEAD-checked when used, and rewritten next save). The §12.4 guarantee holds.

**Recovery on open.** If the live `vault.pmv` will not decrypt, the open path tries
the copies in preference order — **mirror first** (same generation, no loss), then
`bak1`, `bak2`, … (newest-first). Crucially the key is derived from each **distinct
*candidate*** salt, **not** from the (corrupt) live header — a corruption confined to
the live header's salt/params would otherwise produce a useless key and defeat
recovery *even with a perfect mirror*. Since all same-epoch copies share one salt this
is ~1 Argon2 in practice, and a **wrong password** still costs ~1, not *N* (every copy
fails the one derived key identically → the original "wrong password / corrupted"
error is returned). On a writable open the recovery is followed by a **heal** save
that rewrites a fresh `vault.pmv` + mirror from the recovered state; on a heal the
corrupt outgoing primary is deliberately **not** ringed into a generation slot (that
would void a slot with un-decryptable bytes). The user is told what happened via a
recovery notice surfaced in both UIs (mirror recovery = no data lost; generation
recovery = a possible rollback: "re-save and refresh your backups").

**Interaction with rekey/compaction.** A password change or `compact` writes a new
`vault.pmv` (new key / new layout) via the staged `.rekey` roll-forward (§12.3). The
existing mirror and generations are then under the *old* key and are stale, so
`commit_rekey` deletes them and the in-process operation immediately **regenerates**
fresh copies under the new key — so the configured protection is never absent in the
window until the next ordinary save. A crash-recovered roll-forward regenerates them
via the normal auto-save on the next open.

**Known limitation — recovery from a generation is a rollback.** Falling back to a
prior generation happens only when the live file **and** its mirror are both
unreadable (a rare double-failure), and it is inherently lossy (the most recent
save(s) are gone). pass-mgr **surfaces** this with the recovery notice rather than
silently committing it, but it does not keep a separate monotonic high-water mark to
*refuse* the rollback — off-device backups remain the authority for "is this the
newest state?". This is a deliberate scope choice: a double-corruption that loses both
the live file and its same-disk mirror is exactly the situation backups exist for.

**Trade-offs (made explicit so the opt-in is informed).** (1) It is **not a backup**
— same device, same directory; correlated failures (a dying disk, an `rm` of the
folder) take every copy. (2) It leaves **more encrypted copies of old secrets** on
disk for longer (the same privacy consideration as the per-record history feature,
§9.4), which is why it is off by default and the depth is bounded. (3) A small amount
of extra write and disk per save (the file is small, so negligible). Recovery from a
*generation* is a deliberate, surfaced rollback, not silent. The CLI read-only paths
(`decrypt`/`export`/`extract`) deliberately do **not** auto-fall-back — they fail
loudly on a corrupt live file so automation never silently reads an older copy;
recovery (and healing) happens through the interactive open.

## 13. Single-instance guard and post-audit hardening

This section records two related pieces of work: a new **single-instance guard**
for the GUI (§13.1), and the **correctness/hardening fixes** that came out of a
full multi-subsystem bug audit (§13.2). The audit found no memory-safety, crypto,
or integer-overflow defects (the crate is `#![forbid(unsafe_code)]`); every item
below is a correctness, durability, resource-limit, or memory-hygiene improvement.

### 13.1 Single-instance guard (`src/single_instance.rs`)

**Symptom.** A user returned to their machine and found *many* pass-mgr windows
open, each of which had to be closed individually. The binary never spawns itself;
the cause was structural: `gui::run` opened a window via `eframe::run_native`
**immediately**, at the lock screen, *before* the vault (and thus the single-writer
lock, §9.16) is opened. The default GUI is read-only (§4.4), which takes no lock at
all, so nothing detected an already-running instance — every launch (a
double-clicked launcher, a Dock/taskbar icon, a wrapper script) stacked a fresh,
independent window. A second `--write` launch only discovered the contention
*after* both passwords were typed, then sat at the lock screen showing a "Locked"
error rather than focusing the existing window.

**Mechanism.** Before opening the window, `gui::run` calls
`single_instance::acquire(path)`:

- **Primary (first launch for this vault).** Takes an OS advisory lock
  (`File::try_lock`) on a per-vault lock file in the per-user runtime directory —
  the *same* kernel-released mechanism as the vault's `WriteLock` (§9.16), so it is
  crash-safe and never goes stale. On Unix it also binds a tiny `UnixListener`.
- **Secondary (lock already held).** On Unix it connects to that socket to ask the
  primary to raise its window (the primary's background thread issues
  `egui::ViewportCommand::Focus`), then exits without opening a window. On other
  platforms it simply exits. Either way the pile-up is eliminated.

**Design points.**

- **Keyed per canonical vault path**, so two *different* vaults still get two
  windows; only repeated launches of the *same* vault coalesce.
- **Applies in read-only mode too** — that is the default and previously had no
  coordination whatsoever.
- **Never blocks the app.** Any setup error degrades to "run as an unguarded
  primary" (the guard is best-effort, not a security boundary). The socket carries
  **no vault data** — the connection itself is the "raise your window" signal; no
  bytes are trusted. The lock file and socket live under a 0700 runtime dir and the
  socket is chmod 0600.
- **Escape hatch.** `PMVAULT_ALLOW_MULTIPLE=1` bypasses the guard for power users
  who deliberately want several windows for one vault.

### 13.2 Audit-driven correctness & hardening fixes

#### 13.2.1 UI durability — "Saved." now means saved

`OpenVault::save` returns a `Result`, and the front-ends' `persist()` helper
returns a bool that is `true` **only** when the write reached disk. The five GUI
record-save paths, the GUI document **Attach**, GUI `delete_current`, and the TUI
`save_edit` / `delete_selected` previously called `persist()` and then
*unconditionally* overwrote the status line with "Saved." / "Deleted." / "Document
uploaded…". So when a save failed (full disk, or a read-only/poisoned handle after
an interrupted rekey), the user was told it succeeded while the change never
persisted — and the TUI even discarded the edit buffer. The on-disk state was
always *consistent* (this is not corruption; see §12.6), but the reported outcome
was wrong and the unsaved edit was silently lost.

Fix: every success message and screen transition is now gated on `persist()`. On
failure the "Save failed: …" status that `persist()` set is preserved, the record
is left on disk untouched (a "deleted" record reappears only because it was never
actually removed), and the TUI keeps the edit buffer open so the user can retry.
The blob-reclaim paths were already correctly gated on `persist()` (so no dangling
references, §12.6) — only the status messages were not.

#### 13.2.2 Document-store recovery precision (`VolumeStore::open`)

A lost or corrupt manifest is rebuilt by scanning its self-describing volume
(§12.6). The trigger was `Err(_) if volume_exists` — i.e. **any** manifest read
error caused a rebuild, including a transient I/O glitch or a momentary size-cap
trip on a manifest that is actually valid. Because the scan stops at the first
undecryptable frame and silently returns only the prefix, a transient failure on a
*present, valid* manifest could discard its authoritative `end_offset` and drop
later documents. The trigger is now narrowed to genuine corruption
(`Corrupt`/`Crypto`/`Json`) or a genuinely *absent* manifest file; transient
I/O and size-cap errors propagate instead of forcing a lossy scan.

#### 13.2.3 Resource limits (DoS guards, extends §9.13)

- **`add_document` source reads are now bounded.** It guarded size with
  `fs::metadata().len()`, which reports `0` for character devices (`/dev/zero`),
  FIFOs, etc., and can change between the stat and an unbounded `fs::read`. A
  non-regular source is now rejected up front (`fs::metadata().is_file()`, which
  still follows a symlink to a real document), and the read uses a hard ceiling
  (`File::take(MAX_DOC_SIZE + 1)`) so a growing or special file cannot exhaust
  memory.
- **Password generator can no longer hang or over-allocate.** `uniform(n)` computed
  its rejection zone from a 32-bit draw, so for `n > 2³²` the zone collapsed to `0`
  and the sampler looped forever; it now draws 64 bits with a 128-bit zone
  computation, keeping the zone `> 0` for every `n` (output remains exactly uniform,
  no modulo bias). `generate` also rejects an absurd `length` (> `MAX_LENGTH`,
  4096) with a new `GenError::TooLong` rather than attempting a multi-gigabyte
  allocation. The shipped UIs only ever request length 20; this hardens the public
  API against a programmatic caller.

#### 13.2.4 Single-writer invariant for `import_tree` (extends §9.16)

`import_tree` built the whole destination vault (volume + manifest writes, then
`write_vault_file`) and only took the single-writer lock at the very end, via the
final `OpenVault::open`. Its only guard against a concurrent build into the same
fresh directory was a `dest.exists()` check — a TOCTOU. It now acquires
`WriteLock` immediately after creating the directory and holds it for the entire
build (released just before the final reopen re-acquires it), matching the
lock-before-writing discipline of `create`/`open`.

#### 13.2.5 Backup-location guard (`dest_inside`, supports §11.1)

The `compact` pre-backup must never be written inside the tree being rewritten.
When the destination does not yet exist (the normal case), `dest_inside` fell back
to a raw component-wise `starts_with`, which a `./`-prefixed or otherwise
equivalently-spelled path could evade (e.g. `./vault/inside` was not recognized as
inside `vault`). The fallback now lexically normalizes both paths (absolutize
against the cwd, fold away `.`/`..`) before comparing.

#### 13.2.6 Secret memory hygiene (extends §9.6)

These are defense-in-depth improvements to the "best-effort" wiping described in
§9.6:

- **Zeroize before overwrite.** Clicking *Generate* (GUI and TUI) assigned a new
  `String` over the old password; a plain `String` reassignment frees the old heap
  buffer **without** zeroing it. The old value is now `.zeroize()`d first.
- **Wipe on failed auth.** The GUI only wiped the entered master passwords on a
  *successful* unlock; on a wrong-password/error it left them in the `GuiApp`
  buffers. It now wipes on the error paths too (matching the TUI, which rebuilds —
  and thus zeroizes — its `AuthState`). A failed auth is exactly when a user may
  step away.
- **Pre-sized secret buffers.** The GUI master-password fields, the GUI
  account-password edit buffer, and the TUI password `Field` are mutated in place
  one keystroke at a time by the UI frameworks; each capacity growth reallocates
  and frees an un-zeroized fragment of the secret. The buffers are now pre-sized
  (generous `with_capacity` / `reserve`) so typing a normal-length password never
  reallocates, and the TUI's transient incoming copy is zeroized after it is moved
  into the pre-sized buffer.

#### 13.2.7 Regression tests

New tests lock in the externally-checkable fixes: `password::rejects_overlong_length`
and `uniform_terminates_for_n_above_2_pow_32`; `vault::add_document_rejects_non_regular_source`;
and `main::dest_inside_catches_dot_slash_relative_child`; plus the single-instance
lock-arbitration tests in `single_instance`. The persist-gating fixes are covered
by the existing crash/fault-injection suite (§12.5), which already exercises failed
writes.

### 13.3 Windows GUI subsystem — the two-binary split

**Symptom.** On Windows, launching the app showed **two windows**: a command/console
window *and* the GUI. The cause is the subsystem a Windows executable is linked
against. A normal Rust binary is a **console-subsystem** program, so when it is
started from Explorer or a shortcut the OS allocates a console window for it before
the GUI's window appears on top.

**Constraint.** The fix is to link the GUI as a **GUI-subsystem** program
(`#![windows_subsystem = "windows"]`), which suppresses the console. But the subsystem
is fixed at link time — a single executable cannot be a console app for the CLI
subcommands (`decrypt`, `extract`, `compact`, …) and the `--tui` terminal UI *and* a
windowless GUI app. The usual single-binary escape — link as a GUI app and call
`AttachConsole`/`FreeConsole` at runtime to borrow the parent terminal when needed —
requires Win32 FFI, i.e. an `unsafe` block, which the crate forbids
(`#![forbid(unsafe_code)]`).

**Mechanism.** The project therefore builds **two binaries** (the `python.exe` /
`pythonw.exe` pattern):

- **`pass-mgr`** (`src/main.rs`) — the existing **console** binary: all CLI
  subcommands plus the `--tui` terminal UI, unchanged.
- **`pass-mgr-gui`** (`src/bin/pass-mgr-gui.rs`) — a thin **GUI-subsystem** launcher
  carrying `#![cfg_attr(windows, windows_subsystem = "windows")]`. It parses only an
  interactive launch (optional vault `DIR` + `--write`) and calls `gui::run`. The
  `cfg_attr` makes the attribute inert off Windows, so elsewhere `pass-mgr-gui` is
  simply "the GUI".

To guarantee both binaries resolve the vault path identically, the shared path/flag
logic (`default_vault_path`, `vault_file`, `resolve_interactive`) moved out of
`main.rs` into a small library module, `pass_mgr::launch`; `main.rs` imports it, so
its call sites are unchanged. `default-run = "pass-mgr"` keeps `cargo run` /
`cargo install` pointed at the console binary, and the Windows cross-compile CI job
(§12.5/IMPLEMENTATION) now builds `--bins`, so the GUI-subsystem build is checked on
every push. No new dependencies, no `unsafe`.
