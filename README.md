# pass-mgr — your private, offline estate vault

pass-mgr is a small program that keeps your important life and estate information
in **one safe, locked place on your own computer**: account logins, where your
money and property are, your will and trust details, and scans of important
documents. It is locked with **two passwords**, everything is strongly encrypted,
and **it never connects to the internet** — nothing is uploaded, synced, or
shared anywhere.

This is especially useful for estate planning: you can keep everything your
family or executor would need in one organized, protected file.

---

## ⚠️ Please read this first — the 3 things that matter most

1. **You choose two passwords. You need BOTH to open the vault.** Enter them in
   the same order every time.
2. **There is no "forgot password" and no back door. If you lose both passwords,
   the information is gone forever** — by design, so nobody else can get in
   either. Write the two passwords down and keep them somewhere safe (and
   consider leaving them with a trusted person or in a sealed envelope for your
   executor).
3. **Keep a backup.** The vault is a file on your computer. If the computer is
   lost, stolen, or breaks, you lose the vault unless you have a backup copy. The
   program has a one-click **Backup** button — use it regularly and keep a copy on
   a separate drive (see "Making a backup" below).

---

# Part 1 — Using pass-mgr (no technical knowledge needed)

These steps assume the program is already installed on your computer. If it
isn't, see **Part 2** (or ask whoever set it up for you).

## Starting the program

- **Windows:** double-click **`pass-mgr-gui.exe`**. A window opens, with no
  command/console window alongside it. (There is also a `pass-mgr.exe` — that one is
  the command-line version and *does* show a console; it's only for the advanced
  commands further down. For everyday use, always launch `pass-mgr-gui.exe`.)
- **Mac/Linux:** double-click the **`pass-mgr-gui`** program (or `pass-mgr`), or open
  it the way the person who set it up showed you.

When it opens it is in **View-only mode** (a 🔒 READ-ONLY badge shows at the
bottom). You can look at everything but not change anything. This is a safety
feature so you can browse without accidentally editing. To make changes, you use
the **Edit shortcut** described next.

## Turning on editing (one-time setup)

To **create** a vault or **change** anything, the program must be started in
**Edit mode**. The easiest way is to make an "Edit" shortcut once:

**On Windows:**
1. Right-click **`pass-mgr-gui.exe`** → **Show more options** → **Create shortcut**.
   (Use `pass-mgr-gui.exe`, not `pass-mgr.exe`, so edit mode also opens with no
   console window.)
2. Right-click the new shortcut → **Properties**.
3. In the **Target** box, go to the very end, add a space, then type `--write`.
   It should end with `...\pass-mgr-gui.exe --write`.
4. Click **OK**. Rename the shortcut to **"pass-mgr (Edit)"**.

Now: **double-click "pass-mgr (Edit)" when you want to add or change things**, and
the plain program when you only want to look.

> The everyday program stays view-only on purpose. Keep the Edit shortcut for
> when you actually need to make changes.

> **Ready-made shortcuts with icons.** The [`packaging/`](packaging/) folder has
> both shortcuts done for you — **pass-mgr (View)** with a **locked-vault** icon and
> **pass-mgr (Edit)** with an **unlocked-vault** icon. On Linux run
> `packaging/linux/install-shortcuts.sh`; on Windows run
> `packaging\windows\make-shortcuts.ps1`. See [`packaging/README.md`](packaging/README.md).

## Creating your vault the first time (step by step)

1. Start the program using the **Edit** shortcut (above).
2. Because there is no vault yet, you'll see a **Create** screen.
3. Type your **first password**, then type it again to confirm.
4. Type your **second password**, then type it again to confirm.
5. Click **Create**. Your vault is made and opens, ready to fill in.

Choose passwords that are long and memorable to you but hard for others to guess.
**Write both down and store them safely now.**

## Opening your vault later

1. Start the program (Edit shortcut if you want to change things; plain program to
   just look).
2. Type your **first password**, then your **second password**, in the same order
   as when you created the vault.
3. Click **Unlock**. You'll briefly see when the vault was last opened.

If a password is wrong it simply says so — try again, checking the order.

## The six sections (tabs)

Across the top are seven tabs. Click a tab to switch:

1. **Instructions** — notes and instructions for your family/executor (funeral
   wishes, who to contact, where to find things).
2. **Trust and Will** — your will and trust details, and where the originals are.
3. **Assets and Liabilities** — what you own and what you owe (accounts,
   property, vehicles, loans), with values, owners, and beneficiaries.
4. **Accounts** — logins: banks, email, utilities, subscriptions, etc., with
   usernames and passwords.
5. **Real Estate** — properties: address, ownership, taxes, financing (account +
   balance), and per-property **portal logins** (property management, insurance,
   HOA — each with URL, username, password). Each property can also hold uploaded
   **documents** (deed, insurance policy, statements).
6. **Taxes** — one entry per **filing year**, holding that year's tax documents
   (W-2s, 1099s, the return, receipts). Each entry can hold **several** uploaded
   documents, all kept together in that year's own folder inside the vault.
7. **General Documents** — anything else worth keeping: a title, a description,
   and **one uploaded file** per entry (passport scan, birth certificate, a
   contract). Use one entry per document.

## Adding or changing an entry (step by step)

1. Make sure you're in **Edit mode** (no 🔒 badge).
2. Click the tab you want.
3. Click **➕ New** to add a new entry (or click an existing entry to change it).
4. Fill in the boxes. Move between boxes by clicking them.
5. Click **Save**. A dated note is kept each time you change something, so you
   always have a history.

To remove an entry, select it and click **Delete**.

## Attaching a document (a will, a statement, a deed)

You can store scanned documents (PDFs, images) **inside** the vault, encrypted
along with everything else.

1. In **Edit mode**, open a **Trust and Will**, **Assets and Liabilities**, or
   **General Documents** entry (these hold one document each).
2. Optionally type a **Subfolder** to organize the file, set the **Filename** to
   save it as, then pick the file to **Upload / Attach** from your computer.
3. Save. The document is now encrypted inside your vault.

To get a document back out later, open the entry and use **Export** to save a copy
to your computer.

On the **Taxes** and **Real Estate** tabs it works the same way, but each entry can
hold **several** documents: open (or create) the entry, then upload as many files as
you like. Use **Export** or **Remove** on any individual document (by its number).

**How files are organized inside the vault.** Every uploaded document is filed under
`<tab>/<entry>/<timestamp>/[your subfolder]/<your filename>` — e.g. a 2024 tax W-2
lands in `taxes/2024/<when-you-uploaded-it>/[subfolder]/W-2.pdf`. The tab and entry
(filing year, property address, document title, …) are filled in for you; you choose
only the optional subfolder and the filename.

## Showing or copying a password

- Open an **Accounts** entry. Use **reveal** to show a hidden password.
- Use **Copy** to copy a password so you can paste it elsewhere. For your safety
  the program **automatically clears the clipboard 15 seconds later** (and when
  you close the program), so a copied password doesn't linger.

## Changing the colors (theme)

Open the **Config** screen and pick a **Color theme** (Light, Dark, High contrast,
Solarized, or Sepia). The change applies immediately and is remembered for next
time. It's only a display preference — it changes nothing about your data.

## Making a backup (please do this regularly)

1. In **Edit mode**, open the **Config** screen.
2. Find **Backup**, enter a folder to save into (for example a USB drive), and
   click **Backup now**.
3. The program saves a dated, still-encrypted copy of your vault and its
   documents. Keep at least one backup on a **separate** drive or location.

Backups are still encrypted — each one needs the **two passwords that were in effect
when it was made** (see the next section about changing passwords).

## Changing your master passwords

Use the **🔑 Passwords** button (Edit mode) — or `p` in the terminal UI — to set two
new passwords. The program fully re-encrypts your vault under the new passwords.

**Important — this does NOT change your old backups.** A backup is a separate copy,
so changing your passwords only re-encrypts the vault on this computer; any backup you
made earlier still opens with the **old** passwords (and a new backup opens with the
new ones). So after changing your passwords:

- **Make a fresh backup** right away, so you have a recoverable copy under the new
  passwords. (Changing passwords does not auto-backup; only *Compact* does.)
- **If you changed because the old passwords may have been seen by someone else,**
  remember that your **old backups are still readable with those old passwords** —
  securely delete the old backups (or keep them only if you trust where they are).
- To restore an old backup, open it with the passwords it was made under; it will be
  an older copy (anything you changed since is not in it).

## If something goes wrong (power loss, crash, disk full)

pass-mgr is built so that a power cut, a forced shutdown, or a full disk **cannot
corrupt your vault**. Whatever you were doing either fully completed or did not
happen at all — there is never a half-saved, broken state. In almost every case the
fix is the same: **just open the vault again.** It repairs itself automatically when
it opens. (This is about *interruptions*. The rarer case of the file being
physically *damaged* — a failing drive, a bad copy — is covered in the next
section.)

What to expect after an interruption, by what you were doing at the time:

- **Adding, editing, or deleting an entry, or uploading a document.** If the
  interruption happened before it finished, that one change simply didn't take —
  reopen and do it again. Everything else is exactly as it was. A full disk shows an
  error and changes nothing; free up space and try again.
- **Changing your master passwords.** Open the vault again and try the **new**
  passwords first; if those don't work, the change didn't complete, so use the
  **old** passwords. One of the two always works — an interruption can never lock you
  out. (Opening the vault quietly finishes, or cancels, a half-done change.)
- **Compacting (reclaiming space / trimming history — see Part 2).** Same as a
  password change: reopen and you'll have either the old vault or the compacted one,
  never a mix. Compacting also makes a dated backup **before** it starts (unless you
  turned that off), so the pre-compaction state is saved either way.
- **Making a backup, exporting, or extracting documents.** These only ever *read*
  your vault, so it is never at risk. If one was interrupted you may find a
  half-written copy in the destination folder — just delete that partial copy and
  run it again.

**Two rules:**

1. **Always safe to reopen.** After any crash, just start pass-mgr again — recovery
   is automatic; there is nothing manual to run.
2. **Never hand-edit the vault folder.** Don't move, rename, or delete the files
   inside it (`vault.pmv`, the `manifest/` and `volume/` folders, a temporary
   `.rekey/` folder, or `pass-mgr.lock`). They are a matched set — let the program
   manage them. If it ever reports the vault is "locked" after a hard crash, make
   sure no other pass-mgr window is open and try again; the lock releases itself when
   the program exits.

## If the vault file itself is damaged (a failing disk or a bad copy)

The protections above are about *interruptions*. A separate, rarer problem is the
file being physically **damaged** — for example a failing hard drive or USB stick,
bit-rot on old storage, or a copy that didn't finish. pass-mgr handles this safely
too:

- **It never shows you wrong information.** Every part of the vault is sealed with a
  cryptographic check. If anything has been altered or damaged, pass-mgr reports an
  error and refuses to open, rather than showing you scrambled or incorrect data.
  (The very same "can't open" message also appears if you simply mistype a password,
  so first just **re-check both passwords**, in order.)
- **Small damage often repairs itself.** The internal index of your documents can be
  rebuilt automatically from the documents themselves, so losing or damaging that
  index is not fatal — just reopen.
- **One damaged document doesn't block the rest.** If a single stored document is
  damaged, the vault still opens and everything else works normally; only that one
  document shows an error when you try to open it.
- **If the main vault file is damaged, restore your backup.** The main file keeps no
  built-in spare copy — *that is what your backups are for.* Open your most recent
  backup with the same two passwords. (This is exactly why the first thing this guide
  asks is to keep regular backups on a separate drive.)

If even a backup won't open, you can still rescue individual documents from any copy
that *does* open, using **Export** on each entry that has one (or the `extract`
command in Part 2).

## If you are a family member or executor

If someone left you this vault:

1. You need **both passwords**, in order. They should have been written down and
   stored for you.
2. Open the plain program (view-only is fine for reading) and enter the two
   passwords.
3. Browse the tabs — start with **Instructions** and **Trust and Will**.
4. To save copies of stored documents to the computer, use **Export** on each
   entry that has one.

## Where your information is stored

Everything lives in a single locked file on the computer:

| Your system | Where the vault file is |
|-------------|--------------------------|
| Windows | `C:\Users\<you>\AppData\Roaming\pass-mgr\vault.pmv` |
| Mac/Linux | `~/.local/share/pass-mgr/vault.pmv` |

Your uploaded documents are stored right next to it, inside `manifest/` and
`volume/` folders in the same `pass-mgr` directory. Everything is encrypted and
useless to anyone without your two passwords — so treat the **whole folder** as one
unit: back it up together, and don't move or delete pieces of it. Keep it — and your
backups — safe.

---

# Part 2 — For the person who sets it up (technical)

## Getting the program (build from source)

pass-mgr is written in Rust. Install the toolchain from <https://rustup.rs> if you
don't have it, then build:

### Linux

```bash
cargo build --release
./target/release/pass-mgr-gui         # graphical window
./target/release/pass-mgr --tui       # terminal version (works over SSH)
./target/release/pass-mgr decrypt …   # command-line tools (see "advanced" below)
```

The build produces **two programs**: `pass-mgr-gui` (the graphical app) and
`pass-mgr` (the command-line/terminal version). On Linux/Mac they behave the same
way; the split matters on Windows (next), where the GUI build avoids popping a
console window.

If the build complains about missing system libraries, install the dev headers:

```bash
sudo apt install libxcb1-dev libxcb-render0-dev libxcb-shape0-dev libxcb-xfixes0-dev
```

### Windows

```powershell
cargo build --release
.\target\release\pass-mgr-gui.exe        # the graphical app — no console window
.\target\release\pass-mgr.exe --help     # the command-line version
```

The build produces **two `.exe` files**:

- **`pass-mgr-gui.exe`** — the graphical app, built as a Windows *GUI-subsystem*
  program so launching it opens **only** the window, with no command/console window
  beside it. **This is the one to hand to a non-technical user** (along with the
  "Edit shortcut" steps in Part 1).
- **`pass-mgr.exe`** — the *console* version, for the advanced command-line tools
  (`decrypt`, `extract`, `compact`, …) and the `--tui` terminal UI, which need a
  console to show their output.

Each is a **single self-contained file** (the C runtime is linked statically via
`.cargo/config.toml`). Copy them to any **Windows 10 or 11 (x64)** machine and they
run with nothing to install.

> Why two files? A Windows executable is fixed at build time as either a console or
> a GUI program; one file can't be both. So, exactly like Python ships `python.exe`
> (console) and `pythonw.exe` (windowed), pass-mgr ships a console and a windowed
> build. (The crate forbids `unsafe` code, which rules out the alternative of one
> executable that attaches/detaches a console at runtime.)

### Cross-compiling a Windows `.exe` from Linux (optional)

```bash
rustup target add x86_64-pc-windows-gnu      # one-time
sudo apt install mingw-w64                    # one-time: the cross-linker
cargo build --release --target x86_64-pc-windows-gnu
# -> target/x86_64-pc-windows-gnu/release/pass-mgr-gui.exe  (graphical, no console)
# -> target/x86_64-pc-windows-gnu/release/pass-mgr.exe      (command-line / --tui)
```

## Command-line options (advanced)

These are commands of the **console** `pass-mgr` build. For the graphical app, use
**`pass-mgr-gui`** instead (same as `pass-mgr [VAULT]`, but with no console window on
Windows); the `--tui` terminal UI and the subcommands below need the console build.

```text
pass-mgr [VAULT]              Launch the graphical UI (READ-ONLY; or use pass-mgr-gui)
pass-mgr --write [VAULT]      Launch in edit mode (create / edit / delete / upload)
pass-mgr --tui [VAULT]        Launch the terminal UI instead (add --write to edit)
pass-mgr --vol PATH ...       Use PATH as the document archive instead of <VAULT>.vol
pass-mgr decrypt [VAULT]      Decrypt the vault and print its JSON to stdout
pass-mgr extract [VAULT] DIR  Decrypt all stored documents into DIR
pass-mgr backup [VAULT] DIR   Copy the encrypted vault + archive into DIR (timestamped)
pass-mgr compact [VAULT] ...  Reclaim space: re-pack documents and/or trim history
pass-mgr --help               Show help
```

- **Read-only by default.** The UI opens read-only; pass **`--write`** to enable
  creating, editing, deleting, uploading documents, and changing the master
  passwords. A read-only session writes **nothing** to disk. The window shows a
  `🔒 READ-ONLY` badge and hides write controls when not in edit mode.
- Pass a path to use a specific file: `pass-mgr ./work-vault.pmv`.
- **`--vol PATH`** relocates the encrypted document archive (default
  `<VAULT>.vol`, kept beside the vault) — e.g. onto a removable drive:
  `pass-mgr --write --vol /mnt/usb/docs.vol`. Works with the UI, `extract`, and
  `backup`. The archive is cryptographically bound to its vault, so a mismatched
  `.vol` is rejected.

### Decrypting / extracting at the command line

`decrypt` prints the whole vault as JSON (all secrets in plaintext — handle with
care); `extract` writes decrypted copies of all stored documents into a folder.
Both prompt for the two passwords and never modify the vault.

```bash
pass-mgr decrypt ./vault.pmv > backup.json        # interactive prompts
printf 'pw1\npw2\n' | pass-mgr decrypt ./vault.pmv # scripted (passwords via stdin)
pass-mgr extract ./vault.pmv ./out                 # documents -> ./out/...
```

### Compacting (reclaim space)

Editing and deleting leave behind dead data in the document store, and every entry
keeps a growing edit-history log. `compact` reclaims either or both. It opens in
**edit mode** and is **irreversible**, so by default it makes a dated backup of the
encrypted vault **before** it starts. It is crash-safe (a power loss leaves either
the old or the compacted vault, never a mix).

```bash
pass-mgr compact ./myvault --volume                       # drop dead document data
pass-mgr compact ./myvault --json --history-all           # remove all edit history
pass-mgr compact ./myvault --json --history-before 2025-01-01  # keep history on/after that date
pass-mgr compact ./myvault --volume --json --history-all  # both at once
pass-mgr compact ./myvault --volume --dry-run             # just report what it would free
```

- **`--volume`** re-packs the document store, removing the dead blocks left by edits
  and deletes (documents may end up in fewer partitions; this is invisible to your
  entries). **`--json`** trims each entry's edit-history: `--history-all` removes it
  all, or `--history-before YYYY-MM-DD` keeps entries on/after that UTC date. The
  vault-wide audit log is always kept, and a `compacted` event is recorded in it.
- **`--dry-run`** reports what would be reclaimed without changing anything.
  **`--backup DEST`** chooses where the pre-compaction backup goes (must be outside
  the vault folder); **`--no-backup`** skips it. Prompts for the two passwords.

### Terminal (`--tui`) key bindings

**Browse:** `←/→` or `1`–`5` switch tab · `↑/↓` select · `Enter` edit · `n` new ·
`d` delete · `t`/`s`/`o`/`v` Account filters (type/subtype/owner/review) ·
`p` change passwords · `q` quit.

**Edit:** `Tab`/`↑`/`↓` move between fields · `←/→` cycle a dropdown · `Ctrl+S`
save · `Ctrl+G` generate password · `Ctrl+R` reveal · `Ctrl+Y` copy (auto-clears
after 15s and on exit) · `Ctrl+U` upload document · `Ctrl+E` export document ·
`Ctrl+K` detach document · `Esc` cancel.

## How it works & security

- **Two passwords** are combined with a chained **Argon2id** key derivation;
  data is encrypted with **XChaCha20-Poly1305**. The whole file header (including
  the parameters, salt, and nonce) is authenticated, so it can't be tampered with
  undetected.
- The category dropdown lists are stored **inside the encrypted vault** — there
  are no external configuration files.
- Saves are **atomic** (write to a temp file, fsync, rename, fsync the
  directory), so an interrupted write cannot corrupt an existing vault or archive.
  A document append is fsync'd before its manifest is atomically committed, so a
  crash recovers to the last fully-committed state, losing at most the one
  in-flight operation.
- **Corruption fails closed, never silent.** Every read — the vault file, each
  document index (manifest), and each document — is authenticated, so damage,
  tampering, or a wrong password all surface as an explicit error, never as
  wrong/garbled data. A lost or damaged manifest is **rebuilt** by scanning the
  self-describing volume; a damaged main vault file has no in-place spare and is
  recovered from a backup. The recovery scanner is fully bounds-checked, so even a
  maliciously-corrupt volume can't crash it. See `docs/DESIGN.md` §12 (crash-safety)
  and §12.7 (corruption taxonomy & recovery).
- No `unsafe` code; the encryption key is locked out of swap; secrets are wiped
  from memory on close.

For the full architecture, encryption scheme, and security caveats, see
[`docs/DESIGN.md`](docs/DESIGN.md); for how the code is organized, see
[`docs/IMPLEMENTATION.md`](docs/IMPLEMENTATION.md); for the adversarial security
review, mutation testing, fuzzing, and supply-chain results, see
[`docs/HARDENING.md`](docs/HARDENING.md).

## Mobile apps (Android & iOS)

There are now native **Android** and **iOS** apps, built as one **Compose
Multiplatform** (Kotlin) UI on top of the *same audited Rust core* — no crypto or
storage logic is reimplemented. The repo is a Cargo workspace:

- `crates/pass-mgr-core` — the headless, audited vault (crypto + storage + records
  + `OpenVault`), reused by every front-end; `#![forbid(unsafe_code)]`.
- `crates/pass-mgr-desktop` — the desktop CLI/TUI/GUI binaries (`pass-mgr`,
  `pass-mgr-gui`) — unchanged behaviour.
- `crates/pass-mgr-ffi` — a thin [UniFFI](https://mozilla.github.io/uniffi-rs/)
  wrapper the mobile apps call through ([Gobley](https://gobley.dev) generates the
  Kotlin bindings).
- `mobile/` — the Compose Multiplatform Gradle project.

v1 of the apps is a **read-only viewer** (unlock → browse the records → view an
entry → reveal/copy a password). It currently surfaces the first five record types
(Instructions, Trust & Will, Assets, Accounts, Real Estate); the Taxes tab is
desktop-only for now. Copied passwords are auto-cleared from the clipboard after
15 s and immediately on lock. Build/usage details, the offline import model, and the
disclosed mobile security trade-offs are in
[`mobile/README.md`](mobile/README.md). Android builds on Linux/macOS/Windows;
iOS requires a Mac with Xcode.

## Development

```bash
cargo test                              # unit + integration + property tests
cargo test --features fault-injection   # + crash / full-disk recovery tests
cargo clippy --all-targets --all-features -- -D warnings   # lints
cargo audit                             # dependency vulnerability scan
cargo +nightly fuzz run parse_frame     # fuzz a parser (parse_header/_manifest/scan_volume)
sudo tests/dmflakey_powerloss.sh        # real power-loss test (see below)
```

**How crash-safety is tested.** Saves are atomic and fsync-ordered, and that is
verified at four levels (`docs/DESIGN.md` §12.5): exact-on-disk-state tests,
in-process full-disk (`ENOSPC`) injection, subprocess **force-kill** at every commit
point (`tests/crash_recovery.rs`), and a real **power-loss** harness
(`tests/dmflakey_powerloss.sh`). The last one is the deepest: the force-kill tests
only kill the *process* (the OS still flushes its cache, so a missing `fsync` would
go unnoticed), whereas the power-loss harness runs the vault on a Linux `dm-flakey`
device and simulates a power cut that **discards every write the program did not
`fsync`** — then asserts the vault still opens with its data intact. It needs root
(it sets up a loop + device-mapper device under unique, auto-cleaned names) and is
not part of `cargo test`; run it manually with `sudo tests/dmflakey_powerloss.sh`.

Property-based (`proptest`) and `cargo-fuzz` targets additionally hammer the parsers,
the redundancy-ring invariants, the calendar math, and the password generator.

A GitHub Actions workflow (`.github/workflows/ci.yml`) runs the whole suite on every
push and pull request — clippy (warnings denied), the default and `--features
fault-injection` test passes, `cargo audit`, a Windows cross-compile check, and a short
parser fuzz smoke — so the hardening can't silently regress.
