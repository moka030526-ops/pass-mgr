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

- **Windows:** double-click **`pass-mgr.exe`**. A window opens.
- **Mac/Linux:** double-click the **`pass-mgr`** program, or open it the way the
  person who set it up showed you.

When it opens it is in **View-only mode** (a 🔒 READ-ONLY badge shows at the
bottom). You can look at everything but not change anything. This is a safety
feature so you can browse without accidentally editing. To make changes, you use
the **Edit shortcut** described next.

## Turning on editing (one-time setup)

To **create** a vault or **change** anything, the program must be started in
**Edit mode**. The easiest way is to make an "Edit" shortcut once:

**On Windows:**
1. Right-click **`pass-mgr.exe`** → **Show more options** → **Create shortcut**.
2. Right-click the new shortcut → **Properties**.
3. In the **Target** box, go to the very end, add a space, then type `--write`.
   It should end with `...\pass-mgr.exe --write`.
4. Click **OK**. Rename the shortcut to **"pass-mgr (Edit)"**.

Now: **double-click "pass-mgr (Edit)" when you want to add or change things**, and
the plain program when you only want to look.

> The everyday program stays view-only on purpose. Keep the Edit shortcut for
> when you actually need to make changes.

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

## The five sections (tabs)

Across the top are five tabs. Click a tab to switch:

1. **Instructions** — notes and instructions for your family/executor (funeral
   wishes, who to contact, where to find things).
2. **Trust and Will** — your will and trust details, and where the originals are.
3. **Assets and Liabilities** — what you own and what you owe (accounts,
   property, vehicles, loans), with values, owners, and beneficiaries.
4. **Accounts** — logins: banks, email, utilities, subscriptions, etc., with
   usernames and passwords.
5. **Real Estate** — properties: address, ownership, taxes, mortgage/financing.

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

1. In **Edit mode**, open a **Trust and Will** or **Assets and Liabilities**
   entry.
2. Use the **Upload / Attach document** option and pick the file from your
   computer.
3. Save. The document is now encrypted inside your vault.

To get a document back out later, open the entry and use **Export** to save a copy
to your computer.

## Showing or copying a password

- Open an **Accounts** entry. Use **reveal** to show a hidden password.
- Use **Copy** to copy a password so you can paste it elsewhere. For your safety
  the program **automatically clears the clipboard 15 seconds later** (and when
  you close the program), so a copied password doesn't linger.

## Making a backup (please do this regularly)

1. In **Edit mode**, open the **Config** screen.
2. Find **Backup**, enter a folder to save into (for example a USB drive), and
   click **Backup now**.
3. The program saves a dated, still-encrypted copy of your vault and its
   documents. Keep at least one backup on a **separate** drive or location.

Backups are still encrypted — they need the same two passwords to open.

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

Your uploaded documents are in a second locked file next to it
(`vault.pmv.vol`). Both are encrypted and useless to anyone without your two
passwords. Keep them — and your backups — safe.

---

# Part 2 — For the person who sets it up (technical)

## Getting the program (build from source)

pass-mgr is written in Rust. Install the toolchain from <https://rustup.rs> if you
don't have it, then build:

### Linux

```bash
cargo build --release
./target/release/pass-mgr            # graphical window
./target/release/pass-mgr --tui      # terminal version (works over SSH)
```

If the build complains about missing system libraries, install the dev headers:

```bash
sudo apt install libxcb1-dev libxcb-render0-dev libxcb-shape0-dev libxcb-xfixes0-dev
```

### Windows

```powershell
cargo build --release
.\target\release\pass-mgr.exe
```

`target\release\pass-mgr.exe` is a **single self-contained file** (the C runtime
is linked statically via `.cargo/config.toml`). Copy it to any **Windows 10 or 11
(x64)** machine and it runs with nothing to install. Hand this `.exe` to the
non-technical user along with the "Edit shortcut" steps in Part 1.

### Cross-compiling a Windows `.exe` from Linux (optional)

```bash
rustup target add x86_64-pc-windows-gnu      # one-time
sudo apt install mingw-w64                    # one-time: the cross-linker
cargo build --release --target x86_64-pc-windows-gnu
# -> target/x86_64-pc-windows-gnu/release/pass-mgr.exe
```

## Command-line options (advanced)

```text
pass-mgr [VAULT]              Launch the graphical UI (READ-ONLY by default)
pass-mgr --write [VAULT]      Launch in edit mode (create / edit / delete / upload)
pass-mgr --tui [VAULT]        Launch the terminal UI instead (add --write to edit)
pass-mgr --vol PATH ...       Use PATH as the document archive instead of <VAULT>.vol
pass-mgr decrypt [VAULT]      Decrypt the vault and print its JSON to stdout
pass-mgr extract [VAULT] DIR  Decrypt all stored documents into DIR
pass-mgr backup [VAULT] DIR   Copy the encrypted vault + archive into DIR (timestamped)
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
- No `unsafe` code; the encryption key is locked out of swap; secrets are wiped
  from memory on close.

For the full architecture, encryption scheme, and security caveats, see
[`docs/DESIGN.md`](docs/DESIGN.md); for how the code is organized, see
[`docs/IMPLEMENTATION.md`](docs/IMPLEMENTATION.md).

## Development

```bash
cargo test       # run the test suite
cargo clippy     # lints
```
