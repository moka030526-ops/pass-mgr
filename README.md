# pass-mgr

A **standalone, offline** estate vault with both a **graphical** and a
**terminal** UI. Everything is stored strongly-encrypted on your machine — no
network, no sync, no telemetry.

- **Five tabs:** Instructions · Trust and Will · Assets and Liabilities ·
  Accounts · Real Estate.
- **Two passwords**, entered in sequence, are required to open a vault
  (chained Argon2id key derivation).
- **XChaCha20-Poly1305** authenticated encryption; the data is JSON, encrypted
  at rest.
- **Encrypted document volume:** statements/wills are uploaded into a single
  encrypted container (`<vault>.vol`) decrypted as a unit.
- Per-record **change history** with timestamps, **last-access** tracking, and a
  built-in **random password generator**.
- Asset/Account category dropdowns from editable external JSON lists.
- Cross-platform: **Linux and Windows**.

See [`docs/DESIGN.md`](docs/DESIGN.md) for the architecture, crypto details, and
security caveats, and [`docs/IMPLEMENTATION.md`](docs/IMPLEMENTATION.md) for how
the code is structured.

## Prerequisites

The Rust toolchain (`cargo`). Install from <https://rustup.rs> if you don't have
it.

## Build & run

### Linux

```bash
cargo build --release
cargo run --release            # launches the graphical UI
# or run the binary directly:
./target/release/pass-mgr

./target/release/pass-mgr --tui   # use the terminal UI instead (works over SSH)
```

The graphical UI needs a desktop (X11/Wayland). On a headless/SSH session use
`--tui`. Clipboard ("copy password") also uses X11/Wayland; on a desktop it
works out of the box, and on a headless session it degrades gracefully
("Clipboard unavailable"). If a build complains about missing system libraries,
install the dev headers:

```bash
sudo apt install libxcb1-dev libxcb-render0-dev libxcb-shape0-dev libxcb-xfixes0-dev
```

### Windows

In PowerShell or Command Prompt:

```powershell
cargo build --release
cargo run --release
:: or:
.\target\release\pass-mgr.exe
```

The repo's `.cargo/config.toml` statically links the C runtime for the MSVC
toolchain (the Windows default), so `target\release\pass-mgr.exe` is a
self-contained single file — copy it to any **Windows 10 or 11 (x64)** machine
and it runs with nothing to install. (An exe built on Windows 10 runs on Windows
11; Windows is forward-compatible.)

### Cross-compiling a Windows `.exe` from Linux (optional)

```bash
rustup target add x86_64-pc-windows-gnu      # one-time
sudo apt install mingw-w64                    # one-time: the cross-linker
cargo build --release --target x86_64-pc-windows-gnu
# -> target/x86_64-pc-windows-gnu/release/pass-mgr.exe
```

## Usage

```text
pass-mgr [VAULT]            Launch the graphical UI (default vault if omitted)
pass-mgr --tui [VAULT]      Launch the terminal UI instead
pass-mgr decrypt [VAULT]    Decrypt the vault and print its JSON to stdout
pass-mgr --help             Show help
```

Both UIs read and write the same vault and expose the same features across the
five tabs (record list + edit form, document upload/export, history, random
password generation, change master passwords). The graphical UI uses on-screen
buttons; the terminal key bindings are below.

The default vault location is per-user:

| OS      | Path                                   |
|---------|----------------------------------------|
| Linux   | `~/.local/share/pass-mgr/vault.pmv`    |
| Windows | `%APPDATA%\pass-mgr\vault.pmv`         |

Pass a path to use a different file: `pass-mgr ./work-vault.pmv`.

### First run

With no vault present you'll see the **Create** screen: choose two passwords,
each entered twice to confirm. Afterwards every launch shows the **Unlock**
screen, which needs both passwords in sequence.

### Terminal key bindings

**Browse screen**

| Key | Action |
|-----|--------|
| ← / → or Tab, or 1–5 | switch tab |
| ↑ / ↓ | move selection |
| Enter | edit selected record |
| n | new record |
| d | delete selected |
| p | change master passwords |
| q / Esc | quit |

**Edit screen**

| Key | Action |
|-----|--------|
| Tab / ↑ / ↓ | move between fields |
| ← / → | cycle a dropdown field |
| Ctrl+S | save |
| Ctrl+G | generate a random password |
| Ctrl+R | reveal / hide password |
| Ctrl+Y | copy password to clipboard |
| Ctrl+U | upload document into the encrypted volume (Trust/Will, Assets) |
| Ctrl+E | export the attached document to a path |
| Ctrl+K | detach document from the record |
| Esc | cancel |

## Decrypting at the command line

`pass-mgr decrypt` prompts for both passwords (read without echo on a terminal)
and prints the entire vault as JSON. It does **not** modify the vault file.

```bash
pass-mgr decrypt ./vault.pmv > backup.json     # interactive prompts on the terminal
printf 'pw1\npw2\n' | pass-mgr decrypt ./vault.pmv   # scripted (passwords via stdin)
```

> **Warning:** the output contains every password (and password history) in
> plaintext. Treat it as highly sensitive — see `docs/DESIGN.md` §9.10.

## Development

```bash
cargo test       # run the unit test suite
cargo clippy     # lints
```

## The vault files

- `vault.pmv` — the main vault. Starts with magic bytes `PMVAULT\0` (identifiable);
  its 61-byte header (magic, version, KDF parameters, salt, nonce) is plaintext and
  self-describing, and everything after it is authenticated ciphertext (the JSON of
  all records + document metadata).
- `vault.pmv.vol` — the single encrypted **document archive**: every uploaded
  statement/will/document, encrypted together and decrypted as one unit. Created
  only once you upload a document.

Saves are atomic (write to a unique temp file, fsync, rename, then fsync the
directory), so an interrupted write cannot corrupt an existing vault or archive.
Type-list JSON files live (unencrypted) under the data dir's `types/`.
