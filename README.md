# pass-mgr

A **standalone, offline** password manager with both a **graphical** and a
**terminal** UI. Credentials are stored in a single, strongly-encrypted file
that never leaves your machine — no network, no sync, no telemetry.

- **Two passwords**, entered in sequence, are required to open a vault
  (chained Argon2id key derivation).
- **XChaCha20-Poly1305** authenticated encryption; the data is JSON, encrypted
  at rest.
- **Custom types + filters**, full-text search, per-entry **change history**
  with timestamps, and **last-access** tracking.
- Built-in **random password generator**.
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

Both UIs read and write the same vault file and expose the same features
(create/unlock, search + type filters, history, random password generation,
change master passwords). The key-binding tables below apply to the **terminal**
UI; the graphical UI uses on-screen buttons.

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

### Key bindings

**List screen**

| Key | Action |
|-----|--------|
| type | filter entries (search) |
| ↑ / ↓ | move selection |
| Enter | open entry |
| Tab / Ctrl+F | cycle the type filter |
| Ctrl+N | new entry |
| Ctrl+D | delete selected |
| Ctrl+P | change master passwords |
| Esc | clear search, or quit if empty |

**Detail screen**

| Key | Action |
|-----|--------|
| r | reveal / hide password |
| c | copy password to clipboard |
| h | toggle change history |
| e | edit |
| Ctrl+D | delete |
| Esc | back to list |

**Edit screen**

| Key | Action |
|-----|--------|
| Tab / ↑ / ↓ | move between fields |
| Ctrl+G | generate a random password |
| Ctrl+R | reveal / hide password field |
| Ctrl+S | save |
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

## The vault file

The file starts with the magic bytes `PMVAULT\0` so it is easily identifiable.
Its 61-byte header (magic, version, KDF parameters, salt, nonce) is plaintext and
self-describing; everything after it is authenticated ciphertext. Saves are
atomic (write to a temp file, then rename), so an interrupted write cannot
corrupt an existing vault.
