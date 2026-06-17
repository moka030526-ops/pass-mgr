# Desktop shortcuts & icons

Two shortcuts launch the **same** windowed binary (`pass-mgr-gui`) in two modes,
each with its own vault icon:

| Shortcut | Launches | Icon |
|----------|----------|------|
| **pass-mgr (View)** | `pass-mgr-gui` (read-only) | `pass-mgr-locked.*` — a **locked** vault |
| **pass-mgr (Edit)** | `pass-mgr-gui --write` | `pass-mgr-unlocked.*` — an **unlocked** vault |

The locked vault is the safe, view-only default; the unlocked vault means "you can
change things". They are the same vault drawing — only the padlock state and colour
(blue/closed vs amber/open) differ, so a glance at the desktop tells you which mode
you're about to open.

## The icon files (`icons/`)

`icons/make_icons.py` draws them with Pillow (`pip install pillow`), producing both
formats from one source:

```bash
python3 packaging/icons/make_icons.py
```

- `pass-mgr-locked.png` / `pass-mgr-unlocked.png` — 512 px, for Linux.
- `pass-mgr-locked.ico` / `pass-mgr-unlocked.ico` — multi-size (16–256 px), for
  Windows shortcuts.

The generated files are committed, so you only need to re-run the script if you
want to tweak the artwork.

## Linux

One command installs both shortcuts for the current user (onto the Desktop and into
the application menu):

```bash
# uses target/release/pass-mgr-gui if present, else target/debug, else $PATH;
# or pass the binary path explicitly:
packaging/linux/install-shortcuts.sh /usr/local/bin/pass-mgr-gui
```

It copies the PNG icons to `~/.local/share/icons/pass-mgr/`, fills the `Exec=` /
`Icon=` paths into the two `.desktop` files, installs them to
`~/.local/share/applications/`, and copies them to your Desktop (marking them
trusted on GNOME so they run on double-click).

To do it by hand instead: edit `linux/pass-mgr.desktop` and `linux/pass-mgr-edit.desktop`,
replacing `__BIN__` with the path to `pass-mgr-gui` and `__ICONDIR__` with the folder
holding the PNGs, then copy both files to `~/Desktop` and `~/.local/share/applications/`
and `chmod +x` them.

**Two things to know on Linux:**

- **First double-click.** On GNOME a brand-new desktop launcher may need a one-time
  right-click → **Allow Launching** before it will run, even though the installer
  marks it trusted (`gio set … metadata::trusted true`).
- **Point at a stable binary.** The shortcuts store the *absolute path* to
  `pass-mgr-gui`. If you pass a path inside a build tree (`target/release/…`), a later
  `cargo clean` or moving the repo breaks them. For a permanent setup, copy the binary
  somewhere lasting and install against that:

  ```bash
  install -Dm755 target/release/pass-mgr-gui ~/.local/bin/pass-mgr-gui
  packaging/linux/install-shortcuts.sh ~/.local/bin/pass-mgr-gui
  ```

## Windows

1. Put `pass-mgr-gui.exe` somewhere stable (e.g. `C:\Program Files\pass-mgr\`) and
   copy the `icons` folder (with the two `.ico` files) next to it.
2. In PowerShell:

   ```powershell
   powershell -ExecutionPolicy Bypass -File packaging\windows\make-shortcuts.ps1 `
       -InstallDir "C:\Program Files\pass-mgr"
   ```

   This creates **pass-mgr (View)** and **pass-mgr (Edit)** on your Desktop, with the
   locked and unlocked icons respectively.

### Or by hand

1. Right-click `pass-mgr-gui.exe` → **Create shortcut**; put it on the Desktop.
2. For the **Edit** shortcut: Properties → **Target**, append a space and `--write`
   (so it ends `...\pass-mgr-gui.exe --write`).
3. Properties → **Change Icon…** → Browse to `icons\pass-mgr-unlocked.ico` (use
   `pass-mgr-locked.ico` for the read-only one) → OK.
4. Rename the shortcuts to **pass-mgr (View)** and **pass-mgr (Edit)**.

> Both shortcuts point at `pass-mgr-gui.exe` (the GUI build), so neither opens a
> console window. The console `pass-mgr.exe` is only for the command-line tools.
