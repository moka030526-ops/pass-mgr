#!/usr/bin/env bash
# Install two pass-mgr desktop shortcuts for the current user:
#   "pass-mgr (View)"  -> read-only   (locked vault icon)
#   "pass-mgr (Edit)"  -> --write     (unlocked vault icon)
#
# Usage:
#   packaging/linux/install-shortcuts.sh [/path/to/pass-mgr-gui]
#
# With no argument it looks for a built binary (target/release then target/debug)
# and finally `pass-mgr-gui` on your PATH. Icons are copied to
# ~/.local/share/icons/pass-mgr/, and the .desktop launchers are installed to the
# applications menu and copied onto the Desktop (marked trusted where supported).

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
icons_src="$repo/packaging/icons"

# --- locate the binary -------------------------------------------------------
bin="${1:-}"
if [[ -z "$bin" ]]; then
  for cand in "$repo/target/release/pass-mgr-gui" "$repo/target/debug/pass-mgr-gui"; do
    [[ -x "$cand" ]] && bin="$cand" && break
  done
fi
[[ -z "$bin" ]] && bin="$(command -v pass-mgr-gui || true)"
if [[ -z "$bin" ]]; then
  echo "error: could not find pass-mgr-gui. Build it (cargo build --release) or pass its path:" >&2
  echo "       $0 /path/to/pass-mgr-gui" >&2
  exit 1
fi
bin="$(readlink -f "$bin")"
echo "binary: $bin"

# --- ensure the icons exist (regenerate if Pillow is around) -----------------
if [[ ! -f "$icons_src/pass-mgr-locked.png" || ! -f "$icons_src/pass-mgr-unlocked.png" ]]; then
  echo "icons missing; generating with make_icons.py ..."
  python3 "$icons_src/make_icons.py"
fi

icon_dir="$HOME/.local/share/icons/pass-mgr"
mkdir -p "$icon_dir"
cp -f "$icons_src/pass-mgr-locked.png" "$icons_src/pass-mgr-unlocked.png" "$icon_dir/"
echo "icons:  $icon_dir"

# --- write the .desktop launchers -------------------------------------------
apps_dir="$HOME/.local/share/applications"
mkdir -p "$apps_dir"

render() {  # template -> destination, substituting the placeholders
  sed -e "s|__BIN__|$bin|g" -e "s|__ICONDIR__|$icon_dir|g" "$1"
}

view_desktop="$apps_dir/pass-mgr.desktop"
edit_desktop="$apps_dir/pass-mgr-edit.desktop"
render "$here/pass-mgr.desktop"      > "$view_desktop"
render "$here/pass-mgr-edit.desktop" > "$edit_desktop"
chmod +x "$view_desktop" "$edit_desktop"
echo "menu:   $view_desktop"
echo "        $edit_desktop"

# --- copy onto the Desktop (best effort) ------------------------------------
desktop_dir="$(xdg-user-dir DESKTOP 2>/dev/null || echo "$HOME/Desktop")"
if [[ -d "$desktop_dir" ]]; then
  for f in "$view_desktop" "$edit_desktop"; do
    dst="$desktop_dir/$(basename "$f")"
    cp -f "$f" "$dst"
    chmod +x "$dst"
    # GNOME/Nautilus: mark the launcher trusted so it runs on double-click.
    gio set "$dst" metadata::trusted true 2>/dev/null || true
  done
  echo "desktop: $desktop_dir (two shortcuts)"
fi

# refresh the menu database (best effort)
update-desktop-database "$apps_dir" 2>/dev/null || true
echo "done."
