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

# Escape the binary path for use inside the DOUBLE-QUOTED Exec= value. Per the Desktop
# Entry spec, inside quotes the reserved chars \ " $ ` must be backslash-escaped (backslash
# FIRST). Quoting makes a path with spaces a single argument.
bin_de=$bin
bin_de=${bin_de//\\/\\\\}
bin_de=${bin_de//\"/\\\"}
bin_de=${bin_de//\$/\\\$}
bin_de=${bin_de//\`/\\\`}

# Generate a .desktop launcher with printf, which inserts every value LITERALLY. We do NOT
# template via sed or bash `${//}`: BOTH interpret '&' in the replacement as the matched
# text (sed always; bash 5.2+) and sed's '|' delimiter clashes with a '|' in the path — so a
# binary path containing '&' or '|' (legal on Linux, e.g. "My Apps/pass & co") produced a
# corrupt Exec line or aborted the install under `set -e`. printf sidesteps that entirely.
# Mirrors the committed pass-mgr*.desktop reference templates (kept for manual editing).
write_desktop() {  # $1=dest $2=Name $3=Comment $4=exec_suffix $5=icon_png
  printf '%s\n' \
    '[Desktop Entry]' \
    'Type=Application' \
    'Version=1.0' \
    "Name=$2" \
    'GenericName=Encrypted estate vault' \
    "Comment=$3" \
    "Exec=\"$bin_de\"$4" \
    "Icon=$icon_dir/$5" \
    'Terminal=false' \
    'Categories=Utility;Security;' \
    'StartupNotify=true' \
    > "$1"
}

view_desktop="$apps_dir/pass-mgr.desktop"
edit_desktop="$apps_dir/pass-mgr-edit.desktop"
write_desktop "$view_desktop" "pass-mgr (View)" "Open the vault read-only (locked vault icon)" "" "pass-mgr-locked.png"
write_desktop "$edit_desktop" "pass-mgr (Edit)" "Open the vault in edit mode (unlocked vault icon)" " --write" "pass-mgr-unlocked.png"
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
