#!/usr/bin/env bash
# Userspace (no-sudo) Android + Rust cross-build toolchain installer for pass-mgr mobile.
# Installs under $HOME/toolchains: Temurin JDK 17, Android cmdline-tools + SDK + NDK,
# Rust Android/iOS targets, and cargo-ndk. Writes $HOME/toolchains/env.sh for later shells.
# Idempotent: re-running skips already-present pieces.
set -euo pipefail

TOOLS="${TOOLS:-$HOME/toolchains}"
SDK="$TOOLS/android-sdk"
JDK="$TOOLS/jdk17"
CMDTOOLS_BUILD="14742923"
mkdir -p "$TOOLS" "$SDK"
export PATH="$HOME/.cargo/bin:$PATH"

log() { echo "[install $(printf '%(%H:%M:%S)T' -1)] $*"; }

# --- 1. JDK 17 (Temurin) ---------------------------------------------------
if [ ! -x "$JDK/bin/javac" ]; then
  log "downloading Temurin JDK 17..."
  curl -fsSL -o "$TOOLS/jdk17.tgz" \
    "https://api.adoptium.net/v3/binary/latest/17/ga/linux/x64/jdk/hotspot/normal/eclipse"
  mkdir -p "$JDK"
  tar -xzf "$TOOLS/jdk17.tgz" -C "$JDK" --strip-components=1
  rm -f "$TOOLS/jdk17.tgz"
fi
export JAVA_HOME="$JDK"
export PATH="$JAVA_HOME/bin:$PATH"
log "JDK: $(java -version 2>&1 | head -1)"

# --- 2. Android command-line tools ----------------------------------------
SDKM="$SDK/cmdline-tools/latest/bin/sdkmanager"
if [ ! -x "$SDKM" ]; then
  log "downloading Android cmdline-tools ($CMDTOOLS_BUILD)..."
  curl -fsSL -o "$TOOLS/cmdtools.zip" \
    "https://dl.google.com/android/repository/commandlinetools-linux-${CMDTOOLS_BUILD}_latest.zip"
  rm -rf "$SDK/cmdline-tools/tmp" "$SDK/cmdline-tools/latest"
  mkdir -p "$SDK/cmdline-tools/tmp"
  python3 -c "import zipfile,sys; zipfile.ZipFile(sys.argv[1]).extractall(sys.argv[2])" \
    "$TOOLS/cmdtools.zip" "$SDK/cmdline-tools/tmp"
  mv "$SDK/cmdline-tools/tmp/cmdline-tools" "$SDK/cmdline-tools/latest"
  rmdir "$SDK/cmdline-tools/tmp"
  rm -f "$TOOLS/cmdtools.zip"
fi
# Python's zipfile drops the executable bit; restore it so the wrapper scripts run.
chmod -R u+x "$SDK/cmdline-tools/latest/bin" 2>/dev/null || true
export ANDROID_HOME="$SDK"
export ANDROID_SDK_ROOT="$SDK"
log "sdkmanager: $("$SDKM" --version 2>/dev/null || echo '?')"

# --- 3. Accept licenses + install SDK packages ----------------------------
log "accepting licenses..."
yes | "$SDKM" --sdk_root="$SDK" --licenses >/dev/null 2>&1 || true

log "discovering newest NDK + build-tools..."
"$SDKM" --sdk_root="$SDK" --list 2>/dev/null > "$TOOLS/sdk-list.txt" || true
NDK="$(grep -oE 'ndk;[0-9.]+' "$TOOLS/sdk-list.txt" | sort -V | tail -1 || true)"
BT="$(grep -oE 'build-tools;[0-9.]+' "$TOOLS/sdk-list.txt" | sort -V | tail -1 || true)"
[ -z "$NDK" ] && NDK="ndk;27.2.12479018"
[ -z "$BT" ]  && BT="build-tools;35.0.0"
log "installing platform-tools, platforms;android-35, $BT, $NDK ..."
"$SDKM" --sdk_root="$SDK" "platform-tools" "platforms;android-35" "$BT" "$NDK"
NDK_DIR="$(ls -d "$SDK"/ndk/* 2>/dev/null | sort -V | tail -1 || true)"
log "NDK installed at: ${NDK_DIR:-<none>}"

# --- 4. Rust targets + cargo-ndk ------------------------------------------
log "adding Rust Android targets..."
rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android i686-linux-android
log "adding Rust iOS targets (for the Mac build; harmless here)..."
rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios || true
if ! command -v cargo-ndk >/dev/null 2>&1; then
  log "installing cargo-ndk..."
  cargo install cargo-ndk
fi
log "cargo-ndk: $(cargo ndk --version 2>/dev/null || echo '?')"

# --- 5. Emit env.sh -------------------------------------------------------
cat > "$TOOLS/env.sh" <<EOF
# source this to use the pass-mgr mobile toolchain
export JAVA_HOME="$JDK"
export ANDROID_HOME="$SDK"
export ANDROID_SDK_ROOT="$SDK"
export ANDROID_NDK_HOME="${NDK_DIR:-$SDK/ndk}"
export PATH="\$JAVA_HOME/bin:$SDK/cmdline-tools/latest/bin:$SDK/platform-tools:\$HOME/.cargo/bin:\$PATH"
EOF
log "wrote $TOOLS/env.sh"
echo "TOOLCHAIN_INSTALL_DONE"
