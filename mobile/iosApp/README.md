# iOS app (build on a Mac)

The iOS app reuses the same shared Compose UI and the same audited Rust core as
Android. **It can only be built and signed on macOS with Xcode** — the Linux dev
box cannot produce or sign an iOS build.

These Swift files (`iosApp/iOSApp.swift`, `ContentView.swift`, `Info.plist`) are
the host application. The actual UI is the Kotlin `ComposeApp` framework that
Gradle builds from `:composeApp` (its iOS targets are declared in
`composeApp/build.gradle.kts`, guarded to macOS).

## One-time, on the Mac

```bash
# Rust iOS targets
rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios
# Xcode + command line tools installed
xcode-select --install
```

## Wiring the framework into Xcode

Two supported routes (pick one):

1. **Direct framework (recommended).** Create an Xcode App project that contains
   these Swift files, then add a "Run Script" build phase **before** "Compile
   Sources":

   ```
   cd "$SRCROOT/.."
   ./gradlew :composeApp:embedAndSignAppleFrameworkForXcode
   ```

   and add `$(SRCROOT)/../composeApp/build/xcode-frameworks/$(CONFIGURATION)/$(SDK_NAME)`
   to *Framework Search Paths*. Gobley builds the Rust staticlib and links it into
   the `ComposeApp` framework automatically as part of that task.

2. **KMP/Compose project wizard.** Generate a fresh Compose Multiplatform iOS app
   with the JetBrains wizard and drop these Swift files + the `:composeApp` module
   in, keeping `import ComposeApp` and the `MainViewControllerKt.MainViewController`
   entry.

## Notes

- `ContentView.swift` puts the vault in app-private **Application Support** and
  marks it **excluded from iCloud backup** (offline model + rollback safety).
- Add Face ID / Touch ID gating (LocalAuthentication) and Keychain-wrapped unlock
  as defense-in-depth around the two-password KDF — *roadmap*, see `../README.md`.
- Getting a vault onto the device: see "Getting your vault onto the phone" in
  `../README.md`.
