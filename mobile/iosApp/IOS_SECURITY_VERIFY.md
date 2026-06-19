# iOS hardening — Mac build & verification checklist

The round-4 audit added three iOS-parity hardening fixes (R-6, R-13, R-14). They are
**committed source but were NOT build-verified** — the iOS targets only compile on a
Mac with Xcode (this repo's CI/dev box is Linux, which builds the Android APK only).
Work through this checklist on a Mac to confirm they compile and behave.

The Android equivalents are already built & verified (FLAG_SECURE + `EXTRA_IS_SENSITIVE`
in `composeApp/src/androidMain/.../MainActivity.kt`); these iOS changes bring parity.

## 0. Prerequisites

- macOS with **Xcode 15+** and command-line tools (`xcode-select --install`).
- The Kotlin/Native iOS toolchain (Gobley/KMP) — same `mobile/` Gradle project.
- A real iPhone is best for R-6/R-14 (the Simulator can't exercise Universal
  Clipboard/Handoff and its app-switcher snapshot behaves differently).
- For R-6's Universal-Clipboard test: a second Apple device signed into the **same
  iCloud account** with **Handoff ON** (Settings → General → AirPlay & Handoff).

## 1. Build the shared framework + the iOS app

```bash
# From the repo root, build the Compose/KMP framework for the device arch:
mobile/gradlew -p mobile :composeApp:linkReleaseFrameworkIosArm64        # device
# (or :composeApp:linkDebugFrameworkIosSimulatorArm64 for the Simulator)

# Then open the Xcode project and build/run onto the device:
open mobile/iosApp/iosApp.xcodeproj
# Product → Run (⌘R) on the connected iPhone.
```

If the **framework link step fails to compile**, the most likely culprit is the
Kotlin/Native UIKit interop in step 2 (it was written without a Mac to check it) —
see the fix notes there.

## 2. R-6 — clipboard is LOCAL-ONLY with a 15 s expiry

**Code:** `composeApp/src/iosMain/kotlin/com/passmgr/MainViewController.kt`
(`copySecretToPasteboard`, passed into `App(copySecret = …)`).

**What it should do:** copying a password uses `UIPasteboard.setItems(_:options:)` with
`UIPasteboardOptionLocalOnly = true` and `UIPasteboardOptionExpirationDate = now+15s`,
instead of the default `UIPasteboard.string` (which is broadcast via Universal
Clipboard and never expires).

**If it does not compile**, the Kotlin/Native ↔ ObjC bridging of the options
dictionary is the thing to adjust. Known-good alternatives to try, in order:
- The `Map<Any?, *>` literals may need explicit `mapOf<Any?, Any?>(...)`.
- `true` may need to be an explicit `NSNumber` — try `NSNumber(bool = true)`.
- If `setItems(_:options:)` interop is awkward, fall back to setting the property and
  the expiry separately:
  ```kotlin
  val pb = UIPasteboard.generalPasteboard
  pb.items = listOf(mapOf<Any?, Any?>("public.utf8-plain-text" to secret))
  // localOnly + expiry via setItems options is preferred; if unavailable, at minimum
  // set an expiry: pb.setItems(pb.items, options = mapOf(UIPasteboardOptionExpirationDate to NSDate(...)))
  ```

**Behavior test (two devices, Handoff on):**
1. Unlock a vault, open an account, reveal + Copy a password.
2. On the paired Mac, click into any text field and ⌘V **within ~1–2 s**.
   - ✅ PASS: the password does **not** paste (Universal Clipboard did not carry it).
   - ❌ FAIL (regression): the password appears on the Mac.
3. Wait 20 s, then ⌘V on the **iPhone** itself.
   - ✅ PASS: nothing pastes (the 15 s expiry cleared it) — the app's own 15 s wipe
     and the OS expiry are belt-and-suspenders.

## 3. R-13 — Data Protection actually applied

**Code:** `iosApp/iosApp/ContentView.swift` sets
`FileProtectionType.complete` on the vault dir; the bogus `NSFileProtectionComplete`
Info.plist key was removed (it was a silent no-op).

**Verify the attribute is set** (on a jailbroken/test device or via a debug log):
```swift
// Temporary debug line after creating `dir`:
let attrs = try? FileManager.default.attributesOfItem(atPath: dir.path)
print("protection:", attrs?[.protectionKey] ?? "none")   // expect: complete
```
- ✅ PASS: prints `complete`.

**Recommended for full coverage (optional):** add the **Data Protection** capability
so it applies project-wide, not just to the dir we set explicitly:
- Xcode → target → Signing & Capabilities → **+ Capability → Data Protection**.
- This creates an `.entitlements` with
  `com.apple.developer.default-data-protection = NSFileProtectionComplete`.
- Confirm the vault files are unreadable while the device is locked (lock the phone;
  a background read of the file should fail until first unlock).

## 4. R-14 — no secrets in the app-switcher snapshot

**Code:** `iosApp/iosApp/iOSApp.swift` overlays an opaque `Color(.systemBackground)`
whenever `scenePhase != .active` (iOS has no `FLAG_SECURE`; this is the parity fix).

**Behavior test:**
1. Unlock a vault, open an account, **reveal** a password (so a secret is on screen).
2. Swipe up to the **app switcher** (or press Home).
   - ✅ PASS: the app's card shows a blank/opaque screen, not the password.
   - ❌ FAIL: the revealed password/vault contents are visible in the card.
3. Take a screenshot while a secret is shown — confirm the captured image is the
   opaque overlay (note: unlike Android `FLAG_SECURE`, iOS can't *block* the
   screenshot, but the overlay covers it during the background transition; if you want
   to also blank on screenshot, observe `UIApplication.userDidTakeScreenshotNotification`).

## 5. After verifying

- If any of the three needed a code tweak to compile/behave, commit the corrected
  Swift/Kotlin and update `docs/HARDENING.md` §3.1d (R-6/R-13/R-14) from
  "pending Mac verification" to "verified".
- If all three pass as-is, just note the verification (date + device/iOS version) in
  `docs/HARDENING.md` §3.1d so the "pending" caveat can be dropped.
