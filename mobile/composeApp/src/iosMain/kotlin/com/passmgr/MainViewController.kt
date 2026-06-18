package com.passmgr

import androidx.compose.ui.window.ComposeUIViewController
import platform.Foundation.NSDate
import platform.Foundation.dateWithTimeIntervalSinceNow
import platform.UIKit.UIPasteboard
import platform.UIKit.UIPasteboardOptionExpirationDate
import platform.UIKit.UIPasteboardOptionLocalOnly
import platform.UIKit.UIViewController

/**
 * iOS entry point. Returns a UIViewController hosting the shared Compose UI.
 * Called from Swift as `MainViewControllerKt.MainViewController(vaultDir:)`.
 *
 * This file is compiled ONLY for the iOS targets (declared in
 * `composeApp/build.gradle.kts` behind `GobleyHost.Platform.MacOS.isCurrent`),
 * so it is inert on a Linux/Windows Android build.
 *
 * `vaultDir` is the app's Application-Support `vault/` directory, handed in by
 * the Swift host (which also excludes it from iCloud backup).
 */
fun MainViewController(vaultDir: String): UIViewController =
    ComposeUIViewController { App(vaultDir = vaultDir, copySecret = ::copySecretToPasteboard) }

/**
 * Copy a SECRET (a password) to the iOS pasteboard as LOCAL-ONLY with a 15 s expiry.
 * The default `clipboard.setText` path maps to `UIPasteboard.string`, which is
 * `localOnly = false` with no expiry — so Universal Clipboard / Handoff BROADCASTS the
 * password to the user's other Apple devices, and it lingers in the global pasteboard
 * even if the in-app 15 s wipe is pre-empted by process death (audit R-6). Using
 * `setItems(_:options:)` with `LocalOnly = true` keeps it on this device, and
 * `ExpirationDate` lets the OS drop it on its own. Mirrors the Android
 * `EXTRA_IS_SENSITIVE` hardening.
 *
 * NOTE: iOS-only Kotlin/Native UIKit interop — compiled only on a Mac; build-verify there.
 */
private fun copySecretToPasteboard(secret: String) {
    val item: Map<Any?, *> = mapOf("public.utf8-plain-text" to secret)
    val options: Map<Any?, *> = mapOf(
        UIPasteboardOptionLocalOnly to true,
        UIPasteboardOptionExpirationDate to NSDate.dateWithTimeIntervalSinceNow(15.0),
    )
    UIPasteboard.generalPasteboard.setItems(listOf(item), options)
}
