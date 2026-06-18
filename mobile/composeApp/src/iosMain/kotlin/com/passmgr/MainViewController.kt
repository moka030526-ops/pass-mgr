package com.passmgr

import androidx.compose.ui.window.ComposeUIViewController
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
    ComposeUIViewController { App(vaultDir = vaultDir) }
