import SwiftUI
// The Kotlin Multiplatform framework (baseName = "ComposeApp" in
// composeApp/build.gradle.kts). Produced by Gradle on a Mac.
import ComposeApp

/// Bridges the shared Compose UI (a UIViewController) into SwiftUI.
struct ComposeView: UIViewControllerRepresentable {
    func makeUIViewController(context: Context) -> UIViewController {
        // The vault lives in app-private Application Support, excluded from
        // iCloud backup (offline model + generation-rollback safety).
        let fm = FileManager.default
        var dir = fm.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("vault")
        try? fm.createDirectory(at: dir, withIntermediateDirectories: true)
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        try? dir.setResourceValues(values)
        // Apply Data Protection so the (already password-encrypted) vault files are
        // ALSO unreadable while the device is locked, instead of inheriting the weaker
        // default (CompleteUntilFirstUserAuthentication). The old Info.plist
        // `NSFileProtectionComplete` key was a no-op (audit R-13); set it as a real
        // file attribute here. For app-wide coverage also add the Data Protection
        // entitlement (see Info.plist note). Verify on a Mac.
        try? fm.setAttributes([.protectionKey: FileProtectionType.complete], ofItemAtPath: dir.path)

        return MainViewControllerKt.MainViewController(vaultDir: dir.path)
    }

    func updateUIViewController(_ uiViewController: UIViewController, context: Context) {}
}

struct ContentView: View {
    var body: some View {
        ComposeView()
            .ignoresSafeArea(.keyboard) // let Compose handle the IME inset
    }
}
