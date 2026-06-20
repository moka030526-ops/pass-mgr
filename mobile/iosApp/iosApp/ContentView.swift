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
        // Apply Data Protection so the (already password-encrypted) vault files are ALSO
        // unreadable while the device is locked, instead of inheriting the weaker default
        // (CompleteUntilFirstUserAuthentication). The old Info.plist `NSFileProtectionComplete`
        // key was a no-op (audit R-13). Setting the attribute on the DIRECTORY alone does NOT
        // propagate to files the Rust core creates later (vault.pmv, volume blobs, atomic-write
        // temps) — so we (1) re-apply Complete to the dir AND every file already inside it on
        // each launch (covers files stored in earlier sessions), and (2) rely on the
        // `com.apple.developer.default-data-protection = NSFileProtectionComplete` entitlement
        // (iosApp.entitlements) to make FUTURE files default to Complete. Verify on a Mac.
        applyCompleteProtection(to: dir, using: fm)

        return MainViewControllerKt.MainViewController(vaultDir: dir.path)
    }

    func updateUIViewController(_ uiViewController: UIViewController, context: Context) {}

    /// Recursively set `FileProtectionType.complete` on `dir` and every file already inside it.
    /// New files created afterward get Complete from the app's data-protection entitlement.
    private func applyCompleteProtection(to dir: URL, using fm: FileManager) {
        let attrs: [FileAttributeKey: Any] = [.protectionKey: FileProtectionType.complete]
        try? fm.setAttributes(attrs, ofItemAtPath: dir.path)
        if let rels = try? fm.subpathsOfDirectory(atPath: dir.path) {
            for rel in rels {
                try? fm.setAttributes(attrs, ofItemAtPath: dir.appendingPathComponent(rel).path)
            }
        }
    }
}

struct ContentView: View {
    var body: some View {
        ComposeView()
            .ignoresSafeArea(.keyboard) // let Compose handle the IME inset
    }
}
