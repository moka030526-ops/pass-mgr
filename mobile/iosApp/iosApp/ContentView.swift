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
