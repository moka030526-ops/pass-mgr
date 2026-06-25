import SwiftUI
// The shared Kotlin framework (baseName "ComposeApp"), for the AppLifecycle auto-lock signal.
import ComposeApp

@main
struct iOSApp: App {
    // iOS has no `FLAG_SECURE` equivalent (which the Android build sets), so the OS
    // captures an app-switcher snapshot of the live screen when backgrounded —
    // potentially showing a revealed password / vault contents. Cover the UI with an
    // opaque view whenever the scene is not active, so the snapshot (and a quick
    // shoulder-surf on resume) shows nothing sensitive (audit R-14). Verify on a Mac.
    @Environment(\.scenePhase) private var scenePhase

    var body: some Scene {
        WindowGroup {
            ContentView()
                .ignoresSafeArea()
                .overlay {
                    if scenePhase != .active {
                        Color(.systemBackground).ignoresSafeArea()
                    }
                }
                // Auto-lock when the scene leaves the foreground: signal the shared Compose
                // app (AppLifecycle) so it drops the unlocked Vault, mirroring Android's
                // onStop. The opaque overlay above only hides the snapshot; this re-locks.
                // (Kotlin `object` -> Swift `.shared`.) Verify on a Mac.
                .onChange(of: scenePhase) { newPhase in
                    if newPhase != .active {
                        AppLifecycle.shared.onEnterBackground()
                    }
                }
        }
    }
}
