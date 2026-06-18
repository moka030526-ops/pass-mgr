import SwiftUI

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
        }
    }
}
