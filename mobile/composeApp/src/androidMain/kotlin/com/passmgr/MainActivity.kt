package com.passmgr

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.os.Build
import android.os.Bundle
import android.os.PersistableBundle
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent

/**
 * The single Android entry point. The vault lives in app-private storage
 * (`filesDir/vault/`) — never on shared/SAF/cloud-backed storage, where the
 * POSIX rename + directory-fsync atomicity the crash-safety relies on is weaker
 * and a silent cloud restore could defeat generation-rollback detection.
 */
class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Mark the whole window secure: exclude it from screenshots, screen recording,
        // and the recent-apps thumbnail, so a revealed password or vault contents can't
        // leak through those OS surfaces.
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        val vaultDir = filesDir.resolve("vault").apply { mkdirs() }.absolutePath
        setContent { App(vaultDir = vaultDir, copySecret = ::copySensitive) }
    }

    /**
     * Lock the vault whenever the app leaves the foreground. `onStop` fires once the activity
     * is fully hidden (backgrounded, screen off, or another app on top); the shared [App]
     * observes [AppLifecycle] and drops the Vault handle, so the app never resumes still
     * unlocked. (FLAG_SECURE above separately keeps the recents thumbnail blank.)
     */
    override fun onStop() {
        super.onStop()
        AppLifecycle.onEnterBackground()
    }

    /**
     * Copy a password to the clipboard marked SENSITIVE. On Android 13+ the system
     * paste-preview overlay then redacts it instead of rendering the plaintext, and
     * history-aware keyboards (Gboard) are asked not to retain it. (The app's own
     * 15 s + on-lock wipe still applies on top.)
     */
    private fun copySensitive(secret: String) {
        val cm = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        val clip = ClipData.newPlainText("password", secret)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            clip.description.extras =
                PersistableBundle().apply { putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true) }
        }
        cm.setPrimaryClip(clip)
    }
}
