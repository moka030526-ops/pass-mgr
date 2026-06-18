package com.passmgr

import android.os.Bundle
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
        val vaultDir = filesDir.resolve("vault").apply { mkdirs() }.absolutePath
        setContent { App(vaultDir = vaultDir) }
    }
}
