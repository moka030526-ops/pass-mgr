@file:OptIn(ExperimentalMaterial3Api::class)

package com.passmgr

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.ScrollableTabRow
import androidx.compose.material3.Tab
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import com.passmgr.ffi.Vault
import com.passmgr.ffi.VaultException
import com.passmgr.ffi.RecordKind
import com.passmgr.ffi.openVault
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** The five vault tabs, each mapping to a core [RecordKind]. */
private enum class Section(val title: String, val kind: RecordKind) {
    Instructions("Instructions", RecordKind.INSTRUCTION),
    TrustWill("Trust & Will", RecordKind.TRUST_WILL),
    Assets("Assets & Liabilities", RecordKind.ASSET_LIABILITY),
    Accounts("Accounts", RecordKind.ACCOUNT),
    RealEstate("Real Estate", RecordKind.REAL_ESTATE),
}

/**
 * Root composable. Shared verbatim by Android and iOS. Holds the locked/unlocked
 * state; the opaque [Vault] handle is destroyed when locking so the Rust side
 * zeroizes the key.
 */
@Composable
fun App(vaultDir: String) {
    MaterialTheme {
        var vault by remember { mutableStateOf<Vault?>(null) }
        val current = vault
        if (current == null) {
            UnlockScreen(vaultDir) { vault = it }
        } else {
            VaultScreen(current) {
                current.destroy()
                vault = null
            }
        }
    }
}

@Composable
private fun UnlockScreen(vaultDir: String, onUnlocked: (Vault) -> Unit) {
    var pw1 by remember { mutableStateOf("") }
    var pw2 by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()

    Column(
        Modifier.fillMaxSize().padding(24.dp),
        verticalArrangement = Arrangement.Center,
    ) {
        Text("pass-mgr", style = MaterialTheme.typography.headlineMedium)
        Spacer(Modifier.height(4.dp))
        Text("Enter your two passwords, in order.", style = MaterialTheme.typography.bodyMedium)
        Spacer(Modifier.height(20.dp))
        OutlinedTextField(
            value = pw1,
            onValueChange = { pw1 = it },
            label = { Text("First password") },
            singleLine = true,
            visualTransformation = PasswordVisualTransformation(),
            modifier = Modifier.fillMaxWidth(),
        )
        Spacer(Modifier.height(8.dp))
        OutlinedTextField(
            value = pw2,
            onValueChange = { pw2 = it },
            label = { Text("Second password") },
            singleLine = true,
            visualTransformation = PasswordVisualTransformation(),
            modifier = Modifier.fillMaxWidth(),
        )
        Spacer(Modifier.height(20.dp))
        Button(
            enabled = !busy && pw1.isNotEmpty() && pw2.isNotEmpty(),
            onClick = {
                busy = true
                error = null
                scope.launch {
                    // Key derivation (Argon2id) is heavy — keep it off the UI thread.
                    val result = runCatching {
                        withContext(Dispatchers.Default) {
                            openVault(vaultDir, pw1.encodeToByteArray(), pw2.encodeToByteArray())
                        }
                    }
                    busy = false
                    result
                        .onSuccess { onUnlocked(it) }
                        .onFailure { error = friendlyError(it) }
                }
            },
            modifier = Modifier.fillMaxWidth(),
        ) { Text(if (busy) "Unlocking…" else "Unlock") }

        if (busy) {
            Spacer(Modifier.height(16.dp))
            Box(Modifier.fillMaxWidth(), contentAlignment = Alignment.Center) {
                CircularProgressIndicator()
            }
        }
        error?.let {
            Spacer(Modifier.height(16.dp))
            Text(it, color = MaterialTheme.colorScheme.error)
        }
    }
}

/** Map the FFI error to a calm, non-leaking message (wrong-pw == corrupt). */
private fun friendlyError(e: Throwable): String = when (e) {
    is VaultException.NotFound ->
        "No vault found. Copy your encrypted vault folder into the app's storage first."
    is VaultException.WrongPasswordOrCorrupt ->
        "Wrong passwords, or the vault is damaged. Re-check both passwords and their order."
    is VaultException.RekeyPending ->
        "An interrupted password change is pending. Finish it on the desktop app, then try again."
    is VaultException -> e.message ?: "Could not open the vault."
    else -> e.message ?: "Unexpected error."
}

@Composable
private fun VaultScreen(vault: Vault, onLock: () -> Unit) {
    var section by remember { mutableStateOf(Section.Accounts) }
    var selectedId by remember { mutableStateOf<String?>(null) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(if (selectedId == null) "pass-mgr" else section.title) },
                navigationIcon = {
                    if (selectedId != null) {
                        TextButton(onClick = { selectedId = null }) { Text("Back") }
                    }
                },
                actions = { TextButton(onClick = onLock) { Text("Lock") } },
            )
        },
    ) { padding ->
        Box(Modifier.fillMaxSize().padding(padding)) {
            val id = selectedId
            if (id == null) {
                Column(Modifier.fillMaxSize()) {
                    ScrollableTabRow(selectedTabIndex = section.ordinal, edgePadding = 8.dp) {
                        Section.entries.forEach { s ->
                            Tab(
                                selected = s == section,
                                onClick = { section = s },
                                text = { Text(s.title) },
                            )
                        }
                    }
                    val rows = remember(section) { vault.listRecords(section.kind) }
                    if (rows.isEmpty()) {
                        Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                            Text("No entries", style = MaterialTheme.typography.bodyLarge)
                        }
                    } else {
                        LazyColumn(Modifier.fillMaxSize()) {
                            items(rows.size) { i ->
                                ListItem(
                                    headlineContent = { Text(rows[i].label) },
                                    modifier = Modifier.clickable { selectedId = rows[i].id },
                                )
                                HorizontalDivider()
                            }
                        }
                    }
                }
            } else {
                DetailScreen(vault, section.kind, id)
            }
        }
    }
}

@Composable
private fun DetailScreen(vault: Vault, kind: RecordKind, id: String) {
    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
    ) {
        when (kind) {
            RecordKind.INSTRUCTION -> {
                val r = remember(id) { runCatching { vault.getInstruction(id) }.getOrNull() }
                if (r == null) NotFound() else {
                    Field("Title", r.title)
                    Field("Description", r.description)
                }
            }
            RecordKind.TRUST_WILL -> {
                val r = remember(id) { runCatching { vault.getTrustWill(id) }.getOrNull() }
                if (r == null) NotFound() else {
                    Field("Document", r.document)
                    Field("Usage", r.usage)
                    Field("Attached document", if (r.file != null) "yes (open on desktop)" else "none")
                }
            }
            RecordKind.ASSET_LIABILITY -> {
                val r = remember(id) { runCatching { vault.getAsset(id) }.getOrNull() }
                if (r == null) NotFound() else {
                    Field("Kind", r.kind)
                    Field("Description", r.description)
                    Field("Owner", r.owner)
                    Field("Approx. value", r.approxValue)
                    Field("As of", r.asOfDate)
                    Field("Institution", r.institution)
                    Field("Type", r.assetType)
                    Field("Beneficiary", r.beneficiary)
                    Field("URL", r.url)
                    if (r.statement != null) Field("Attached statement", "yes (open on desktop)")
                }
            }
            RecordKind.ACCOUNT -> {
                val r = remember(id) { runCatching { vault.getAccount(id) }.getOrNull() }
                if (r == null) NotFound() else {
                    Field("Type", r.accountType)
                    Field("Subtype", r.accountSubtype)
                    Field("Owner", r.owner)
                    Field("Username", r.username)
                    PasswordField(r.password)
                    Field("URL", r.url)
                    Field("Description", r.description)
                }
            }
            RecordKind.REAL_ESTATE -> {
                val r = remember(id) { runCatching { vault.getRealEstate(id) }.getOrNull() }
                if (r == null) NotFound() else {
                    Field("Address", r.address)
                    Field("Ownership", r.ownership)
                    Field("Taxes", r.taxes)
                    Field("HOA", r.hoa)
                    Field("Income account", r.incomeAccount)
                    Field("Financing account", r.financingAccount)
                    Field("Payment account", r.paymentAccount)
                }
            }
        }
    }
}

@Composable
private fun NotFound() {
    Text("This entry is no longer available.", color = MaterialTheme.colorScheme.error)
}

@Composable
private fun Field(label: String, value: String) {
    if (value.isBlank()) return
    Column(Modifier.fillMaxWidth().padding(vertical = 6.dp)) {
        Text(label, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.primary)
        Text(value, style = MaterialTheme.typography.bodyLarge)
    }
    HorizontalDivider()
}

/**
 * Password row: hidden by default, with a reveal toggle and a copy button that
 * auto-clears the clipboard after 15s (re-implementing the desktop's wipe — the
 * OS gives no auto-clear contract).
 */
@Composable
private fun PasswordField(password: String) {
    var revealed by remember { mutableStateOf(false) }
    var copied by remember { mutableStateOf(false) }
    val clipboard = LocalClipboardManager.current

    Column(Modifier.fillMaxWidth().padding(vertical = 6.dp)) {
        Text("Password", style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.primary)
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(
                text = if (revealed) password else "•".repeat(password.length.coerceIn(1, 16)),
                style = MaterialTheme.typography.bodyLarge,
                modifier = Modifier.weight(1f),
            )
            TextButton(onClick = { revealed = !revealed }) { Text(if (revealed) "Hide" else "Reveal") }
            TextButton(onClick = {
                clipboard.setText(AnnotatedString(password))
                copied = true
            }) { Text("Copy") }
        }
        if (copied) {
            Text("Copied — clipboard clears in 15s", style = MaterialTheme.typography.bodySmall)
        }
    }
    HorizontalDivider()

    if (copied) {
        LaunchedClipboardClear {
            clipboard.setText(AnnotatedString(""))
            copied = false
        }
    }
}

@Composable
private fun LaunchedClipboardClear(onClear: () -> Unit) {
    androidx.compose.runtime.LaunchedEffect(Unit) {
        delay(15_000)
        onClear()
    }
}
