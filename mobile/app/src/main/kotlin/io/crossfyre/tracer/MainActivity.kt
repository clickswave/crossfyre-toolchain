package io.crossfyre.tracer

import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInstaller
import android.net.Uri
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.launch
import java.io.File
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import org.json.JSONObject

/**
 * Control surface for the Crossfyre mobile tracer. Pair to a workspace (QR), install the on-device CA,
 * pick apps (or whole device), start/stop capture, and - the important part - watch a LIVE status panel
 * that shows exactly what capture is doing: flows seen, certificate rejections (the tell-tale of an app
 * that does not trust the CA), shapes captured, and shapes shipped. Styled to match the crossfyre web app.
 */
class MainActivity : ComponentActivity() {

    private var running by mutableStateOf(false)
    private var paired by mutableStateOf(false)
    private val selectedApps = mutableStateListOf<String>()
    // "all" = whole device, "only" = capture just selectedApps, "except" = capture all but selectedApps
    // (the escape hatch for certificate-pinned apps that break under MITM).
    private var scopeMode by mutableStateOf(TracerVpnService.MODE_ALL)

    private val vpnConsent =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) {
            launchService(); running = true
        }

    // A scanned pairing waiting for the user to confirm the host. Scanning is not
    // consent: this value decides where captured traffic goes and where a patched
    // APK is fetched from, so the user is shown the host before anything is saved.
    private var pendingPair by mutableStateOf<Pairing?>(null)
    private var pairError by mutableStateOf("")

    private val scan = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { res ->
        if (res.resultCode == RESULT_OK) {
            res.data?.getStringExtra(ScannerActivity.EXTRA_QR)?.let {
                val parsed = Pairing.parseQr(it)
                if (parsed == null) {
                    pairError = "That QR code is not a valid Crossfyre pairing (it must use https)."
                } else {
                    pairError = ""
                    pendingPair = parsed
                }
            }
        }
    }

    /** Commit the pairing the user just approved. */
    private fun confirmPairing() {
        pendingPair?.let {
            Pairing.persist(this, it)
            paired = true
        }
        pendingPair = null
    }

    // Server-assisted patch flow state.
    private var patching by mutableStateOf(false)
    private var patchStatus by mutableStateOf("")
    private var patchProgress by mutableStateOf<Float?>(0f) // 0..1 across the whole flow
    private var creepJob: kotlinx.coroutines.Job? = null
    private var pendingInstall: List<File>? = null
    private var pendingPkg: String? = null
    private val INSTALL_ACTION = "io.crossfyre.tracer.INSTALL_RESULT"
    private val UNINSTALL_ACTION = "io.crossfyre.tracer.UNINSTALL_RESULT"

    // Uninstall the original (its signature differs from our patched build) via PackageInstaller, and
    // chain the install off the uninstall SUCCESS - not a fire-and-forget intent - so the old package
    // is definitely gone first. Otherwise the install is treated as an UPDATE and fails with
    // INSTALL_FAILED_UPDATE_INCOMPATIBLE (signatures do not match).
    private fun requestUninstall(pkg: String) {
        val flags = PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_MUTABLE
        val pi = PendingIntent.getBroadcast(this, 2, Intent(UNINSTALL_ACTION).setPackage(packageName), flags)
        packageManager.packageInstaller.uninstall(pkg, pi.intentSender)
    }

    // Handles both the uninstall and the install PackageInstaller results (a shared receiver).
    private val installReceiver = object : BroadcastReceiver() {
        override fun onReceive(c: Context, i: Intent) {
            val status = i.getIntExtra(PackageInstaller.EXTRA_STATUS, -1)
            if (status == PackageInstaller.STATUS_PENDING_USER_ACTION) {
                // Only ever launch a handed-over Intent while WE have a patch in
                // flight. Belt and braces with RECEIVER_NOT_EXPORTED: launching
                // an arbitrary Intent from this context is the valuable half of
                // an intent-redirection bug, so it should not be reachable at a
                // moment when no install is pending either.
                if (!patching) return
                @Suppress("DEPRECATION")
                val confirm = i.getParcelableExtra<Intent>(Intent.EXTRA_INTENT)
                confirm?.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                runCatching { startActivity(confirm) }
                return
            }
            val msg = i.getStringExtra(PackageInstaller.EXTRA_STATUS_MESSAGE)
            if (i.action == UNINSTALL_ACTION) {
                if (status == PackageInstaller.STATUS_SUCCESS) {
                    patchStatus = "Installing the patched build…"
                    patchProgress = 0.995f
                    pendingInstall?.let { doInstall(it) }
                } else {
                    patching = false
                    patchStatus = "Couldn't remove the old app: ${msg ?: "cancelled"}"
                }
            } else { // INSTALL_ACTION
                if (status == PackageInstaller.STATUS_SUCCESS) {
                    patching = false
                    patchProgress = 1f
                    patchStatus = "Patched + installed. Start capture, then use the app: it'll trust the CA."
                } else {
                    patching = false
                    patchStatus = "Install failed: ${msg ?: "unknown"}"
                }
            }
        }
    }

    private fun patchApp(pkg: String) {
        val pair = Pairing.load(this)
        if (pair == null) { patchStatus = "Pair a workspace first."; return }
        val ca = File(getExternalFilesDir(null), "crossfyre-ca.crt")
        if (!ca.exists()) { patchStatus = "Generate + install the CA first."; return }
        patching = true
        patchStatus = "Starting…"
        patchProgress = null
        lifecycleScope.launch {
            try {
                val patched = Patcher.buildPatched(applicationContext, pkg, pair.apiUrl, pair.workflowId, pair.token, ca) { step ->
                    patchStatus = step.label
                    val f = step.fraction
                    if (f != null) {
                        // A real measured phase (upload/download): take it, stop any server-phase creep.
                        creepJob?.cancel(); creepJob = null
                        if (f > (patchProgress ?: 0f)) patchProgress = f // monotonic
                    } else if (step.label.startsWith("Patching") && creepJob == null) {
                        // Server phase has no feed: creep the same bar 0.45 -> 0.54 so it keeps moving.
                        creepJob = lifecycleScope.launch {
                            var v = (patchProgress ?: 0.45f).coerceAtLeast(0.45f)
                            while (v < 0.54f) { delay(700); v += 0.01f; patchProgress = v }
                        }
                    }
                }
                creepJob?.cancel(); creepJob = null
                pendingInstall = patched
                pendingPkg = pkg
                patchStatus = "Uninstalling the old build (you'll re-login), then installing the patched one…"
                patchProgress = 0.99f
                requestUninstall(pkg)
            } catch (e: Exception) {
                creepJob?.cancel(); creepJob = null
                patching = false
                // e.message is null for plenty of exceptions, and "Patch failed: null" tells
                // nobody anything. Patcher passes the server's own sentence through here.
                patchStatus = "Patch failed: " + (e.message?.takeIf { it.isNotBlank() }
                    ?: "something went wrong on the way to the server.")
            }
        }
    }

    private fun doInstall(splits: List<File>) {
        val pi = packageManager.packageInstaller
        val params = PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_INSTALL)
        pendingPkg?.let { params.setAppPackageName(it) }
        val sid = pi.createSession(params)
        pi.openSession(sid).use { session ->
            for (apk in splits) {
                session.openWrite(apk.name, 0, apk.length()).use { out ->
                    apk.inputStream().use { it.copyTo(out) }
                    session.fsync(out)
                }
            }
            val flags = PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_MUTABLE
            val pending = PendingIntent.getBroadcast(this, sid, Intent(INSTALL_ACTION).setPackage(packageName), flags)
            session.commit(pending.intentSender)
        }
        patchStatus = "Confirm the install…"
    }

    private var caStatus by mutableStateOf("")
    // Shown after unpair: the CA stays trusted until the user removes it by hand.
    private var showRemoveCaHint by mutableStateOf(false)
    // Device-side consent for full capture; see FullCapturePrefs.
    private var allowFullCapture by mutableStateOf(false)
    private var pendingCaPem: String? = null
    private val caSave =
        registerForActivityResult(ActivityResultContracts.CreateDocument("application/x-x509-ca-cert")) { uri ->
            val pem = pendingCaPem
            caStatus = if (uri != null && pem != null) {
                runCatching {
                    contentResolver.openOutputStream(uri)?.use { it.write(pem.toByteArray()) }
                    "Saved. Install it: Settings > Security > Encryption & credentials > " +
                        "Install a certificate > CA certificate."
                }.getOrElse { "Error saving: ${it.message}" }
            } else "Save cancelled."
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        runCatching { Native.setStorageDir(filesDir.absolutePath) }
        paired = Pairing.load(this) != null
        allowFullCapture = FullCapturePrefs.allowed(this)
        // Restore persisted scope so the operator's choice survives closing the app.
        val (mode, apps) = ScopePrefs.load(this)
        scopeMode = mode
        selectedApps.clear()
        selectedApps.addAll(apps)
        // The foreground service keeps the process alive while capturing, so this static reflects the
        // real capture state after the app was reopened.
        running = TracerVpnService.active
        // NOT_EXPORTED on every API level. minSdk is 26, and below API 33 a
        // dynamically registered receiver defaults to EXPORTED with no
        // permission, so any app could broadcast our own INSTALL_RESULT action
        // with an arbitrary Intent in EXTRA_INTENT and have us launch it from
        // this context (intent redirection). ContextCompat routes older levels
        // through androidx's signature-permission shim.
        androidx.core.content.ContextCompat.registerReceiver(
            this,
            installReceiver,
            IntentFilter(INSTALL_ACTION).apply { addAction(UNINSTALL_ACTION) },
            androidx.core.content.ContextCompat.RECEIVER_NOT_EXPORTED
        )
        setContent { CrossfyreTheme { Screen() } }
    }

    override fun onDestroy() {
        super.onDestroy()
        runCatching { unregisterReceiver(installReceiver) }
    }

    override fun onResume() {
        super.onResume()
        // If capture was stopped from the notification while the app was backgrounded, reflect it.
        running = TracerVpnService.active
    }

    private fun persistScope() {
        ScopePrefs.save(this, scopeMode, selectedApps.toSet())
    }

    private fun unpair() {
        if (running) toggleCapture()
        Pairing.clear(this)
        // Delete the interception CA's key material too. Clearing only the
        // pairing left `ca.key` on disk and, more importantly, left the
        // certificate installed and trusted in the OS user store: a user who
        // unpairs reasonably believes they are done, while their device goes on
        // trusting a CA whose private key is still present.
        runCatching { java.io.File(filesDir, "ca.pem").delete() }
        runCatching { java.io.File(filesDir, "ca.key").delete() }
        runCatching { java.io.File(getExternalFilesDir(null), "crossfyre-ca.crt").delete() }
        paired = false
        caStatus = ""
        showRemoveCaHint = true
    }

    /** Open the OS security settings so the user can remove the trusted CA. */
    private fun openSecuritySettings() {
        runCatching {
            startActivity(Intent(android.provider.Settings.ACTION_SECURITY_SETTINGS))
        }
        showRemoveCaHint = false
    }

    private fun launchService() {
        persistScope()
        startService(
            Intent(this, TracerVpnService::class.java)
                .setAction(TracerVpnService.ACTION_START)
                .putExtra(TracerVpnService.EXTRA_MODE, scopeMode)
                .putExtra(TracerVpnService.EXTRA_APPS, selectedApps.toTypedArray())
        )
    }

    private fun toggleCapture() {
        if (running) {
            startService(Intent(this, TracerVpnService::class.java).setAction(TracerVpnService.ACTION_STOP))
            running = false
        } else {
            val prepare = VpnService.prepare(this)
            if (prepare != null) vpnConsent.launch(prepare) else { launchService(); running = true }
        }
    }

    private fun installCa() {
        val pem = runCatching { Native.generateCaPem() }.getOrElse { caStatus = "ERROR: ${it.message}"; return }
        if (pem.startsWith("ERROR")) { caStatus = pem; return }
        pendingCaPem = pem
        runCatching { java.io.File(getExternalFilesDir(null), "crossfyre-ca.crt").writeText(pem) }
        caStatus = "Choose where to save the CA (Downloads is fine)…"
        caSave.launch("crossfyre-ca.crt")
    }

    private fun userApps(): List<Pair<String, String>> =
        packageManager.getInstalledApplications(0)
            .filter { it.flags and ApplicationInfo.FLAG_SYSTEM == 0 && it.packageName != packageName }
            .map { it.packageName to packageManager.getApplicationLabel(it).toString() }
            .sortedBy { it.second.lowercase() }

    // ── UI ────────────────────────────────────────────────────────────────────

    @OptIn(ExperimentalMaterial3Api::class)
    @Composable
    private fun Screen() {
        var routing by remember { mutableStateOf("normal") }
        var showPicker by remember { mutableStateOf(false) }
        var showCaHelp by remember { mutableStateOf(false) }
        val apps = remember { userApps() }
        var stats by remember { mutableStateOf<Stats?>(null) }

        // The pairing confirmation. The host is the whole point of this dialog:
        // it is the one piece of information that distinguishes pairing with your
        // own workspace from pairing with someone else's server.
        pendingPair?.let { p ->
            AlertDialog(
                onDismissRequest = { pendingPair = null },
                title = { Text("Pair with this server?") },
                text = {
                    Column {
                        Text("Captured traffic from this device will be sent to:")
                        Spacer(Modifier.height(8.dp))
                        Text(Pairing.hostOf(p.apiUrl), style = MaterialTheme.typography.titleMedium)
                        Spacer(Modifier.height(8.dp))
                        Text(
                            "Only continue if you recognise this address. Pairing also lets " +
                                "this server supply app builds that you install.",
                            style = MaterialTheme.typography.bodySmall
                        )
                    }
                },
                confirmButton = { TextButton(onClick = { confirmPairing() }) { Text("Pair") } },
                dismissButton = { TextButton(onClick = { pendingPair = null }) { Text("Cancel") } }
            )
        }
        if (showRemoveCaHint) {
            AlertDialog(
                onDismissRequest = { showRemoveCaHint = false },
                title = { Text("Remove the Crossfyre certificate") },
                text = {
                    Text(
                        "Unpairing deleted this app's certificate files, but Android still " +
                            "trusts the certificate you installed. Remove it under " +
                            "Security > Encryption & credentials > User credentials."
                    )
                },
                confirmButton = { TextButton(onClick = { openSecuritySettings() }) { Text("Open settings") } },
                dismissButton = { TextButton(onClick = { showRemoveCaHint = false }) { Text("Later") } }
            )
        }
        if (pairError.isNotEmpty()) {
            AlertDialog(
                onDismissRequest = { pairError = "" },
                title = { Text("Could not pair") },
                text = { Text(pairError) },
                confirmButton = { TextButton(onClick = { pairError = "" }) { Text("OK") } }
            )
        }

        // Poll the native counters while capturing so the panel stays live.
        LaunchedEffect(running) {
            if (!running) { stats = null; return@LaunchedEffect }
            while (running) {
                stats = withContext(Dispatchers.Default) { runCatching { Stats.parse(Native.captureStats()) }.getOrNull() }
                delay(1000)
            }
        }

        Scaffold(containerColor = Cfx.bg) { pad ->
            Column(
                Modifier
                    .padding(pad)
                    .fillMaxSize()
                    .verticalScroll(rememberScrollState())
                    .padding(horizontal = 16.dp)
                    .padding(bottom = 24.dp),
                verticalArrangement = Arrangement.spacedBy(14.dp)
            ) {
                Header()
                StatusCard(running, stats, hasCaHelp = { showCaHelp = true })

                SectionCard("Workspace", step = "1") {
                    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                        OutlinedAccentButton(if (paired) "Re-pair" else "Scan QR") {
                            scan.launch(Intent(this@MainActivity, ScannerActivity::class.java))
                        }
                        StatusPill(if (paired) "Paired" else "Not paired", if (paired) Cfx.success else Cfx.text3)
                        if (paired) {
                            Spacer(Modifier.weight(1f))
                            TextButton(onClick = { unpair() }) { Text("Unpair", color = Cfx.text3) }
                        }
                    }
                }

                SectionCard("Certificate", step = "2") {
                    Text(
                        "Capture terminates TLS with an on-device CA. Install it, then trust it in the app you test.",
                        style = MaterialTheme.typography.bodySmall
                    )
                    Spacer(Modifier.height(10.dp))
                    PrimaryButton("Generate + install CA", fill = false) { installCa() }
                    if (caStatus.isNotEmpty()) {
                        Spacer(Modifier.height(8.dp))
                        Text(caStatus, style = MaterialTheme.typography.bodySmall, color = Cfx.text2)
                    }
                    Spacer(Modifier.height(8.dp))
                    TextButton(onClick = { showCaHelp = !showCaHelp }, contentPadding = PaddingValues(0.dp)) {
                        Text(if (showCaHelp) "Hide trust steps" else "Chrome won't work: how to trust it ›", color = Cfx.ember, fontSize = 13.sp)
                    }
                    if (showCaHelp) CaHelp()
                }

                SectionCard("Scope", step = "3") {
                    val n = selectedApps.size
                    val (title, sub) = when {
                        scopeMode == TracerVpnService.MODE_ONLY && n > 0 -> "Only $n app(s)" to "capture just the selected apps"
                        scopeMode == TracerVpnService.MODE_EXCEPT && n > 0 -> "All except $n app(s)" to "the selected apps bypass the tracer and keep working"
                        else -> "Whole device" to "every app routes through the tracer"
                    }
                    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
                        Column(Modifier.weight(1f).padding(end = 8.dp)) {
                            Text(title, style = MaterialTheme.typography.titleMedium, color = Cfx.text)
                            Text(sub, style = MaterialTheme.typography.bodySmall)
                        }
                        OutlinedAccentButton("Choose") { showPicker = true }
                    }
                    Spacer(Modifier.height(8.dp))
                    Text(
                        "Pinned apps (banking, dating, etc.) reject the CA and can't be captured, so they may fail to connect while captured. Put them in \"All except\" to keep them working.",
                        style = MaterialTheme.typography.bodySmall, color = Cfx.text3
                    )
                }

                SectionCard("Egress routing", step = "4") {
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        ChoiceChip("Normal", routing == "normal", true) { routing = "normal" }
                        ChoiceChip("Through node (soon)", false, false) {}
                    }
                }

                Spacer(Modifier.height(4.dp))

                // Full capture is a device decision. The workspace can ask for it;
                // this switch is what grants it, and the copy below states which
                // of the two behaviours is actually in force.
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Switch(checked = allowFullCapture, enabled = !running, onCheckedChange = {
                        allowFullCapture = it
                        FullCapturePrefs.set(this@MainActivity, it)
                    })
                    Spacer(Modifier.width(8.dp))
                    Text(
                        "Send full requests (headers and bodies)",
                        style = MaterialTheme.typography.bodySmall, color = Cfx.text2
                    )
                }
                if (allowFullCapture && running) {
                    Text(
                        "FULL CAPTURE IS ON. Headers and bodies, including credentials, are being uploaded.",
                        style = MaterialTheme.typography.bodySmall, color = Cfx.danger
                    )
                }

                Spacer(Modifier.height(4.dp))
                PrimaryButton(if (running) "Stop capture" else "Start capture", enabled = paired, fill = true, danger = running) { toggleCapture() }
                if (!paired) Text("Pair a workspace first.", style = MaterialTheme.typography.bodySmall, color = Cfx.text3)
                Text(
                    if (allowFullCapture)
                        "Only capture apps and targets you are authorized to test. Full requests, including headers and bodies, are sent to your workspace."
                    else
                        "Only capture apps and targets you are authorized to test. Only request shape is sent: bodies and secrets stay on the device unless you turn on full requests above.",
                    style = MaterialTheme.typography.bodySmall, color = Cfx.text3
                )
            }
        }

        if (showPicker) {
            AppPickerSheet(apps, selectedApps, onDismiss = { persistScope(); showPicker = false })
        }

        // Patch progress / result.
        if (patching) {
            AlertDialog(
                onDismissRequest = {},
                confirmButton = {},
                containerColor = Cfx.surfaceRaised,
                title = { Text("Patching app", color = Cfx.text) },
                text = {
                    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                        val p = patchProgress
                        if (p != null) {
                            LinearProgressIndicator(progress = { p }, color = Cfx.ember, trackColor = Cfx.surfaceInput, modifier = Modifier.fillMaxWidth())
                        } else {
                            LinearProgressIndicator(color = Cfx.ember, trackColor = Cfx.surfaceInput, modifier = Modifier.fillMaxWidth())
                        }
                        Text(patchStatus, color = Cfx.text2, style = MaterialTheme.typography.bodySmall)
                        Text(
                            "The app is repackaged on the server to trust the CA, then reinstalled. You'll confirm an uninstall and an install.",
                            color = Cfx.text3, style = MaterialTheme.typography.bodySmall
                        )
                    }
                }
            )
        } else if (patchStatus.isNotEmpty()) {
            AlertDialog(
                onDismissRequest = { patchStatus = "" },
                containerColor = Cfx.surfaceRaised,
                confirmButton = { TextButton(onClick = { patchStatus = "" }) { Text("OK", color = Cfx.ember) } },
                title = { Text("Patch", color = Cfx.text) },
                text = { Text(patchStatus, color = Cfx.text2) }
            )
        }
    }

    @Composable
    private fun Header() {
        Column(Modifier.fillMaxWidth().padding(top = 18.dp, bottom = 2.dp)) {
            Image(
                painter = painterResource(R.drawable.cfx_wordmark),
                contentDescription = "Crossfyre",
                modifier = Modifier.height(26.dp)
            )
            Text("Mobile Tracer", fontFamily = Cfx.mono, fontSize = 12.sp, letterSpacing = 2.sp, color = Cfx.text3, modifier = Modifier.padding(start = 2.dp, top = 4.dp))
        }
    }

    @Composable
    private fun StatusCard(running: Boolean, s: Stats?, hasCaHelp: () -> Unit) {
        val diag = diagnose(running, s)
        Column(
            Modifier
                .fillMaxWidth()
                .clip(RoundedCornerShape(14.dp))
                .background(Cfx.surface)
                .border(1.dp, if (running) Cfx.emberLine else Cfx.line, RoundedCornerShape(14.dp))
                .padding(16.dp)
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Box(Modifier.size(10.dp).clip(CircleShape).background(if (running) Cfx.success else Cfx.text3))
                Spacer(Modifier.width(8.dp))
                Text(if (running) "CAPTURING" else "IDLE", fontFamily = Cfx.mono, fontWeight = FontWeight.Bold, letterSpacing = 2.sp, color = if (running) Cfx.text else Cfx.text2, fontSize = 14.sp)
            }
            Spacer(Modifier.height(14.dp))
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                StatCell("FLOWS", s?.flows, Modifier.weight(1f))
                StatCell("TLS", s?.tlsFlows, Modifier.weight(1f))
                StatCell("SHAPES", s?.events, Modifier.weight(1f), accent = (s?.events ?: 0) > 0)
                StatCell("SENT", s?.ingestSent, Modifier.weight(1f), accent = (s?.ingestSent ?: 0) > 0)
            }
            if (s != null && !s.lastEvent.isNullOrBlank()) {
                Spacer(Modifier.height(12.dp))
                Text("last: ${s.lastEvent}", fontFamily = Cfx.mono, fontSize = 11.sp, color = Cfx.text2, maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
            if (diag != null) {
                Spacer(Modifier.height(12.dp))
                DiagBanner(diag)
            }
        }
    }

    @Composable
    private fun StatCell(label: String, value: Long?, modifier: Modifier = Modifier, accent: Boolean = false) {
        Column(
            modifier
                .clip(RoundedCornerShape(10.dp))
                .background(Cfx.surfaceRaised)
                .padding(vertical = 12.dp, horizontal = 6.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Text(value?.toString() ?: "—", fontFamily = Cfx.mono, fontWeight = FontWeight.Bold, fontSize = 20.sp, color = if (accent) Cfx.ember else Cfx.text)
            Spacer(Modifier.height(2.dp))
            Text(label, fontFamily = Cfx.mono, fontSize = 10.sp, letterSpacing = 1.sp, color = Cfx.text3)
        }
    }

    @Composable
    private fun DiagBanner(d: Diag) {
        val (bg, line, fg) = when (d.level) {
            Level.SUCCESS -> Triple(Cfx.successTint, Cfx.success, Cfx.successLight)
            Level.WARN -> Triple(Cfx.warningTint, Cfx.warning, Cfx.warningLight)
            Level.INFO -> Triple(Cfx.emberTint, Cfx.emberLine, Cfx.emberLight)
        }
        Column(
            Modifier.fillMaxWidth().clip(RoundedCornerShape(10.dp)).background(bg).border(1.dp, line, RoundedCornerShape(10.dp)).padding(12.dp)
        ) {
            Text(d.title, color = fg, fontWeight = FontWeight.SemiBold, fontSize = 13.sp)
            if (d.body.isNotEmpty()) {
                Spacer(Modifier.height(4.dp))
                Text(d.body, color = Cfx.text2, fontSize = 12.sp)
            }
        }
    }

    @Composable
    private fun CaHelp() {
        Column(Modifier.padding(top = 8.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            val steps = listOf(
                "Unrooted Android installs the CA as a USER cert. Since Android 7, most apps (including Chrome) IGNORE user CAs, so their HTTPS can't be captured.",
                "Best test app: Firefox for Android. Open Firefox, go to about:config, search enterprise, set security.enterprise_roots.enabled = true.",
                "Firefox now trusts the Android user CA store. Browse an HTTPS site in Firefox and shapes will appear here.",
                "Whole-device capture across every app (incl. Chrome) needs a system CA, which requires root."
            )
            steps.forEachIndexed { i, t ->
                Row {
                    Text("${i + 1}.", fontFamily = Cfx.mono, color = Cfx.ember, fontSize = 12.sp, modifier = Modifier.width(20.dp))
                    Text(t, color = Cfx.text2, fontSize = 12.sp)
                }
            }
        }
    }

    @OptIn(ExperimentalMaterial3Api::class)
    @Composable
    private fun AppPickerSheet(apps: List<Pair<String, String>>, selected: MutableList<String>, onDismiss: () -> Unit) {
        val sheet = rememberModalBottomSheetState(skipPartiallyExpanded = true)
        var query by remember { mutableStateOf("") }
        val filtered = remember(query) {
            if (query.isBlank()) apps else apps.filter { it.second.contains(query, true) || it.first.contains(query, true) }
        }
        ModalBottomSheet(onDismissRequest = onDismiss, sheetState = sheet, containerColor = Cfx.surfaceRaised, dragHandle = { BottomSheetDefaults.DragHandle() }) {
            Column(Modifier.fillMaxWidth().padding(horizontal = 16.dp).padding(bottom = 8.dp)) {
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
                    Text("Scope apps", style = MaterialTheme.typography.titleMedium, color = Cfx.text)
                    TextButton(onClick = { scopeMode = TracerVpnService.MODE_ALL; selected.clear(); onDismiss() }) {
                        Text("Whole device", color = Cfx.ember, fontSize = 13.sp)
                    }
                }
                Spacer(Modifier.height(8.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    ChoiceChip("Only these", scopeMode == TracerVpnService.MODE_ONLY, true) { scopeMode = TracerVpnService.MODE_ONLY }
                    ChoiceChip("All except these", scopeMode == TracerVpnService.MODE_EXCEPT, true) { scopeMode = TracerVpnService.MODE_EXCEPT }
                }
                Text(
                    if (scopeMode == TracerVpnService.MODE_EXCEPT) "Selected apps bypass the tracer (keep pinned apps here)."
                    else "Capture only the selected apps.",
                    style = MaterialTheme.typography.bodySmall, color = Cfx.text3, modifier = Modifier.padding(top = 6.dp)
                )
                OutlinedTextField(
                    value = query, onValueChange = { query = it },
                    placeholder = { Text("Search apps", color = Cfx.text3) },
                    singleLine = true,
                    keyboardOptions = KeyboardOptions(imeAction = ImeAction.Search),
                    modifier = Modifier.fillMaxWidth().padding(vertical = 8.dp),
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedBorderColor = Cfx.emberLine, unfocusedBorderColor = Cfx.line,
                        focusedTextColor = Cfx.text, unfocusedTextColor = Cfx.text1,
                        cursorColor = Cfx.ember, focusedContainerColor = Cfx.surfaceInput, unfocusedContainerColor = Cfx.surfaceInput
                    )
                )
                LazyColumn(Modifier.fillMaxWidth().heightIn(max = 420.dp)) {
                    items(filtered, key = { it.first }) { (pkg, label) ->
                        val checked = selected.contains(pkg)
                        Row(
                            Modifier.fillMaxWidth().clip(RoundedCornerShape(8.dp))
                                .background(if (checked) Cfx.emberTint else Color.Transparent)
                                .padding(vertical = 4.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Checkbox(
                                checked = checked,
                                onCheckedChange = {
                                    if (it) {
                                        selected.add(pkg)
                                        if (scopeMode == TracerVpnService.MODE_ALL) scopeMode = TracerVpnService.MODE_ONLY
                                    } else selected.remove(pkg)
                                },
                                colors = CheckboxDefaults.colors(checkedColor = Cfx.ember, uncheckedColor = Cfx.text3, checkmarkColor = Color.Black)
                            )
                            Column(Modifier.weight(1f)) {
                                Text(label, color = Cfx.text1, fontSize = 14.sp, maxLines = 1, overflow = TextOverflow.Ellipsis)
                                Text(pkg, color = Cfx.text3, fontFamily = Cfx.mono, fontSize = 10.sp, maxLines = 1, overflow = TextOverflow.Ellipsis)
                            }
                            // Patch a pinned app on the server so it trusts the CA (unroot bypass).
                            TextButton(onClick = { patchApp(pkg) }, enabled = !patching) {
                                Text("Patch", color = Cfx.emberLight, fontSize = 12.sp)
                            }
                        }
                    }
                }
                Spacer(Modifier.height(8.dp))
                PrimaryButton("Done", fill = true) { onDismiss() }
                Spacer(Modifier.height(12.dp))
            }
        }
    }

    // ── small reusable pieces ──────────────────────────────────────────────────

    @Composable
    private fun SectionCard(title: String, step: String, content: @Composable ColumnScope.() -> Unit) {
        Column(
            Modifier.fillMaxWidth().clip(RoundedCornerShape(14.dp)).background(Cfx.surface).border(1.dp, Cfx.line, RoundedCornerShape(14.dp)).padding(16.dp)
        ) {
            Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.padding(bottom = 12.dp)) {
                Box(Modifier.size(20.dp).clip(RoundedCornerShape(6.dp)).background(Cfx.emberTint).border(1.dp, Cfx.emberLine, RoundedCornerShape(6.dp)), contentAlignment = Alignment.Center) {
                    Text(step, fontFamily = Cfx.mono, fontSize = 11.sp, color = Cfx.ember, fontWeight = FontWeight.Bold)
                }
                Spacer(Modifier.width(10.dp))
                Text(title, fontFamily = Cfx.mono, fontSize = 12.sp, letterSpacing = 1.5.sp, color = Cfx.text2, fontWeight = FontWeight.SemiBold)
            }
            content()
        }
    }

    @Composable
    private fun PrimaryButton(text: String, enabled: Boolean = true, fill: Boolean, danger: Boolean = false, onClick: () -> Unit) {
        Button(
            onClick = onClick, enabled = enabled,
            modifier = if (fill) Modifier.fillMaxWidth().height(52.dp) else Modifier.height(46.dp),
            shape = RoundedCornerShape(10.dp),
            colors = ButtonDefaults.buttonColors(
                containerColor = if (danger) Cfx.danger else Cfx.ember,
                contentColor = if (danger) Color.White else Color(0xFF14100E),
                disabledContainerColor = Cfx.surfaceRaised, disabledContentColor = Cfx.text3
            )
        ) { Text(text, fontWeight = FontWeight.SemiBold, letterSpacing = 0.5.sp) }
    }

    @Composable
    private fun OutlinedAccentButton(text: String, onClick: () -> Unit) {
        OutlinedButton(
            onClick = onClick, shape = RoundedCornerShape(10.dp),
            border = androidx.compose.foundation.BorderStroke(1.dp, Cfx.emberLine),
            colors = ButtonDefaults.outlinedButtonColors(contentColor = Cfx.emberLight)
        ) { Text(text, fontWeight = FontWeight.Medium) }
    }

    @Composable
    private fun ChoiceChip(text: String, selected: Boolean, enabled: Boolean, onClick: () -> Unit) {
        val border = if (selected) Cfx.emberLine else Cfx.line
        val bg = if (selected) Cfx.emberTint else Color.Transparent
        val fg = when { !enabled -> Cfx.text3; selected -> Cfx.emberLight; else -> Cfx.text2 }
        Box(
            Modifier.clip(RoundedCornerShape(20.dp)).background(bg).border(1.dp, border, RoundedCornerShape(20.dp))
                .then(if (enabled) Modifier.clickableNoRipple(onClick) else Modifier)
                .padding(horizontal = 14.dp, vertical = 8.dp)
        ) { Text(text, color = fg, fontSize = 13.sp, fontWeight = if (selected) FontWeight.SemiBold else FontWeight.Normal) }
    }

    @Composable
    private fun StatusPill(text: String, color: Color) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Box(Modifier.size(7.dp).clip(CircleShape).background(color))
            Spacer(Modifier.width(6.dp))
            Text(text, color = Cfx.text2, fontSize = 13.sp, fontFamily = Cfx.mono)
        }
    }
}

// ── plumbing outside the Activity ──────────────────────────────────────────────

private fun Modifier.clickableNoRipple(onClick: () -> Unit): Modifier =
    this.clickable(onClick = onClick)

private enum class Level { SUCCESS, WARN, INFO }
private data class Diag(val level: Level, val title: String, val body: String)

private data class Stats(
    val flows: Long, val tlsFlows: Long, val caRejected: Long, val flowErrors: Long,
    val events: Long, val ingestSent: Long, val ingestRejected: Long, val ingestFailed: Long,
    val lastEvent: String, val lastError: String
) {
    companion object {
        fun parse(json: String): Stats {
            val o = JSONObject(json)
            return Stats(
                o.optLong("flows"), o.optLong("tls_flows"), o.optLong("ca_rejected"), o.optLong("flow_errors"),
                o.optLong("events"), o.optLong("ingest_sent"), o.optLong("ingest_rejected"), o.optLong("ingest_failed"),
                o.optString("last_event"), o.optString("last_error")
            )
        }
    }
}

/** Turn the raw counters into one actionable message: the whole point of the panel. */
private fun diagnose(running: Boolean, s: Stats?): Diag? {
    if (!running || s == null) return null
    if (s.events > 0 && s.ingestSent > 0)
        return Diag(Level.SUCCESS, "Capturing and shipping shapes.", "Open the workflow in the web app to see the asset graph fill in.")
    if (s.events > 0 && s.ingestRejected > 0)
        return Diag(Level.WARN, "Server rejected the shapes.", "Likely a stale token: re-pair the QR (regenerating it rotates the token).")
    if (s.events > 0 && s.ingestFailed > 0)
        return Diag(Level.WARN, "Captured shapes but can't reach the server.", "Check the Ingest URL (base only, no path) and that the tunnel is up.")
    if (s.caRejected > 0 && s.events == 0L)
        return Diag(Level.WARN, "Apps are refusing the certificate.", "They don't trust the user CA. Chrome ignores it. Use Firefox (see trust steps) or an app that trusts user certs.")
    if (s.flows > 0 && s.events == 0L)
        return Diag(Level.INFO, "Seeing traffic, no shapes yet.", "Browse an HTTPS site in an app that trusts the CA (Firefox), or wait for a request.")
    return Diag(Level.INFO, "No traffic captured yet.", "Make sure the app you're testing is in scope, then generate some requests.")
}
