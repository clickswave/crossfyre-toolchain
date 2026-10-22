package io.crossfyre.mobile.ui

import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.PathEffect
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import io.crossfyre.mobile.AppModel
import io.crossfyre.mobile.BuildConfig
import io.crossfyre.mobile.Level
import io.crossfyre.mobile.Overlay
import io.crossfyre.mobile.Phase
import io.crossfyre.mobile.Push
import io.crossfyre.mobile.R
import io.crossfyre.mobile.RecentRequest
import io.crossfyre.mobile.Scope
import io.crossfyre.mobile.ago
import io.crossfyre.mobile.capLine
import io.crossfyre.mobile.fingerprintLines
import io.crossfyre.mobile.fmt
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/** The scrolling column every section draws into: `.content`. */
@Composable
fun Content(key: Any, content: @Composable ColumnScope.() -> Unit) {
    val scroll = remember(key) { androidx.compose.foundation.ScrollState(0) }
    Column(
        Modifier.fillMaxSize().verticalScroll(scroll).padding(start = 16.dp, end = 16.dp, top = 16.dp, bottom = 28.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
        content = content,
    )
}

@Composable
fun EnvChip(m: AppModel) {
    when (m.env) {
        "dev" -> Chip("Dev", Tone.WARN, modifier = Modifier.padding(end = 4.dp))
        "staging" -> Chip("Staging", Tone.INFO, modifier = Modifier.padding(end = 4.dp))
    }
}

// ── Capture card ─────────────────────────────────────────────────────────────

@Composable
fun StateChip(phase: Phase) {
    when (phase) {
        Phase.CAPTURING -> Chip("Capturing", Tone.OK, big = true, dot = true)
        Phase.STARTING -> Chip("Starting", Tone.WARN, big = true, dot = true)
        Phase.IDLE -> Chip("Idle", Tone.NONE, big = true, dot = true)
    }
}

@Composable
fun CaptureCard(m: AppModel, tracer: Boolean) {
    val c = cfx
    val phase = m.phase
    val lineStyle = TextStyle(fontFamily = CfxFonts.ui, fontSize = 14.5.sp, lineHeight = 21.sp, color = c.text1)

    // Two idle states where Start cannot work, and the card says why in place of
    // offering a button that would fail.
    if (phase == Phase.IDLE && m.revoked) {
        CfxCard {
            Row { StateChip(phase) }
            Text("Signed out. This phone's key was revoked in the dashboard, so it can't renew its session to start a capture.", style = lineStyle)
            CfxButton("Sign in again", Kind.PRIMARY, block = true) { m.toSignIn() }
        }
        return
    }
    if (phase == Phase.IDLE && m.qrEnded && !m.fromAccount) {
        CfxCard {
            Row { StateChip(phase) }
            Text("The session ended when capture stopped.", style = lineStyle)
            // Signed in already, the way out is one of the account's own workspaces,
            // which renew themselves; "Sign in" would mean signing out first.
            if (m.signedIn) {
                Banner(Level.INFO, "Scan a new code to capture again.", "A pairing code lasts for one capture. Make a new pairing QR for the session in the dashboard, or pair with one of your workspaces so this phone renews its own session.")
                CfxButton("Scan a new code", Kind.PRIMARY, block = true, icon = R.drawable.ic_qr_code) { m.scan() }
                CfxButton("Pick a workspace instead", Kind.TEXT, block = true) { m.openWorkspaces(back = true) }
            } else {
                Banner(Level.INFO, "Scan a new code to capture again.", "A pairing code lasts for one capture. Make a new pairing QR for the session in the dashboard, or sign in so this phone renews its own session.")
                CfxButton("Scan a new code", Kind.PRIMARY, block = true, icon = R.drawable.ic_qr_code) { m.scan() }
                CfxButton("Sign in instead", Kind.TEXT, block = true) { m.toSignIn() }
            }
        }
        return
    }

    CfxCard(live = phase == Phase.CAPTURING) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            StateChip(phase)
            Box(Modifier.weight(1f))
            if (phase == Phase.CAPTURING && m.since > 0) {
                Text("since " + SimpleDateFormat("HH:mm", Locale.getDefault()).format(Date(m.since)),
                    style = TextStyle(fontFamily = CfxFonts.mono, fontSize = 12.5.sp, color = c.text3))
            }
        }
        Text(capLine(phase, m.scope, m.stats, m.destination), style = lineStyle)
        if (tracer && phase != Phase.IDLE) Counters(m)
        if (m.startFailed && phase == Phase.IDLE) {
            Banner(
                Level.WARN, "Capture did not start.",
                m.failMessage ?: "Android did not bring the tunnel up. Try again. If it keeps happening, another VPN app may be holding the connection: check Settings › Network & internet › VPN.",
                listOf("Try again" to { m.onStartTapped() }),
            )
        }
        m.startError?.let { if (phase == Phase.IDLE) Banner(it) }
        val d = m.diagnosis()
        if (d != null && (tracer || d.level != Level.OK)) {
            Banner(d.level, d.title, d.body, d.action?.let { a -> listOf(a.label to { m.diagAction(a) }) } ?: emptyList())
        }
        if (phase == Phase.CAPTURING && m.notificationsBlocked) {
            Banner(
                Level.WARN, "The capture notification is off.",
                "Notifications are off for Crossfyre Mobile, so nothing in the shade says a capture is running or offers to stop it. Capture is running.",
                listOf("Turn notifications on" to { m.notificationSettings() }),
            )
        }
        if (phase == Phase.CAPTURING && m.fullCapture) {
            Banner(Level.DANGER, "Full requests are on.", "Headers and bodies, credentials included, are being sent to ${m.destination}.")
        }
        when {
            phase == Phase.STARTING || m.renewing ->
                CfxButton("Starting…", Kind.SECONDARY, block = true, busy = true, enabled = false) {}
            phase == Phase.CAPTURING ->
                CfxButton("Stop capture", Kind.DANGER, block = true, icon = R.drawable.ic_stop) { m.stopCapture() }
            else ->
                CfxButton("Start capture", Kind.PRIMARY, block = true, icon = R.drawable.ic_play) { m.onStartTapped() }
        }
    }
}

@Composable
private fun Counters(m: AppModel) {
    val c = cfx
    val s = m.stats
    val starting = m.phase == Phase.STARTING
    val cells = listOf(
        Triple("Flows", s?.flows ?: 0, false),
        Triple("TLS", s?.tlsFlows ?: 0, false),
        Triple("Requests", s?.events ?: 0, (s?.events ?: 0) > 0),
        Triple("Sent", s?.ingestSent ?: 0, (s?.ingestSent ?: 0) > 0),
    )
    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
        for ((label, n, accent) in cells) {
            Column(
                Modifier.weight(1f).background(c.surface2).border(1.dp, c.lineSubtle).padding(start = 4.dp, end = 4.dp, top = 10.dp, bottom = 9.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                // A plain hyphen while starting: no number yet is not the same as zero.
                Text(if (starting) "-" else fmt(n), maxLines = 1,
                    style = TextStyle(fontFamily = CfxFonts.mono, fontWeight = FontWeight.Bold, fontSize = 20.sp, lineHeight = 23.sp, color = if (accent) c.ember else c.text))
                Text(label.uppercase(), maxLines = 1, modifier = Modifier.padding(top = 3.dp),
                    style = TextStyle(fontFamily = CfxFonts.ui, fontWeight = FontWeight.Bold, fontSize = 10.sp, lineHeight = 12.sp, letterSpacing = 0.6.sp, color = c.text3))
            }
        }
    }
}

// ── Home ─────────────────────────────────────────────────────────────────────

@Composable
fun HomeContent(m: AppModel) {
    val c = cfx
    CaptureCard(m, tracer = false)

    val ws = m.workspace
    if (m.pairing != null && !m.fromAccount) {
        // The QR carries a workflow id and a token, not a workspace name, so this
        // is all the phone can say about where its traffic goes.
        CfxCard {
            Eyebrow("Workspace")
            AppHead(R.drawable.ic_qr_code, "Web Tracer session", "Paired with a QR code" + if (m.qrEnded) " · ended" else "", strong = false)
            Facts(listOf("Server" to m.pairingHost), compact = true, mono = setOf("Server"))
            if (!m.qrEnded) Row { CfxButton("Scan another code", Kind.SECONDARY, small = true) { m.scan() } }
        }
    } else if (ws != null) {
        CfxCard {
            Eyebrow("Workspace")
            AppHead(
                if (ws.kind == "team") R.drawable.ic_buildings else R.drawable.ic_user,
                ws.name, if (ws.kind == "team") "${ws.org.ifEmpty { "Organization" }} · organization" else "Personal",
            )
            Facts(listOf("Session" to m.sessionName, "Server" to m.pairingHost), compact = true, mono = setOf("Server"))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
                CfxButton("Switch workspace", Kind.SECONDARY, small = true) { m.openWorkspaces(back = true) }
                CfxButton("Dashboard", Kind.TEXT, small = true, icon = R.drawable.ic_arrow_square_out, iconSize = 16.dp) { m.openDashboard() }
            }
        }
    }

    val u = m.user
    if (u != null) {
        CfxList {
            CfxRow(
                title = u.username.ifEmpty { u.email }, first = true, sub = u.email.takeIf { u.username.isNotEmpty() },
                leading = { Avatar(initialsOf(u.username.ifEmpty { u.email })) }, chevron = R.drawable.ic_caret_right,
                onClick = { m.goTab("settings") },
            )
        }
    } else {
        CfxCard(tight = true) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                Avatar(null)
                Text("Not signed in", style = TextStyle(fontFamily = CfxFonts.ui, fontWeight = FontWeight.SemiBold, fontSize = 14.sp, color = c.text))
            }
            Text("Sign in to pick a workspace from a list instead of scanning a code each time.", style = T.hint())
            Row { CfxButton("Sign in", Kind.SECONDARY, small = true) { m.toSignIn() } }
        }
    }

    CfxList {
        if (m.patch.available) {
            val stale = m.staleCount.size
            val current = (m.patchedCount - stale).coerceAtLeast(0)
            val sub = (if (current > 0) "$current patched" else "Nothing patched yet") + if (stale > 0) " · $stale to patch again" else ""
            CfxRow("Patch a pinned app", first = true, icon = R.drawable.ic_package, sub = sub, chevron = R.drawable.ic_caret_right, onClick = { m.goTab("patch") })
        }
        CfxRow("Node", first = !m.patch.available, icon = R.drawable.ic_hard_drives, sub = "Not available yet", chevron = R.drawable.ic_lock_simple, onClick = { m.goTab("node") })
    }
}

@Composable
fun AppHead(icon: Int, title: String, sub: String, strong: Boolean = true) {
    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(14.dp)) {
        Ic(icon, 26.dp, cfx.text3)
        Column {
            Text(title, style = T.rowTitle().copy(fontWeight = if (strong) FontWeight.SemiBold else FontWeight.Medium))
            Text(sub, style = T.rowSub())
        }
    }
}

// ── Tracer ───────────────────────────────────────────────────────────────────

@Composable
fun TracerContent(m: AppModel) {
    val c = cfx
    CaptureCard(m, tracer = true)
    val locked = m.phase != Phase.IDLE
    val scope = m.scope
    GroupLabel("Set up")
    CfxList {
        CfxRow(
            title = "Scope · ${scope.title()}", first = true, icon = R.drawable.ic_device_mobile,
            sub = if (scope.effectiveMode == Scope.ALL) scope.sub { m.labelOf(it) } else null,
            subContent = if (scope.effectiveMode == Scope.ALL) null else ({
                Box(Modifier.padding(top = 4.dp)) { Wrap { for (p in m.scopeApps) AppChip(m.labelOf(p)) } }
            }),
            note = if (locked) "Stop capture to change the scope." else null,
            chevron = if (locked) R.drawable.ic_lock_simple else R.drawable.ic_caret_right,
            onClick = { m.openScope() },
        )
        CfxRow(
            title = "Send full requests", icon = R.drawable.ic_cloud_arrow_up,
            sub = if (m.fullCapture) "On: headers and bodies go too, credentials included, when the session in the dashboard asks for them."
            else "Off: only the shape of each request leaves the phone. Values, headers and bodies stay here.",
            note = if (locked) "Stop capture to change this." else null,
            trailing = { CfxSwitch(m.fullCapture, enabled = !locked, label = "Send full requests") { m.toggleFull() } },
        )
        val stale = m.staleCount.size
        CfxRow(
            title = "Certificate", icon = R.drawable.ic_certificate,
            sub = if (m.cert.exists) "Made on this phone · " + if (m.cert.inAndroid) "installed in Android" else "not installed in Android" else "Not made yet",
            note = if (m.patch.available && stale > 0) "$stale patched ${if (stale == 1) "app trusts" else "apps trust"} an older one" else null,
            noteTone = Tone.WARN,
            chevron = R.drawable.ic_caret_right,
            onClick = { m.push = Push.Certificate },
        )
    }

    val reqs = m.recent
    val capturing = m.phase == Phase.CAPTURING
    Row(Modifier.fillMaxWidth().padding(start = 2.dp, end = 2.dp, top = 6.dp).tuck(bottom = 6.dp), verticalAlignment = Alignment.CenterVertically) {
        Eyebrow(if (reqs.isNotEmpty() && !capturing) "From the last capture" else "Recent requests", Modifier.weight(1f))
        if (reqs.isNotEmpty()) CfxButton("Dashboard", Kind.TEXT, small = true, icon = R.drawable.ic_arrow_square_out, iconSize = 14.dp) { m.openDashboard() }
    }
    if (reqs.isEmpty()) {
        Empty(
            R.drawable.ic_broadcast, "No requests yet",
            if (capturing) "Use an app in scope. Its requests show up here as they are sent."
            else "Start capture, then use an app in scope. Requests show up here as they are sent.",
        )
    } else {
        var now by remember { mutableLongStateOf(System.currentTimeMillis()) }
        LaunchedEffect(Unit) {
            while (true) {
                now = System.currentTimeMillis()
                kotlinx.coroutines.delay(1000)
            }
        }
        CfxList {
            reqs.take(14).forEachIndexed { i, r -> ReqRow(r, i == 0, now) { m.overlay = Overlay.Request(r.key) } }
        }
        Text(
            "Kept on this phone until the next capture starts. " +
                if (m.fullCapture) "Headers and bodies are in the dashboard." else "With full requests off, only the shape of each request was sent. Tap one to see exactly what.",
            style = T.hint(),
        )
    }
    Authz()
}

@Composable
fun statusColor(status: Int?): androidx.compose.ui.graphics.Color = when (status?.div(100)) {
    2 -> cfx.success
    3 -> cfx.info
    4 -> cfx.warning
    5 -> cfx.danger
    else -> cfx.text3
}

@Composable
private fun ReqRow(r: RecentRequest, first: Boolean, now: Long, onClick: () -> Unit) {
    val c = cfx
    Row(
        Modifier.fillMaxWidth().topLine(c.lineSubtle, !first).tap(onClick = onClick).padding(horizontal = 14.dp, vertical = 10.dp),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Text(r.method, modifier = Modifier.width(52.dp), maxLines = 1,
            style = TextStyle(fontFamily = CfxFonts.mono, fontWeight = FontWeight.Bold, fontSize = 11.sp, lineHeight = 18.sp, color = c.text3))
        Column(Modifier.weight(1f)) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                val url = buildAnnotatedString {
                    withStyle(SpanStyle(color = c.text3)) { append(r.host) }
                    append(r.path)
                }
                Text(url, maxLines = 1, overflow = TextOverflow.Ellipsis, modifier = Modifier.weight(1f),
                    style = TextStyle(fontFamily = CfxFonts.mono, fontSize = 12.5.sp, lineHeight = 18.sp, color = c.text))
                Text(r.status?.toString() ?: "-", style = TextStyle(fontFamily = CfxFonts.mono, fontWeight = FontWeight.Bold, fontSize = 12.sp, lineHeight = 18.sp, color = statusColor(r.status)))
            }
            Text(ago(((now - r.atMs) / 1000).coerceAtLeast(0)), style = TextStyle(fontFamily = CfxFonts.ui, fontSize = 12.sp, lineHeight = 16.sp, color = c.text3))
        }
    }
}

// ── Certificate ──────────────────────────────────────────────────────────────

@Composable
fun CertificateContent(m: AppModel) {
    val direct = m.patch.available
    val stale = if (direct) m.staleCount else emptyList()
    if (stale.isNotEmpty()) {
        val names = stale.map { m.labelOf(it) }
        Banner(
            Level.WARN,
            "${stale.size} patched ${if (stale.size == 1) "app trusts" else "apps trust"} an older certificate.",
            "${names.joinToString(", ")} will not decrypt until you patch ${if (stale.size == 1) "it" else "them"} again.",
            listOf("Go to Patch" to { m.goTab("patch") }),
        )
    }
    val cert = m.cert
    if (cert.exists) {
        CfxCard {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(14.dp)) {
                Ic(R.drawable.ic_certificate, 30.dp, cfx.text3)
                Column {
                    Text("Crossfyre Mobile certificate", style = T.rowTitle().copy(fontWeight = FontWeight.SemiBold))
                    Text("Made on this phone on " + SimpleDateFormat("d MMM yyyy", Locale.UK).format(Date(cert.madeAt)), style = T.rowSub())
                }
            }
            Facts(
                listOf(
                    "SHA-256" to fingerprintLines(cert.fingerprint.orEmpty()).joinToString("\n"),
                    "Private key" to "Stays on this phone",
                    "In Android" to if (cert.inAndroid) "Installed as a user certificate" else "Not installed",
                ),
                mono = setOf("SHA-256"),
            )
        }
    } else {
        Empty(R.drawable.ic_certificate, "No certificate yet", "One is made the first time you capture${if (direct) " or patch an app" else ""}. It stays on this phone.")
    }
    Text(
        "Capture decrypts HTTPS with this certificate. " + if (direct) "Patching an app builds it into that app, so most testing needs nothing installed in Android."
        else "Apps only accept it if they trust user certificates. Most apps made for Android 7 or later do not, apart from browsers set up to and debug builds of your own apps.",
        style = T.body(),
    )
    CfxCard {
        Eyebrow("Install it in Android")
        Text(
            if (direct) "Only for apps you can't patch, and only if they trust user certificates." else "For apps that trust user certificates, such as Firefox once it is set up below.",
            style = T.body(),
        )
        HowTo(
            listOf(
                "Save the certificate file.",
                "In Android settings, search for **CA certificate**, open it, and pick the file. Searching is quicker than the menus, which differ from phone to phone.",
                "Android asks for your screen lock, then warns that the network may be monitored. The warning stays for as long as the certificate is installed.",
            )
        )
        Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
            CfxButton("Save certificate file", Kind.PRIMARY, block = true, icon = R.drawable.ic_download_simple) { m.saveCertificate() }
            CfxButton("Open Android security settings", Kind.SECONDARY, block = true) { m.securitySettings() }
        }
    }
    CfxCard {
        Toggle("Chrome won't use it. Firefox will.", m.chromeHelp) { m.chromeHelp = !m.chromeHelp }
        if (m.chromeHelp) {
            HowTo(
                listOf(
                    "Android installs it as a user certificate. Since Android 7 most apps ignore those, Chrome included, so their HTTPS stays unread.",
                    "Firefox can be told to trust them. Open `about:config`, search for `enterprise`, and set `security.enterprise_roots.enabled` to true.",
                    "Browse an HTTPS site in Firefox. Its requests show up in the Tracer.",
                    "Every app trusting it, Chrome included, needs it installed as a system certificate, and that needs root.",
                )
            )
        }
    }
    CfxCard {
        Eyebrow("Reset")
        Text("Makes a new certificate the next time you capture. Do this if you think the private key may have been exposed.", style = T.body())
        Row {
            CfxButton("Reset certificate", Kind.DANGER_TEXT, icon = R.drawable.ic_arrow_counter_clockwise, enabled = cert.exists) { m.overlay = Overlay.ResetCert }
        }
    }
}

// ── Node ─────────────────────────────────────────────────────────────────────

@Composable
fun NodeContent() {
    val c = cfx
    Column(
        Modifier.fillMaxWidth().padding(start = 18.dp, end = 18.dp, top = 56.dp, bottom = 24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Box {
            Box(
                Modifier.size(76.dp).background(c.surface2).drawBehind {
                    drawRect(c.lineStrong, style = Stroke(1.dp.toPx(), pathEffect = PathEffect.dashPathEffect(floatArrayOf(6f, 6f))))
                },
                contentAlignment = Alignment.Center,
            ) { Ic(R.drawable.ic_hard_drives, 36.dp, c.text4) }
            Box(
                Modifier.align(Alignment.BottomEnd).offset(x = 11.dp, y = 11.dp).size(30.dp).clip(CircleShape)
                    .background(c.surfaceRaised).border(1.dp, c.lineStrong, CircleShape),
                contentAlignment = Alignment.Center,
            ) { Ic(R.drawable.ic_lock_simple, 15.dp, c.text3) }
        }
        Text("Node", style = TextStyle(fontFamily = CfxFonts.head, fontWeight = FontWeight.SemiBold, fontSize = 20.sp, lineHeight = 26.sp, color = c.text2))
        Chip("Not available yet")
        Text(
            "This phone will be able to work as a node for your workspace, so the requests your scans send leave from the phone's own connection. It is not built yet, so there is nothing to set up here.",
            textAlign = TextAlign.Center, modifier = Modifier.widthIn(max = 300.dp),
            style = TextStyle(fontFamily = CfxFonts.ui, fontSize = 15.sp, lineHeight = 23.sp, color = c.text3),
        )
    }
}

// ── Settings ─────────────────────────────────────────────────────────────────

@Composable
fun SettingsContent(m: AppModel) {
    val c = cfx
    GroupLabel("Account")
    val u = m.user
    if (u != null) {
        CfxList {
            CfxRow(u.username.ifEmpty { u.email }, first = true, sub = u.email.takeIf { u.username.isNotEmpty() }, leading = { Avatar(initialsOf(u.username.ifEmpty { u.email })) })
            CfxRow("Signed in with", value = if (m.signedInWith == "browser") "Browser" else "Password")
            CfxRow("Sign out", icon = R.drawable.ic_sign_out, sub = "Revokes this phone's key", danger = true, onClick = { m.overlay = Overlay.SignOut })
            DeleteAccountRow(m)
        }
    } else {
        CfxList {
            CfxRow(
                "Not signed in", first = true, sub = if (m.pairing != null) "Paired with a QR code" else null, leading = { Avatar(null) },
                trailing = { CfxButton("Sign in", Kind.SECONDARY, small = true) { m.toSignIn() } },
            )
            DeleteAccountRow(m)
        }
    }

    GroupLabel("Workspace")
    CfxList {
        val ws = m.workspace
        var first = true
        if (ws != null && m.fromAccount) {
            CfxRow(
                ws.name, first = true, icon = if (ws.kind == "team") R.drawable.ic_buildings else R.drawable.ic_user,
                sub = if (ws.kind == "team") "${ws.org.ifEmpty { "Organization" }} · organization" else "Personal",
                value = "Switch", chevron = R.drawable.ic_caret_right, onClick = { m.openWorkspaces(back = true) },
            )
            first = false
        } else if (m.pairing != null) {
            CfxRow("Web Tracer session", first = true, icon = R.drawable.ic_qr_code, sub = "Paired with a QR code")
            first = false
        }
        CfxRow("Pair with a QR code", first = first, icon = R.drawable.ic_qr_code, sub = "For a session someone set up in the dashboard", chevron = R.drawable.ic_caret_right, onClick = { m.scan() })
        if (m.pairing != null) {
            CfxRow("Unpair this phone", icon = R.drawable.ic_link_break, sub = "Stops capture. The certificate and patched apps stay.", onClick = { m.overlay = Overlay.Unpair })
        }
    }

    GroupLabel("App")
    CfxList {
        Column(Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 10.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Text("Appearance", style = T.rowTitle())
            Seg(listOf("phone" to "Match phone", "dark" to "Dark", "light" to "Light"), m.appearance) { m.setAppearanceKey(it) }
        }
        val n = m.notificationState
        CfxRow(
            "Capture notification", icon = if (n == "On") R.drawable.ic_bell else R.drawable.ic_bell_slash,
            sub = "Shows while capturing, with a Stop button", value = n,
            valueTone = when (n) { "On" -> Tone.OK; "Off" -> Tone.WARN; else -> Tone.NONE },
            onClick = { m.notificationSettings() },
        )
        CfxRow("What capture does to this phone", icon = R.drawable.ic_book_open, chevron = R.drawable.ic_caret_right, onClick = { m.overlay = Overlay.HowTo })
    }

    GroupLabel("Environment")
    CfxList {
        // Read-only even on the dev build: the account key belongs to the server
        // it was issued by, so the server changes on the sign-in screen or not at all.
        CfxRow(
            "Server", first = true, sub = if (m.env == "dev") m.origin else "https://${m.host}", subMono = true,
            note = if (m.env == "dev") "To use another server, sign out and change it on the sign-in screen." else null,
            trailing = {
                when (m.env) {
                    "dev" -> Chip("Dev", Tone.WARN)
                    "staging" -> Chip("Staging", Tone.INFO)
                    else -> Chip("Production")
                }
            },
        )
        CfxRow("Build", sub = if (m.patch.available) "Direct download from crossfyre.io" else "Google Play")
    }
    Text("Production, staging and dev are separate apps, each with its own certificate, so they can be installed side by side.", style = T.hint())

    GroupLabel("About")
    CfxList {
        CfxRow(
            "Crossfyre Mobile", first = true,
            sub = "Version ${BuildConfig.VERSION_NAME} (${BuildConfig.VERSION_CODE}) · ${BuildConfig.APPLICATION_ID}",
            leading = { Image(painterResource(R.drawable.cfx_mark), contentDescription = null, modifier = Modifier.size(28.dp)) },
        )
        CfxRow("Source code", icon = R.drawable.ic_code, sub = "github.com/clickswave/crossfyre-toolchain", subMono = true, chevron = R.drawable.ic_arrow_square_out,
            onClick = { m.openUrl("https://github.com/clickswave/crossfyre-toolchain") })
        CfxRow("Privacy policy", icon = R.drawable.ic_file_text, chevron = R.drawable.ic_arrow_square_out, onClick = { m.openUrl("https://crossfyre.io/privacy") })
        CfxRow("Terms of service", icon = R.drawable.ic_file_text, chevron = R.drawable.ic_arrow_square_out, onClick = { m.openUrl("https://crossfyre.io/terms") })
        CfxRow("Acceptable use", icon = R.drawable.ic_shield_check, chevron = R.drawable.ic_arrow_square_out, onClick = { m.openUrl("https://crossfyre.io/acceptable-use") })
        CfxRow("Open source licences", icon = R.drawable.ic_scales, chevron = R.drawable.ic_caret_right, onClick = { m.push = Push.Licences })
    }
    Text("Clickswave Labs Pvt Ltd", style = TextStyle(fontFamily = CfxFonts.ui, fontSize = 13.sp, lineHeight = 19.sp, color = c.text3), textAlign = TextAlign.Center, modifier = Modifier.fillMaxWidth())
}

/**
 * Deleting the account happens on the website, which asks who you are first.
 * Offered here as well because a person looking for it in the app should find it.
 */
@Composable
private fun DeleteAccountRow(m: AppModel) {
    CfxRow(
        "Delete account", icon = R.drawable.ic_prohibit, sub = "Opens crossfyre.io, where the account and its data are deleted",
        chevron = R.drawable.ic_arrow_square_out, onClick = { m.openUrl("https://crossfyre.io/privacy#delete-account") },
    )
}

// ── Licences ─────────────────────────────────────────────────────────────────

/** What the APK carries that is not ours, by group. */
val LICENCES = listOf(
    "App" to listOf("Crossfyre Mobile" to "Apache-2.0"),
    "Android" to listOf(
        "AndroidX and Jetpack Compose" to "Apache-2.0",
        "CameraX" to "Apache-2.0",
        "ZXing" to "Apache-2.0",
    ),
    "Capture core" to listOf(
        "rustls" to "Apache-2.0, ISC or MIT",
        "aws-lc-rs" to "ISC, and Apache-2.0 or ISC",
        "tokio" to "MIT",
        "hyper" to "MIT",
        "ipstack" to "Apache-2.0",
        "rcgen" to "MIT or Apache-2.0",
        "reqwest" to "MIT or Apache-2.0",
        "webpki-roots" to "CDLA-Permissive-2.0",
        "brotli" to "BSD-3-Clause and MIT",
        "zstd" to "MIT",
        "flate2" to "MIT or Apache-2.0",
        "jni" to "MIT or Apache-2.0",
    ),
    "Fonts and icons" to listOf(
        "Inter, Outfit, JetBrains Mono, Orbitron" to "SIL Open Font License 1.1",
        "Phosphor Icons" to "MIT",
    ),
)

@Composable
fun LicencesContent(m: AppModel) {
    Text("Crossfyre Mobile is open source under the Apache License 2.0, and is built on the components below. Tap one to read its licence.", style = T.body())
    for ((group, items) in LICENCES) {
        GroupLabel(group)
        CfxList {
            items.forEachIndexed { i, (name, lic) ->
                CfxRow(name, first = i == 0, sub = lic, chevron = R.drawable.ic_caret_right, onClick = { m.overlay = Overlay.Licence(name, lic) })
            }
        }
    }
    CfxList {
        CfxRow("Full notices", first = true, icon = R.drawable.ic_file_text, sub = "Every component, including the ones these depend on", chevron = R.drawable.ic_caret_right,
            onClick = { m.overlay = Overlay.Licence("Full notices", "Every component, with its licence") })
    }
}
