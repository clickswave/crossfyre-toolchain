package io.crossfyre.mobile.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxScope
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import io.crossfyre.mobile.AppModel
import io.crossfyre.mobile.Level
import io.crossfyre.mobile.Overlay
import io.crossfyre.mobile.R
import io.crossfyre.mobile.Scope
import io.crossfyre.mobile.ago
import io.crossfyre.mobile.displayHost

/** The four facts of what a capture does, shared by the disclosure and the how-to sheet. */
@Composable
fun CaptureFacts(m: AppModel) {
    val c = cfx
    val items = listOf(
        Triple(R.drawable.ic_certificate, "A certificate made on this phone", "Its private key never leaves the phone."),
        Triple(R.drawable.ic_device_mobile, "A VPN that stays on the phone", "Android routes traffic through this app. Nothing is tunnelled to a remote server."),
        Triple(
            R.drawable.ic_lock_key_open, "HTTPS decrypted for apps in scope",
            "Each request is read, then sent on to where it was going. Scope starts as the whole phone; narrow it first if you would rather it did not see everything.",
        ),
        Triple(
            R.drawable.ic_cloud_arrow_up, "Sent to ${m.destination}",
            "Method, host, path and status of each request, on ${m.pairingHost}. Headers and bodies only if you turn on full requests.",
        ),
    )
    Column(verticalArrangement = Arrangement.spacedBy(14.dp)) {
        for ((icon, title, sub) in items) {
            Row(horizontalArrangement = Arrangement.spacedBy(14.dp)) {
                Box(Modifier.size(36.dp).background(c.surface2).border(1.dp, c.lineStrong), contentAlignment = Alignment.Center) {
                    Ic(icon, 20.dp, c.ember)
                }
                Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(1.dp)) {
                    Text(title, style = T.rowTitle().copy(fontWeight = FontWeight.SemiBold))
                    Text(sub, style = T.rowSub())
                }
            }
        }
    }
}

/**
 * "Before the first capture": the prominent disclosure, on a page of its own.
 *
 * Shown before Android's notification and VPN prompts, and again at every Start
 * until it is agreed to. It says what the VpnService is used for, what is read,
 * and where it goes, and nothing else: full requests have their own consent, so
 * this one is not bundled with another.
 */
@Composable
fun Disclosure(m: AppModel) {
    val c = cfx
    val https = m.pairing?.apiUrl?.startsWith("https://") ?: m.origin.startsWith("https://")
    val items = listOf(
        Triple(
            R.drawable.ic_device_mobile, "A VPN that stays on this phone",
            "Android routes the traffic of apps in scope through this app, which reads each request and sends it on to where it was going. Nothing is tunnelled to a remote VPN server.",
        ),
        Triple(
            R.drawable.ic_lock_key_open, "HTTPS read only where the app allows it",
            "HTTPS is read only for apps that trust the certificate this app made on the phone. Its private key never leaves the phone.",
        ),
        Triple(
            R.drawable.ic_cloud_arrow_up, "Sent to ${m.destination}",
            "For each request, the method, host, path and status are sent${if (https) " over HTTPS" else ""} to your workspace on ${m.pairingHost}. Headers and bodies are sent only if you turn on full requests.",
        ),
        Triple(
            R.drawable.ic_shield_check, "Apps outside the scope are not touched",
            "Scope starts as the whole phone; change it first if you would rather it did not.",
        ),
    )
    Solo(
        bar = { AppBar("Before the first capture", onBack = { m.declineDisclosure() }, plain = true) },
        dock = {
            Dock {
                CfxButton("Agree and start", Kind.PRIMARY, block = true) { m.agreeDisclosure() }
                CfxButton("Not now", Kind.TEXT_DIM, block = true) { m.declineDisclosure() }
            }
        },
    ) {
        Text(
            "Crossfyre Mobile uses Android's VPN feature (VpnService) to capture the traffic of the apps in your capture scope, so you can test apps you own or are authorized to test.",
            style = T.lede(),
        )
        Column(verticalArrangement = Arrangement.spacedBy(14.dp)) {
            for ((icon, title, sub) in items) {
                Row(horizontalArrangement = Arrangement.spacedBy(14.dp)) {
                    Box(Modifier.size(36.dp).background(c.surface2).border(1.dp, c.lineStrong), contentAlignment = Alignment.Center) {
                        Ic(icon, 20.dp, c.ember)
                    }
                    Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(1.dp)) {
                        Text(title, style = T.rowTitle().copy(fontWeight = FontWeight.SemiBold))
                        Text(sub, style = T.rowSub())
                    }
                }
            }
        }
        Authz()
        Text(
            "Android asks next to allow a VPN connection" + if (m.prefs.notificationsAsked) "." else ", and to show the capture notification.",
            style = T.hint(),
        )
    }
}

@Composable
fun BoxScope.Overlays(m: AppModel) {
    val c = cfx
    val ctx = LocalContext.current
    when (val o = m.overlay) {
        null, Overlay.Disclosure -> Unit
        Overlay.HowTo -> Sheet(
            title = { SheetTitle("What capture does to this phone") }, onDismiss = { m.overlay = null }, tall = true,
            foot = { CfxButton("View the source", Kind.SECONDARY, block = true, icon = R.drawable.ic_code) { m.openUrl("https://github.com/clickswave/crossfyre-toolchain") } },
        ) {
            CaptureFacts(m)
            Text("If any of that is not what you want, do not start a capture. The source is public, so you can check this against the code.", style = T.body())
        }

        Overlay.Scope -> Sheet(
            title = { SheetTitle("Scope") }, onDismiss = { m.overlay = null }, tall = true,
            foot = { CfxButton("Done", Kind.PRIMARY, block = true) { m.overlay = null } },
        ) {
            val mode = m.scopeMode
            Seg(listOf(Scope.ALL to "Whole phone", Scope.ONLY to "Only these", Scope.EXCEPT to "All except"), mode) { m.chooseScopeMode(it) }
            Text(
                when (mode) {
                    Scope.ONLY -> "Only the apps you tick go through the Tracer. Everything else works as normal."
                    Scope.EXCEPT -> "Every app goes through the Tracer except the ones you tick. Put apps that pin their certificate here so they keep working."
                    else -> "Every app on the phone goes through the Tracer. Crossfyre Mobile itself never does."
                },
                style = T.hint(),
            )
            if (mode == Scope.ALL) {
                Text("Apps that pin their certificate, such as most banking apps, may fail to connect while capture runs. Switch to All except and tick them to keep them working.", style = T.hint())
            } else {
                SearchBox(m.scopeQuery, { m.scopeQuery = it }, "Search apps")
                val apps = m.apps
                if (apps == null) {
                    CfxList(plain = true) { repeat(5) { SkelRow(first = it == 0) } }
                } else {
                    val q = m.scopeQuery.trim().lowercase()
                    val list = apps.filter { q.isEmpty() || it.label.lowercase().contains(q) || it.pkg.contains(q) }
                    if (list.isEmpty()) {
                        Empty(R.drawable.ic_magnifying_glass, "No apps match \"${m.scopeQuery}\"", "Search by the app's name or its package name.")
                    } else {
                        CfxList(plain = true) {
                            list.forEachIndexed { i, a ->
                                val on = m.scopeApps.contains(a.pkg)
                                val n = appNote(m, a.pkg)
                                CfxRow(
                                    a.label, first = i == 0, tight = true, selected = on,
                                    leading = { Checkbox(on) }, sub = a.pkg, subMono = true,
                                    note = n?.first, noteTone = n?.second ?: Tone.NONE,
                                    trailing = { IconBtn(R.drawable.ic_info, "About ${a.label}", c.text3, 20.dp) { m.openApp(a.pkg) } },
                                    onClick = { m.toggleScopeApp(a.pkg) },
                                )
                            }
                        }
                    }
                }
            }
        }

        Overlay.FullConsent -> Sheet(
            title = { SheetTitle("Send full requests?") }, onDismiss = { m.overlay = null },
            foot = {
                CfxButton("Send full requests", Kind.PRIMARY, block = true) { m.allowFull() }
                CfxButton("Keep it off", Kind.GHOST, block = true) { m.overlay = null }
            },
        ) {
            Text(
                marked("Headers and bodies will go to **${m.destination}** on ${m.pairingHost}, as well as the shape of each request. That includes whatever the apps send: passwords, session tokens, cookies and personal data."),
                style = T.body(),
            )
            Text("The workspace can ask for full requests. Only this switch grants them, and it stays off until you turn it on here.", style = T.body())
            Authz()
        }

        is Overlay.Request -> {
            val r = m.recent.firstOrNull { it.key == o.key }
            if (r == null) {
                m.overlay = null
            } else {
                Sheet(
                    title = {
                        Text(buildAnnotatedString {
                            withStyle(SpanStyle(fontFamily = CfxFonts.mono, fontSize = 15.sp)) { append(r.method) }
                            append(" ")
                            append(r.pathOnly)
                        }, style = T.head())
                    },
                    onDismiss = { m.overlay = null },
                    foot = { CfxButton("Open in the dashboard", Kind.SECONDARY, block = true, icon = R.drawable.ic_arrow_square_out) { m.openDashboard() } },
                ) {
                    val rows = buildList {
                        add("Host" to r.host)
                        add("Path" to r.path)
                        add("Status" to (r.status?.toString() ?: "No response"))
                        if (r.bodyFields.isNotEmpty()) add("Body fields" to r.bodyFields.joinToString(", "))
                        add("Credential" to if (r.authed) "Carried one. Only that fact is sent." else "None")
                        add("When" to ago(((System.currentTimeMillis() - r.atMs) / 1000).coerceAtLeast(0)))
                        add("Sent to" to if (r.sent) m.destination else "Not sent")
                    }
                    Facts(rows, mono = setOf("Host", "Path", "Status", "Body fields"), valueColor = mapOf("Status" to statusColor(r.status)))
                    if (m.fullCapture) Banner(Level.INFO, "Headers and bodies were sent too.", "Open it in the dashboard to read them.")
                    else Banner(Level.INFO, "This is everything that left the phone.", "Query values, header values and bodies stayed here, because full requests are off.")
                }
            }
        }

        Overlay.Server -> {
            var value by remember { mutableStateOf(m.origin) }
            var bad by remember { mutableStateOf(false) }
            Sheet(
                title = { SheetTitle("Server") }, onDismiss = { m.overlay = null },
                foot = {
                    CfxButton("Done", Kind.PRIMARY, block = true) {
                        if (m.changeOrigin(value)) m.overlay = null else bad = true
                    }
                },
            ) {
                Field(
                    "Address of the Crossfyre server",
                    {
                        InputBox(
                            value, { value = it; bad = false }, mono = true, bad = bad, label = "Address of the Crossfyre server",
                            keyboard = KeyboardOptions(keyboardType = KeyboardType.Uri, autoCorrectEnabled = false),
                        )
                    },
                    error = if (bad) "Use https, or http on a private address." else null,
                )
                Text(marked("The emulator reaches this computer at `http://10.0.2.2:12004`. A phone needs the computer's address on the same network instead."), style = T.hint())
                Text("Only the dev build can change this, and only the dev build accepts http, on a private address.", style = T.hint())
            }
        }

        is Overlay.Preflight -> CfxDialog(
            "These apps won't decrypt", onDismiss = { m.overlay = null },
            actions = {
                CfxButton("Cancel", Kind.TEXT_DIM) { m.overlay = null }
                CfxButton("Start anyway", Kind.WARN_TEXT) { m.startAnyway() }
            },
        ) {
            Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                for (name in o.apps) Text("•  $name trusts an older certificate.")
            }
            Text(
                "Patch ${if (o.apps.size == 1) "it" else "them"} again from the Patch tab, or start anyway and capture only what ${if (o.apps.size == 1) "it sends" else "they send"} unencrypted.",
                style = T.hint(),
            )
        }

        is Overlay.PairConfirm -> CfxDialog(
            "Pair with this server?", onDismiss = { m.overlay = null },
            actions = {
                CfxButton("Cancel", Kind.TEXT_DIM) { m.overlay = null }
                CfxButton("Pair", Kind.TEXT) { m.confirmPairing(o.pairing) }
            },
        ) {
            // The host is the whole point of this dialog: it is the one thing that
            // tells pairing with your own workspace apart from someone else's server.
            Text("Captured traffic from this phone will be sent to:")
            Text(
                displayHost(o.pairing.apiUrl),
                style = TextStyle(fontFamily = CfxFonts.mono, fontWeight = FontWeight.SemiBold, fontSize = 16.sp, lineHeight = 22.sp, color = c.text),
                modifier = Modifier.fillMaxWidth().background(c.surfaceInput).border(1.dp, c.line).padding(horizontal = 12.dp, vertical = 10.dp),
            )
            Text(
                "Only continue if you recognise this address." +
                    if (m.patch.available) " Pairing also lets this server supply the app builds you install from the Patch tab." else "",
                style = T.hint(),
            )
        }

        Overlay.PairInvalid -> CfxDialog(
            "Not a pairing code", onDismiss = { m.overlay = null },
            actions = { CfxButton("OK", Kind.TEXT) { m.overlay = null } },
        ) {
            Text("That QR code is not a Crossfyre pairing code. Pairing codes come from a Web Tracer session in the dashboard, and point at an https address.")
        }

        Overlay.ResetCert -> {
            val n = remember { m.patch.patchedCount() }
            CfxDialog(
                "Reset certificate?", onDismiss = { m.overlay = null },
                actions = {
                    CfxButton("Cancel", Kind.TEXT_DIM) { m.overlay = null }
                    CfxButton("Reset", Kind.TEXT, color = c.danger) { m.resetCertificate() }
                },
            ) {
                Text(
                    "A new certificate is made the next time you capture." + when {
                        !m.patch.available || n == 0 -> ""
                        n == 1 -> " The app you have patched trusts the current one, so it will stop decrypting until you patch it again."
                        else -> " The $n apps you have patched trust the current one, so they will stop decrypting until you patch them again."
                    }
                )
                Text("Do this if you think the private key may have been exposed.")
            }
        }

        Overlay.RemoveOldCert -> CfxDialog(
            "Remove the old certificate", onDismiss = { m.overlay = null },
            actions = {
                CfxButton("Later", Kind.TEXT_DIM) { m.overlay = null }
                CfxButton("Open settings", Kind.TEXT) { m.securitySettings() }
            },
        ) {
            Text(marked("This app's certificate has been reset, but if you installed the old one in Android, Android still trusts it. To remove it, search Android settings for **User credentials**."))
        }

        Overlay.SignOut -> CfxDialog(
            "Sign out?", onDismiss = { m.overlay = null },
            actions = {
                CfxButton("Cancel", Kind.TEXT_DIM) { m.overlay = null }
                CfxButton("Sign out", Kind.TEXT, color = c.danger) { m.signOut() }
            },
        ) {
            Text("Capture stops and this phone's key is revoked. The certificate and any patched apps stay on the phone.")
        }

        Overlay.Unpair -> CfxDialog(
            "Unpair this phone?", onDismiss = { m.overlay = null },
            actions = {
                CfxButton("Cancel", Kind.TEXT_DIM) { m.overlay = null }
                CfxButton("Unpair", Kind.TEXT, color = c.danger) { m.unpair() }
            },
        ) {
            val ws = m.workspace
            Text(
                marked(
                    "Capture stops and the phone forgets " + (if (ws != null && m.fromAccount) "**${ws.name}**" else "this session") +
                        ". The session stays in the dashboard. The certificate and patched apps are kept."
                )
            )
        }

        is Overlay.Licence -> Sheet(title = { SheetTitle(o.name) }, onDismiss = { m.overlay = null }, tall = true) {
            Text(o.licence, style = T.rowSub())
            val texts = remember(o) { licenceTexts(o.name, o.licence).map { (title, res) -> title to readRaw(ctx, res) } }
            for ((title, text) in texts) {
                if (texts.size > 1) Eyebrow(title)
                LicenceText(text)
            }
        }
    }
}

@Composable
private fun LicenceText(text: String) {
    val c = cfx
    Text(
        text,
        style = TextStyle(fontFamily = CfxFonts.mono, fontSize = 11.5.sp, lineHeight = 18.sp, color = c.text2),
        modifier = Modifier.fillMaxWidth().background(c.surfaceInput).border(1.dp, c.line).padding(12.dp),
    )
}

/** The licence texts a component's licence names, in the order it names them. */
fun licenceTexts(name: String, licence: String): List<Pair<String, Int>> {
    if (name == "Full notices") return listOf("Notices" to R.raw.notices)
    val found = mutableListOf<Pair<Int, Pair<String, Int>>>()
    fun find(token: String, title: String, res: Int) {
        val i = licence.indexOf(token)
        if (i >= 0) found += i to (title to res)
    }
    find("Apache", "Apache License 2.0", R.raw.apache_2_0)
    find("MIT", "MIT", R.raw.mit)
    find("ISC", "ISC", R.raw.isc)
    find("BSD-3", "BSD 3-Clause", R.raw.bsd_3_clause)
    find("CDLA", "CDLA Permissive 2.0", R.raw.cdla_permissive_2_0)
    find("Open Font", "SIL Open Font License 1.1", R.raw.ofl)
    return found.sortedBy { it.first }.map { it.second }
}

private fun readRaw(ctx: android.content.Context, res: Int): String =
    runCatching { ctx.resources.openRawResource(res).bufferedReader().use { it.readText() } }.getOrDefault("")
