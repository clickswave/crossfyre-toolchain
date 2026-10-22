package io.crossfyre.mobile.ui

import android.os.Build
import android.os.SystemClock
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.navigationBars
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBars
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.em
import androidx.compose.ui.unit.sp
import io.crossfyre.mobile.AppModel
import io.crossfyre.mobile.BuildConfig
import io.crossfyre.mobile.DeviceStatus
import io.crossfyre.mobile.ListStatus
import io.crossfyre.mobile.ListTrouble
import io.crossfyre.mobile.Overlay
import io.crossfyre.mobile.R
import io.crossfyre.mobile.account.Workspace
import io.crossfyre.mobile.codeEnds
import kotlinx.coroutines.delay

/** A full-screen page with no tab bar: `.solo`. Its content scrolls, under an optional bar and over an optional dock. */
@Composable
fun Solo(
    bar: (@Composable () -> Unit)? = null,
    dock: (@Composable () -> Unit)? = null,
    centered: Boolean = false,
    content: @Composable ColumnScope.() -> Unit,
) {
    Column(Modifier.fillMaxSize().background(cfx.ground).imePadding()) {
        bar?.invoke()
        BoxWithConstraints(Modifier.weight(1f).fillMaxWidth()) {
            val min = maxHeight
            Column(
                Modifier.fillMaxWidth().verticalScroll(rememberScrollState())
                    .then(if (bar == null) Modifier.windowInsetsPadding(WindowInsets.statusBars) else Modifier)
                    .heightIn(min = if (centered) min else 0.dp)
                    .padding(start = 16.dp, end = 16.dp, top = if (bar == null) 16.dp else 8.dp, bottom = if (dock == null) 36.dp else 16.dp)
                    .then(if (dock == null) Modifier.windowInsetsPadding(WindowInsets.navigationBars) else Modifier),
                verticalArrangement = if (centered) Arrangement.spacedBy(14.dp, Alignment.CenterVertically) else Arrangement.spacedBy(14.dp),
                content = content,
            )
        }
        dock?.invoke()
    }
}

// ── Sign in ──────────────────────────────────────────────────────────────────

@Composable
fun SignInScreen(m: AppModel) {
    val c = cfx
    Solo(centered = true) {
        Column(
            Modifier.fillMaxWidth().padding(top = 18.dp, bottom = 6.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(14.dp),
        ) {
            Image(painterResource(R.drawable.cfx_mark), contentDescription = null, modifier = Modifier.size(56.dp))
            Wordmark(17.sp)
        }
        // Staging and dev are separate apps and say so on the first screen, so
        // nobody signs a dev build into production by mistake. Only the dev build
        // can change its server, because a dev stack's LAN address moves around.
        when (m.env) {
            "staging" -> Box(Modifier.fillMaxWidth(), contentAlignment = Alignment.Center) {
                Chip("Staging build · ${m.host}", Tone.INFO)
            }
            "dev" -> Row(
                Modifier.fillMaxWidth().tap { m.overlay = Overlay.Server }.padding(vertical = 4.dp),
                horizontalArrangement = Arrangement.spacedBy(8.dp, Alignment.CenterHorizontally),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Chip("Dev build", Tone.WARN)
                Text(m.host, style = T.mono(13.sp).copy(color = c.text1))
                Text("Change", style = TextStyle(fontFamily = CfxFonts.ui, fontWeight = FontWeight.SemiBold, fontSize = 13.5.sp, color = c.ember))
            }
        }
        Column(Modifier.fillMaxWidth(), horizontalAlignment = Alignment.CenterHorizontally) {
            Text("Sign in", style = T.title(), textAlign = TextAlign.Center)
            Text("With the account you use on crossfyre.io.", style = T.lede(), textAlign = TextAlign.Center)
        }
        m.siError?.let { Banner(it) }
        Field(
            "Username or email",
            {
                InputBox(
                    m.siUser, { m.siUser = it }, bad = m.siEmpty && m.siUser.isBlank(), enabled = !m.siBusy,
                    label = "Username or email",
                    keyboard = KeyboardOptions(keyboardType = KeyboardType.Email, imeAction = ImeAction.Next, autoCorrectEnabled = false),
                )
            },
            error = if (m.siEmpty && m.siUser.isBlank()) "Enter your username or email." else null,
        )
        Field(
            "Password",
            {
                InputBox(
                    m.siPass, { m.siPass = it }, password = !m.siShow, bad = m.siEmpty && m.siPass.isEmpty(), enabled = !m.siBusy,
                    label = "Password",
                    keyboard = KeyboardOptions(keyboardType = KeyboardType.Password, imeAction = ImeAction.Go, autoCorrectEnabled = false),
                    actions = KeyboardActions(onGo = { m.signIn() }),
                    trailing = {
                        IconBtn(
                            if (m.siShow) R.drawable.ic_eye_slash else R.drawable.ic_eye,
                            if (m.siShow) "Hide password" else "Show password", c.text2, 20.dp,
                        ) { m.siShow = !m.siShow }
                    },
                )
            },
            error = if (m.siEmpty && m.siPass.isEmpty()) "Enter your password." else null,
        )
        Row(Modifier.fillMaxWidth().tuck(top = 8.dp, bottom = 4.dp).offset(x = 6.dp), horizontalArrangement = Arrangement.End) {
            CfxButton("Forgot password?", Kind.TEXT_DIM, small = true) { m.openUrl("${m.origin}/auth/forgot-password") }
        }
        CfxButton(if (m.siBusy) "Signing in…" else "Sign in", Kind.PRIMARY, block = true, busy = m.siBusy) { m.signIn() }
        OrDivider()
        CfxButton("Sign in with browser", Kind.SECONDARY, block = true, icon = R.drawable.ic_globe_simple, iconSize = 20.dp, enabled = !m.siBusy) { m.browserSignIn() }
        Text("For accounts made with Google, which have no password.", style = T.hint(), textAlign = TextAlign.Center, modifier = Modifier.fillMaxWidth())
        CfxButton("Pair with a QR code instead", Kind.TEXT, block = true, icon = R.drawable.ic_qr_code, iconSize = 20.dp) { m.scan() }
        val foot = buildAnnotatedString {
            append("No account yet? ")
            withStyle(SpanStyle(color = c.ember, fontWeight = FontWeight.SemiBold)) { append("Create one on crossfyre.io") }
        }
        Text(
            foot, textAlign = TextAlign.Center,
            style = TextStyle(fontFamily = CfxFonts.ui, fontSize = 13.sp, lineHeight = 19.sp, color = c.text3),
            modifier = Modifier.fillMaxWidth().tap { m.openUrl("${m.origin}/auth/signup") },
        )
    }
}

@Composable
private fun OrDivider() {
    val c = cfx
    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
        Box(Modifier.weight(1f).height(1.dp).background(c.line))
        Text("or", style = TextStyle(fontFamily = CfxFonts.ui, fontSize = 12.5.sp, color = c.text3))
        Box(Modifier.weight(1f).height(1.dp).background(c.line))
    }
}

// ── Sign in with browser ─────────────────────────────────────────────────────

@Composable
fun DeviceScreen(m: AppModel) {
    val c = cfx
    Solo(bar = { AppBar("Sign in with browser", onBack = { m.cancelDevice() }, plain = true) }) {
        when (m.deviceStatus) {
            DeviceStatus.OPENING -> Empty(null, "Opening your browser…", plain = true) { Spinner(16.dp, c.text2) }
            DeviceStatus.WAITING -> {
                val text = buildAnnotatedString {
                    append("Your browser opened ")
                    withStyle(SpanStyle(fontFamily = CfxFonts.mono, fontSize = 13.sp)) { append("${m.host}/device") }
                    append(". Sign in there, with Google if that is how you made the account, then approve this phone.")
                }
                Text(text, style = T.lede())
                CfxCard(tight = true) {
                    Eyebrow("The page shows this code")
                    val ends = codeEnds(m.deviceCode)
                    val code = buildAnnotatedString {
                        if (ends == null) append(m.deviceCode) else {
                            append(ends.first)
                            withStyle(SpanStyle(color = c.text4)) { append(" … ") }
                            append(ends.second)
                        }
                    }
                    Text(
                        code,
                        style = TextStyle(fontFamily = CfxFonts.mono, fontWeight = FontWeight.Medium, fontSize = 15.sp, lineHeight = 23.sp, letterSpacing = 0.02.em, color = c.text),
                        modifier = Modifier.fillMaxWidth().background(c.surfaceInput).border(1.dp, c.line).padding(horizontal = 14.dp, vertical = 12.dp),
                    )
                    Text("Approve only if the page shows the same code.", style = T.hint())
                }
                CfxCard(tight = true) {
                    Eyebrow("It lists this phone as")
                    Facts(
                        listOf(
                            "Device" to Build.MODEL,
                            "System" to "Android ${Build.VERSION.RELEASE}",
                            "App" to "Crossfyre Mobile ${BuildConfig.VERSION_NAME}",
                        )
                    )
                }
                var now by remember { mutableLongStateOf(SystemClock.elapsedRealtime()) }
                LaunchedEffect(m.deviceDeadline) {
                    while (true) {
                        now = SystemClock.elapsedRealtime()
                        delay(1000)
                    }
                }
                val left = ((m.deviceDeadline - now) / 1000).coerceAtLeast(0)
                Row(
                    Modifier.fillMaxWidth().padding(vertical = 4.dp),
                    horizontalArrangement = Arrangement.spacedBy(10.dp, Alignment.CenterHorizontally),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Spinner(16.dp, c.text2)
                    Text(
                        "Waiting for approval · ${left / 60}:${(left % 60).toString().padStart(2, '0')} left",
                        style = TextStyle(fontFamily = CfxFonts.ui, fontSize = 14.sp, color = c.text2),
                    )
                }
                CfxButton("Open the page again", Kind.SECONDARY, block = true, icon = R.drawable.ic_arrow_square_out) { m.reopenApproval() }
                CfxButton("Cancel", Kind.GHOST, block = true) { m.cancelDevice() }
            }
            DeviceStatus.DENIED -> {
                Empty(R.drawable.ic_prohibit, "Sign-in denied", "Someone pressed Deny on the page. Nothing was issued to this phone.")
                CfxButton("Start again", Kind.PRIMARY, block = true) { m.browserSignIn() }
                CfxButton("Back to sign in", Kind.GHOST, block = true) { m.cancelDevice() }
            }
            DeviceStatus.EXPIRED -> {
                Empty(R.drawable.ic_hourglass_medium, "The request expired", "A sign-in request lasts 10 minutes. Start a new one and approve it from the page that opens.")
                CfxButton("Start again", Kind.PRIMARY, block = true) { m.browserSignIn() }
                CfxButton("Back to sign in", Kind.GHOST, block = true) { m.cancelDevice() }
            }
            DeviceStatus.ERROR -> {
                m.deviceError?.let { Banner(it) }
                CfxButton("Try again", Kind.PRIMARY, block = true) { m.browserSignIn() }
                CfxButton("Back to sign in", Kind.GHOST, block = true) { m.cancelDevice() }
            }
        }
    }
}

// ── Choose a workspace ───────────────────────────────────────────────────────

@Composable
fun WorkspacesScreen(m: AppModel) {
    val c = cfx
    val ready = m.wsStatus == ListStatus.READY
    Solo(
        bar = { AppBar("Choose a workspace", onBack = if (m.wsBack) ({ m.back() }) else null, plain = true) },
        dock = {
            Dock {
                if (ready) {
                    val hint = buildAnnotatedString {
                        append("It shows up there as ")
                        withStyle(SpanStyle(color = c.text, fontWeight = FontWeight.SemiBold)) { append(m.sessionName) }
                        append(".")
                    }
                    Text(hint, style = T.hint(), textAlign = TextAlign.Center, modifier = Modifier.fillMaxWidth())
                }
                CfxButton(
                    if (m.wsBusy) "Pairing…" else "Pair this phone", Kind.PRIMARY, block = true, busy = m.wsBusy,
                    enabled = ready && m.wsSel != null,
                ) { m.pairSelected() }
                CfxButton("Use a QR code instead", Kind.TEXT, block = true, icon = R.drawable.ic_qr_code, iconSize = 20.dp) { m.scan() }
            }
        },
    ) {
        val u = m.user
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(10.dp)) {
            Avatar(initialsOf(u?.username ?: u?.email ?: ""), small = true)
            val who = buildAnnotatedString {
                append("Signed in as ")
                withStyle(SpanStyle(color = c.text, fontWeight = FontWeight.SemiBold)) { append(u?.username?.ifEmpty { u.email } ?: "") }
            }
            Text(who, style = TextStyle(fontFamily = CfxFonts.ui, fontSize = 14.sp, color = c.text2), modifier = Modifier.weight(1f))
            CfxButton("Not you?", Kind.TEXT_DIM, small = true) { m.signOut() }
        }
        Text("Traffic captured on this phone goes to the workspace you pick. You can change it later.", style = T.lede())
        m.wsError?.let { Banner(it) }
        when (m.wsStatus) {
            ListStatus.LOADING -> {
                GroupLabel("Loading your workspaces")
                CfxList {
                    repeat(4) { SkelRow(first = it == 0) }
                }
            }
            ListStatus.ERROR -> {
                val n = m.wsNotice
                if (n != null) {
                    val actions = when (m.wsTrouble) {
                        ListTrouble.UNVERIFIED -> listOf("Try again" to { m.loadWorkspaces() }, "Open the dashboard" to { m.openUrl("${m.origin}/home") })
                        ListTrouble.SUSPENDED -> listOf("Open support" to { m.openUrl("${m.origin}/support") })
                        else -> listOf("Try again" to { m.loadWorkspaces() })
                    }
                    Banner(n, actions)
                }
            }
            ListStatus.EMPTY -> Empty(R.drawable.ic_buildings, "No workspaces yet", "Create one in the dashboard, then come back. This list reloads when you return to the app.") {
                CfxButton("Open the dashboard", Kind.SECONDARY, small = true, icon = R.drawable.ic_arrow_square_out, iconSize = 16.dp) {
                    m.openUrl("${m.origin}/home/workspaces")
                }
            }
            ListStatus.READY -> {
                val personal = m.workspaces.filter { it.ownerKind != "team" }
                val byOrg = m.workspaces.filter { it.ownerKind == "team" }.groupBy { it.org ?: "Organization" }
                if (personal.isNotEmpty()) {
                    GroupLabel("Personal")
                    CfxList { personal.forEachIndexed { i, w -> WsRow(m, w, i == 0) } }
                }
                for ((org, list) in byOrg) {
                    GroupLabel("$org · organization")
                    CfxList { list.forEachIndexed { i, w -> WsRow(m, w, i == 0) } }
                }
            }
        }
    }
}

@Composable
private fun WsRow(m: AppModel, w: Workspace, first: Boolean) {
    val on = m.wsSel == w.id
    val bits = listOfNotNull(w.role.takeIf { it.isNotBlank() }?.replaceFirstChar { it.uppercase() }, if (w.isActive) "current in the dashboard" else null)
    CfxRow(
        title = w.name,
        first = first,
        leading = { Radio(on) },
        sub = bits.joinToString(" · ").ifEmpty { null },
        trailing = if (w.isDemo) ({ Chip("Sample data") }) else null,
        selected = on,
        onClick = { m.wsSel = w.id; m.wsError = null },
    )
}
