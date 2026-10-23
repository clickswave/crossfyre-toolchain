package io.crossfyre.mobile.ui

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.clearAndSetSemantics
import io.crossfyre.mobile.AppModel
import io.crossfyre.mobile.Overlay
import io.crossfyre.mobile.Phase
import io.crossfyre.mobile.Push
import io.crossfyre.mobile.R
import io.crossfyre.mobile.Route

@Composable
fun AppRoot(m: AppModel) {
    val job by m.patch.job.collectAsState()
    // While a sheet, dialog or the disclosure is up, what is under it is not there
    // for TalkBack either: only the top layer can be read and acted on.
    val covered = m.overlay != null || job != null
    Box(Modifier.fillMaxSize().background(cfx.ground)) {
        Box(Modifier.fillMaxSize().then(if (covered) Modifier.clearAndSetSemantics { } else Modifier)) {
            when (m.route) {
                Route.SIGN_IN -> SignInScreen(m)
                Route.DEVICE -> DeviceScreen(m)
                Route.WORKSPACES -> WorkspacesScreen(m)
                Route.MAIN -> MainScreen(m)
            }
        }
        if (m.overlay == Overlay.Disclosure) Disclosure(m)
        Overlays(m)
        job?.let { PatchSheets(m, it) }
        m.toast?.let { Toast(it.text, it.icon, aboveTabs = m.route == Route.MAIN && m.overlay == null) }
    }
    val canGoBack = m.overlay != null || (job != null && job?.running == false) || m.push != null ||
        m.route == Route.DEVICE || (m.route == Route.WORKSPACES && m.wsBack) || (m.route == Route.MAIN && m.tab != "home") ||
        job?.running == true
    BackHandler(enabled = canGoBack) { m.back() }
}

@Composable
private fun MainScreen(m: AppModel) {
    val tab = if (m.tab == "patch" && !m.patch.available) "home" else m.tab
    LaunchedEffect(tab) {
        if (tab == "patch" || tab == "tracer" || tab == "home") m.loadApps()
        m.refreshPatchStates()
    }
    Column(Modifier.fillMaxSize()) {
        when (val p = m.push) {
            Push.Certificate -> AppBar("Certificate", onBack = { m.push = null })
            is Push.App -> AppBar(m.facts[p.pkg]?.label ?: m.labelOf(p.pkg), onBack = { m.push = null })
            Push.Licences -> AppBar("Open source licences", onBack = { m.push = null })
            null -> when (tab) {
                "home" -> AppBar(brand = true) { EnvChip(m) }
                "tracer" -> AppBar("Tracer") {
                    EnvChip(m)
                    IconBtn(R.drawable.ic_question, "What capture does to this phone") { m.overlay = Overlay.HowTo }
                }
                "patch" -> AppBar("Patch a pinned app") { EnvChip(m) }
                "node" -> AppBar("Node") { EnvChip(m) }
                else -> AppBar("Settings") { EnvChip(m) }
            }
        }
        Box(Modifier.weight(1f).fillMaxWidth()) {
            when (val p = m.push) {
                Push.Certificate -> Content("certificate") { CertificateContent(m) }
                is Push.App -> Content("app-${p.pkg}") { AppContent(m, p.pkg) }
                Push.Licences -> Content("licences") { LicencesContent(m) }
                null -> when (tab) {
                    "home" -> Content("home") { HomeContent(m) }
                    "tracer" -> Content("tracer") { TracerContent(m) }
                    "patch" -> Content("patch") { PatchContent(m) }
                    "node" -> Content("node") { NodeContent() }
                    else -> Content("settings") { SettingsContent(m) }
                }
            }
        }
        Tabs(
            listOfNotNull(
                TabSpec("home", R.drawable.ic_house, "Home"),
                TabSpec("tracer", R.drawable.ic_broadcast, "Tracer", live = m.phase == Phase.CAPTURING),
                if (m.patch.available) TabSpec("patch", R.drawable.ic_package, "Patch") else null,
                TabSpec("node", R.drawable.ic_hard_drives, "Node", locked = true),
                TabSpec("settings", R.drawable.ic_gear_six, "Settings"),
            ),
            current = tab,
        ) { m.goTab(it) }
    }
}
