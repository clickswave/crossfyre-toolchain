package io.crossfyre.mobile.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxScope
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import io.crossfyre.mobile.AppModel
import io.crossfyre.mobile.Level
import io.crossfyre.mobile.R
import io.crossfyre.mobile.apps.AppFacts
import io.crossfyre.mobile.apps.Apps
import io.crossfyre.mobile.patch.PATCH_STAGES
import io.crossfyre.mobile.patch.PatchJob
import io.crossfyre.mobile.patch.PatchState
import io.crossfyre.mobile.patch.PatchStep
import io.crossfyre.mobile.patch.result

/** The note under an app in the scope and patch lists, with its colour. */
@Composable
fun appNote(m: AppModel, pkg: String): Pair<String, Tone>? {
    val f = m.facts[pkg]
    if (!m.patch.available) return Apps.noteWithoutPatching(f, pkg)?.let { it to Tone.NONE }
    val st = m.patchStates[pkg] ?: PatchState.NONE
    return when {
        f?.shielded == true -> "Shielded: may refuse to run once patched" to Tone.DANGER
        st == PatchState.STALE -> "Patch again: trusts an older certificate" to Tone.WARN
        st == PatchState.CURRENT -> "Patched with this certificate" to Tone.OK
        f?.flutter == true -> "Flutter: patch it to read its API" to Tone.NONE
        else -> null
    }
}

@Composable
fun PatchContent(m: AppModel) {
    Text(
        "Apps that pin their certificate refuse capture. Patching rewrites and re-signs an app on Crossfyre's servers so it trusts this phone's certificate, then installs it back.",
        style = T.body(),
    )
    val stale = m.staleCount
    if (stale.isNotEmpty()) {
        Banner(
            Level.WARN,
            "${stale.size} ${if (stale.size == 1) "app needs" else "apps need"} patching again.",
            "${stale.joinToString(", ") { m.labelOf(it) }} ${if (stale.size == 1) "trusts" else "trust"} an older certificate.",
        )
    }
    SearchBox(m.patchQuery, { m.patchQuery = it }, "Search installed apps")
    val apps = m.apps
    if (apps == null) {
        CfxList { repeat(5) { SkelRow(first = it == 0, iconSize = 40.dp, titleW = 0.5f, subW = 0.7f) } }
        Text("Reading installed apps…", style = T.hint(), textAlign = TextAlign.Center, modifier = Modifier.fillMaxWidth())
    } else {
        val q = m.patchQuery.trim().lowercase()
        val list = apps.filter { q.isEmpty() || it.label.lowercase().contains(q) || it.pkg.contains(q) }
        if (list.isEmpty()) {
            Empty(R.drawable.ic_magnifying_glass, "No apps match \"${m.patchQuery}\"", "Search by the app's name or its package name.")
        } else {
            CfxList {
                list.forEachIndexed { i, a ->
                    val n = appNote(m, a.pkg)
                    CfxRow(
                        a.label, first = i == 0, leading = { AppIcon(a.label) }, sub = a.pkg, subMono = true,
                        note = n?.first, noteTone = n?.second ?: Tone.NONE, chevron = R.drawable.ic_caret_right,
                        onClick = { m.openApp(a.pkg) },
                    )
                }
            }
        }
    }
    Authz("Only patch apps you own or are authorized to test.")
}

@Composable
fun AppContent(m: AppModel, pkg: String) {
    val c = cfx
    val direct = m.patch.available
    val f: AppFacts? = m.facts[pkg]
    val label = f?.label ?: m.labelOf(pkg)
    val st = m.patchStates[pkg] ?: PatchState.NONE
    CfxCard {
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(14.dp)) {
            AppIcon(label, 52.dp)
            Column(Modifier.weight(1f)) {
                Text(label, style = TextStyle(fontFamily = CfxFonts.head, fontWeight = FontWeight.SemiBold, fontSize = 18.sp, lineHeight = 24.sp, color = c.text))
                Text(pkg, style = T.rowSub().copy(fontFamily = CfxFonts.mono, fontSize = 12.sp))
            }
        }
        if (direct) {
            Row {
                when (st) {
                    PatchState.CURRENT -> Chip("Patched with this certificate", Tone.OK)
                    PatchState.STALE -> Chip("Patch again", Tone.WARN)
                    PatchState.NONE -> Chip("Not patched")
                }
            }
        }
    }
    if (f == null) {
        CfxCard {
            Eyebrow("Reading the app…")
            for (w in listOf(0.7f, 0.5f, 0.8f, 0.4f)) Skel(w, 12.dp)
        }
        return
    }
    var libsOpen by remember(pkg) { mutableStateOf(false) }
    CfxCard {
        Eyebrow("What is in it")
        Facts(
            buildList {
                add("Size" to "${f.sizeMb} MB")
                add("Framework" to f.framework)
                add("Network stacks" to f.stacks)
                add("Resources" to if (f.packed) "Packed (relocated, unpacked at runtime)" else "Normal")
                add("Shield signs" to if (f.shieldLibs.isNotEmpty()) "${f.shieldLibs.size} machine-named libraries" else "None found")
                if (direct) add(
                    "Patched" to when (st) {
                        PatchState.CURRENT -> "Yes, with this certificate"
                        PatchState.STALE -> "Yes, with an older certificate"
                        PatchState.NONE -> "No"
                    }
                )
            }
        )
        if (f.nativeLibs.isNotEmpty()) {
            Toggle("Native libraries (${f.nativeLibs.size})", libsOpen) { libsOpen = !libsOpen }
            if (libsOpen) {
                Text(f.nativeLibs.joinToString(", "), style = TextStyle(fontFamily = CfxFonts.mono, fontSize = 12.sp, lineHeight = 19.sp, color = c.text3))
            }
        }
    }
    val outlook = m.patch.outlook(f, st == PatchState.CURRENT)
    Banner(if (direct && f.shielded) Level.DANGER else Level.INFO, "What to expect", outlook)
    if (direct) {
        val job by m.patch.job.collectAsState()
        val exportable by m.patch.exportable.collectAsState()
        CfxButton(
            if (st == PatchState.NONE) "Patch this app" else "Patch again", Kind.PRIMARY, block = true, icon = R.drawable.ic_package,
            enabled = job?.running != true,
        ) { m.startPatch(pkg) }
        if (exportable == pkg) {
            CfxButton("Export patched APK", Kind.SECONDARY, block = true, icon = R.drawable.ic_export) { m.exportPatched() }
        }
        Column(Modifier.padding(top = 4.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Note(R.drawable.ic_arrows_down_up, "Android asks you twice: once to remove the original, once to install the patched build. Removing it clears the app's data, so you will sign in to it again.")
            Note(R.drawable.ic_clock, "A large app takes a few minutes, most of it on the server.")
        }
    }
}

@Composable
private fun Note(icon: Int, text: String) {
    Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
        Ic(icon, 16.dp, cfx.text3, Modifier.padding(top = 2.dp))
        Text(text, style = TextStyle(fontFamily = CfxFonts.ui, fontSize = 13.5.sp, lineHeight = 19.sp, color = cfx.text3))
    }
}

/** The patch in progress, or its result. Drawn over everything, and not dismissed by a tap outside. */
@Composable
fun BoxScope.PatchSheets(m: AppModel, job: PatchJob) {
    val c = cfx
    if (job.running) {
        Sheet(
            title = { SheetTitle("Patching ${job.label}") },
            onDismiss = null,
            foot = {
                if (job.cancellable) CfxButton("Cancel", Kind.GHOST, block = true) { m.cancelPatch() }
                else Text("Android is installing now. This part cannot be cancelled from here.", style = T.hint(), textAlign = TextAlign.Center, modifier = Modifier.fillMaxWidth())
            },
        ) {
            Meter(job.meter)
            Column(Modifier.padding(top = 0.dp)) {
                PATCH_STAGES.forEachIndexed { i, title ->
                    val state = when {
                        i < job.stage -> 0
                        i == job.stage -> 1
                        else -> 2
                    }
                    Row(Modifier.fillMaxWidth().padding(vertical = 9.dp), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                        Box(
                            Modifier.size(24.dp).clip(CircleShape)
                                .background(if (state == 0) c.success else androidx.compose.ui.graphics.Color.Transparent)
                                .border(2.dp, when (state) { 0 -> c.success; 1 -> c.emberLineStrong; else -> c.lineStrong }, CircleShape),
                            contentAlignment = Alignment.Center,
                        ) {
                            when (state) {
                                0 -> Ic(R.drawable.ic_check, 14.dp, c.ground)
                                1 -> Spinner(12.dp, c.ember)
                            }
                        }
                        Column(Modifier.weight(1f)) {
                            Text(title, style = TextStyle(fontFamily = CfxFonts.ui, fontSize = 14.5.sp, lineHeight = 21.sp, color = if (state == 2) c.text3 else c.text))
                            if (state == 1) Text(job.detail, style = TextStyle(fontFamily = CfxFonts.ui, fontSize = 13.sp, lineHeight = 18.sp, color = c.text2))
                        }
                    }
                }
            }
            Text(
                "You can use other apps while this runs. If you close Crossfyre Mobile from your recent apps, the patch stops and nothing is installed.",
                style = T.hint(),
            )
        }
        return
    }
    val (title, first, second) = job.result() ?: return
    val ok = job.step == PatchStep.DONE
    Sheet(
        title = { SheetTitle(title) },
        onDismiss = null,
        foot = {
            if (ok) {
                CfxButton("Go to the Tracer", Kind.PRIMARY, block = true) { m.patchFinished(); m.goTab("tracer") }
                CfxButton("Export patched APK", Kind.SECONDARY, block = true, icon = R.drawable.ic_export) { m.exportPatched() }
                CfxButton("Done", Kind.TEXT_DIM, block = true) { m.patchFinished() }
            } else {
                CfxButton("Patch again", Kind.PRIMARY, block = true) { m.patchFinished(); m.startPatch(job.pkg) }
                CfxButton("Close", Kind.TEXT_DIM, block = true) { m.patchFinished() }
            }
        },
    ) {
        Box(
            Modifier.size(52.dp).clip(CircleShape)
                .background(if (ok) c.successTint else c.warningTint)
                .border(1.dp, (if (ok) c.success else c.warning).copy(alpha = 0.4f), CircleShape),
            contentAlignment = Alignment.Center,
        ) { Ic(if (ok) R.drawable.ic_check else R.drawable.ic_warning, 26.dp, if (ok) c.success else c.warning) }
        Text(first, style = T.body())
        Text(second, style = T.body())
    }
}
