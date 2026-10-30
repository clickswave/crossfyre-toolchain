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
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import io.crossfyre.mobile.AppModel
import io.crossfyre.mobile.ApproverState
import io.crossfyre.mobile.EnrolStatus
import io.crossfyre.mobile.Level
import io.crossfyre.mobile.R

// ── Turning approvals on ─────────────────────────────────────────────────────

/** The facts of approvals, shared by the explainer and the README's account of them. */
@Composable
fun ApprovalFacts(m: AppModel) {
    val c = cfx
    val items = listOf(
        Triple(
            R.drawable.ic_shield_check, "Nothing starts until you approve it here",
            "When an agent working with your account asks for something that needs a person, such as a scan on more than one node or requests that can change data on a target, Crossfyre waits. This phone shows the workspace, the action, each target with the scope entry that allows it, and where the request came from.",
        ),
        Triple(
            R.drawable.ic_key, "A key made on this phone",
            "Turning this on makes a signing key in the Android keystore. Its private half never leaves the phone. The app sends the public half to ${m.host} with this phone's model name and install ID, and you confirm the phone once in a signed-in browser.",
        ),
        Triple(
            R.drawable.ic_lock_key_open, "An unlock for every approval",
            "Your answer is signed with that key after you unlock the phone, so a CLI or agent key on a computer cannot approve for you. Denying needs no unlock.",
        ),
        Triple(
            R.drawable.ic_clock, "Checked while the app is open",
            "While the app is on screen it asks ${m.host} every few seconds for approvals waiting for you. There is no push notification: with the app closed, requests reach you through the alerts you set up in the dashboard. Pending approvals, recent decisions and activity are kept in memory while the app is open and are not written to the phone's storage.",
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

@Composable
fun BoxScope.ApprovalsExplainSheet(m: AppModel) {
    val secure = m.deviceSecure
    Sheet(
        title = { SheetTitle("Approve agent actions") }, onDismiss = { m.overlay = null }, tall = true,
        foot = {
            if (secure) {
                CfxButton(if (m.approverState == ApproverState.BROKEN) "Turn on again" else "Turn on", Kind.PRIMARY, block = true) { m.turnOnApprovals() }
            } else {
                CfxButton("Set a screen lock", Kind.PRIMARY, block = true) { m.securitySettings() }
            }
            CfxButton("Not now", Kind.TEXT_DIM, block = true) { m.overlay = null }
        },
    ) {
        m.approverTrouble?.let { Banner(Level.WARN, "This phone stopped approving.", it) }
        if (!secure) {
            Banner(Level.WARN, "This phone has no screen lock.", "The approval key needs one, so that every approval asks for your PIN, pattern, password or fingerprint. Set one, then come back.")
        }
        ApprovalFacts(m)
        Text(
            "An agent that drives your signed-in browser can do anything you can do there, including confirming a phone it set up itself. Approvals protect against agents that hold your keys outside the browser.",
            style = T.hint(),
        )
        Text("Signing out, turning this off, or revoking this phone's key in the dashboard stops the key from working.", style = T.hint())
    }
}

@Composable
fun BoxScope.EnrolSheet(m: AppModel) {
    val c = cfx
    val status = m.enrolStatus
    val waiting = m.approverState == ApproverState.ENROLLING
    Sheet(
        title = { SheetTitle("Confirm this phone in the browser") }, onDismiss = { if (waiting) m.overlay = null else m.cancelEnrol() },
        foot = {
            when {
                waiting && status == EnrolStatus.WAITING -> {
                    CfxButton("Open the page again", Kind.SECONDARY, block = true, icon = R.drawable.ic_arrow_square_out) { m.reopenEnrol() }
                    CfxButton("Cancel", Kind.TEXT_DIM, block = true) { m.cancelEnrol() }
                }
                waiting -> CfxButton("Cancel", Kind.TEXT_DIM, block = true) { m.cancelEnrol() }
                else -> {
                    CfxButton("Try again", Kind.PRIMARY, block = true) { m.turnOnApprovals() }
                    CfxButton("Close", Kind.TEXT_DIM, block = true) { m.overlay = null }
                }
            }
        },
    ) {
        when {
            waiting && status == EnrolStatus.STARTING -> Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                Spinner(16.dp)
                Text("Making the key and sending its public half…", style = T.body())
            }
            waiting -> {
                Text("A page opened in your browser. Check that it shows this fingerprint, then confirm the phone there.", style = T.body())
                Text(
                    m.enrolFingerprint.uppercase(),
                    style = TextStyle(fontFamily = CfxFonts.mono, fontWeight = FontWeight.SemiBold, fontSize = 20.sp, lineHeight = 28.sp, color = c.text),
                    modifier = Modifier.fillMaxWidth().background(c.surfaceInput).border(1.dp, c.line).padding(horizontal = 12.dp, vertical = 10.dp),
                )
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                    Spinner(16.dp)
                    Text("Waiting for the browser", style = T.hint())
                }
                Text("If the fingerprints differ, deny it in the browser and cancel here.", style = T.hint())
            }
            status == EnrolStatus.DENIED -> Banner(Level.WARN, "The phone was denied in the browser.", "Nothing was turned on, and the key this phone made was deleted.")
            status == EnrolStatus.EXPIRED -> Banner(Level.WARN, "The request expired before it was confirmed.", "Nothing was turned on, and the key this phone made was deleted.")
            else -> m.enrolError?.let { Banner(it) }
        }
    }
}

@Composable
fun BoxScope.ApprovalsOffDialog(m: AppModel) {
    val c = cfx
    CfxDialog(
        "Stop approving on this phone?", onDismiss = { m.overlay = null },
        actions = {
            CfxButton("Cancel", Kind.TEXT_DIM) { m.overlay = null }
            CfxButton("Turn off", Kind.TEXT, color = c.danger) { m.turnOffApprovals() }
        },
    ) {
        Text("The approval key is deleted from this phone, and the server stops accepting it.")
        m.approverFingerprint?.let { Text("Key ${it.uppercase()}", style = TextStyle(fontFamily = CfxFonts.mono, fontSize = 13.sp, color = c.text2)) }
    }
}

/** The Approvals group in Settings. */
@Composable
fun ApprovalsSettings(m: AppModel) {
    GroupLabel("Approvals")
    CfxList {
        if (!m.signedIn) {
            CfxRow(
                "Sign in to approve agent actions", first = true, icon = R.drawable.ic_shield_check,
                sub = "A QR pairing cannot approve anything",
                trailing = { CfxButton("Sign in", Kind.SECONDARY, small = true) { m.toSignIn() } },
            )
            return@CfxList
        }
        val state = m.approverState
        CfxRow(
            "Approve agent actions on this phone", first = true, icon = R.drawable.ic_shield_check,
            sub = when (state) {
                ApproverState.OFF -> "Approve what an agent asks to do, with an unlock on this phone"
                ApproverState.ENROLLING -> "Waiting for you to confirm this phone in the browser"
                ApproverState.ACTIVE -> "Key " + m.approverFingerprint.orEmpty().uppercase()
                ApproverState.BROKEN -> "Turned off. Tap to turn it on again."
            },
            subMono = state == ApproverState.ACTIVE,
            note = if (state == ApproverState.BROKEN) m.approverTrouble else null, noteTone = Tone.WARN,
            value = when (state) {
                ApproverState.ACTIVE -> "On"
                ApproverState.ENROLLING -> "Waiting"
                else -> "Off"
            },
            valueTone = if (state == ApproverState.ACTIVE) Tone.OK else Tone.NONE,
            chevron = R.drawable.ic_caret_right,
            onClick = { m.openApprovals() },
        )
    }
}
