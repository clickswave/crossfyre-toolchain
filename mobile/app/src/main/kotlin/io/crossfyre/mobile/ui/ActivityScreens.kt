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
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import io.crossfyre.mobile.ACTIVITY_LOG
import io.crossfyre.mobile.ActivityHeader
import io.crossfyre.mobile.AppModel
import io.crossfyre.mobile.ApproverState
import io.crossfyre.mobile.EnrolStatus
import io.crossfyre.mobile.Level
import io.crossfyre.mobile.ListStatus
import io.crossfyre.mobile.Overlay
import io.crossfyre.mobile.R
import io.crossfyre.mobile.activityHeader
import io.crossfyre.mobile.activityLine
import io.crossfyre.mobile.ago
import io.crossfyre.mobile.approve.ActivityEvent
import io.crossfyre.mobile.approve.ActivityScope
import io.crossfyre.mobile.approve.HistoryRow
import io.crossfyre.mobile.approve.PendingApproval
import io.crossfyre.mobile.approve.Summary
import io.crossfyre.mobile.approve.TargetRef
import io.crossfyre.mobile.approve.approvalView
import io.crossfyre.mobile.approve.countdown
import io.crossfyre.mobile.channelLabel
import io.crossfyre.mobile.riskChips
import io.crossfyre.mobile.shortDate
import java.time.Instant

// ── Turning approvals on ─────────────────────────────────────────────────────

/** The facts of approvals, shared by the explainer and the README's account of them. */
@Composable
fun ApprovalFacts(m: AppModel) {
    val c = cfx
    val items = listOf(
        Triple(
            R.drawable.ic_shield_check, "Nothing starts until you approve it here",
            "When an agent working with your account asks for something that needs a person, such as a scan on more than one node or requests that can change data on a target, Crossfyre waits. This phone shows the workspace, the action, each target with the scope entry that allows it, and where the request came from. Only requests made with your own account come here.",
        ),
        Triple(
            R.drawable.ic_key, "A key made on this phone",
            "Turning this on makes a signing key in the Android keystore. Its private half never leaves the phone. The app sends the public half to ${m.host} with this phone's model name and install ID, and you confirm the phone once in a signed-in browser.",
        ),
        Triple(
            R.drawable.ic_lock_key_open, "An unlock for every approval",
            "Your answer is signed with that key after you unlock the phone, so a CLI or agent key on a computer cannot approve for you. While this phone approves, a yes from the dashboard or from the agent's own client does not count. Either can still deny, and denying needs no unlock.",
        ),
        Triple(
            R.drawable.ic_clock, "Checked while the app is open",
            "While the app is on screen it asks ${m.host} every few seconds for approvals waiting for you. There is no push notification: with the app closed, requests reach you through the alerts you set up in the dashboard. Pending approvals and recent decisions are kept in memory while the app is open and are not written to the phone's storage.",
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

// ── The Activity tab ─────────────────────────────────────────────────────────
//
// Everything here that came from an agent or a scanned system is drawn with a
// plain Text: never through marked(), which reads backticks and asterisks, and
// never as a link. The strings were cleaned when they were read.

/** A clock that ticks once a second while it is on screen, for countdowns. */
@Composable
private fun ticking(): Long {
    var now by remember { mutableLongStateOf(android.os.SystemClock.elapsedRealtime()) }
    LaunchedEffect(Unit) {
        while (true) {
            now = android.os.SystemClock.elapsedRealtime()
            kotlinx.coroutines.delay(1000)
        }
    }
    return now
}

/** On Home, above everything: an agent is waiting for this phone. */
@Composable
fun PendingBanner(m: AppModel) {
    val first = m.pending.firstOrNull() ?: return
    val c = cfx
    val s = remember(first.summaryJson) { Summary.parse(first.summaryJson) }
    Column(
        Modifier.fillMaxWidth().background(c.warningTint).border(1.dp, c.mix(c.warning, 0.35f)).padding(horizontal = 14.dp, vertical = 12.dp),
        verticalArrangement = Arrangement.spacedBy(3.dp),
    ) {
        Text(
            if (m.pending.size == 1) "An agent is waiting for your approval" else "${m.pending.size} agent requests are waiting for you",
            style = TextStyle(fontFamily = CfxFonts.ui, fontWeight = FontWeight.SemiBold, fontSize = 14.5.sp, lineHeight = 20.sp, color = c.warningLight),
        )
        Text(listOfNotNull(s?.action?.label?.ifEmpty { null }, s?.workspace?.name?.ifEmpty { null }).joinToString(" · ").ifEmpty { "Open it to see what was asked." },
            style = T.hint().copy(color = c.text2))
        Row(Modifier.padding(top = 4.dp)) {
            CfxButton("Review", Kind.TEXT, small = true) { m.openApproval(first.id) }
            CfxButton("All activity", Kind.TEXT_DIM, small = true) { m.goTab("activity") }
        }
    }
}

@Composable
fun ActivityContent(m: AppModel) {
    val tick = ticking()
    val now = m.serverNow(tick)
    when (activityHeader(m.signedIn, m.approverState)) {
        ActivityHeader.SIGN_IN -> {
            Empty(
                R.drawable.ic_clock, "Sign in to see activity",
                "Approvals and your decisions on them come with an account. A QR pairing has neither.",
            ) { CfxButton("Sign in", Kind.SECONDARY, small = true) { m.toSignIn() } }
            return
        }
        ActivityHeader.TURN_ON -> CfxCard {
            Eyebrow("Approvals")
            m.approverTrouble?.let { Text(it, style = T.body().copy(color = cfx.warningLight)) }
            Text("Turn on approvals to approve what an agent asks to do, with an unlock on this phone.", style = T.body())
            Row { CfxButton("Turn on approvals", Kind.PRIMARY, small = true) { m.overlay = Overlay.ApprovalsExplain } }
        }
        ActivityHeader.ENROLLING -> CfxCard {
            Eyebrow("Approvals")
            Text("Waiting for you to confirm this phone in the browser.", style = T.body())
            Row { CfxButton("Show", Kind.SECONDARY, small = true) { m.overlay = Overlay.Enrol } }
        }
        ActivityHeader.LIVE -> {
            GroupLabel("Waiting for you")
            if (m.pending.isEmpty()) {
                CfxCard(tight = true) {
                    Text("Nothing is waiting.", style = T.rowTitle())
                    Text("When an agent asks for something that needs you, it shows up here while the app is open.", style = T.hint())
                }
            } else {
                CfxList { m.pending.forEachIndexed { i, a -> PendingRow(m, a, i == 0, now) } }
            }
            m.pendingTrouble?.let { Text(it, style = T.hint().copy(color = cfx.warning)) }
        }
    }

    GroupLabel("Recent decisions")
    when {
        m.history.isNotEmpty() -> CfxList { m.history.take(20).forEachIndexed { i, h -> HistoryItem(h, i == 0, now) } }
        m.historyStatus == ListStatus.LOADING -> CfxList { repeat(2) { SkelRow(first = it == 0) } }
        m.historyStatus == ListStatus.ERROR -> Text("Couldn't load recent decisions.", style = T.hint())
        else -> Text("No decisions yet.", style = T.hint())
    }

    if (ACTIVITY_LOG) ActivityLog(m, now)
    Text("Read from ${m.host} while the app is open and kept in memory. Nothing on this tab is written to the phone's storage.", style = T.hint())
}

@Composable
private fun ActivityLog(m: AppModel, now: Instant) {
    GroupLabel("Activity")
    val scopes = m.activityScopes
    if (scopes.size > 1) {
        Seg(
            scopes.map { sc -> key(sc) to if (sc is ActivityScope.Workspace) sc.name.ifEmpty { "Workspace" } else "Your account" },
            key(m.activityScope),
        ) { k -> scopes.firstOrNull { key(it) == k }?.let { m.chooseActivityScope(it) } }
    }
    m.activityNotice?.let { Banner(it, listOf("Try again" to { m.loadActivity() })) }
    when {
        m.activity.isNotEmpty() -> {
            CfxList { m.activity.forEachIndexed { i, e -> EventRow(m, e, i == 0, now) } }
            if (m.activityNext != null) {
                CfxButton("Show older", Kind.SECONDARY, block = true, busy = m.activityMoreBusy) { m.loadActivity(more = true) }
            }
        }
        m.activityStatus == ListStatus.LOADING -> CfxList { repeat(3) { SkelRow(first = it == 0) } }
        m.activityStatus == ListStatus.EMPTY -> Text("Nothing has happened here yet, or this account cannot read this view.", style = T.hint())
    }
}

private fun key(s: ActivityScope): String = when (s) {
    is ActivityScope.Workspace -> "ws:" + s.id
    ActivityScope.Account -> "account"
}

private fun secondsBetween(a: Instant?, b: Instant): Long = if (a == null) 0 else (b.epochSecond - a.epochSecond).coerceAtLeast(0)

@Composable
private fun PendingRow(m: AppModel, a: PendingApproval, first: Boolean, now: Instant) {
    val v = approvalView(a, now, m.approverState == ApproverState.ACTIVE)
    val s = v.summary
    CfxRow(
        s?.action?.label?.ifEmpty { null } ?: "Agent request", first = first, icon = R.drawable.ic_shield_check,
        sub = listOfNotNull(s?.workspace?.name?.ifEmpty { null }, s?.requester?.username?.ifEmpty { null }?.let { "asked by $it" }).joinToString(" · ").ifEmpty { null },
        note = when {
            !v.checked -> "Could not be checked: deny it or open it in the dashboard"
            s?.whole == false -> "Not shown in full: deny it or open it in the dashboard"
            else -> null
        },
        noteTone = Tone.WARN,
        value = countdown(v.secondsLeft), valueTone = if (v.secondsLeft < 60) Tone.WARN else Tone.NONE,
        chevron = R.drawable.ic_caret_right,
        onClick = { m.openApproval(a.id) },
    )
}

@Composable
private fun HistoryItem(h: HistoryRow, first: Boolean, now: Instant) {
    val (word, tone) = when (h.status) {
        "approved" -> "Approved" to Tone.OK
        "denied" -> "Denied" to Tone.DANGER
        "expired" -> "Expired" to Tone.NONE
        "cancelled" -> "Cancelled" to Tone.NONE
        else -> h.status.replaceFirstChar { it.uppercase() } to Tone.NONE
    }
    val via = when (h.decidedVia) {
        "phone" -> h.deviceName.ifEmpty { "a phone" }.let { "on $it" }
        "dashboard" -> "in the dashboard"
        "agent_client" -> "in the agent's client"
        "agent_cancel" -> "by the agent"
        "expiry" -> "by expiry"
        else -> ""
    }
    val launched = when (h.launchState) {
        "launched" -> "started"
        "launching" -> "starting"
        "failed" -> "did not start"
        else -> ""
    }
    CfxRow(
        h.actionLabel.ifEmpty { "Agent request" }, first = first,
        sub = listOf(h.workspaceName, via, ago(secondsBetween(h.decidedAt ?: h.createdAt, now))).filter { it.isNotEmpty() }.joinToString(" · "),
        note = launched.ifEmpty { null }?.let { "The request $it" }, noteTone = if (h.launchState == "failed") Tone.WARN else Tone.NONE,
        trailing = { Chip(word, tone) },
    )
}

@Composable
private fun EventRow(m: AppModel, e: ActivityEvent, first: Boolean, now: Instant) {
    CfxRow(
        activityLine(e), first = first,
        sub = listOf(e.subjectName, channelLabel(e.channel), ago(secondsBetween(e.at, now))).filter { it.isNotEmpty() }.joinToString(" · "),
        note = when (e.outcome) {
            "refused" -> "Refused"
            "error" -> "Failed"
            else -> null
        },
        noteTone = Tone.WARN,
        chevron = R.drawable.ic_caret_right,
        onClick = { m.overlay = Overlay.Event(e.id) },
    )
}

@Composable
fun BoxScope.EventSheet(m: AppModel, id: Long) {
    val e = m.activity.firstOrNull { it.id == id } ?: run { m.overlay = null; return }
    Sheet(title = { SheetTitle(activityLine(e)) }, onDismiss = { m.overlay = null }) {
        val rows = buildList {
            e.at?.let { add("When" to java.time.format.DateTimeFormatter.ofPattern("d MMM yyyy, HH:mm").withZone(java.time.ZoneId.systemDefault()).format(it)) }
            add("Who" to e.actorName.ifEmpty { e.actorKind })
            channelLabel(e.channel).takeIf { it.isNotEmpty() }?.let { add("Through" to it) }
            e.credentialLabel.takeIf { it.isNotEmpty() }?.let { add("Key" to it) }
            add("Action" to e.action)
            add("Outcome" to e.outcome)
            if (e.subjectName.isNotEmpty() || e.subjectType.isNotEmpty()) add("Subject" to listOf(e.subjectName, e.subjectType).filter { it.isNotEmpty() }.joinToString(", "))
            e.workspace?.let { add("Workspace" to it.name) }
            e.team?.let { add("Team" to it.name) }
            e.org?.let { add("Organization" to it.name) }
            addAll(e.detail)
        }
        Facts(rows, mono = setOf("Action", "Key"))
    }
}

/**
 * One approval, top to bottom: what is asked, who asked, where, each target with
 * the scope entry that admits it, the nodes, the options, the agent's own words
 * marked as such, and the time left by the server's clock.
 */
@Composable
fun BoxScope.ApprovalSheet(m: AppModel, id: String) {
    val c = cfx
    val a = m.approvalFor(id) ?: run { m.overlay = null; return }
    val now = m.serverNow(ticking())
    val v = approvalView(a, now, m.approverState == ApproverState.ACTIVE)
    val s = v.summary
    val busy = m.deciding == id
    Sheet(
        title = { SheetTitle(s?.action?.label?.ifEmpty { null } ?: "Agent request") },
        onDismiss = { m.overlay = null }, tall = true,
        foot = {
            when {
                a.status != "pending" -> Text(settledLine(a.status), style = T.body())
                v.secondsLeft <= 0 -> Text("This request expired. Nothing was started.", style = T.body())
                else -> Text("Expires in " + countdown(v.secondsLeft), style = T.mono(13.5.sp).copy(color = if (v.secondsLeft < 60) c.warning else c.text2))
            }
            m.decisionNotice?.let { Banner(it) }
            v.blocked?.takeIf { a.status == "pending" && v.secondsLeft > 0 }?.let { Text(it, style = T.hint().copy(color = c.warning)) }
            if (v.canDeny || v.canApprove) {
                Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                    CfxButton("Deny", Kind.DANGER_TEXT, Modifier.weight(1f), enabled = v.canDeny && !busy) { m.deny(id) }
                    if (v.canApprove) {
                        CfxButton("Approve", Kind.PRIMARY, Modifier.weight(1f), icon = R.drawable.ic_lock_key_open, busy = busy) { m.approve(id) }
                    }
                }
            } else {
                CfxButton("Close", Kind.SECONDARY, block = true) { m.overlay = null }
            }
        },
    ) {
        if (s == null) {
            Text("This request could not be read on this phone.", style = T.body())
            return@Sheet
        }
        val chips = riskChips(s)
        if (chips.isNotEmpty()) Wrap { for (chip in chips) Chip(chip, if (chip.startsWith("Can change")) Tone.DANGER else Tone.WARN) }

        Eyebrow("Who asked")
        Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
            Text("${s.requester.username.ifEmpty { "Someone" }}, through an agent", style = T.rowTitle())
            if (s.requester.keyName.isNotEmpty()) Text("Key: ${s.requester.keyName}", style = T.rowSub())
            val from = listOf(s.requester.ip, s.requester.location).filter { it.isNotEmpty() }.joinToString(", ")
            if (from.isNotEmpty()) Text("From $from", style = T.rowSub())
            if (s.requester.client.isNotEmpty()) {
                // One line, whatever the agent put in it, with the warning always in view.
                Row {
                    Text(
                        "Client says: ${s.requester.client}", style = T.rowSub(), maxLines = 1, overflow = TextOverflow.Ellipsis,
                        modifier = Modifier.weight(1f, fill = false),
                    )
                    Text(" (not verified)", style = T.rowSub(), maxLines = 1)
                }
            }
            Text(ago(secondsBetween(s.requestedAt ?: a.createdAt, now)), style = T.rowSub())
        }

        Eyebrow("Workspace")
        Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
            Text(s.workspace.name.ifEmpty { "Unnamed workspace" }, style = T.rowTitle())
            if (s.workspace.org.isNotEmpty()) Text(s.workspace.org, style = T.rowSub())
        }

        Eyebrow(if (s.targets.size == 1) "Target" else "${s.targets.size} targets")
        Targets(s.targets)

        if (s.nodes.isNotEmpty()) {
            Eyebrow(if (s.nodes.size == 1) "Node" else "${s.nodes.size} nodes")
            Text(s.nodes.joinToString(", ") { it.name.ifEmpty { it.id } }, style = T.body())
        }

        if (s.options.isNotEmpty()) {
            Eyebrow("Options")
            Facts(s.options, compact = true, mono = s.options.map { it.first }.toSet())
        }

        if (s.reason.isNotEmpty()) {
            Column(
                Modifier.fillMaxWidth().background(c.surface2).border(1.dp, c.line).padding(12.dp),
                verticalArrangement = Arrangement.spacedBy(4.dp),
            ) {
                Eyebrow("In the agent's words, not checked")
                Text(s.reason, style = T.body().copy(color = c.text2))
            }
        }
    }
}

private fun settledLine(status: String): String = when (status) {
    "approved" -> "Approved."
    "denied" -> "Denied. Nothing was started."
    "expired" -> "This request expired. Nothing was started."
    else -> "This request is no longer waiting. It was decided elsewhere, cancelled, or it expired."
}

@Composable
private fun Targets(targets: List<TargetRef>) {
    val c = cfx
    var all by remember { mutableStateOf(false) }
    val shown = if (all) targets else targets.take(20)
    Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
        for (t in shown) {
            // Three lines until asked for the rest: on a request that writes, the
            // end of a path is often where it says what it does.
            var open by remember(t) { mutableStateOf(false) }
            var cut by remember(t) { mutableStateOf(false) }
            Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                Text(
                    t.target.ifEmpty { t.host }, style = T.mono(13.sp),
                    maxLines = if (open) Int.MAX_VALUE else 3, overflow = TextOverflow.Ellipsis,
                    onTextLayout = { if (!open) cut = it.hasVisualOverflow },
                )
                if (cut && !open) Row { CfxButton("Show the whole target", Kind.TEXT, small = true) { open = true } }
                val adm = t.admittedBy
                if (adm == null || adm.entry.isEmpty()) {
                    Text("No scope entry was named for this target.", style = T.rowSub().copy(color = c.warning))
                } else {
                    Text(
                        buildAnnotatedString {
                            append("Allowed by ")
                            withStyle(SpanStyle(fontFamily = CfxFonts.mono, fontSize = 12.5.sp, color = c.text1)) { append(adm.entry) }
                            if (adm.addedBy.isNotEmpty()) append(", added by ${adm.addedBy}")
                            if (adm.addedOn.isNotEmpty()) append(" on ${shortDate(adm.addedOn)}")
                            if (adm.note.isNotEmpty()) append(" (${adm.note})")
                        },
                        style = T.rowSub(),
                    )
                }
            }
        }
        if (targets.size > 20 && !all) {
            Row { CfxButton("+${targets.size - 20} more", Kind.TEXT, small = true) { all = true } }
        }
    }
}

