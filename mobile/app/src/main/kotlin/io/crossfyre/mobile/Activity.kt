package io.crossfyre.mobile

import io.crossfyre.mobile.approve.ActivityEvent
import io.crossfyre.mobile.approve.Summary
import java.time.LocalDate
import java.time.format.DateTimeFormatter
import java.util.Locale

/** What the top of the Activity tab is about, from who is signed in and whether the phone approves. */
enum class ActivityHeader {
    /** Not signed in, or paired by QR only: nothing here can be read or approved. */
    SIGN_IN,
    /** Signed in, not approving: offer to turn approvals on. */
    TURN_ON,
    /** Waiting for the browser to confirm this phone. */
    ENROLLING,
    /** Approving: show what waits. */
    LIVE,
}

fun activityHeader(signedIn: Boolean, approver: ApproverState): ActivityHeader = when {
    !signedIn -> ActivityHeader.SIGN_IN
    approver == ApproverState.ACTIVE -> ActivityHeader.LIVE
    approver == ApproverState.ENROLLING -> ActivityHeader.ENROLLING
    else -> ActivityHeader.TURN_ON
}

/** How a channel is named on screen. */
fun channelLabel(channel: String): String = when (channel) {
    "dashboard" -> "Dashboard"
    "cli" -> "CLI"
    "mcp" -> "Agent"
    "valkyrie" -> "Valkyrie"
    "mobile" -> "Mobile"
    "system" -> "Crossfyre"
    else -> ""
}

/**
 * An activity row as a sentence: "asha started a scan". An action without a
 * phrase of its own is shown by its key in words, "asha · node egress changed",
 * so a new action on the server still reads as something rather than as a code.
 */
fun activityLine(e: ActivityEvent): String {
    val who = e.actorName.ifEmpty { if (e.actorKind == "system") "Crossfyre" else "Someone" }
    return PHRASES[e.action]?.let { "$who $it" } ?: "$who · ${e.action.replace('.', ' ').replace('_', ' ')}"
}

private val PHRASES = mapOf(
    "scan.created" to "created a scan",
    "scan.started" to "started a scan",
    "scan.halted" to "stopped a scan",
    "scan.deleted" to "deleted a scan",
    "routine.started" to "started a routine",
    "scope.added" to "added a scope entry",
    "scope.removed" to "removed a scope entry",
    "scope.refused" to "was refused a target outside the scope",
    "scope.narrowed" to "had targets outside the scope dropped",
    "scope.warned" to "used a target outside the scope",
    "scope.filtered" to "had results outside the scope filtered",
    "approval.requested" to "asked for an approval",
    "approval.granted" to "approved an agent request",
    "approval.denied" to "denied an agent request",
    "approval.expired" to "let an approval lapse",
    "approval.cancelled" to "cancelled an approval",
    "approver.added" to "added an approval phone",
    "approver.removed" to "removed an approval phone",
    "mcp_key.created" to "created an agent key",
    "mcp_key.revoked" to "revoked an agent key",
    "node.shell_exec" to "ran a command on a node",
    "bench.sent" to "sent a request from the Bench",
    "mobile.paired" to "paired a phone",
    "member.joined" to "joined",
    "member.invited" to "invited a member",
    "member.removed" to "removed a member",
    "api_key.created" to "created a key",
    "api_key.revoked" to "revoked a key",
    "permission.refused" to "was refused an action",
    "node.egress_changed" to "changed a node's egress",
    "node.egress_tested" to "tested a node's egress",
    "activity.exported" to "exported activity",
)

/** The badges an approval wears, in the order the screen shows them. */
fun riskChips(s: Summary): List<String> = buildList {
    val risk = s.action.risk
    if ("fleet" in risk) add(if (s.nodes.size > 1) "Runs on ${s.nodes.size} nodes" else "Runs on several nodes")
    if ("writes" in risk || s.action.writes) add("Can change data on the target")
    if ("active" in risk) add("Active testing")
    for (r in risk) if (r !in KNOWN_RISK) add(r)
}

private val KNOWN_RISK = setOf("fleet", "writes", "active", "traffic")

/** "12 Oct" for a scope entry's date, or the text as it came when it is not a date. */
fun shortDate(s: String): String =
    runCatching { LocalDate.parse(s.take(10)).format(DateTimeFormatter.ofPattern("d MMM", Locale.UK)) }.getOrDefault(s)
