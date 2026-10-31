package io.crossfyre.mobile

import io.crossfyre.mobile.approve.ActivityEvent
import io.crossfyre.mobile.approve.HistoryRow
import io.crossfyre.mobile.approve.InboxItem
import io.crossfyre.mobile.approve.InboxPage
import io.crossfyre.mobile.approve.PendingApproval
import io.crossfyre.mobile.approve.Summary
import java.net.URI
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

/**
 * What Home's banner and the Activity tab's badge count as waiting. The list is
 * asked for only while the phone approves, so in any other state it is stale,
 * and a phone that cannot approve is not waited for.
 */
fun waitingForYou(approver: ApproverState, pending: List<PendingApproval>): List<PendingApproval> =
    if (approver == ApproverState.ACTIVE) pending else emptyList()

/**
 * Whether the tab reads and shows the activity log. A key route can be called
 * with any account key, the CLI's on the host an agent runs on included, and
 * the log names the people, keys and targets of every workspace the account
 * belongs to. `/cli/activity/list` answers only a key whose own approver is
 * active, under the owner's roles, and never exports, so the tab reads it, and
 * only while this phone approves.
 */
const val ACTIVITY_LOG = true

/** The scan states in which a stop has something to stop. */
private val RUNNING = setOf("running", "populating")
private val HEX64 = Regex("^[0-9a-fA-F]{64}$")

/**
 * Whether a decided request's scan can be stopped from this phone: it was
 * approved, it launched a scan, that scan still runs, and the row carries the
 * digest a stop is signed over. Without the digest the platform could only
 * refuse the signature, so the button is not offered.
 */
fun stoppable(h: HistoryRow): Boolean =
    h.status == "approved" && h.launchState == "launched" && h.workflowId.isNotEmpty() &&
        h.workflowStatus in RUNNING && HEX64.matches(h.digest)

/**
 * The page a notification's link opens: `{origin}{link}`, for a link that is a
 * path on this app's own server and nothing else. It must start with one `/`
 * (two would name another host), hold no space, backslash or control character,
 * and come out on the same scheme, host and port as [origin]. Anything else
 * opens nothing.
 */
fun notificationUrl(origin: String, link: String?): String? {
    if (link.isNullOrEmpty() || !link.startsWith("/") || link.startsWith("//")) return null
    if (link.any { it.isWhitespace() || it.isISOControl() || it == '\\' }) return null
    val base = origin.trimEnd('/')
    val url = base + link
    val u = runCatching { URI(url) }.getOrNull() ?: return null
    val o = runCatching { URI(base) }.getOrNull() ?: return null
    if (u.scheme == null || !u.scheme.equals(o.scheme, ignoreCase = true)) return null
    if (u.host == null || !u.host.equals(o.host, ignoreCase = true) || u.port != o.port) return null
    if (u.rawUserInfo != null) return null
    return url
}

/**
 * The Notifications section's rows: pages as they arrive, newest first, and
 * rows marked read once the server says so. Plain data, so it is tested on the
 * JVM; nothing of it is written to storage.
 */
data class InboxList(
    val items: List<InboxItem> = emptyList(),
    val total: Int = 0,
    val unread: Int = 0,
    /** The last page read; 0 before the first. */
    val page: Int = 0,
) {
    /** Whether there are older rows than the ones shown. */
    val more: Boolean get() = page > 0 && items.size < total

    /**
     * With [p] read: page 1 replaces what was shown, a later page adds the rows
     * not already shown. Pages count from the newest row, so one that arrived in
     * between moves the rest down and a later page can repeat a row.
     */
    fun with(p: InboxPage): InboxList =
        if (p.page <= 1) InboxList(p.items, p.total, p.unread, 1)
        else InboxList(items + p.items.filter { n -> items.none { it.id == n.id } }, p.total, p.unread, p.page)

    /** [ids] marked read on the server, with [unread] the count it gave back. */
    fun read(ids: Collection<String>, unread: Int): InboxList =
        copy(items = items.map { if (it.id in ids) it.copy(read = true) else it }, unread = unread)

    /** Every row marked read on the server. */
    fun allRead(unread: Int): InboxList = copy(items = items.map { it.copy(read = true) }, unread = unread)
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

/**
 * Who or what decided a request, as the Recent decisions list says it. A deny sent
 * with an account key is neither a phone's signature nor the dashboard: the history
 * names it `account_key` and the Cloud API `other`, and either is a device signed in
 * to the account.
 */
fun decidedBy(via: String, deviceName: String): String = when (via) {
    "phone" -> deviceName.ifEmpty { "a phone" }.let { "on $it" }
    "dashboard" -> "in the dashboard"
    "agent_client" -> "in the agent's client"
    "account_key", "other" -> "from a signed-in device"
    "agent_cancel" -> "by the agent"
    "expiry" -> "by expiry"
    else -> ""
}

/** "12 Oct" for a scope entry's date, or the text as it came when it is not a date. */
fun shortDate(s: String): String =
    runCatching { LocalDate.parse(s.take(10)).format(DateTimeFormatter.ofPattern("d MMM", Locale.UK)) }.getOrDefault(s)
