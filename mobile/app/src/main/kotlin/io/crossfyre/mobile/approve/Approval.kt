package io.crossfyre.mobile.approve

import org.json.JSONArray
import org.json.JSONObject
import java.net.URI
import java.security.MessageDigest
import java.time.Instant
import java.time.OffsetDateTime
import java.time.format.DateTimeFormatter

/**
 * The approval protocol as the phone sees it.
 *
 * An agent working with someone's account asks the platform to do something
 * that needs a person: a scan across more than one node, or requests that can
 * change data on a target. The platform keeps the request, describes it in
 * `summary_json`, and waits. The phone shows that description, and when its
 * owner unlocks it and taps Approve, it signs the exact text it showed, by its
 * SHA-256, with a key that exists only in this phone's keystore.
 *
 * Nothing here touches Android, so all of it runs in plain JVM tests.
 */
object ApprovalProtocol {
    /** The first line of every signed message, so a signature cannot be reused for anything else. */
    const val CONTEXT = "crossfyre-approval-v1"

    /**
     * What the phone signs: six lines of UTF-8, joined by `\n`, with no newline at
     * the end. The server rebuilds the same bytes from its own copy of the digest,
     * so a phone that showed one request cannot approve another.
     */
    fun signingBytes(id: String, decision: String, digest: String, signedAt: Long, approverId: String): ByteArray =
        listOf(CONTEXT, id, decision, digest, signedAt.toString(), approverId)
            .joinToString("\n")
            .toByteArray(Charsets.UTF_8)

    fun sha256Hex(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }

    /**
     * Whether [digest] is the SHA-256 of the summary text exactly as received.
     *
     * The phone recomputes it rather than trusting the field next to it, and offers
     * Approve only when the two agree, because the digest is what gets signed and
     * the text is what the person read.
     */
    fun digestMatches(summaryJson: String, digest: String): Boolean {
        if (!HEX64.matches(digest)) return false
        return sha256Hex(summaryJson.toByteArray(Charsets.UTF_8)) == digest.lowercase()
    }

    private val HEX64 = Regex("^[0-9a-fA-F]{64}$")
}

/** Approval ids: a UUID on the wire and in the link a notification carries. */
object ApprovalIds {
    private val UUID = Regex("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")

    fun normal(id: String): String? = id.trim().lowercase().takeIf { UUID.matches(it) }

    /**
     * The approval id in a link to `/m/approve/<id>`, or null.
     *
     * Only a link to the server this app talks to counts: same scheme, host and
     * port. A link that names another host could point the phone at a request it
     * never received, so it opens nothing.
     */
    fun fromLink(link: String, origin: String): String? {
        val u = runCatching { URI(link) }.getOrNull() ?: return null
        val o = runCatching { URI(origin) }.getOrNull() ?: return null
        if (!u.scheme.equals(o.scheme, ignoreCase = true)) return null
        if (!u.host.equals(o.host, ignoreCase = true)) return null
        if (portOf(u) != portOf(o)) return null
        val path = u.rawPath ?: return null
        val rest = path.removePrefix("/m/approve/").takeIf { it != path } ?: return null
        return normal(rest.trimEnd('/'))
    }

    private fun portOf(u: URI): Int = when {
        u.port > 0 -> u.port
        u.scheme.equals("https", ignoreCase = true) -> 443
        u.scheme.equals("http", ignoreCase = true) -> 80
        else -> -1
    }
}

/**
 * Text that came from an agent or a scanned system, made safe to show.
 *
 * The same rules as the server's and the MCP server's: escape sequences, control
 * characters other than newline and tab, and the code points that render as
 * nothing or reorder what is around them are removed, and the result is capped
 * by characters. A request that hides words from the person approving it must
 * not get the approval those words would have lost it.
 */
object Untrusted {
    private val ANSI = Regex("\u001b\\[[0-?]*[ -/]*[@-~]|\u001b][^\u0007\u001b]*(?:\u0007|\u001b\\\\)|\u001b[@-Z\\\\-_]")

    fun clean(s: String, cap: Int): String {
        val cleaned = ANSI.replace(s, "")
        val out = StringBuilder()
        var kept = 0
        var i = 0
        while (i < cleaned.length) {
            val cp = cleaned.codePointAt(i)
            i += Character.charCount(cp)
            if ((Character.isISOControl(cp) && cp != '\n'.code && cp != '\t'.code) || invisible(cp)) continue
            if (kept == cap) break
            out.appendCodePoint(cp)
            kept++
        }
        return out.toString()
    }

    private fun invisible(c: Int): Boolean =
        c in 0x200B..0x200F || c in 0x2060..0x2064 || c == 0xFEFF ||
            c in 0x202A..0x202E || c in 0x2066..0x2069 || c == 0x061C || c == 0x180E ||
            c == 0x00AD || c == 0x034F || c == 0x115F || c == 0x1160 || c == 0x3164 || c == 0xFFA0 ||
            c in 0xFE00..0xFE0F || c in 0xE0100..0xE01EF || c in 0x180B..0x180F ||
            c == 0x2028 || c == 0x2029 || c in 0x206A..0x206F || c in 0xFFF9..0xFFFB ||
            c == 0x17B4 || c == 0x17B5 ||
            c in 0x0600..0x0605 || c == 0x06DD || c == 0x070F || c == 0x0890 || c == 0x0891 || c == 0x08E2 ||
            c == 0x110BD || c == 0x110CD || c in 0x13430..0x1343F || c in 0x1BCA0..0x1BCA3 ||
            c in 0x1D173..0x1D17A || c in 0xE0000..0xE007F

    /** Caps from the protocol: names, scope entries, the agent's reason, option values. */
    const val NAME = 80
    const val ENTRY = 255
    const val REASON = 200
    const val OPTION = 200
    const val OPTION_KEYS = 20
}

/** One approval waiting for this account, as `/cli/approvals/pending` lists it. */
data class PendingApproval(
    val id: String,
    val status: String,
    val createdAt: Instant?,
    val expiresAt: Instant?,
    val summaryJson: String,
    val digest: String,
)

/** Who asked. Everything but [username] and [keyName] is the agent's own account of itself. */
data class Requester(
    val username: String,
    val keyName: String,
    val client: String,
    val ip: String,
    val location: String,
)

data class WorkspaceRef(val id: String, val name: String, val org: String)

data class ActionRef(val tool: String, val label: String, val risk: List<String>, val writes: Boolean)

/** The scope entry that lets a target be tested, and who put it there. */
data class Admission(val entry: String, val addedBy: String, val addedOn: String, val note: String)

data class TargetRef(val target: String, val host: String, val admittedBy: Admission?)

data class NodeRef(val id: String, val name: String)

/**
 * What the phone shows, read out of `summary_json`. Every string is cleaned and
 * capped on the way in, whatever the server already did to it.
 */
data class Summary(
    val version: Int,
    val id: String,
    val requestedAt: Instant?,
    val expiresAt: Instant?,
    val requester: Requester,
    val workspace: WorkspaceRef,
    val action: ActionRef,
    val targets: List<TargetRef>,
    val nodes: List<NodeRef>,
    val options: List<Pair<String, String>>,
    val reason: String,
    val requestDigest: String,
) {
    companion object {
        /** The summary, or null when the text is not a version-1 summary this app can show. */
        fun parse(summaryJson: String): Summary? {
            val o = runCatching { JSONObject(summaryJson) }.getOrNull() ?: return null
            val version = o.optInt("v", 0)
            if (version != 1) return null
            val id = o.text("id", 64).takeIf { it.isNotEmpty() } ?: return null
            val action = o.optJSONObject("action") ?: return null
            val req = o.optJSONObject("requester") ?: JSONObject()
            val ws = o.optJSONObject("workspace") ?: JSONObject()
            return Summary(
                version = version,
                id = id,
                requestedAt = instant(o.text("requested_at", 64)),
                expiresAt = instant(o.text("expires_at", 64)),
                requester = Requester(
                    username = req.text("username", Untrusted.NAME),
                    keyName = req.text("key_name", Untrusted.NAME),
                    client = req.text("client", Untrusted.NAME),
                    ip = req.text("ip", Untrusted.NAME),
                    location = req.text("location", Untrusted.NAME),
                ),
                workspace = WorkspaceRef(ws.text("id", 64), ws.text("name", Untrusted.NAME), ws.text("org", Untrusted.NAME)),
                action = ActionRef(
                    tool = action.text("tool", Untrusted.NAME),
                    label = action.text("label", Untrusted.NAME),
                    risk = action.optJSONArray("risk").strings(Untrusted.NAME),
                    writes = action.optBoolean("writes", false),
                ),
                targets = o.optJSONArray("targets").objects().map { t ->
                    TargetRef(
                        target = t.text("target", Untrusted.ENTRY),
                        host = t.text("host", Untrusted.ENTRY),
                        admittedBy = t.optJSONObject("admitted_by")?.let { a ->
                            Admission(
                                entry = a.text("entry", Untrusted.ENTRY),
                                addedBy = a.text("added_by", Untrusted.NAME),
                                addedOn = a.text("added_on", 32),
                                note = a.text("note", Untrusted.NAME),
                            )
                        },
                    )
                },
                nodes = o.optJSONArray("nodes").objects().map { NodeRef(it.text("id", 64), it.text("name", Untrusted.NAME)) },
                options = o.optJSONObject("options")?.let { opts ->
                    opts.keys().asSequence().sorted().take(Untrusted.OPTION_KEYS).map { k ->
                        Untrusted.clean(k, 64) to Untrusted.clean(scalar(opts.opt(k)), Untrusted.OPTION)
                    }.toList()
                }.orEmpty(),
                reason = o.text("reason", Untrusted.REASON),
                requestDigest = o.text("request_digest", 64),
            )
        }

        private fun scalar(v: Any?): String = when (v) {
            null, JSONObject.NULL -> ""
            is JSONArray -> (0 until v.length()).joinToString(", ") { scalar(v.opt(it)) }
            else -> v.toString()
        }
    }
}

/** What the screen offers for one approval, decided from the facts and nothing else. */
data class ApprovalView(
    val approval: PendingApproval,
    val summary: Summary?,
    /** The text was the one the digest names, and it reads as a summary of this approval. */
    val checked: Boolean,
    val secondsLeft: Long,
    val canApprove: Boolean,
    val canDeny: Boolean,
    /** Why Approve is not offered, when it is not. */
    val blocked: String?,
)

/**
 * Decide what the approval screen offers.
 *
 * Approve needs all of: a digest that matches the text, a summary that parses and
 * names this approval, an approval still pending and not past its expiry by the
 * server's clock, and this phone's approver active. Deny needs only a pending
 * approval: refusing is always safe.
 */
fun approvalView(a: PendingApproval, serverNow: Instant, approverActive: Boolean): ApprovalView {
    val summary = Summary.parse(a.summaryJson)
    val checked = ApprovalProtocol.digestMatches(a.summaryJson, a.digest) && summary != null && summary.id == a.id
    val expires = a.expiresAt ?: summary?.expiresAt
    val left = if (expires == null) 0L else (expires.epochSecond - serverNow.epochSecond).coerceAtLeast(0)
    val pending = a.status == "pending" && left > 0
    val blocked = when {
        !checked -> "This request could not be checked. Deny it, or open it in the dashboard."
        !pending -> "This request is no longer waiting."
        !approverActive -> "This phone does not approve agent actions. Turn on Approvals in Settings."
        else -> null
    }
    return ApprovalView(a, summary, checked, left, canApprove = blocked == null, canDeny = pending, blocked = blocked)
}

/**
 * How often the phone asks for pending approvals while it is open: every five
 * seconds for two minutes after it comes to the front, or while something is
 * waiting, and every fifteen otherwise. Nothing asks while it is out of sight.
 */
object PollPolicy {
    const val FAST_MS = 5_000L
    const val SLOW_MS = 15_000L
    const val FAST_WINDOW_MS = 120_000L

    fun next(sinceResumeMs: Long, hasPending: Boolean): Long =
        if (hasPending || sinceResumeMs < FAST_WINDOW_MS) FAST_MS else SLOW_MS
}

/** The server's clock, carried forward on this phone's monotonic one, so a wrong phone clock does not matter. */
class ServerClock(private val serverAt: Instant, private val elapsedAtMs: Long) {
    fun now(elapsedNowMs: Long): Instant = serverAt.plusMillis((elapsedNowMs - elapsedAtMs).coerceAtLeast(0))
}

/** "7:42", for a countdown. */
fun countdown(seconds: Long): String {
    val s = seconds.coerceAtLeast(0)
    return "%d:%02d".format(s / 60, s % 60)
}

/** A timestamp from the server: RFC 3339, with `Z` or an offset. */
fun instant(s: String?): Instant? {
    if (s.isNullOrBlank()) return null
    return runCatching { OffsetDateTime.parse(s, DateTimeFormatter.ISO_OFFSET_DATE_TIME).toInstant() }.getOrNull()
        ?: runCatching { Instant.parse(s) }.getOrNull()
}

internal fun JSONObject.text(name: String, cap: Int): String =
    if (!has(name) || isNull(name)) "" else Untrusted.clean(opt(name).toString(), cap)

internal fun JSONArray?.objects(): List<JSONObject> =
    if (this == null) emptyList() else (0 until length()).mapNotNull { optJSONObject(it) }

internal fun JSONArray?.strings(cap: Int): List<String> =
    if (this == null) emptyList()
    else (0 until length()).mapNotNull { i -> if (isNull(i)) null else Untrusted.clean(opt(i).toString(), cap) }.filter { it.isNotEmpty() }
