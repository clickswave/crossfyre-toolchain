package io.crossfyre.mobile

import org.json.JSONArray

/** What the capture card claims. */
enum class Phase { IDLE, STARTING, CAPTURING }

/**
 * Capture has three states and asking for it is not the same as having it.
 *
 * Asking starts a tunnel, an interface from Android and the native stack, and
 * that takes a moment. Showing only what was asked for said Capturing before
 * anything was; showing only what the service reached said Idle in the gap. Both
 * are claims about somebody's traffic, so the gap gets its own word, and a start
 * that never arrives is said out loud once [graceMs] has passed.
 *
 * Times are `elapsedRealtime`, because this measures a duration and the wall
 * clock can move under it.
 */
class StartWatch(private val graceMs: Long = 8_000L) {
    private var askedAt = 0L

    /** The last start was asked for and never came up. */
    var failed: Boolean = false
        private set

    fun asked(now: Long) {
        askedAt = now
        failed = false
    }

    fun stopped() {
        askedAt = 0L
        failed = false
    }

    /** Read the service's state, and say which of the three the card should show. */
    fun phase(serviceActive: Boolean, now: Long): Phase {
        if (serviceActive) {
            askedAt = 0L
            failed = false
            return Phase.CAPTURING
        }
        if (askedAt > 0L) {
            if (now - askedAt > graceMs) {
                askedAt = 0L
                failed = true
                return Phase.IDLE
            }
            return Phase.STARTING
        }
        return Phase.IDLE
    }
}

/**
 * Which apps go through the tunnel.
 *
 * `all` is the whole phone, `only` the ticked apps, and `except` everything but
 * them, which is how apps that pin their certificate keep working while the rest
 * is captured. A list mode with nothing ticked means the whole phone, which is
 * also what the service does with it.
 */
data class Scope(val mode: String, val apps: List<String>) {
    val effectiveMode: String get() = if (apps.isEmpty()) ALL else mode

    fun title(): String {
        val n = apps.size
        val noun = if (n == 1) "app" else "apps"
        return when (effectiveMode) {
            ONLY -> "Only $n $noun"
            EXCEPT -> "All except $n $noun"
            else -> "Whole phone"
        }
    }

    fun sub(labelOf: (String) -> String): String {
        val names = apps.joinToString(", ") { labelOf(it) }
        return when (effectiveMode) {
            ONLY -> names
            EXCEPT -> "Left alone: $names"
            else -> "Every app except Crossfyre Mobile itself"
        }
    }

    /** The scope inside a sentence: "the whole phone", "only 2 apps". */
    fun inline(): String = if (effectiveMode == ALL) "the whole phone" else title().lowercase()

    companion object {
        const val ALL = "all"
        const val ONLY = "only"
        const val EXCEPT = "except"
    }
}

/** The one line under the state chip on the capture card. */
internal fun capLine(phase: Phase, scope: Scope, s: Stats?, destination: String): String {
    val scopeText = scope.inline()
    return when (phase) {
        Phase.IDLE -> "Not capturing. Scope: $scopeText."
        Phase.STARTING -> "Android is bringing the tunnel up."
        Phase.CAPTURING -> {
            val sent = s?.ingestSent ?: 0
            val captured = s?.events ?: 0
            if (s != null && s.notSent) {
                "${requests(captured)} captured, ${fmt(sent)} sent. Scope: $scopeText."
            } else {
                "${requests(sent)} sent to $destination. Scope: $scopeText."
            }
        }
    }
}

private fun requests(n: Long) = "${fmt(n)} ${if (n == 1L) "request" else "requests"}"

/** A count with thousands separators, as the counters show it. */
fun fmt(n: Long): String = "%,d".format(java.util.Locale.US, n)

/** What starting a capture has to get past, in the order it asks. */
enum class StartStep {
    /** The one-time account of what capture does, before Android's own prompts. */
    DISCLOSE,
    /** An app in scope will not decrypt, and the person has not said to start anyway. */
    PREFLIGHT,
    /** Android 13 and later only show the capture notification once allowed. */
    NOTIFICATIONS,
    /** Android's VPN consent. */
    VPN,
    START,
}

/**
 * The next thing between a tap on Start and a running capture.
 *
 * Notifications are asked before the VPN rather than after, because the VPN
 * dialog is the one that matters and a permission sheet stacked on its answer
 * reads like the app is still asking for things after being told yes. Each is
 * asked once per tap: an answer of no is a reason to say so on the card, not to
 * refuse to capture.
 */
fun nextStartStep(
    disclosed: Boolean,
    preflightWarnings: Boolean,
    preflightAcknowledged: Boolean,
    notificationsToAsk: Boolean,
    vpnConsentNeeded: Boolean,
): StartStep = when {
    !disclosed -> StartStep.DISCLOSE
    preflightWarnings && !preflightAcknowledged -> StartStep.PREFLIGHT
    notificationsToAsk -> StartStep.NOTIFICATIONS
    vpnConsentNeeded -> StartStep.VPN
    else -> StartStep.START
}

/**
 * One captured request as the phone kept it: the reduced shape that is sent,
 * never a value.
 */
data class RecentRequest(
    val method: String,
    val url: String,
    val status: Int?,
    val authed: Boolean,
    val bodyFields: List<String>,
    val atMs: Long,
    val sent: Boolean,
) {
    val host: String get() = runCatching { java.net.URI(url).host }.getOrNull() ?: ""

    /** The path with its query, whose values were blanked before it was kept. */
    val path: String
        get() {
            val afterScheme = url.substringAfter("://", url)
            val i = afterScheme.indexOf('/')
            return if (i < 0) "/" else afterScheme.substring(i)
        }

    val pathOnly: String get() = path.substringBefore('?')

    /** Which request this is, stable while newer ones arrive above it. */
    val key: String get() = "$atMs|$method|$url"

    companion object {
        fun parseList(json: String): List<RecentRequest> {
            val a = runCatching { JSONArray(json) }.getOrNull() ?: return emptyList()
            return (0 until a.length()).mapNotNull { i ->
                val o = a.optJSONObject(i) ?: return@mapNotNull null
                val fields = o.optJSONArray("body_params")
                RecentRequest(
                    method = o.optString("method", "GET"),
                    url = o.optString("url"),
                    status = if (o.isNull("status") || !o.has("status")) null else o.optInt("status"),
                    authed = o.optBoolean("authed", false),
                    bodyFields = if (fields == null) emptyList() else (0 until fields.length()).map { fields.optString(it) },
                    atMs = o.optLong("at_ms"),
                    sent = o.optBoolean("sent", false),
                )
            }
        }
    }
}

/** "just now", "12s ago", "3m ago". */
fun ago(seconds: Long): String = when {
    seconds < 2 -> "just now"
    seconds < 60 -> "${seconds}s ago"
    seconds < 3600 -> "${seconds / 60}m ago"
    else -> "${seconds / 3600}h ago"
}

/**
 * The two ends of a device code, which is what the approval page shows large.
 *
 * The whole code is long enough to wrap twice on a phone and nobody compares
 * the middle of it; the ends are what a person checks. Short codes are shown
 * whole.
 */
fun codeEnds(code: String): Pair<String, String>? {
    if (code.length <= 24) return null
    val head = code.substringBefore('_', "").let { prefix ->
        if (prefix.isNotEmpty() && prefix.length < 8) code.take(prefix.length + 1 + 8) else code.take(12)
    }
    return head to code.takeLast(8)
}

/** A SHA-256 in hex as four lines of four groups, the way it is read aloud. */
fun fingerprintLines(hex: String): List<String> =
    hex.uppercase().chunked(4).chunked(4).map { it.joinToString(" ") }

/**
 * The host as a person would type it: no scheme, and the port only when there
 * is one. A dev stack is told apart by its port, so that stays.
 */
fun displayHost(origin: String): String {
    val uri = runCatching { java.net.URI(origin) }.getOrNull() ?: return origin
    val host = uri.host ?: return origin
    return if (uri.port > 0) "$host:${uri.port}" else host
}
