package io.crossfyre.mobile

import org.json.JSONObject

/** The button a diagnosis offers, when there is one thing to do about it. */
enum class DiagAction(val label: String) {
    OPEN_DASHBOARD("Open in dashboard"),
    PAIR_AGAIN("Pair again"),
    SCAN_NEW_CODE("Scan a new code"),
}

data class Diag(val level: Level, val title: String, val body: String, val action: DiagAction? = null)

internal data class Stats(
    val flows: Long, val tlsFlows: Long, val caRejected: Long, val flowErrors: Long,
    val events: Long, val ingestSent: Long, val ingestRejected: Long, val ingestFailed: Long,
    val quicDropped: Long,
    val lastEvent: String, val lastError: String
) {
    /** Requests were captured and none of them could be delivered. */
    val notSent: Boolean get() = events > 0 && ingestSent == 0L && (ingestRejected > 0 || ingestFailed > 0)

    companion object {
        fun parse(json: String): Stats {
            val o = JSONObject(json)
            return Stats(
                o.optLong("flows"), o.optLong("tls_flows"), o.optLong("ca_rejected"), o.optLong("flow_errors"),
                o.optLong("events"), o.optLong("ingest_sent"), o.optLong("ingest_rejected"), o.optLong("ingest_failed"),
                o.optLong("quic_dropped"),
                o.optString("last_event"), o.optString("last_error")
            )
        }
    }
}

/**
 * Turn the raw counters into one actionable message: the whole point of the panel.
 *
 * @param patching this build can patch apps. The Play build cannot, and advice
 *   that sends someone to a Patch tab it does not have is worse than none.
 * @param renewable the pairing came from the signed-in account, so pairing again
 *   from the phone gets a new token. A QR pairing can only be replaced by
 *   scanning a new code.
 * @param host the server the requests go to, named when it does not answer.
 */
internal fun diagnose(
    running: Boolean,
    s: Stats?,
    patchedInScope: Boolean = false,
    flutterInScope: Boolean = false,
    patching: Boolean,
    renewable: Boolean,
    host: String = "The server",
): Diag? {
    if (!running || s == null) return null
    if (s.events > 0 && s.ingestSent > 0)
        return Diag(Level.OK, "Capturing and sending requests.", "Open the session in the dashboard to see them land.", DiagAction.OPEN_DASHBOARD)
    if (s.events > 0 && s.ingestRejected > 0)
        return if (renewable) {
            Diag(
                Level.WARN, "The server rejected the requests.",
                "The session token no longer works, usually because a pairing QR was made for this phone's session in the dashboard. Pairing again gets the phone a new token.",
                DiagAction.PAIR_AGAIN,
            )
        } else {
            Diag(
                Level.WARN, "The server rejected the requests.",
                "The session token no longer works, usually because a new pairing QR was made for this session in the dashboard. Scan the new one.",
                DiagAction.SCAN_NEW_CODE,
            )
        }
    if (s.events > 0 && s.ingestFailed > 0)
        return Diag(Level.WARN, "Captured requests, but the server can't be reached.", "$host isn't answering. Check the phone's connection.")
    // Two different refusals, and they need different advice. If OTHER hosts are
    // decrypting, the app already trusts this certificate, so a host that still
    // refuses is pinning its own API in code, and patching again will not help.
    // Telling someone to patch an app they have already patched is worse than
    // saying nothing: it sends them round a loop that cannot fix it.
    if (s.caRejected > 0 && flutterInScope)
        return if (patching) {
            Diag(Level.WARN, "A Flutter app is refusing the certificate.", "Flutter ships its own TLS stack, which only a patch can reach. Patch this app again from the Patch tab with the current build.")
        } else {
            Diag(Level.WARN, "A Flutter app is refusing the certificate.", "Flutter ships its own TLS stack and ignores Android's certificate settings, so its own API can't be read on this build.")
        }
    if (s.caRejected > 0 && patchedInScope && patching)
        return Diag(Level.WARN, "This app is patched and still refusing.", "It pins its own API in code, which patching does not remove, so those requests cannot be decrypted. Other hosts in the app will still capture normally.")
    if (s.caRejected > 0)
        return Diag(
            Level.WARN, "Apps are refusing the certificate.",
            "They don't trust this phone's certificate. " + if (patching) {
                "Patch the app from the Patch tab, or use one that trusts user certificates. Chrome ignores them entirely."
            } else {
                "Only apps that trust user certificates can be read on this build, and Chrome is not one of them. Firefox can be set up to: see Certificate."
            },
        )
    // HTTP/3 cannot be intercepted, so it is dropped to force a TCP fallback. An
    // app whose API is behind a CDN speaking h3 can sit there retrying QUIC for
    // up to a minute first, and while it does, the only thing captured is the
    // analytics traffic from SDKs that never tried h3. That looks exactly like
    // "capture is broken", so name it rather than leaving the operator guessing.
    val quic = "${s.quicDropped} QUIC ${if (s.quicDropped == 1L) "flow" else "flows"}"
    if (s.quicDropped > 0 && s.events == 0L)
        return Diag(Level.WARN, "Blocking HTTP/3 so traffic falls back to TCP.", "$quic dropped. Apps behind an HTTP/3 CDN can stall up to a minute before retrying over TCP. Give it a moment, then repeat the action.")
    if (s.flows > 0 && s.events == 0L)
        return Diag(Level.INFO, "Seeing traffic, no requests yet.", "Use an app that trusts the certificate, or wait for a request.")
    if (s.quicDropped > 0)
        return Diag(Level.INFO, "Capturing. Some HTTP/3 was dropped.", "$quic blocked so the app would retry over TCP, where it can be decrypted.")
    return Diag(Level.INFO, "No traffic captured yet.", "Make sure the app you're testing is in scope, then use it.")
}
