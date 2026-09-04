package io.crossfyre.tracer

import android.content.Context

/**
 * The workspace pairing: `api_url`, `workflow_id`, and a scoped `token`, obtained by scanning a QR
 * from the web app. Persisted so capture can POST events to the right workspace. The QR payload is a
 * JSON object: {"api_url":"...","workflow_id":"...","token":"..."}.
 */
data class Pairing(val apiUrl: String, val workflowId: String, val token: String) {
    companion object {
        private const val PREFS = "pairing"

        fun load(ctx: Context): Pairing? {
            val p = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            val api = p.getString("api_url", null) ?: return null
            val wf = p.getString("workflow_id", null) ?: return null
            val tok = p.getString("token", null) ?: return null
            return Pairing(api, wf, tok)
        }

        /**
         * Parse and validate a scanned QR payload WITHOUT persisting it.
         *
         * Scanning a QR code is not consent. This value decides where every
         * captured request is sent and, through [Patcher], where the APK that
         * gets installed on this device comes from, so a code from a sticker,
         * a screenshot or a chat message must not be able to configure the app
         * on its own. The caller shows the host to the user and calls [persist]
         * only if they agree.
         *
         * Returns null when the payload is malformed or the URL is not one we
         * will talk to.
         */
        fun parseQr(payload: String): Pairing? {
            if (payload.length > 4096) return null
            val obj = runCatching { org.json.JSONObject(payload) }.getOrNull() ?: return null
            val api = normaliseApiUrl(obj.optString("api_url")) ?: return null
            val wf = obj.optString("workflow_id").ifEmpty { return null }
            val tok = obj.optString("token").ifEmpty { return null }
            if (wf.length > 200 || tok.length > 4096) return null
            return Pairing(api, wf, tok)
        }

        /** Commit a pairing the user has seen and accepted. */
        fun persist(ctx: Context, p: Pairing) {
            ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
                .putString("api_url", p.apiUrl)
                .putString("workflow_id", p.workflowId)
                .putString("token", p.token)
                .apply()
        }

        /**
         * The control-plane origin, or null if we will not use it.
         *
         * Requires https, because the Rust capture path uses its own TLS stack
         * and so does not inherit the platform's cleartext ban: an `http://`
         * ingest URL shipped every captured request, headers and bodies
         * included, in the clear. Debug builds additionally allow http on
         * loopback and private ranges so the dev stack still works.
         */
        fun normaliseApiUrl(raw: String): String? {
            val s = raw.trim().removeSuffix("/")
            if (s.isEmpty() || s.length > 2048) return null
            if (s.any { it.isISOControl() }) return null
            val uri = runCatching { java.net.URI(s) }.getOrNull() ?: return null
            val host = uri.host ?: return null
            if (uri.userInfo != null) return null
            return when (uri.scheme?.lowercase()) {
                "https" -> s
                "http" -> if (BuildConfig.DEBUG && isLocalHost(host)) s else null
                else -> null
            }
        }

        private fun isLocalHost(host: String): Boolean =
            host == "localhost" ||
                host == "127.0.0.1" ||
                host.startsWith("10.") ||
                host.startsWith("192.168.") ||
                Regex("^172\\.(1[6-9]|2[0-9]|3[01])\\.").containsMatchIn(host)

        /** Host shown to the user in the pairing confirmation. */
        fun hostOf(apiUrl: String): String =
            runCatching { java.net.URI(apiUrl).host }.getOrNull() ?: apiUrl

        /** Forget the workspace pairing (Unpair). */
        fun clear(ctx: Context) {
            ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().clear().apply()
        }
    }
}

/**
 * The device's own answer to full capture.
 *
 * The control plane can ask for full capture (headers and bodies rather than
 * request shape); this is the only thing that grants it. Kept separate from the
 * pairing so that re-pairing cannot quietly carry consent with it, and default
 * false so the app's stated privacy behaviour is what actually happens.
 */
object FullCapturePrefs {
    private const val PREFS = "capture"

    fun allowed(ctx: Context): Boolean =
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getBoolean("allow_full", false)

    fun set(ctx: Context, allow: Boolean) {
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().putBoolean("allow_full", allow).apply()
    }
}

/**
 * Persisted capture scope, so the operator's choice survives closing the app: mode ('all' | 'only' |
 * 'except') plus the selected package names.
 */
object ScopePrefs {
    private const val PREFS = "scope"

    fun save(ctx: Context, mode: String, apps: Set<String>) {
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
            .putString("mode", mode)
            .putStringSet("apps", apps)
            .apply()
    }

    /** (mode, apps) with sensible defaults when nothing is stored. */
    fun load(ctx: Context): Pair<String, Set<String>> {
        val p = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        return Pair(p.getString("mode", "all") ?: "all", p.getStringSet("apps", emptySet()) ?: emptySet())
    }
}

/**
 * Which CA each app was patched with.
 *
 * Patching embeds the CA into the app (`apk-mitm --certificate ca.pem`), so a
 * patched app trusts exactly one certificate forever. Rotate the CA and every
 * previously patched app keeps trusting the old one and fails the handshake with
 * `CertificateUnknown` the moment it is captured.
 *
 * Nothing used to record this, so nothing could tell you it had happened. The
 * app looked patched, the switch looked on, and capture produced an empty tab
 * and a TLS alert in a log nobody reads. Storing the fingerprint at patch time
 * is what lets the scope list say "re-patch needed" instead of leaving you to
 * work it out.
 */
object PatchPrefs {
    private const val PREFS = "patches"

    /** Record that [pkg] was patched with the CA identified by [caFingerprint]. */
    fun record(ctx: Context, pkg: String, caFingerprint: String) {
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit().putString(pkg, caFingerprint).apply()
    }

    /** The CA fingerprint [pkg] was patched with, or null if we never patched it. */
    fun caFor(ctx: Context, pkg: String): String? =
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString(pkg, null)

    fun forget(ctx: Context, pkg: String) {
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().remove(pkg).apply()
    }

    /** Every package we have patched, whether or not it is still current. */
    fun all(ctx: Context): Map<String, String> {
        @Suppress("UNCHECKED_CAST")
        return ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).all
            .filterValues { it is String } as Map<String, String>
    }

    /** Packages patched with a CA that is no longer the current one. */
    fun stale(ctx: Context, currentCa: String?): List<String> {
        if (currentCa.isNullOrEmpty()) return emptyList()
        return all(ctx).filterValues { it != currentCa }.keys.sorted()
    }

    fun clear(ctx: Context) {
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().clear().apply()
    }
}
