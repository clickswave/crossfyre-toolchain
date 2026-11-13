package io.crossfyre.mobile

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
         * captured request is sent and, in the direct build, where the APK that
         * gets installed by a patch comes from, so a code from a sticker,
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

        /** Commit a pairing the user has seen and accepted. A new pairing has not ended. */
        fun persist(ctx: Context, p: Pairing) {
            ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
                .putString("api_url", p.apiUrl)
                .putString("workflow_id", p.workflowId)
                .putString("token", p.token)
                .putBoolean("ended", false)
                .putBoolean("refused", false)
                .commit()
        }

        /**
         * The session this pairing belongs to has ended.
         *
         * Stopping capture sends the final batch marked as the end of the
         * session, and the ingest refuses that session's token from then on. A
         * phone signed in to an account pairs again by itself at the next start;
         * a QR pairing cannot, so the app has to remember that its code is spent
         * and ask for a new one rather than start a capture that ships nothing.
         */
        fun ended(ctx: Context): Boolean =
            ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getBoolean("ended", false)

        fun markEnded(ctx: Context) {
            ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().putBoolean("ended", true).apply()
        }

        /**
         * The server turned this pairing's token away and the last capture
         * stopped for it, whether the app was open or not. Cleared by the next
         * pairing and by the next capture to start.
         */
        fun refused(ctx: Context): Boolean =
            ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getBoolean("refused", false)

        fun markRefused(ctx: Context, refused: Boolean = true) {
            ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().putBoolean("refused", refused).apply()
        }

        /**
         * The control-plane origin, or null if we will not use it.
         *
         * Requires https, because the Rust capture path uses its own TLS stack
         * and so does not inherit the platform's cleartext ban: an `http://`
         * ingest URL shipped every captured request, headers and bodies
         * included, in the clear. A debug build, and every build of the dev
         * flavour, additionally allows http on loopback and private ranges so a
         * dev stack on the LAN still works. Production and staging never do.
         */
        fun normaliseApiUrl(
            raw: String,
            allowLocalHttp: Boolean = BuildConfig.DEBUG || BuildConfig.LOCAL_HTTP,
        ): String? {
            val s = raw.trim().removeSuffix("/")
            if (s.isEmpty() || s.length > 2048) return null
            if (s.any { it.isISOControl() }) return null
            val uri = runCatching { java.net.URI(s) }.getOrNull() ?: return null
            val host = uri.host ?: return null
            if (uri.userInfo != null) return null
            return when (uri.scheme?.lowercase()) {
                "https" -> s
                "http" -> if (allowLocalHttp && isLocalHost(host)) s else null
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
 * The device's own answer to full requests, for one pairing.
 *
 * The control plane can ask for full capture (headers and bodies rather than
 * request shape) and for each request to be held for a decision; this is the
 * only thing that grants either. A yes is kept with the pairing it was given
 * for, the server and the session, and is not a yes for any other. It used to
 * be one switch for the whole phone, so turning it on for your own workspace
 * and later pairing with somebody else's server by QR gave that server full
 * requests as well. Off by default, so the app's stated privacy behaviour is
 * what actually happens.
 *
 * A yes kept before it was tied to a pairing is not read. It was given on a
 * consent sheet that did not mention holding requests, so it is asked again.
 */
object FullCapturePrefs {
    private const val PREFS = "capture"
    /** The pairing the yes was given for, as [keyOf] writes it. */
    private const val GIVEN_FOR = "allow_full_for"
    /** The yes from before it was tied to a pairing. */
    private const val UNTIED = "allow_full"

    /** What a yes is kept against. Pairing again renews the token, not the session, so it keeps the yes. */
    fun keyOf(p: Pairing): String = "${p.apiUrl}\n${p.workflowId}"

    /** Whether a yes given for [givenFor] covers [pairing]. */
    fun covers(givenFor: String?, pairing: Pairing?): Boolean =
        givenFor != null && pairing != null && givenFor == keyOf(pairing)

    /** The pairing the yes was given for, or null when there is none. */
    fun givenFor(ctx: Context): String? =
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString(GIVEN_FOR, null)

    fun allowed(ctx: Context, pairing: Pairing?): Boolean = covers(givenFor(ctx), pairing)

    /** Allow full requests for [pairing], or take the yes back. */
    fun set(ctx: Context, pairing: Pairing?, allow: Boolean) {
        val e = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().remove(UNTIED)
        if (allow && pairing != null) e.putString(GIVEN_FOR, keyOf(pairing)) else e.remove(GIVEN_FOR)
        e.apply()
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
