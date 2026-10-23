package io.crossfyre.mobile.account

/**
 * The install id the pairing route keys a phone's session on.
 *
 * One per install, kept across sign-outs, so pairing the same phone with the same
 * workspace again re-arms its one session instead of adding another to the list.
 */
object DeviceIds {
    private val SHAPE = Regex("^[A-Za-z0-9._-]{8,128}$")

    /** A random UUID: 36 characters, all of them ones the route accepts. */
    fun fresh(): String = java.util.UUID.randomUUID().toString()

    /**
     * What the route accepts: 8 to 128 characters of A-Z a-z 0-9 . _ - and never
     * "..", which the server refuses because the id ends up in a path.
     */
    fun isValid(id: String): Boolean = SHAPE.matches(id) && ".." !in id
}

/**
 * Whether the stored session token still works, decided without asking the server.
 *
 * Stopping capture sends a final batch marked as the end of the session, and the
 * ingest refuses that session's token from then on. A phone paired from the account
 * renews it by pairing again; a QR pairing cannot be renewed from the phone at all.
 * Pairing again also mints a new token and retires the old one, so it must not
 * happen under a capture or a patch that is using the current one.
 */
class SessionState {
    var live: Boolean = false
        private set

    /** A pair call just returned a token for a session that has not ended. */
    fun paired() {
        live = true
    }

    /** Capture stopped, which ended the session the token belongs to. */
    fun ended() {
        live = false
    }

    /**
     * Pair again before using the token?
     *
     * @param inUse a capture or a patch is running on the current token.
     * @param renewable the pairing came from the account, which can mint another.
     */
    fun mustRepair(inUse: Boolean, renewable: Boolean): Boolean = renewable && !inUse && !live
}
