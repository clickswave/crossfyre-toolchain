package io.crossfyre.mobile

/** What an intent delivered to the capture service asks it to do. */
internal enum class Command { START, STOP }

/**
 * Only the app's own start starts a capture, because only it carries the
 * person's scope. Everything else Android may deliver is read as stop: a sticky
 * restart arrives with no intent, and an always-on VPN with the VpnService
 * action, and starting on either captured the whole phone without being asked.
 */
internal fun commandFor(action: String?): Command =
    if (action == TracerVpnService.ACTION_START) Command.START else Command.STOP

/**
 * Stopping, as a list of steps that all run, once, in order.
 *
 * A step that throws is reported and the rest still run. Before this, one
 * failure part way through left the tunnel up and the notification showing with
 * the app saying it had stopped.
 *
 * @return the names of the steps that failed, empty on a second run.
 */
internal class Teardown(private val steps: List<Pair<String, () -> Unit>>) {
    private var done = false

    fun run(): List<String> {
        if (done) return emptyList()
        done = true
        return steps.mapNotNull { (name, step) -> if (runCatching(step).isFailure) name else null }
    }
}

/**
 * The capture service's own look at whether the server still takes the
 * session's token.
 *
 * Once the ingest is refused it sends nothing more, but the tunnel went on
 * intercepting the in-scope apps' traffic until the app came to the front and
 * stopped it, and during a capture the app is usually in the background. The
 * service asks the native side every [EVERY_MS] instead and stops the capture
 * itself, once, while it runs.
 *
 * @param stats the native side's counters as JSON, or null when it has none.
 * @param refused stops the capture.
 * @param after runs the next look after a delay.
 */
internal class TokenWatch(
    private val stats: () -> String?,
    private val refused: () -> Unit,
    private val after: (Long, () -> Unit) -> Unit,
) {
    private var on = false

    fun start() {
        on = true
        after(EVERY_MS, ::look)
    }

    /** The capture stopped for another reason: a look already scheduled does nothing. */
    fun cancel() {
        on = false
    }

    private fun look() {
        if (!on) return
        val json = runCatching { stats() }.getOrNull()
        if (json != null && runCatching { Stats.parse(json).tokenRefused }.getOrDefault(false)) {
            on = false
            refused()
            return
        }
        after(EVERY_MS, ::look)
    }

    companion object {
        const val EVERY_MS = 1_000L
    }
}
