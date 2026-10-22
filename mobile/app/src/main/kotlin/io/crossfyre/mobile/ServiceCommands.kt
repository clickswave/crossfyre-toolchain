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
