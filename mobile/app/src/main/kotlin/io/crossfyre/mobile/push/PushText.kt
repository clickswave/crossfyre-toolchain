package io.crossfyre.mobile.push

import io.crossfyre.mobile.approve.InboxItem

/** What a push draws: the channel it goes on, its two lines, and the link a tap opens. */
data class Alert(val channel: String, val title: String, val text: String, val link: String)

/**
 * A push names an inbox row and carries none of its text, so the phone reads the
 * row and draws that. When the row cannot be read (no connection, the server
 * busy) the push still says what kind of thing arrived.
 */
object PushText {
    const val APPROVALS = "approvals"
    const val ALERTS = "alerts"

    /** The longest text a notification shows. The row's text is already cleaned by the client. */
    private const val TEXT_MAX = 300

    fun of(type: String, row: InboxItem?, link: String?): Alert {
        val channel = if (type == "approval.requested") APPROVALS else ALERTS
        val title = row?.title?.takeIf { it.isNotBlank() } ?: fallback(type)
        val text = row?.body?.takeIf { it.isNotBlank() }?.take(TEXT_MAX) ?: "Open Crossfyre Mobile to see it."
        val opens = row?.link?.takeIf { it.isNotEmpty() } ?: link.orEmpty()
        return Alert(channel, title, text, opens)
    }

    private fun fallback(type: String): String = when {
        type == "approval.requested" -> "An agent is waiting for your approval"
        type == "workflow.completed" -> "A scan finished"
        type == "workflow.failed" -> "A scan failed"
        type.startsWith("finding.") -> "A scan found something"
        type == "node.offline" -> "A node went offline"
        type.startsWith("billing.") || type == "subscription_renewal" -> "Your Crossfyre plan"
        else -> "Crossfyre"
    }
}
