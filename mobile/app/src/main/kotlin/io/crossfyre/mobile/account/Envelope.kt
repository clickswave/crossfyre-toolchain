package io.crossfyre.mobile.account

import io.crossfyre.mobile.approve.Untrusted
import org.json.JSONObject
import java.io.IOException

/**
 * One answer from a `/cli` route, read as the envelope `{status, message, errors, data}`
 * when it is one. Shared by the account client and the approvals client, which
 * read the same envelope from the same server.
 */
internal class Answer(val status: Int, val envelope: JSONObject?, private val retryAfterSeconds: Long? = null) {
    val ok = status in 200..299 && envelope != null
    val data: JSONObject? = envelope?.optJSONObject("data")
    private val message = envelope?.str("message")?.takeIf { it.isNotBlank() }
    private val firstError = envelope?.optJSONArray("errors")?.let { e ->
        if (e.length() > 0 && !e.isNull(0)) e.optString(0).takeIf { it.isNotBlank() } else null
    }

    /** A 4xx in the server's own words, which say what to do; anything else as a failure. */
    fun <T> refusal(reason: Refusal = Refusal.OTHER): Outcome<T> {
        val said = when {
            message == null -> null
            firstError == null || message.contains(firstError) -> message
            else -> "$message: $firstError"
        }
        return Outcome.Failed(
            if (status in 400..499) {
                Problem.Refused(status, said ?: "The server refused the request (HTTP $status).", reason)
            } else {
                Problem.Broken(status, said ?: "The server failed (HTTP $status). Try again in a moment.")
            }
        )
    }

    /**
     * The refusals that are about the account rather than the request: the
     * same two from the list and from pairing, and neither is something the
     * phone can fix, so each names where to go instead.
     */
    fun <T> accountRefusal(): Outcome<T>? = when {
        data?.optBoolean("email_unverified") == true -> refusal(Refusal.EMAIL_UNVERIFIED)
        data?.has("suspended") == true -> refusal(Refusal.ACCOUNT_SUSPENDED)
        else -> null
    }

    /**
     * A member whose role lacks a permission: which role, and what it may not do.
     *
     * The sentence is the phone's own, made from `data.role.name` and
     * `data.permission`, and not the server's message, which carries the role's
     * name as an org admin typed it. That name is cleaned and cut like every other
     * name the phone shows, and loses the marks a banner reads as formatting. The
     * permission key that follows in `errors` is for the dashboard and is left out.
     */
    fun <T> roleRefusal(): Outcome<T> {
        val role = data?.optJSONObject("role")?.str("name")
            ?.let { Untrusted.plain(it, Untrusted.NAME).trim() }
            ?.takeIf { it.isNotEmpty() }
        val what = doing(data?.str("permission"))
        val text = if (role == null) {
            "Your role in this workspace does not allow $what."
        } else {
            "Your role in this workspace ($role) does not allow $what."
        }
        return Outcome.Failed(Problem.Refused(status, text, Refusal.MISSING_PERMISSION))
    }

    /** What a permission lets a member do, in the server's words for it. */
    private fun doing(permission: String?): String = when (permission) {
        "workflow.create" -> "creating scans"
        "workflow.run" -> "starting scans"
        "workflow.halt" -> "stopping scans"
        "workflow.delete" -> "deleting scans"
        else -> "this"
    }

    /** `data.reason`, the machine-readable half of a refusal, when the server gave one. */
    fun reason(): String? = data?.str("reason")

    /** A 429, with how long the server asked the phone to wait before it calls again. */
    fun <T> limited(): Outcome<T> = Outcome.Failed(
        Problem.Refused(
            status,
            message ?: "Too many requests. Wait a minute before trying again.",
            Refusal.RATE_LIMITED,
            retryAfterSeconds,
        )
    )

    /** Whether the server's own words mention [word], for refusals with no flag to read. */
    fun says(word: String): Boolean =
        (message.orEmpty() + " " + firstError.orEmpty()).contains(word, ignoreCase = true)

    fun <T> unreadable(): Outcome<T> = Outcome.Failed(
        Problem.Broken(status, "The server answered with something this app cannot read (HTTP $status).")
    )
}

/** POST [body] to `{origin}/api/v1/cli/{route}` and read what came back. */
internal fun <T> cliCall(
    transport: Transport,
    origin: String,
    host: String,
    route: String,
    body: JSONObject,
    read: (Answer) -> Outcome<T>,
): Outcome<T> {
    val reply = try {
        transport.post("$origin/api/v1/cli/$route", body.toString())
    } catch (e: IOException) {
        return Outcome.Failed(Problem.Unreachable(host))
    }
    val envelope = runCatching { JSONObject(reply.body) }.getOrNull()
    return read(Answer(reply.status, envelope, reply.retryAfterSeconds))
}

/**
 * A string field, or null when it is absent or JSON null.
 *
 * Not `optString`: Android's org.json turns a JSON null into the four letters
 * "null", and the reference library turns it into "". Neither is a value.
 */
internal fun JSONObject.str(name: String): String? =
    if (!has(name) || isNull(name)) null else optString(name)
