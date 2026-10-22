package io.crossfyre.mobile.account

import io.crossfyre.mobile.Pairing
import org.json.JSONObject
import java.io.IOException
import java.net.URI
import java.net.URLEncoder

/** The signed-in account, as the sign-in routes describe it. */
data class AccountUser(
    val id: String,
    val username: String,
    val email: String,
    val accountType: String,
    val emailVerified: Boolean,
)

/** One entry of the dashboard's workspace switcher. */
data class Workspace(
    val id: String,
    val name: String,
    /** "user" for a personal workspace, "team" for one that belongs to a team. */
    val ownerKind: String,
    val role: String,
    val isActive: Boolean,
    val isDemo: Boolean,
) {
    /** "Personal · your credits", or "<organization> · org billing" for a team's. */
    var billingSource: String = ""
        internal set

    /** The organization a team workspace belongs to, as the dashboard groups them. */
    val org: String?
        get() = if (ownerKind == "team") billingSource.substringBefore(" · ").ifBlank { null } else null
}

/** A password or browser sign-in that worked: the account key and whose it is. */
data class SignedIn(val key: String, val user: AccountUser)

/**
 * What the phone tells the approval page about itself. [client] names the kind
 * of client, which the server uses to word the approval page and the key's name
 * as Crossfyre Mobile rather than as the CLI.
 */
data class ClientInfo(val hostname: String, val os: String, val version: String, val client: String = "mobile")

/** A browser sign-in that has started and is waiting for someone to approve it. */
data class DeviceLogin(
    val deviceCode: String,
    val approvalUrl: String,
    val intervalSeconds: Int,
    val expiresInSeconds: Int,
)

/** Where a browser sign-in has got to. */
sealed interface Poll {
    data object Waiting : Poll
    data class Approved(val signedIn: SignedIn) : Poll
    data object Denied : Poll
    data object Expired : Poll
}

/** What /cli/mobile/pair hands back: the pairing a QR code carries, and its names. */
data class Paired(
    val pairing: Pairing,
    val workspaceId: String,
    val workspaceName: String,
    val sessionName: String,
    val created: Boolean,
)

/** Why a call did not work, as a sentence for the screen. */
sealed interface Problem {
    val text: String

    /** No answer at all: no network, DNS, TLS, a timeout. */
    data class Unreachable(val host: String) : Problem {
        override val text get() = "Could not reach $host. Check the connection and try again."
    }

    /** The key is absent, unknown or revoked, so the account has to sign in again. */
    data object SignedOut : Problem {
        override val text = "You have been signed out. Sign in again."
    }

    data object WrongPassword : Problem {
        override val text = "That username or email and password do not match."
    }

    /** An account made with Google has no password to type. */
    data object UseGoogle : Problem {
        override val text =
            "This account signs in with Google, so it has no password. Use Sign in with browser."
    }

    /** Someone said no on the approval page. */
    data object Declined : Problem {
        override val text = "The sign-in was declined in the browser."
    }

    /** Nobody approved the sign-in before it lapsed. */
    data object Expired : Problem {
        override val text = "The sign-in request expired before it was approved. Start again."
    }

    /**
     * A refusal in the server's own words, which say what to do about it.
     *
     * [reason] is which refusal it is, read from the envelope's flags, so a
     * screen can give each its own sentence and next step. It is kept out of
     * equality on purpose: two refusals are the same when the server said the
     * same thing.
     */
    data class Refused(val status: Int, override val text: String) : Problem {
        var reason: Refusal = Refusal.OTHER
            private set

        constructor(status: Int, text: String, reason: Refusal) : this(status, text) {
            this.reason = reason
        }
    }

    /** The server failed, or answered with something this app cannot read. */
    data class Broken(val status: Int, override val text: String) : Problem
}

/** The refusals a screen treats differently from the rest. */
enum class Refusal {
    OTHER,
    /** An enterprise account whose request has not been approved yet. */
    IN_REVIEW,
    /** The login limiter said no for now. */
    RATE_LIMITED,
    /** Signing in works, but the account cannot use a workspace until its address is verified. */
    EMAIL_UNVERIFIED,
    ACCOUNT_SUSPENDED,
    WORKSPACE_ARCHIVED,
    /** The organization or owner the workspace belongs to is suspended. */
    WORKSPACE_SUSPENDED,
    /** Removed from the workspace, or it was deleted, since the list was loaded. */
    NOT_MEMBER,
    /** The server no longer knows the thing asked about, such as a lapsed device code. */
    UNKNOWN,
}

sealed interface Outcome<out T> {
    data class Ok<T>(val value: T) : Outcome<T>
    data class Failed(val problem: Problem) : Outcome<Nothing>
}

/** An HTTP answer: the status, and the body as text. */
data class Reply(val status: Int, val body: String)

/** POST a JSON body, return whatever came back. Throws only when nothing did. */
fun interface Transport {
    @Throws(IOException::class)
    fun post(url: String, json: String): Reply
}

/**
 * The account routes the CLI and the Workbench sign in through, from a phone.
 *
 * Every call is a POST of a JSON body to `{origin}/api/v1/cli/...` with no cookie
 * and no auth header; the account key travels in the body. Every answer is the
 * envelope `{status, message, errors, data}`, except a body the server could not
 * parse, which comes back as plain text with a 4xx.
 */
class AccountApi(origin: String, private val transport: Transport) {
    val origin: String = origin.trimEnd('/')

    /** The name a failure is reported against: the host, not the whole origin. */
    private val host: String = runCatching { URI(this.origin).host }.getOrNull() ?: this.origin

    fun login(identifier: String, password: String, keyName: String): Outcome<SignedIn> {
        val body = JSONObject().put("identifier", identifier).put("password", password).put("key_name", keyName)
        return call("login", body) { a ->
            when {
                a.ok -> a.data?.let(::signedIn)?.let { Outcome.Ok(it) } ?: a.unreadable()
                // Unknown account and wrong password get the same answer, on purpose.
                a.status == 401 -> Outcome.Failed(Problem.WrongPassword)
                a.status == 409 && a.data?.optBoolean("use_google") == true -> Outcome.Failed(Problem.UseGoogle)
                a.status == 403 && a.data?.optBoolean("pending") == true -> a.refusal(Refusal.IN_REVIEW)
                a.status == 429 -> a.refusal(Refusal.RATE_LIMITED)
                else -> a.refusal()
            }
        }
    }

    fun startDeviceLogin(client: ClientInfo): Outcome<DeviceLogin> {
        val info = JSONObject()
            .put("hostname", client.hostname)
            .put("os", client.os)
            .put("version", client.version)
            .put("client", client.client)
        return call("device/start", JSONObject().put("client_info", info)) { a ->
            if (!a.ok) return@call a.refusal()
            val d = a.data ?: return@call a.unreadable()
            val code = d.str("device_code")
            if (code.isNullOrEmpty()) return@call a.unreadable()
            // Not the server's verification_uri_complete: that is built from an
            // origin setting some environments leave unset, which sends a staging
            // phone to production's approval page. The page is always on the
            // origin this app is talking to.
            Outcome.Ok(
                DeviceLogin(
                    deviceCode = code,
                    approvalUrl = approvalUrl(code),
                    intervalSeconds = d.optInt("interval", 3),
                    expiresInSeconds = d.optInt("expires_in", 600),
                )
            )
        }
    }

    fun pollDeviceLogin(deviceCode: String): Outcome<Poll> =
        call("device/poll", JSONObject().put("device_code", deviceCode)) { a ->
            // The server no longer knows the code: it lapsed and was cleaned up, or
            // it was handed over already. Either way there is nothing left to wait on.
            if (a.status == 404) return@call a.refusal(Refusal.UNKNOWN)
            if (!a.ok) return@call a.refusal()
            val d = a.data ?: return@call a.unreadable()
            when (d.str("status")) {
                "pending" -> Outcome.Ok(Poll.Waiting)
                "denied" -> Outcome.Ok(Poll.Denied)
                "expired" -> Outcome.Ok(Poll.Expired)
                // Handed over exactly once, so an approval without a key in it
                // is a broken answer rather than a sign-in to wait on.
                "approved" -> signedIn(d)?.let { Outcome.Ok(Poll.Approved(it)) } ?: a.unreadable()
                else -> a.unreadable()
            }
        }

    fun verifyKey(key: String): Outcome<AccountUser> =
        call("verify-key", JSONObject().put("api_key", key)) { a ->
            when {
                a.ok -> a.data?.optJSONObject("user")?.let(::user)?.let { Outcome.Ok(it) } ?: a.unreadable()
                a.status == 401 -> Outcome.Failed(Problem.SignedOut)
                else -> a.refusal()
            }
        }

    fun workspaces(key: String): Outcome<List<Workspace>> =
        call("workspace/list", JSONObject().put("api_key", key)) { a ->
            when {
                a.ok -> {
                    val list = a.data?.optJSONArray("workspaces") ?: return@call a.unreadable()
                    Outcome.Ok((0 until list.length()).mapNotNull { list.optJSONObject(it)?.let(::workspace) })
                }
                a.status == 401 -> Outcome.Failed(Problem.SignedOut)
                a.status == 403 -> a.accountRefusal() ?: a.refusal()
                else -> a.refusal()
            }
        }

    fun pair(key: String, workspaceId: String, deviceId: String, deviceName: String): Outcome<Paired> {
        val body = JSONObject()
            .put("api_key", key)
            .put("workspace_id", workspaceId)
            .put("device_id", deviceId)
            .put("device_name", deviceName)
        return call("mobile/pair", body) { a ->
            when {
                a.ok -> {
                    val d = a.data ?: return@call a.unreadable()
                    val workflow = d.str("workflow_id")
                    val token = d.str("token")
                    // Without both there is nothing a capture could use, and keeping
                    // half a pairing would only fail later, further from the cause.
                    if (workflow.isNullOrEmpty() || token.isNullOrEmpty()) return@call a.unreadable()
                    Outcome.Ok(
                        Paired(
                            pairing = Pairing(origin, workflow, token),
                            workspaceId = d.str("workspace_id") ?: workspaceId,
                            workspaceName = d.str("workspace_name").orEmpty(),
                            sessionName = d.str("session_name").orEmpty(),
                            created = d.optBoolean("created", a.status == 201),
                        )
                    )
                }
                a.status == 401 -> Outcome.Failed(Problem.SignedOut)
                a.status == 403 && a.data?.optBoolean("archived") == true -> a.refusal(Refusal.WORKSPACE_ARCHIVED)
                a.status == 403 && a.data?.has("workspace_suspended") == true -> a.refusal(Refusal.WORKSPACE_SUSPENDED)
                a.status == 403 -> a.accountRefusal() ?: a.refusal(if (a.says("member")) Refusal.NOT_MEMBER else Refusal.OTHER)
                else -> a.refusal()
            }
        }
    }

    /** Revoke the key. A key the server no longer knows is as signed out as it gets. */
    fun logout(key: String): Outcome<Unit> =
        call("logout", JSONObject().put("api_key", key)) { a ->
            if (a.ok || a.status == 401) Outcome.Ok(Unit) else a.refusal()
        }

    fun approvalUrl(deviceCode: String): String =
        "$origin/device?code=" + URLEncoder.encode(deviceCode, "UTF-8")

    // ── plumbing ─────────────────────────────────────────────────────────────

    /** One answer from the server, read as the envelope when it is one. */
    private class Answer(val status: Int, val envelope: JSONObject?) {
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

        /** Whether the server's own words mention [word], for refusals with no flag to read. */
        fun says(word: String): Boolean =
            (message.orEmpty() + " " + firstError.orEmpty()).contains(word, ignoreCase = true)

        fun <T> unreadable(): Outcome<T> = Outcome.Failed(
            Problem.Broken(status, "The server answered with something this app cannot read (HTTP $status).")
        )
    }

    private fun <T> call(route: String, body: JSONObject, read: (Answer) -> Outcome<T>): Outcome<T> {
        val reply = try {
            transport.post("$origin/api/v1/cli/$route", body.toString())
        } catch (e: IOException) {
            return Outcome.Failed(Problem.Unreachable(host))
        }
        val envelope = runCatching { JSONObject(reply.body) }.getOrNull()
        return read(Answer(reply.status, envelope))
    }

    private fun signedIn(d: JSONObject): SignedIn? {
        val key = d.str("api_key")?.takeIf { it.isNotEmpty() } ?: return null
        val user = d.optJSONObject("user")?.let(::user) ?: return null
        return SignedIn(key, user)
    }

    private fun user(u: JSONObject): AccountUser? {
        val id = u.str("id") ?: return null
        return AccountUser(
            id = id,
            username = u.str("username").orEmpty(),
            email = u.str("email").orEmpty(),
            accountType = u.str("account_type").orEmpty(),
            emailVerified = u.optBoolean("email_verified", false),
        )
    }

    private fun workspace(w: JSONObject): Workspace? {
        val id = w.str("id") ?: return null
        return Workspace(
            id = id,
            name = w.str("name").orEmpty(),
            ownerKind = w.str("owner_kind").orEmpty(),
            role = w.str("role").orEmpty(),
            isActive = w.optBoolean("is_active", false),
            isDemo = w.optBoolean("is_demo", false),
        ).also { it.billingSource = w.str("billing_source").orEmpty() }
    }
}

/**
 * A string field, or null when it is absent or JSON null.
 *
 * Not `optString`: Android's org.json turns a JSON null into the four letters
 * "null", and the reference library turns it into "". Neither is a value.
 */
private fun JSONObject.str(name: String): String? =
    if (!has(name) || isNull(name)) null else optString(name)
