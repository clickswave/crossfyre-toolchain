package io.crossfyre.mobile.approve

import io.crossfyre.mobile.account.Answer
import io.crossfyre.mobile.account.Outcome
import io.crossfyre.mobile.account.Problem
import io.crossfyre.mobile.account.Refusal
import io.crossfyre.mobile.account.Transport
import io.crossfyre.mobile.account.cliCall
import io.crossfyre.mobile.account.str
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.isActive
import org.json.JSONArray
import org.json.JSONObject
import java.net.URI
import java.net.URLEncoder
import java.time.Instant
import java.util.Base64

/** An enrolment that has started and waits for the person to confirm the phone in a browser. */
data class Enrolment(
    val approverId: String,
    val code: String,
    val confirmUrl: String,
    /** This phone's own fingerprint of its key, which the browser page shows too. */
    val fingerprint: String,
    val intervalSeconds: Int,
    val expiresInSeconds: Int,
)

enum class EnrolState { PENDING, ACTIVE, DENIED, EXPIRED }

/** The approver the server holds for this phone's key, as the pending list reports it. */
data class Approver(val id: String, val status: String, val deviceName: String)

data class PendingList(val serverTime: Instant?, val approver: Approver?, val approvals: List<PendingApproval>)

/** One decided approval, for the Recent decisions list. */
data class HistoryRow(
    val id: String,
    val status: String,
    val actionLabel: String,
    val workspaceName: String,
    val createdAt: Instant?,
    val decidedAt: Instant?,
    /** phone, dashboard, agent_client, account_key, expiry or agent_cancel. */
    val decidedVia: String,
    val deviceName: String,
    /** launching, launched or failed, once the platform has acted on an approval. */
    val launchState: String,
    val workflowId: String,
    val workflowStatus: String,
    /** SHA-256 hex of the approval's summary text: what a stop is signed over. Empty from a platform that does not send it. */
    val digest: String,
)

/** The Recent decisions list, with the platform's time when it answered. */
data class History(val serverTime: Instant?, val rows: List<HistoryRow>)

/** What a signed stop came to. */
sealed interface StopAnswer {
    /** The scan stopped. */
    data class Stopped(val workflowStatus: String, val operationsCancelled: Int) : StopAnswer

    /**
     * The signature's time was more than five minutes from the platform's clock,
     * which was [serverTime] when it answered. Nothing was stopped; a stop signed
     * at the platform's time goes through.
     */
    data class Stale(val serverTime: Instant) : StopAnswer
}

/** One of the account's notifications, as `/cli/inbox/list` gives it. */
data class InboxItem(
    val id: String,
    /** node, workflow, billing, finding, account, system or approval. */
    val category: String,
    val eventType: String,
    /** info, success, warning or error. */
    val severity: String,
    val title: String,
    /** Its lines, each cleaned like any other text from the server. Empty when there is none. */
    val body: String,
    /**
     * An in-app path such as `/m/approve/<id>`, exactly as sent, or empty. It is
     * never opened as it stands: [io.crossfyre.mobile.notificationUrl] decides
     * whether it is a page on this app's own server.
     */
    val link: String,
    val read: Boolean,
    val createdAt: Instant?,
)

/**
 * One page of notifications, newest first. [unread] counts the account's unread
 * ones, whatever the page holds. [limit] is the page size the server used, so
 * page [page] covered rows up to `page * limit` of [total].
 */
data class InboxPage(val items: List<InboxItem>, val total: Int, val unread: Int, val page: Int, val limit: Int)

/** What marking notifications read came to: the rows that changed and the unread ones left. */
data class InboxMarked(val marked: Int, val unread: Int)

/** Which activity to read: the paired workspace, or the account's own. */
sealed interface ActivityScope {
    data class Workspace(val id: String, val name: String) : ActivityScope
    data object Account : ActivityScope
}

data class Named(val id: String, val name: String)

/** One row of the activity log, in the shape `/activity/list` gives it. */
data class ActivityEvent(
    val id: Long,
    val at: Instant?,
    val org: Named?,
    val team: Named?,
    val workspace: Named?,
    val actorKind: String,
    val actorName: String,
    val channel: String,
    val credentialLabel: String,
    val credentialKind: String,
    val action: String,
    val outcome: String,
    val subjectType: String,
    val subjectName: String,
    val detail: List<Pair<String, String>>,
)

data class ActivityPage(val events: List<ActivityEvent>, val nextBeforeId: Long?)

/**
 * The approval routes, from the phone.
 *
 * The same plumbing as the account client: a JSON POST to `{origin}/api/v1/cli/...`
 * with the phone's own account key in the body, answered with the envelope. Every
 * route here is one the phone calls about its own account: its approver, the
 * approvals waiting for it, and what happened in its workspace.
 */
class ApprovalApi(origin: String, private val transport: Transport) {
    val origin: String = origin.trimEnd('/')
    private val host: String = runCatching { URI(this.origin).host }.getOrNull() ?: this.origin

    /**
     * Send this phone's public key, and get the code the browser confirms it with.
     *
     * The confirmation page is built from the origin this app talks to, not taken
     * from the answer, for the same reason as the sign-in page: a server whose
     * public address is set wrong would send a staging phone to production.
     *
     * [made] hears the approver id as soon as the answer names one, before the
     * rest of the answer is checked. The server has made that approver either
     * way, so a caller that refuses the answer still knows what to revoke.
     */
    fun enrolStart(
        key: String,
        deviceId: String,
        deviceName: String,
        publicKey: ByteArray,
        made: (String) -> Unit = {},
    ): Outcome<Enrolment> {
        val body = JSONObject()
            .put("api_key", key)
            .put("device_id", deviceId)
            .put("device_name", deviceName)
            .put("public_key", Base64.getEncoder().encodeToString(publicKey))
        val mine = Spki.fingerprint(publicKey)
        return call("approver/start", body) { a ->
            when {
                a.ok -> {
                    val d = a.data ?: return@call a.unreadable()
                    val id = d.str("approver_id")
                    if (!id.isNullOrEmpty()) made(id)
                    val code = d.str("enrol_code")
                    if (id.isNullOrEmpty() || code.isNullOrEmpty()) return@call a.unreadable()
                    // The server says which key it received. If that is not the key
                    // this phone made, something between them changed it, and the
                    // browser would be confirming a key that is not this phone's.
                    val theirs = d.str("fingerprint")
                    if (theirs != null && Spki.normalFingerprint(theirs) != Spki.normalFingerprint(mine)) {
                        return@call Outcome.Failed(
                            Problem.Broken(a.status, "The server received a different key from the one this phone made. Nothing was turned on.")
                        )
                    }
                    Outcome.Ok(
                        Enrolment(
                            approverId = id,
                            code = code,
                            confirmUrl = confirmUrl(code),
                            fingerprint = mine,
                            intervalSeconds = d.optInt("interval", 3),
                            expiresInSeconds = d.optInt("expires_in", 600),
                        )
                    )
                }
                a.status == 401 -> Outcome.Failed(Problem.SignedOut)
                a.status == 409 -> a.refusal(Refusal.TOO_MANY_APPROVERS)
                a.status == 403 -> a.accountRefusal() ?: a.refusal()
                else -> a.refusal()
            }
        }
    }

    fun enrolPoll(key: String, code: String): Outcome<EnrolState> =
        call("approver/poll", JSONObject().put("api_key", key).put("enrol_code", code)) { a ->
            when {
                a.ok -> when (a.data?.str("status")) {
                    "pending" -> Outcome.Ok(EnrolState.PENDING)
                    "active" -> Outcome.Ok(EnrolState.ACTIVE)
                    "denied" -> Outcome.Ok(EnrolState.DENIED)
                    "expired" -> Outcome.Ok(EnrolState.EXPIRED)
                    else -> a.unreadable()
                }
                a.status == 401 -> Outcome.Failed(Problem.SignedOut)
                a.status == 404 -> a.refusal(Refusal.UNKNOWN)
                else -> a.refusal()
            }
        }

    /** Stop this phone approving. Idempotent; an approver the server no longer knows is as revoked as it gets. */
    fun revoke(key: String, approverId: String): Outcome<Unit> =
        call("approver/revoke", JSONObject().put("api_key", key).put("approver_id", approverId)) { a ->
            when {
                a.ok || a.status == 404 -> Outcome.Ok(Unit)
                a.status == 401 -> Outcome.Failed(Problem.SignedOut)
                else -> a.refusal()
            }
        }

    fun pending(key: String): Outcome<PendingList> =
        call("approvals/pending", JSONObject().put("api_key", key)) { a ->
            when {
                a.ok -> {
                    val d = a.data ?: return@call a.unreadable()
                    val list = d.optJSONArray("approvals") ?: return@call a.unreadable()
                    val approver = d.optJSONObject("approver")?.let { o ->
                        o.str("id")?.let { Approver(it, o.str("status").orEmpty(), Untrusted.clean(o.str("device_name").orEmpty(), Untrusted.NAME)) }
                    }
                    val approvals = list.objects().mapNotNull { o ->
                        val id = o.str("id")?.let(ApprovalIds::normal) ?: return@mapNotNull null
                        PendingApproval(
                            id = id,
                            status = o.str("status").orEmpty(),
                            createdAt = instant(o.str("created_at")),
                            expiresAt = instant(o.str("expires_at")),
                            // Kept exactly as received: its bytes are what the digest covers.
                            summaryJson = o.str("summary_json").orEmpty(),
                            digest = o.str("digest").orEmpty(),
                        )
                    }
                    Outcome.Ok(PendingList(instant(d.str("server_time")), approver, approvals))
                }
                a.status == 401 -> Outcome.Failed(Problem.SignedOut)
                a.status == 403 -> a.accountRefusal() ?: a.refusal()
                else -> a.refusal()
            }
        }

    /** Approve, with the signature the unlock produced over [ApprovalProtocol.signingBytes]. */
    fun approve(key: String, approvalId: String, approverId: String, signedAt: Long, signature: ByteArray): Outcome<String> {
        val body = JSONObject()
            .put("api_key", key)
            .put("approval_id", approvalId)
            .put("decision", "approve")
            .put("approver_id", approverId)
            .put("signed_at", signedAt)
            .put("signature", Base64.getEncoder().encodeToString(signature))
        return call("approvals/decide", body, ::decided)
    }

    /** Deny. No signature and no unlock: saying no is safe from anywhere. */
    fun deny(key: String, approvalId: String): Outcome<String> {
        val body = JSONObject().put("api_key", key).put("approval_id", approvalId).put("decision", "deny")
        return call("approvals/decide", body, ::decided)
    }

    /**
     * What a decision came to: the approval's status after it, or the refusal.
     *
     * A role refusal is read by its reason before anything reads the server's
     * words, which carry the role's name as an org admin typed it: a role called
     * "Scan Approvers" said "approver" and cost the phone its approver.
     */
    private fun decided(a: Answer): Outcome<String> = when {
        a.ok -> Outcome.Ok(a.data?.str("status") ?: a.data?.optJSONObject("approval")?.str("status") ?: "")
        a.status == 401 -> Outcome.Failed(Problem.SignedOut)
        a.status == 404 -> a.refusal(Refusal.UNKNOWN)
        a.status == 403 && a.reason() == "missing_permission" -> a.roleRefusal()
        a.status == 403 && a.data?.optBoolean("approver_inactive") == true -> a.refusal(Refusal.APPROVER_INACTIVE)
        a.status == 403 && a.says("approver") -> a.refusal(Refusal.APPROVER_INACTIVE)
        a.status == 403 -> a.accountRefusal() ?: a.refusal()
        a.status == 409 -> a.refusal(Refusal.NOT_PENDING)
        a.status == 410 -> a.refusal(Refusal.APPROVAL_EXPIRED)
        a.status == 422 -> a.refusal(Refusal.BAD_SIGNATURE)
        else -> a.refusal()
    }

    fun history(key: String, before: Instant? = null): Outcome<History> {
        val body = JSONObject().put("api_key", key)
        if (before != null) body.put("before", before.toString())
        return call("approvals/history", body) { a ->
            when {
                a.ok -> {
                    val list = a.data?.optJSONArray("approvals") ?: a.data?.optJSONArray("history") ?: return@call a.unreadable()
                    Outcome.Ok(History(instant(a.data?.str("server_time")), list.objects().mapNotNull { o ->
                        val id = o.str("id")?.let(ApprovalIds::normal) ?: return@mapNotNull null
                        HistoryRow(
                            id = id,
                            status = o.text("status", 20),
                            actionLabel = o.text("action_label", Untrusted.NAME),
                            workspaceName = o.text("workspace_name", Untrusted.NAME),
                            createdAt = instant(o.str("created_at")),
                            decidedAt = instant(o.str("decided_at")),
                            decidedVia = o.text("decided_via", 20),
                            deviceName = o.text("device_name", Untrusted.NAME),
                            launchState = o.text("launch_state", 20),
                            workflowId = o.text("workflow_id", 64),
                            workflowStatus = o.text("workflow_status", 20),
                            digest = o.text("digest", 64),
                        )
                    }))
                }
                a.status == 401 -> Outcome.Failed(Problem.SignedOut)
                a.status == 403 -> a.accountRefusal() ?: a.refusal()
                else -> a.refusal()
            }
        }
    }

    /**
     * Stop the scan an approval launched, with the signature the unlock produced
     * over [ApprovalProtocol.signingBytes] with `stop` as the decision. It is
     * signed at the platform's time: a stop has nothing of its own to use up, so
     * the platform takes one only within five minutes of its clock.
     */
    fun stop(key: String, approvalId: String, approverId: String, signedAt: Long, signature: ByteArray): Outcome<StopAnswer> {
        val body = JSONObject()
            .put("api_key", key)
            .put("approval_id", approvalId)
            .put("approver_id", approverId)
            .put("signed_at", signedAt)
            .put("signature", Base64.getEncoder().encodeToString(signature))
        return call("approvals/stop", body) { a ->
            phoneRefusal(a) ?: when {
                a.ok -> Outcome.Ok(
                    StopAnswer.Stopped(a.data?.text("workflow_status", 20).orEmpty(), a.data?.optInt("operations_cancelled", 0) ?: 0)
                )
                a.status == 422 && a.reason() == "stale_signature" ->
                    instant(a.data?.str("server_time"))?.let { Outcome.Ok(StopAnswer.Stale(it)) } ?: a.refusal(Refusal.STALE_SIGNATURE)
                a.status == 422 -> a.refusal(Refusal.BAD_SIGNATURE)
                a.status == 404 -> a.refusal(Refusal.UNKNOWN)
                a.status == 409 && a.reason() == "not_running" -> a.refusal(Refusal.NOT_RUNNING)
                a.status == 409 -> a.refusal(Refusal.NOT_LAUNCHED)
                a.status == 403 && a.reason() == "missing_permission" -> a.roleRefusal()
                a.status == 403 && a.says("member") -> a.refusal(Refusal.NOT_MEMBER)
                else -> a.refusal()
            }
        }
    }

    /** A page of the account's notifications, newest first. Answered only for a phone that approves. */
    fun inbox(key: String, page: Int = 1, limit: Int = 20, unreadOnly: Boolean = false): Outcome<InboxPage> {
        val asked = limit.coerceIn(1, 50)
        val body = JSONObject().put("api_key", key).put("page", page.coerceAtLeast(1)).put("limit", asked)
        if (unreadOnly) body.put("filter", "unread")
        return call("inbox/list", body) { a ->
            phoneRefusal(a) ?: when {
                a.ok -> {
                    val d = a.data ?: return@call a.unreadable()
                    val items = d.optJSONArray("items") ?: return@call a.unreadable()
                    if (!d.has("unread")) return@call a.unreadable()
                    val read = items.objects().mapNotNull(::notification)
                    Outcome.Ok(
                        InboxPage(
                            read, d.optInt("total", read.size), d.optInt("unread", 0), d.optInt("page", page),
                            d.optInt("limit", asked).coerceAtLeast(1),
                        )
                    )
                }
                else -> a.refusal()
            }
        }
    }

    /** Mark these notifications read. Ids that are not the account's, or already read, change nothing. */
    fun inboxRead(key: String, ids: List<String>): Outcome<InboxMarked> =
        markRead(JSONObject().put("api_key", key).put("ids", JSONArray(ids)))

    /** Mark every notification of the account read. */
    fun inboxReadAll(key: String): Outcome<InboxMarked> =
        markRead(JSONObject().put("api_key", key).put("all", true))

    private fun markRead(body: JSONObject): Outcome<InboxMarked> = call("inbox/read", body) { a ->
        phoneRefusal(a) ?: when {
            a.ok -> {
                val d = a.data ?: return@call a.unreadable()
                if (!d.has("unread")) return@call a.unreadable()
                Outcome.Ok(InboxMarked(d.optInt("marked", 0), d.optInt("unread", 0)))
            }
            else -> a.refusal()
        }
    }

    /**
     * A page of the activity log, newest first, in the shape `/activity/list`
     * gives it, read as the key's owner under their roles. The platform answers
     * it only for a key whose own approver is active, never a CLI or Workbench
     * key, and never exports from it.
     */
    fun activity(key: String, scope: ActivityScope, beforeId: Long? = null, limit: Int = 30): Outcome<ActivityPage> {
        val body = JSONObject().put("api_key", key).put("limit", limit.coerceIn(1, 200))
        when (scope) {
            is ActivityScope.Workspace -> body.put("workspace_id", scope.id)
            ActivityScope.Account -> body.put("account", true)
        }
        if (beforeId != null) body.put("before_id", beforeId)
        return call("activity/list", body) { a ->
            phoneRefusal(a) ?: when {
                a.ok -> {
                    val d = a.data ?: return@call a.unreadable()
                    val events = d.optJSONArray("events") ?: return@call a.unreadable()
                    val next = if (d.has("next_before_id") && !d.isNull("next_before_id")) d.optLong("next_before_id") else null
                    Outcome.Ok(ActivityPage(events.objects().mapNotNull(::event), next))
                }
                else -> a.refusal()
            }
        }
    }

    fun confirmUrl(code: String): String = "$origin/m/enrol?code=" + URLEncoder.encode(code, "UTF-8")

    private fun event(o: JSONObject): ActivityEvent? {
        if (!o.has("id")) return null
        val id = o.optLong("id", -1).takeIf { it >= 0 } ?: return null
        fun named(name: String): Named? = o.optJSONObject(name)?.let { n ->
            Named(n.text("id", 64), n.text("name", Untrusted.NAME)).takeIf { it.id.isNotEmpty() || it.name.isNotEmpty() }
        }
        val actor = o.optJSONObject("actor") ?: JSONObject()
        val cred = o.optJSONObject("credential")
        val subject = o.optJSONObject("subject")
        return ActivityEvent(
            id = id,
            at = instant(o.str("at")),
            org = named("org"),
            team = named("team"),
            workspace = named("workspace"),
            actorKind = actor.text("kind", 20),
            actorName = actor.text("name", Untrusted.NAME).ifEmpty { actor.text("name_then", Untrusted.NAME) },
            channel = o.text("channel", 20),
            credentialLabel = cred?.text("label", Untrusted.NAME).orEmpty(),
            credentialKind = cred?.text("kind", 20).orEmpty(),
            action = o.text("action", 64),
            outcome = o.text("outcome", 20),
            subjectType = subject?.text("type", 40).orEmpty(),
            subjectName = subject?.text("name", Untrusted.NAME).orEmpty(),
            detail = details(o.optJSONObject("detail")),
        )
    }

    /** The detail fields a person can read at a glance: scalars and short lists, cleaned and capped. */
    private fun details(d: JSONObject?): List<Pair<String, String>> {
        if (d == null) return emptyList()
        return d.keys().asSequence().sorted().mapNotNull { k ->
            val v = d.opt(k)
            val text = when (v) {
                null, JSONObject.NULL -> null
                is JSONObject -> null
                is org.json.JSONArray -> (0 until v.length()).map { v.opt(it) }
                    .filter { it !is JSONObject && it !is org.json.JSONArray && it != JSONObject.NULL }
                    .take(10).joinToString(", ").takeIf { it.isNotEmpty() }
                else -> v.toString()
            } ?: return@mapNotNull null
            Untrusted.clean(k, 40) to Untrusted.clean(text, Untrusted.OPTION)
        }.take(8).toList()
    }

    private fun notification(o: JSONObject): InboxItem? {
        val id = o.text("id", 64).takeIf { it.isNotEmpty() } ?: return null
        // Kept as sent, never cleaned into something else: a link with anything
        // odd in it is not opened at all.
        val link = o.str("link")?.takeIf { it.length <= LINK_MAX }.orEmpty()
        return InboxItem(
            id = id,
            category = o.text("category", 20),
            eventType = o.text("event_type", 64),
            severity = o.text("severity", 20),
            title = o.text("title", Untrusted.REASON),
            body = lines(o.str("body").orEmpty()),
            link = link,
            read = o.optBoolean("read", false),
            createdAt = instant(o.str("created_at")),
        )
    }

    /**
     * The phone's refusals that every key route of its own can give before its
     * checks: a key the server no longer knows, approvals switched off on the
     * platform, a phone that does not approve now, and the account's own
     * refusals. Null for anything else, which the route reads.
     */
    private fun <T> phoneRefusal(a: Answer): Outcome<T>? = when {
        a.ok -> null
        a.status == 401 -> Outcome.Failed(Problem.SignedOut)
        a.status == 404 && a.reason() == "mcp_disabled" -> a.refusal(Refusal.APPROVALS_OFF)
        a.status == 403 && a.data?.optBoolean("approver_inactive") == true -> a.refusal(Refusal.APPROVER_INACTIVE)
        a.status == 403 -> a.accountRefusal()
        else -> null
    }

    /** Every call here shares one limit per key on the platform; a 429 says how long to leave it. */
    private fun <T> call(route: String, body: JSONObject, read: (Answer) -> Outcome<T>): Outcome<T> =
        cliCall(transport, origin, host, route, body) { a -> if (a.status == 429) a.limited() else read(a) }

    private companion object {
        const val LINK_MAX = 2048
        const val BODY_LINES = 8

        /** A notification's text: each line cleaned and capped, blank ones dropped, at most [BODY_LINES]. */
        fun lines(raw: String): String =
            raw.split('\n').map { Untrusted.clean(it, Untrusted.OPTION) }.filter { it.isNotBlank() }.take(BODY_LINES).joinToString("\n")
    }
}

/**
 * Wait for the browser to confirm this phone, deny it, or let it lapse.
 *
 * The same shape as the sign-in wait: the interval the server asked for, never
 * faster than once a second. A poll that gets no answer, a server error or a 429
 * is tried again rather than ending the wait, because the person is in the
 * browser on this same phone while it runs and can still confirm it there; a 429
 * doubles the interval, up to thirty seconds.
 */
suspend fun awaitEnrolment(
    enrolment: Enrolment,
    poll: (String) -> Outcome<EnrolState>,
    sleep: suspend (Long) -> Unit,
    now: () -> Long,
): Outcome<EnrolState> {
    var interval = enrolment.intervalSeconds.coerceIn(1, 30) * 1000L
    val deadline = now() + enrolment.expiresInSeconds.coerceAtLeast(1) * 1000L
    while (now() < deadline) {
        sleep(interval)
        when (val answer = poll(enrolment.code)) {
            is Outcome.Ok -> if (answer.value != EnrolState.PENDING) return answer
            is Outcome.Failed -> when (val p = answer.problem) {
                is Problem.Unreachable -> Unit
                is Problem.Broken -> if (p.status !in 500..599) return answer
                is Problem.Refused -> if (p.status == 429) interval = (interval * 2).coerceAtMost(30_000L) else return answer
                else -> return answer
            }
        }
    }
    return Outcome.Ok(EnrolState.EXPIRED)
}

/**
 * Enrol this phone with the public half of a key it has just made: send it, let
 * [opened] show the fingerprint and open the confirmation page, and wait.
 *
 * What comes of it is written to [ledger] before this returns. An approver the
 * server created and the browser did not confirm here is let go of and revoked,
 * however the wait ended, cancelling included, because the browser page stays
 * open: a Confirm pressed after the phone stopped waiting would otherwise make
 * an approver whose key the phone has already deleted. So is one whose start
 * the phone refused.
 */
suspend fun enrol(
    api: ApprovalApi,
    key: String,
    deviceId: String,
    deviceName: String,
    publicKey: ByteArray,
    ledger: ApproverLedger,
    opened: suspend (Enrolment) -> Unit,
    sleep: suspend (Long) -> Unit,
    now: () -> Long,
): Outcome<EnrolState> {
    // An approver the server made and this phone refused, for a key that is not
    // this phone's or with no code to confirm it by, is revoked like any other
    // the phone lets go of. Whoever changed the key also holds the code.
    var made: String? = null
    val e = when (val started = api.enrolStart(key, deviceId, deviceName, publicKey) { made = it }) {
        is Outcome.Ok -> started.value
        is Outcome.Failed -> {
            made?.let { id ->
                ledger.letGo(id)
                ledger.settle { api.revoke(key, it) }
            }
            return started
        }
    }
    // Cancelled while the start was on its way: the server made an approver
    // all the same, and nothing will wait for it.
    if (!currentCoroutineContext().isActive) {
        ledger.letGo(e.approverId)
        throw CancellationException("The enrolment was cancelled while it started.")
    }
    ledger.started(e.approverId)
    val result = try {
        opened(e)
        awaitEnrolment(e, { code -> api.enrolPoll(key, code) }, sleep, now)
    } catch (c: CancellationException) {
        ledger.stopped(e.approverId)
        throw c
    }
    if (result is Outcome.Ok && result.value == EnrolState.ACTIVE && ledger.confirmed(e.approverId, e.fingerprint)) return result
    ledger.stopped(e.approverId)
    ledger.settle { id -> api.revoke(key, id) }
    return result
}
