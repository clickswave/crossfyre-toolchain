package io.crossfyre.mobile.approve

import io.crossfyre.mobile.account.Outcome
import io.crossfyre.mobile.account.Problem
import io.crossfyre.mobile.account.Refusal
import io.crossfyre.mobile.account.Reply
import io.crossfyre.mobile.account.Transport
import io.crossfyre.mobile.reasonOf
import kotlinx.coroutines.runBlocking
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.IOException
import java.security.KeyPairGenerator
import java.security.spec.ECGenParameterSpec
import java.time.Instant
import java.util.Base64

/**
 * The approvals client against canned answers in the shapes the routes give.
 * Every refusal is asserted as the problem the screen shows, by status, so a
 * route that is missing (404) can never read as a refusal the screen expects.
 */
class ApprovalApiTest {

    private class Fake(vararg replies: Reply) : Transport {
        val queue = ArrayDeque(replies.toList())
        val calls = mutableListOf<Pair<String, JSONObject>>()
        var failWith: IOException? = null

        override fun post(url: String, json: String): Reply {
            calls += url to JSONObject(json)
            failWith?.let { throw it }
            return queue.removeFirst()
        }
    }

    private fun envelope(status: Int, message: String, data: Any? = null, errors: List<String> = emptyList(), retryAfter: Long? = null) =
        Reply(status, JSONObject().put("status", status).put("message", message)
            .put("errors", JSONArray(errors)).put("data", data ?: JSONObject.NULL).toString(), retryAfter)

    private fun api(fake: Fake) = ApprovalApi("https://crossfyre.io/", fake)

    private fun <T> ok(o: Outcome<T>): T = when (o) {
        is Outcome.Ok -> o.value
        is Outcome.Failed -> { fail("expected success, got ${o.problem}"); throw IllegalStateException() }
    }

    private fun problem(o: Outcome<*>): Problem = when (o) {
        is Outcome.Failed -> o.problem
        is Outcome.Ok -> { fail("expected a problem, got ${o.value}"); throw IllegalStateException() }
    }

    private val key = "cfk_" + "b".repeat(40)
    private val id = "3f9c1e0b-6a2d-4b8e-9c71-0d5e2f4a8b13"
    private val spki = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair().public.encoded

    // ── enrolment ─────────────────────────────────────────────────────────

    @Test
    fun enrolling_sends_the_install_the_name_and_the_public_key() {
        val fake = Fake(envelope(200, "ok", JSONObject()
            .put("approver_id", "ap-1").put("enrol_code", "cfe_" + "c".repeat(64))
            .put("confirm_url", "https://elsewhere.example/m/enrol?code=x")
            .put("fingerprint", Spki.fingerprint(spki).uppercase()).put("interval", 3).put("expires_in", 600)))
        val e = ok(api(fake).enrolStart(key, "install-0001", "Pixel 8", spki))

        val (url, body) = fake.calls.single()
        assertEquals("https://crossfyre.io/api/v1/cli/approver/start", url)
        assertEquals(setOf("api_key", "device_id", "device_name", "public_key"), body.keySet())
        assertEquals(key, body.getString("api_key"))
        assertEquals("install-0001", body.getString("device_id"))
        assertEquals("Pixel 8", body.getString("device_name"))
        assertTrue(Base64.getDecoder().decode(body.getString("public_key")).contentEquals(spki))
        assertEquals("ap-1", e.approverId)
        // The page is on the server this app talks to, whatever the answer named.
        assertEquals("https://crossfyre.io/m/enrol?code=cfe_" + "c".repeat(64), e.confirmUrl)
        assertEquals(Spki.fingerprint(spki), e.fingerprint)
    }

    @Test
    fun an_enrolment_for_a_key_the_phone_did_not_send_is_refused() {
        val p = problem(api(Fake(envelope(200, "ok", JSONObject()
            .put("approver_id", "ap-1").put("enrol_code", "cfe_x").put("fingerprint", "0000 0000 0000 0000"))))
            .enrolStart(key, "install-0001", "Pixel 8", spki))
        assertTrue(p is Problem.Broken)
        assertTrue(p.text.contains("different key"))
    }

    @Test
    fun enrolment_refusals_are_told_apart() {
        assertEquals(Problem.SignedOut, problem(api(Fake(envelope(401, "Invalid key"))).enrolStart(key, "i", "n", spki)))
        assertEquals(Refusal.TOO_MANY_APPROVERS, reasonOf(problem(api(Fake(envelope(409, "Five phones already approve for this account"))).enrolStart(key, "i", "n", spki))))
        val bad = problem(api(Fake(envelope(400, "public_key is not a P-256 key"))).enrolStart(key, "i", "n", spki))
        assertEquals(Problem.Refused(400, "public_key is not a P-256 key"), bad)
        assertEquals(Refusal.EMAIL_UNVERIFIED, reasonOf(problem(api(Fake(envelope(403, "Verify", JSONObject().put("email_unverified", true)))).enrolStart(key, "i", "n", spki))))
        assertTrue(problem(api(Fake(envelope(500, "boom"))).enrolStart(key, "i", "n", spki)) is Problem.Broken)
        assertTrue(problem(api(Fake().apply { failWith = IOException("down") }).enrolStart(key, "i", "n", spki)) is Problem.Unreachable)
    }

    @Test
    fun the_enrolment_poll_reads_each_state_and_a_lapsed_code() {
        for ((wire, state) in listOf("pending" to EnrolState.PENDING, "active" to EnrolState.ACTIVE, "denied" to EnrolState.DENIED, "expired" to EnrolState.EXPIRED)) {
            val fake = Fake(envelope(200, "ok", JSONObject().put("status", wire)))
            assertEquals(state, ok(api(fake).enrolPoll(key, "cfe_1")))
            assertEquals(setOf("api_key", "enrol_code"), fake.calls.single().second.keySet())
            assertEquals("https://crossfyre.io/api/v1/cli/approver/poll", fake.calls.single().first)
        }
        assertEquals(Refusal.UNKNOWN, reasonOf(problem(api(Fake(envelope(404, "Unknown code"))).enrolPoll(key, "cfe_1"))))
        assertTrue(problem(api(Fake(envelope(200, "ok", JSONObject().put("status", "maybe")))).enrolPoll(key, "cfe_1")) is Problem.Broken)
    }

    @Test
    fun the_enrolment_wait_ends_on_an_answer_and_rides_out_a_dropped_connection() = runBlocking {
        val e = Enrolment("ap-1", "cfe_1", "u", "fp", intervalSeconds = 3, expiresInSeconds = 30)
        var clock = 0L
        val answers = ArrayDeque(listOf<Outcome<EnrolState>>(
            Outcome.Ok(EnrolState.PENDING), Outcome.Failed(Problem.Unreachable("crossfyre.io")), Outcome.Ok(EnrolState.ACTIVE),
        ))
        val r = awaitEnrolment(e, { answers.removeFirst() }, { clock += it }, { clock })
        assertEquals(Outcome.Ok(EnrolState.ACTIVE), r)
        assertEquals(9_000L, clock)

        clock = 0
        val never = awaitEnrolment(e, { Outcome.Ok(EnrolState.PENDING) }, { clock += it }, { clock })
        assertEquals(Outcome.Ok(EnrolState.EXPIRED), never)

        val refused = awaitEnrolment(e, { Outcome.Failed(Problem.SignedOut) }, { }, { 0L })
        assertEquals(Outcome.Failed(Problem.SignedOut), refused)
    }

    @Test
    fun the_enrolment_wait_rides_out_a_server_error_and_slows_down_for_a_rate_limit() = runBlocking {
        val e = Enrolment("ap-1", "cfe_1", "u", "fp", intervalSeconds = 3, expiresInSeconds = 60)
        var clock = 0L
        val answers = ArrayDeque(listOf<Outcome<EnrolState>>(
            Outcome.Failed(Problem.Broken(502, "Bad gateway")),
            Outcome.Failed(Problem.Refused(429, "Slow down")),
            Outcome.Failed(Problem.Broken(503, "Unavailable")),
            Outcome.Ok(EnrolState.ACTIVE),
        ))
        val r = awaitEnrolment(e, { answers.removeFirst() }, { clock += it }, { clock })
        assertEquals(Outcome.Ok(EnrolState.ACTIVE), r)
        assertEquals("three seconds, three, then six after the 429", 18_000L, clock)

        // A refusal that asking again will not change ends the wait, and so does
        // an answer this app cannot read.
        val forbidden = Outcome.Failed(Problem.Refused(403, "No"))
        assertEquals(forbidden, awaitEnrolment(e, { forbidden }, { }, { 0L }))
        val unreadable = Outcome.Failed(Problem.Broken(200, "The server answered with something this app cannot read (HTTP 200)."))
        assertEquals(unreadable, awaitEnrolment(e, { unreadable }, { }, { 0L }))
    }

    @Test
    fun revoking_is_idempotent_and_sends_the_approver() {
        val fake = Fake(envelope(200, "ok"), envelope(404, "No such approver"))
        assertEquals(Unit, ok(api(fake).revoke(key, "ap-1")))
        assertEquals(Unit, ok(api(fake).revoke(key, "ap-1")))
        assertEquals("https://crossfyre.io/api/v1/cli/approver/revoke", fake.calls[0].first)
        assertEquals("ap-1", fake.calls[0].second.getString("approver_id"))
        assertEquals(Problem.SignedOut, problem(api(Fake(envelope(401, "Invalid key"))).revoke(key, "ap-1")))
    }

    // ── pending ───────────────────────────────────────────────────────────

    @Test
    fun the_pending_list_keeps_the_summary_text_exactly() {
        val summary = "{\"id\":\"$id\",  \"v\":1}"
        val fake = Fake(envelope(200, "ok", JSONObject()
            .put("server_time", "2026-10-30T09:14:02Z")
            .put("approver", JSONObject().put("id", "ap-1").put("status", "active").put("device_name", "Pixel 8"))
            .put("approvals", JSONArray()
                .put(JSONObject().put("id", id.uppercase()).put("status", "pending").put("created_at", "2026-10-30T09:12:44Z")
                    .put("expires_at", "2026-10-30T09:22:44Z").put("summary_json", summary).put("digest", "ab".repeat(32)))
                .put(JSONObject().put("id", "apr_not_a_uuid").put("status", "pending")))))
        val list = ok(api(fake).pending(key))

        assertEquals(JSONObject().put("api_key", key).toString(), fake.calls.single().second.toString())
        assertEquals("https://crossfyre.io/api/v1/cli/approvals/pending", fake.calls.single().first)
        assertEquals(Instant.parse("2026-10-30T09:14:02Z"), list.serverTime)
        assertEquals(Approver("ap-1", "active", "Pixel 8"), list.approver)
        assertEquals(1, list.approvals.size)
        assertEquals(id, list.approvals[0].id)
        assertEquals(summary, list.approvals[0].summaryJson)
        assertEquals(Instant.parse("2026-10-30T09:22:44Z"), list.approvals[0].expiresAt)
    }

    @Test
    fun a_pending_list_with_no_approver_says_so() {
        val list = ok(api(Fake(envelope(200, "ok", JSONObject().put("server_time", "2026-10-30T09:14:02Z")
            .put("approver", JSONObject.NULL).put("approvals", JSONArray())))).pending(key))
        assertNull(list.approver)
        assertTrue(list.approvals.isEmpty())
        assertEquals(Problem.SignedOut, problem(api(Fake(envelope(401, "Invalid key"))).pending(key)))
        assertEquals(Refusal.ACCOUNT_SUSPENDED, reasonOf(problem(api(Fake(envelope(403, "Suspended", JSONObject().put("suspended", true)))).pending(key))))
        assertTrue(problem(api(Fake(envelope(200, "ok", JSONObject()))).pending(key)) is Problem.Broken)
    }

    // ── decisions ─────────────────────────────────────────────────────────

    @Test
    fun an_approval_carries_the_signature_and_nothing_else_it_does_not_need() {
        val fake = Fake(envelope(200, "Approved", JSONObject().put("status", "approved")))
        val sig = byteArrayOf(0x30, 0x44, 1, 2, 3)
        assertEquals("approved", ok(api(fake).approve(key, id, "ap-1", 1793345642, sig)))

        val (url, body) = fake.calls.single()
        assertEquals("https://crossfyre.io/api/v1/cli/approvals/decide", url)
        assertEquals(setOf("api_key", "approval_id", "decision", "approver_id", "signed_at", "signature"), body.keySet())
        assertEquals("approve", body.getString("decision"))
        assertEquals(1793345642L, body.getLong("signed_at"))
        assertEquals(Base64.getEncoder().encodeToString(sig), body.getString("signature"))
    }

    @Test
    fun a_denial_carries_no_signature() {
        val fake = Fake(envelope(200, "Denied", JSONObject().put("status", "denied")))
        assertEquals("denied", ok(api(fake).deny(key, id)))
        val body = fake.calls.single().second
        assertEquals(setOf("api_key", "approval_id", "decision"), body.keySet())
        assertEquals("deny", body.getString("decision"))
    }

    @Test
    fun each_decision_refusal_is_its_own_problem() {
        fun refusalOf(reply: Reply) = problem(api(Fake(reply)).approve(key, id, "ap-1", 1, byteArrayOf(1)))
        assertEquals(Problem.SignedOut, refusalOf(envelope(401, "Invalid key")))
        assertEquals(Refusal.UNKNOWN, reasonOf(refusalOf(envelope(404, "No such approval"))))
        assertEquals(Refusal.APPROVER_INACTIVE, reasonOf(refusalOf(envelope(403, "approver_inactive", JSONObject().put("approver_inactive", true)))))
        assertEquals(Refusal.APPROVER_INACTIVE, reasonOf(refusalOf(envelope(403, "This approver is not active"))))
        assertEquals(Refusal.NOT_PENDING, reasonOf(refusalOf(envelope(409, "Already denied", JSONObject().put("status", "denied")))))
        assertEquals(Refusal.APPROVAL_EXPIRED, reasonOf(refusalOf(envelope(410, "Expired"))))
        assertEquals(Refusal.BAD_SIGNATURE, reasonOf(refusalOf(envelope(422, "bad_signature"))))
        assertTrue(refusalOf(envelope(503, "Approvals unavailable")) is Problem.Broken)
        assertFalse(refusalOf(envelope(403, "Suspended", JSONObject().put("suspended", true))).let { reasonOf(it) == Refusal.APPROVER_INACTIVE })
    }

    // ── history and activity ──────────────────────────────────────────────

    @Test
    fun the_history_reads_each_row_and_skips_ones_without_an_id() {
        val fake = Fake(envelope(200, "ok", JSONObject().put("server_time", "2026-10-31T13:57:01Z").put("approvals", JSONArray()
            .put(JSONObject().put("id", id).put("status", "approved").put("action_label", "Launch a vulnerability scan")
                .put("workspace_name", "Acme external").put("created_at", "2026-10-30T09:12:44Z").put("decided_at", "2026-10-30T09:13:10Z")
                .put("decided_via", "phone").put("device_name", "Pixel 8").put("launch_state", "launched").put("workflow_id", "wf-1")
                .put("digest", "ab".repeat(32)))
            .put(JSONObject().put("status", "denied")))))
        val history = ok(api(fake).history(key, before = Instant.parse("2026-10-31T00:00:00Z")))
        val rows = history.rows
        assertEquals(1, rows.size)
        assertEquals("phone", rows[0].decidedVia)
        assertEquals("launched", rows[0].launchState)
        assertEquals("", rows[0].workflowStatus)
        // What a stop is signed over, and the platform's time to sign it at.
        assertEquals("ab".repeat(32), rows[0].digest)
        assertEquals(Instant.parse("2026-10-31T13:57:01Z"), history.serverTime)
        assertEquals("2026-10-31T00:00:00Z", fake.calls.single().second.getString("before"))
        assertEquals("https://crossfyre.io/api/v1/cli/approvals/history", fake.calls.single().first)
    }

    @Test
    fun a_history_from_a_platform_without_digests_has_none_to_sign() {
        val history = ok(api(Fake(envelope(200, "ok", JSONObject().put("approvals", JSONArray()
            .put(JSONObject().put("id", id).put("status", "approved")))))).history(key))
        assertEquals("", history.rows.single().digest)
        assertNull(history.serverTime)
    }

    // ── stop ──────────────────────────────────────────────────────────────

    @Test
    fun a_stop_is_signed_like_an_approval_and_says_what_it_stopped() {
        val fake = Fake(envelope(200, "Stopped", JSONObject().put("id", id).put("workflow_id", "wf-1").put("result", "stopped")
            .put("workflow_status", "stopped").put("operations_cancelled", 3)))
        val sig = byteArrayOf(0x30, 0x45, 9, 8, 7)
        val r = ok(api(fake).stop(key, id, "ap-1", 1793500000, sig))
        assertEquals(StopAnswer.Stopped("stopped", 3), r)

        val (url, body) = fake.calls.single()
        assertEquals("https://crossfyre.io/api/v1/cli/approvals/stop", url)
        // No decision field: the route is the decision, and the signature names it.
        assertEquals(setOf("api_key", "approval_id", "approver_id", "signed_at", "signature"), body.keySet())
        assertEquals(id, body.getString("approval_id"))
        assertEquals("ap-1", body.getString("approver_id"))
        // An integer, never a string: the platform refuses a string before the handler.
        assertTrue(body.get("signed_at") is Number)
        assertEquals(1793500000L, body.getLong("signed_at"))
        assertEquals(Base64.getEncoder().encodeToString(sig), body.getString("signature"))
    }

    @Test
    fun a_stop_signed_off_the_platform_clock_hands_back_its_time() {
        val stale = envelope(422, "stale_signature", JSONObject().put("reason", "stale_signature").put("server_time", "2026-10-31T14:00:00.123456Z"))
        assertEquals(StopAnswer.Stale(Instant.parse("2026-10-31T14:00:00.123456Z")), ok(api(Fake(stale)).stop(key, id, "ap-1", 1, byteArrayOf(1))))
        // Without the time there is nothing to sign again at: it is a refusal.
        val noTime = envelope(422, "stale_signature", JSONObject().put("reason", "stale_signature"))
        assertEquals(Refusal.STALE_SIGNATURE, reasonOf(problem(api(Fake(noTime)).stop(key, id, "ap-1", 1, byteArrayOf(1)))))
    }

    @Test
    fun each_stop_refusal_is_its_own_problem() {
        fun refusalOf(reply: Reply) = problem(api(Fake(reply)).stop(key, id, "ap-1", 1, byteArrayOf(1)))
        assertEquals(Problem.SignedOut, refusalOf(envelope(401, "Not logged in", JSONObject())))
        assertEquals(Refusal.UNKNOWN, reasonOf(refusalOf(envelope(404, "No such approval", JSONObject()))))
        assertEquals(Refusal.APPROVALS_OFF, reasonOf(refusalOf(envelope(404, "Approvals are switched off", JSONObject().put("reason", "mcp_disabled")))))
        assertEquals(Refusal.APPROVER_INACTIVE, reasonOf(refusalOf(envelope(403, "approver_inactive", JSONObject().put("approver_inactive", true)))))
        assertEquals(Refusal.BAD_SIGNATURE, reasonOf(refusalOf(envelope(422, "bad_signature", JSONObject()))))
        assertEquals(Refusal.NOT_LAUNCHED, reasonOf(refusalOf(envelope(409, "This approval did not launch a scan",
            JSONObject().put("reason", "not_launched").put("status", "pending")))))
        assertEquals(Refusal.NOT_RUNNING, reasonOf(refusalOf(envelope(409, "That scan is not running",
            JSONObject().put("reason", "not_running").put("workflow_status", "stopped")))))
        val role = refusalOf(envelope(403, "Your role in this workspace (Viewer) does not allow stopping scans.",
            JSONObject().put("reason", "missing_permission").put("permission", "workflow.halt")
                .put("role", JSONObject().put("id", "viewer").put("name", "Viewer")),
            errors = listOf("workflow.halt is required")))
        assertEquals(Refusal.MISSING_PERMISSION, reasonOf(role))
        assertEquals("Your role in this workspace (Viewer) does not allow stopping scans.", role.text)
        assertEquals(Refusal.NOT_MEMBER, reasonOf(refusalOf(envelope(403, "Not a member of this workspace"))))
        assertEquals(Refusal.ACCOUNT_SUSPENDED, reasonOf(refusalOf(envelope(403, "Suspended", JSONObject().put("suspended", true)))))
        assertTrue(refusalOf(envelope(500, "boom")) is Problem.Broken)
    }

    // ── notifications ─────────────────────────────────────────────────────

    private fun note(id: String, read: Boolean, link: Any? = "/m/approve/$id", body: Any? = "Launch a crawl\nWorkspace: Acme\n\nOpen https://crossfyre.io/m/approve/$id") =
        JSONObject().put("id", id).put("category", "approval").put("event_type", "approval.requested").put("severity", "warning")
            .put("title", "An agent is waiting for your approval").put("body", body ?: JSONObject.NULL)
            .put("link", link ?: JSONObject.NULL).put("read", read).put("created_at", "2026-10-31T13:56:58.401796Z")

    @Test
    fun the_inbox_reads_a_page_and_keeps_each_line_of_a_body_apart() {
        val fake = Fake(envelope(200, "Notifications", JSONObject()
            .put("items", JSONArray().put(note(id, false)).put(note("n-2", true, link = null, body = "a\u202Eb\tc")).put(JSONObject().put("title", "no id")))
            .put("total", 8).put("unread", 5).put("page", 2).put("limit", 20)))
        val page = ok(api(fake).inbox(key, page = 2))

        val (url, body) = fake.calls.single()
        assertEquals("https://crossfyre.io/api/v1/cli/inbox/list", url)
        assertEquals(setOf("api_key", "page", "limit"), body.keySet())
        assertEquals(2, body.getInt("page"))
        assertEquals(20, body.getInt("limit"))
        assertEquals(8, page.total)
        assertEquals(5, page.unread)
        assertEquals(2, page.page)
        assertEquals(2, page.items.size)
        val n = page.items[0]
        assertEquals(id, n.id)
        assertEquals("approval", n.category)
        assertEquals("warning", n.severity)
        assertFalse(n.read)
        assertEquals("/m/approve/$id", n.link)
        // Each line cleaned on its own, the blank one dropped.
        assertEquals("Launch a crawl\nWorkspace: Acme\nOpen https://crossfyre.io/m/approve/$id", n.body)
        assertEquals(Instant.parse("2026-10-31T13:56:58.401796Z"), n.createdAt)
        assertEquals("", page.items[1].link)
        assertEquals("abc", page.items[1].body)
        assertTrue(page.items[1].read)
    }

    @Test
    fun the_unread_filter_is_asked_for_by_name() {
        val fake = Fake(envelope(200, "Notifications", JSONObject().put("items", JSONArray()).put("total", 0).put("unread", 0).put("page", 1)))
        ok(api(fake).inbox(key, limit = 500, unreadOnly = true))
        val body = fake.calls.single().second
        assertEquals("unread", body.getString("filter"))
        assertEquals(50, body.getInt("limit"))
    }

    @Test
    fun marking_read_sends_the_ids_or_all_and_reads_what_is_left() {
        val fake = Fake(envelope(200, "Marked read", JSONObject().put("marked", 2).put("unread", 3)),
            envelope(200, "Marked read", JSONObject().put("marked", 3).put("unread", 0)))
        assertEquals(InboxMarked(2, 3), ok(api(fake).inboxRead(key, listOf(id, "n-2"))))
        assertEquals(InboxMarked(3, 0), ok(api(fake).inboxReadAll(key)))
        assertEquals("https://crossfyre.io/api/v1/cli/inbox/read", fake.calls[0].first)
        assertEquals(setOf("api_key", "ids"), fake.calls[0].second.keySet())
        assertEquals(listOf(id, "n-2"), fake.calls[0].second.getJSONArray("ids").toList())
        assertEquals(setOf("api_key", "all"), fake.calls[1].second.keySet())
        assertTrue(fake.calls[1].second.getBoolean("all"))
        val bad = problem(api(Fake(envelope(400, "Name 1 to 100 notification ids", JSONObject()))).inboxRead(key, emptyList()))
        assertEquals(Problem.Refused(400, "Name 1 to 100 notification ids"), bad)
    }

    /**
     * Notifications, the log and stop answer only a key whose own approver is
     * active. A phone that does not approve is told so, not shown an error.
     */
    @Test
    fun a_phone_that_does_not_approve_is_told_so_by_every_route_only_an_approver_reads() {
        val inactive = { envelope(403, "approver_inactive", JSONObject().put("approver_inactive", true)) }
        assertEquals(Refusal.APPROVER_INACTIVE, reasonOf(problem(api(Fake(inactive())).inbox(key))))
        assertEquals(Refusal.APPROVER_INACTIVE, reasonOf(problem(api(Fake(inactive())).inboxReadAll(key))))
        assertEquals(Refusal.APPROVER_INACTIVE, reasonOf(problem(api(Fake(inactive())).activity(key, ActivityScope.Account))))
        assertEquals(Refusal.APPROVER_INACTIVE, reasonOf(problem(api(Fake(inactive())).stop(key, id, "ap-1", 1, byteArrayOf(1)))))
        val off = { envelope(404, "Approvals are switched off", JSONObject().put("reason", "mcp_disabled")) }
        assertEquals(Refusal.APPROVALS_OFF, reasonOf(problem(api(Fake(off())).inbox(key))))
        assertEquals(Refusal.APPROVALS_OFF, reasonOf(problem(api(Fake(off())).activity(key, ActivityScope.Account))))
    }

    @Test
    fun a_rate_limit_on_any_approval_route_carries_the_wait_the_server_asked_for() {
        val limited = { envelope(429, "Too many requests", JSONObject().put("reason", "rate_limited"), retryAfter = 60) }
        for (call in listOf<(ApprovalApi) -> Outcome<*>>(
            { it.pending(key) }, { it.history(key) }, { it.inbox(key) }, { it.activity(key, ActivityScope.Account) },
            { it.stop(key, id, "ap-1", 1, byteArrayOf(1)) }, { it.deny(key, id) },
        )) {
            val p = problem(call(api(Fake(limited())))) as Problem.Refused
            assertEquals(Refusal.RATE_LIMITED, p.reason)
            assertEquals(429, p.status)
            assertEquals(60L, p.retryAfterSeconds)
        }
        // No header: the wait is left to the caller.
        assertNull((problem(api(Fake(envelope(429, "Too many requests"))).inbox(key)) as Problem.Refused).retryAfterSeconds)
    }

    @Test
    fun the_activity_page_reads_the_activity_list_shape() {
        val event = JSONObject()
            .put("id", 18232).put("at", "2026-10-30T09:12:44Z")
            .put("org", JSONObject().put("id", "o1").put("name", "Acme"))
            .put("team", JSONObject().put("id", "t1").put("name", "Red"))
            .put("workspace", JSONObject().put("id", "w1").put("name", "Red Workspace"))
            .put("actor", JSONObject().put("kind", "user").put("id", "u1").put("name", "asha").put("name_then", "asha"))
            .put("channel", "mcp")
            .put("credential", JSONObject().put("id", "k1").put("label", "cfm_ab12cd34, kali laptop").put("kind", "mcp_key"))
            .put("action", "scan.started").put("outcome", "ok")
            .put("subject", JSONObject().put("type", "workflow").put("id", "wf").put("name", "api sweep"))
            .put("detail", JSONObject().put("targets", JSONArray(listOf("api.example.com"))).put("target_count", 1).put("node_count", 2)
                .put("nested", JSONObject().put("x", 1)))
            .put("client_ip", JSONObject.NULL)
        val fake = Fake(envelope(200, "ok", JSONObject().put("events", JSONArray().put(event)).put("next_before_id", 18183).put("can_export", true)))
        val page = ok(api(fake).activity(key, ActivityScope.Workspace("w1", "Red Workspace"), beforeId = 18300, limit = 30))

        val body = fake.calls.single().second
        assertEquals("https://crossfyre.io/api/v1/cli/activity/list", fake.calls.single().first)
        assertEquals(setOf("api_key", "workspace_id", "before_id", "limit"), body.keySet())
        assertEquals(18300L, body.getLong("before_id"))
        assertEquals(18183L, page.nextBeforeId)
        val e = page.events.single()
        assertEquals(18232L, e.id)
        assertEquals("asha", e.actorName)
        assertEquals("mcp", e.channel)
        assertEquals("cfm_ab12cd34, kali laptop", e.credentialLabel)
        assertEquals("api sweep", e.subjectName)
        assertEquals(listOf("node_count" to "2", "target_count" to "1", "targets" to "api.example.com"), e.detail)
    }

    @Test
    fun the_account_view_asks_for_the_account_and_a_last_page_has_no_next() {
        val fake = Fake(envelope(200, "ok", JSONObject().put("events", JSONArray()).put("next_before_id", JSONObject.NULL)))
        val page = ok(api(fake).activity(key, ActivityScope.Account))
        val body = fake.calls.single().second
        assertEquals(setOf("api_key", "account", "limit"), body.keySet())
        assertTrue(body.getBoolean("account"))
        assertNull(page.nextBeforeId)
        assertEquals(Problem.SignedOut, problem(api(Fake(envelope(401, "Invalid key"))).activity(key, ActivityScope.Account)))
        val export = problem(api(Fake(envelope(400, "Export the activity log from the dashboard", JSONObject().put("reason", "export_not_here"))))
            .activity(key, ActivityScope.Account))
        assertEquals(Problem.Refused(400, "Export the activity log from the dashboard"), export)
    }
}
