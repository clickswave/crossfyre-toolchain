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

    private fun envelope(status: Int, message: String, data: Any? = null) =
        Reply(status, JSONObject().put("status", status).put("message", message)
            .put("errors", JSONArray()).put("data", data ?: JSONObject.NULL).toString())

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
        val fake = Fake(envelope(200, "ok", JSONObject().put("approvals", JSONArray()
            .put(JSONObject().put("id", id).put("status", "approved").put("action_label", "Launch a vulnerability scan")
                .put("workspace_name", "Acme external").put("created_at", "2026-10-30T09:12:44Z").put("decided_at", "2026-10-30T09:13:10Z")
                .put("decided_via", "phone").put("device_name", "Pixel 8").put("launch_state", "launched").put("workflow_id", "wf-1"))
            .put(JSONObject().put("status", "denied")))))
        val rows = ok(api(fake).history(key, before = Instant.parse("2026-10-31T00:00:00Z")))
        assertEquals(1, rows.size)
        assertEquals("phone", rows[0].decidedVia)
        assertEquals("launched", rows[0].launchState)
        assertEquals("", rows[0].workflowStatus)
        assertEquals("2026-10-31T00:00:00Z", fake.calls.single().second.getString("before"))
        assertEquals("https://crossfyre.io/api/v1/cli/approvals/history", fake.calls.single().first)
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
    }
}
