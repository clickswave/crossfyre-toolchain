package io.crossfyre.mobile.account

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.IOException

/**
 * The account client against canned answers in the shapes the routes give.
 *
 * Each refusal is asserted as the problem the screen will show, because the point
 * of mapping them is that a Google account is told to use the browser and a
 * revoked key is told to sign in again, rather than both reading "error".
 */
class AccountApiTest {

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

    private fun envelope(status: Int, message: String, data: Any? = null, errors: List<String> = emptyList()) =
        Reply(status, JSONObject()
            .put("status", status)
            .put("message", message)
            .put("errors", JSONArray(errors))
            .put("data", data ?: JSONObject.NULL)
            .toString())

    private val user = JSONObject()
        .put("id", "u-1").put("username", "kew").put("email", "kew@example.com")
        .put("account_type", "personal").put("email_verified", true)

    private fun api(fake: Fake) = AccountApi("https://crossfyre.io/", fake)

    private fun <T> ok(o: Outcome<T>): T = when (o) {
        is Outcome.Ok -> o.value
        is Outcome.Failed -> { fail("expected success, got ${o.problem}"); throw IllegalStateException() }
    }

    private fun problem(o: Outcome<*>): Problem = when (o) {
        is Outcome.Failed -> o.problem
        is Outcome.Ok -> { fail("expected a problem, got ${o.value}"); throw IllegalStateException() }
    }

    // ── password ───────────────────────────────────────────────────────────

    @Test
    fun a_password_sign_in_posts_the_three_fields_to_cli_login() {
        val fake = Fake(envelope(200, "Logged in", JSONObject()
            .put("api_key", "cfk_" + "a".repeat(32)).put("key_prefix", "cfk_aaaa").put("user", user)))
        val signedIn = ok(api(fake).login("kew@example.com", "hunter2", "Crossfyre Mobile on Pixel 8"))

        assertEquals("cfk_" + "a".repeat(32), signedIn.key)
        assertEquals(AccountUser("u-1", "kew", "kew@example.com", "personal", true), signedIn.user)
        val (url, body) = fake.calls.single()
        assertEquals("https://crossfyre.io/api/v1/cli/login", url)
        assertEquals("kew@example.com", body.getString("identifier"))
        assertEquals("hunter2", body.getString("password"))
        assertEquals("Crossfyre Mobile on Pixel 8", body.getString("key_name"))
    }

    @Test
    fun a_wrong_password_is_said_as_one() {
        val p = problem(api(Fake(envelope(401, "Could not log in"))).login("kew", "x", "k"))
        assertEquals(Problem.WrongPassword, p)
    }

    @Test
    fun a_google_account_is_sent_to_the_browser() {
        val reply = envelope(409, "This account uses Google sign-in", JSONObject().put("use_google", true))
        assertEquals(Problem.UseGoogle, problem(api(Fake(reply)).login("kew", "x", "k")))
    }

    @Test
    fun an_enterprise_account_in_review_is_told_so_in_the_servers_words() {
        val reply = envelope(403, "Your enterprise request is in review", JSONObject().put("pending", true))
        val p = problem(api(Fake(reply)).login("kew", "x", "k"))
        assertEquals(Problem.Refused(403, "Your enterprise request is in review"), p)
    }

    @Test
    fun the_rate_limit_is_passed_on() {
        val p = problem(api(Fake(envelope(429, "Too many login attempts. Try again later."))).login("a", "b", "c"))
        assertEquals(Problem.Refused(429, "Too many login attempts. Try again later."), p)
    }

    @Test
    fun a_plain_text_rejection_does_not_read_as_a_crash() {
        val p = problem(api(Fake(Reply(422, "Failed to deserialize the JSON body"))).login("a", "b", "c"))
        assertTrue(p is Problem.Refused)
        assertEquals(422, (p as Problem.Refused).status)
    }

    @Test
    fun a_server_failure_says_so() {
        val p = problem(api(Fake(envelope(500, "Login failed"))).login("a", "b", "c"))
        assertTrue(p.toString(), p is Problem.Broken && p.status == 500)
    }

    @Test
    fun no_answer_names_the_host() {
        val fake = Fake().apply { failWith = IOException("connect timed out") }
        assertEquals(Problem.Unreachable("crossfyre.io"), problem(api(fake).login("a", "b", "c")))
    }

    // ── browser ────────────────────────────────────────────────────────────

    @Test
    fun the_approval_page_is_on_our_own_origin_whatever_the_server_says() {
        // The server builds verification_uri_complete from an origin that no env
        // file sets, so on staging it would point at production.
        val fake = Fake(envelope(200, "Login started", JSONObject()
            .put("device_code", "cfd_abc123")
            .put("verification_uri", "https://crossfyre.io/device")
            .put("verification_uri_complete", "https://crossfyre.io/device?code=cfd_abc123")
            .put("expires_in", 600).put("interval", 3)))
        val staging = AccountApi("https://staging.crossfyre.io", fake)
        val login = ok(staging.startDeviceLogin(ClientInfo("Pixel 8", "Android 16", "0.2.0")))

        assertEquals("https://staging.crossfyre.io/device?code=cfd_abc123", login.approvalUrl)
        assertEquals(3, login.intervalSeconds)
        assertEquals(600, login.expiresInSeconds)
        val (url, body) = fake.calls.single()
        assertEquals("https://staging.crossfyre.io/api/v1/cli/device/start", url)
        val info = body.getJSONObject("client_info")
        assertEquals("Pixel 8", info.getString("hostname"))
        assertEquals("Android 16", info.getString("os"))
        assertEquals("0.2.0", info.getString("version"))
    }

    @Test
    fun the_approval_url_escapes_the_code() {
        val a = AccountApi("http://10.0.2.2:12004", Fake())
        assertEquals("http://10.0.2.2:12004/device?code=cfd_a%26b%3Dc", a.approvalUrl("cfd_a&b=c"))
    }

    @Test
    fun polling_reads_each_state() {
        fun poll(data: JSONObject) = ok(api(Fake(envelope(200, "ok", data))).pollDeviceLogin("cfd_x"))
        assertEquals(Poll.Waiting, poll(JSONObject().put("status", "pending")))
        assertEquals(Poll.Denied, poll(JSONObject().put("status", "denied")))
        assertEquals(Poll.Expired, poll(JSONObject().put("status", "expired")))
        val approved = poll(JSONObject().put("status", "approved")
            .put("api_key", "cfk_" + "b".repeat(32)).put("user", user))
        assertEquals(Poll.Approved(SignedIn("cfk_" + "b".repeat(32),
            AccountUser("u-1", "kew", "kew@example.com", "personal", true))), approved)
    }

    @Test
    fun an_approval_without_a_key_is_not_taken_for_a_sign_in() {
        val p = problem(api(Fake(envelope(200, "ok", JSONObject().put("status", "approved"))))
            .pollDeviceLogin("cfd_x"))
        assertTrue(p.toString(), p is Problem.Broken)
    }

    @Test
    fun an_unknown_login_request_is_refused() {
        val reply = envelope(404, "Unknown login request", JSONObject().put("status", "unknown"))
        val p = problem(api(Fake(reply)).pollDeviceLogin("cfd_gone"))
        assertTrue(p.toString(), p is Problem.Refused && p.status == 404)
    }

    // ── key, workspaces, pairing, sign-out ─────────────────────────────────

    @Test
    fun a_stored_key_is_checked_and_a_revoked_one_signs_out() {
        val good = ok(api(Fake(envelope(200, "Valid", JSONObject().put("user", user)))).verifyKey("cfk_x"))
        assertEquals("kew", good.username)
        assertEquals(Problem.SignedOut, problem(api(Fake(envelope(401, "Invalid API key"))).verifyKey("cfk_x")))
    }

    @Test
    fun the_workspace_list_is_read_in_the_order_given() {
        val list = JSONArray()
            .put(JSONObject().put("id", "w1").put("name", "Personal").put("owner_kind", "user")
                .put("owner_id", "u-1").put("role", "lead").put("is_active", true).put("is_demo", false)
                .put("billing_source", "user"))
            .put(JSONObject().put("id", "w2").put("name", "Red team").put("owner_kind", "team")
                .put("owner_id", "t-1").put("role", "viewer").put("is_active", false).put("is_demo", true)
                .put("billing_source", "org"))
        val fake = Fake(envelope(200, "Workspaces", JSONObject().put("workspaces", list)))
        val got = ok(api(fake).workspaces("cfk_k"))

        assertEquals(listOf(
            Workspace("w1", "Personal", "user", "lead", isActive = true, isDemo = false),
            Workspace("w2", "Red team", "team", "viewer", isActive = false, isDemo = true),
        ), got)
        val (url, body) = fake.calls.single()
        assertEquals("https://crossfyre.io/api/v1/cli/workspace/list", url)
        assertEquals("cfk_k", body.getString("api_key"))
    }

    @Test
    fun an_unknown_key_listing_workspaces_signs_out() {
        assertEquals(Problem.SignedOut, problem(api(Fake(envelope(401, "Not logged in"))).workspaces("cfk_k")))
    }

    @Test
    fun a_suspension_carries_its_reason() {
        val reply = envelope(403, "Account suspended", JSONObject().put("suspended", true),
            errors = listOf("Chargeback under review"))
        val p = problem(api(Fake(reply)).workspaces("cfk_k"))
        assertEquals(Problem.Refused(403, "Account suspended: Chargeback under review"), p)
    }

    @Test
    fun pairing_sends_the_install_id_and_comes_back_as_a_pairing_for_our_origin() {
        val data = JSONObject()
            .put("workflow_id", "wf-9").put("token", "cfxt_" + "c".repeat(32))
            .put("workspace_id", "w1").put("workspace_name", "Personal")
            .put("session_name", "Crossfyre Mobile: Pixel 8").put("created", true)
        for (status in listOf(201, 200)) {
            val fake = Fake(envelope(status, if (status == 201) "Paired" else "Paired again", data))
            val paired = ok(api(fake).pair("cfk_k", "w1", "3f1c9a4e-0000-4000-8000-000000000000", "Pixel 8"))

            assertEquals("https://crossfyre.io", paired.pairing.apiUrl)
            assertEquals("wf-9", paired.pairing.workflowId)
            assertEquals("cfxt_" + "c".repeat(32), paired.pairing.token)
            assertEquals("Personal", paired.workspaceName)
            assertEquals("Crossfyre Mobile: Pixel 8", paired.sessionName)
            val (url, body) = fake.calls.single()
            assertEquals("https://crossfyre.io/api/v1/cli/mobile/pair", url)
            assertEquals("cfk_k", body.getString("api_key"))
            assertEquals("w1", body.getString("workspace_id"))
            assertEquals("3f1c9a4e-0000-4000-8000-000000000000", body.getString("device_id"))
            assertEquals("Pixel 8", body.getString("device_name"))
        }
    }

    @Test
    fun a_workspace_refusal_is_shown_in_the_servers_words() {
        val reply = envelope(403, "This workspace is archived", JSONObject().put("archived", true))
        assertEquals(Problem.Refused(403, "This workspace is archived"),
            problem(api(Fake(reply)).pair("cfk_k", "w1", "dev-12345678", "Pixel")))
        assertEquals(Problem.SignedOut,
            problem(api(Fake(envelope(401, "Not logged in"))).pair("cfk_k", "w1", "dev-12345678", "Pixel")))
    }

    @Test
    fun a_pairing_without_a_token_is_not_kept() {
        val reply = envelope(201, "Paired", JSONObject().put("workflow_id", "wf-9"))
        val p = problem(api(Fake(reply)).pair("cfk_k", "w1", "dev-12345678", "Pixel"))
        assertTrue(p.toString(), p is Problem.Broken)
    }

    @Test
    fun signing_out_counts_as_done_when_the_key_is_already_gone() {
        val fake = Fake(envelope(200, "Signed out", JSONObject().put("revoked", true)),
            envelope(401, "Not logged in"))
        assertEquals(Outcome.Ok(Unit), api(fake).logout("cfk_k"))
        assertEquals(Outcome.Ok(Unit), api(fake).logout("cfk_k"))
        assertEquals("https://crossfyre.io/api/v1/cli/logout", fake.calls.first().first)
    }

    @Test
    fun no_call_puts_the_key_anywhere_but_the_body() {
        val fake = Fake(envelope(200, "Workspaces", JSONObject().put("workspaces", JSONArray())))
        api(fake).workspaces("cfk_secret")
        assertFalse(fake.calls.single().first.contains("cfk_secret"))
    }

    @Test
    fun a_team_workspace_is_grouped_under_the_organization_its_billing_names() {
        val list = JSONArray()
            .put(JSONObject().put("id", "w3").put("name", "client-app-audit").put("owner_kind", "team")
                .put("role", "operator").put("billing_source", "Northwind Security · org billing"))
            .put(JSONObject().put("id", "w1").put("name", "workspace1").put("owner_kind", "user")
                .put("role", "lead").put("billing_source", "Personal · your credits"))
        val got = ok(api(Fake(envelope(200, "Workspaces", JSONObject().put("workspaces", list)))).workspaces("cfk_k"))
        assertEquals("Northwind Security", got[0].org)
        assertEquals(null, got[1].org)
    }

    @Test
    fun a_refusal_keeps_the_servers_words_and_says_which_it_is() {
        val reply = envelope(403, "Your enterprise request is in review", JSONObject().put("pending", true))
        val p = problem(api(Fake(reply)).login("kew", "x", "k")) as Problem.Refused
        assertEquals(Refusal.IN_REVIEW, p.reason)
        assertEquals(Refusal.RATE_LIMITED, (problem(api(Fake(envelope(429, "Slow down"))).login("a", "b", "c")) as Problem.Refused).reason)
        val gone = problem(api(Fake(envelope(404, "Unknown login request"))).pollDeviceLogin("cfd_gone")) as Problem.Refused
        assertEquals(Refusal.UNKNOWN, gone.reason)
    }
}
