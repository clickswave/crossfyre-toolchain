package io.crossfyre.mobile

import io.crossfyre.mobile.account.AccountApi
import io.crossfyre.mobile.account.Outcome
import io.crossfyre.mobile.account.Problem
import io.crossfyre.mobile.account.Reply
import io.crossfyre.mobile.account.Transport
import io.crossfyre.mobile.approve.ApprovalApi
import io.crossfyre.mobile.approve.ActivityScope
import io.crossfyre.mobile.approve.SignOutLeft
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * Every refusal the sign-in, workspace and pairing routes can give, as the
 * screen will word it. Each goes through the real client with the server's
 * envelope, so a flag the server stops sending shows up here as the wrong
 * banner rather than on someone's phone.
 */
class NoticesTest {

    private fun envelope(status: Int, message: String, data: JSONObject? = null) = Reply(
        status,
        JSONObject().put("status", status).put("message", message).put("errors", JSONArray())
            .put("data", data ?: JSONObject()).toString(),
    )

    private fun api(reply: Reply) = AccountApi("https://crossfyre.io", Transport { _, _ -> reply })

    private fun problem(o: Outcome<*>): Problem = when (o) {
        is Outcome.Failed -> o.problem
        is Outcome.Ok -> { fail("expected a refusal, got ${o.value}"); throw IllegalStateException() }
    }

    private fun signIn(reply: Reply) = signInNotice(problem(api(reply).login("meera", "x", "k")), "crossfyre.io")
    private fun list(reply: Reply) = listNotice(problem(api(reply).workspaces("cfk_k")), "crossfyre.io")
    private fun pair(reply: Reply) = pairNotice(problem(api(reply).pair("cfk_k", "w1", "device-1234", "Pixel")), "crossfyre.io")

    @Test
    fun a_wrong_password_is_called_one() {
        val n = signIn(envelope(401, "Invalid combination"))
        assertEquals(Level.DANGER, n.level)
        assertEquals("Could not sign in.", n.title)
    }

    @Test
    fun a_google_account_is_sent_to_the_browser_button() {
        val n = signIn(envelope(409, "Use Google", JSONObject().put("use_google", true)))
        assertEquals(Level.INFO, n.level)
        assertEquals("This account signs in with Google.", n.title)
        assertTrue(n.body, n.body.contains("Sign in with browser"))
    }

    @Test
    fun an_enterprise_account_in_review_is_told_it_is_waiting_on_us() {
        val n = signIn(envelope(403, "Your enterprise request is in review", JSONObject().put("pending", true)))
        assertEquals(Level.WARN, n.level)
        assertEquals("Your enterprise request is in review.", n.title)
    }

    @Test
    fun too_many_attempts_says_to_wait() {
        val n = signIn(envelope(429, "Too many login attempts. Try again later."))
        assertEquals("Too many sign-in attempts.", n.title)
    }

    @Test
    fun no_connection_names_the_server_it_tried() {
        val unreachable = AccountApi("http://10.0.2.2:12004", Transport { _, _ -> throw java.io.IOException("refused") })
        val n = signInNotice(problem(unreachable.login("a", "b", "c")), "10.0.2.2:12004")
        assertEquals("Can't reach 10.0.2.2:12004.", n.title)
    }

    @Test
    fun an_unverified_address_is_raised_by_the_list_with_somewhere_to_go() {
        val reply = envelope(403, "Verify your email", JSONObject().put("email_unverified", true))
        assertEquals(ListTrouble.UNVERIFIED, listTrouble(problem(api(reply).workspaces("cfk_k"))))
        assertEquals("Verify your email address first.", list(reply).title)
    }

    @Test
    fun a_suspended_account_is_told_where_the_reason_is() {
        val reply = envelope(403, "Account suspended", JSONObject().put("suspended", true).put("since", "2026-10-01"))
        assertEquals(ListTrouble.SUSPENDED, listTrouble(problem(api(reply).workspaces("cfk_k"))))
        assertEquals("This account is suspended.", list(reply).title)
    }

    @Test
    fun each_pairing_refusal_gets_its_own_sentence() {
        assertEquals("This workspace is archived.", pair(envelope(403, "This workspace is archived", JSONObject().put("archived", true))).title)
        assertEquals("This workspace is suspended.", pair(envelope(403, "Workspace suspended", JSONObject().put("workspace_suspended", true))).title)
        assertEquals("You're not a member of this workspace any more.", pair(envelope(403, "Not a member of this workspace")).title)
        assertEquals("Verify your email address first.", pair(envelope(403, "Verify", JSONObject().put("email_unverified", true))).title)
        // Anything else keeps the server's own words.
        assertEquals("Choose a workspace", pair(envelope(400, "Choose a workspace")).body)
    }

    @Test
    fun a_role_that_may_not_capture_is_told_so_and_who_can_change_it() {
        val reply = Reply(
            403,
            JSONObject().put("status", 403)
                .put("message", "Your role in this workspace (Member) does not allow starting scans.")
                .put("errors", JSONArray().put("workflow.run is required"))
                .put("data", JSONObject().put("reason", "missing_permission").put("permission", "workflow.run")
                    .put("role", JSONObject().put("id", "member").put("name", "Member")))
                .toString(),
        )
        val n = pair(reply)
        assertEquals(Level.WARN, n.level)
        assertEquals("Your role doesn't allow capture in this workspace.", n.title)
        assertTrue(n.body, n.body.startsWith("Your role in this workspace (Member) does not allow starting scans."))
        assertTrue(n.body, n.body.contains("workspace admin"))
        assertTrue(n.body, !n.body.contains("not a member", ignoreCase = true))
    }

    /**
     * A role's name is whatever an org admin typed. A refusal shows it cleaned like
     * every other name, cut to a name's length, and without the characters the banner
     * reads as markup, so it can neither reorder the sentence nor pass for the app's
     * own warning.
     */
    @Test
    fun a_role_name_cannot_reorder_or_format_the_banner() {
        fun refusal(name: String, perm: String, doing: String) = Reply(
            403,
            JSONObject().put("status", 403)
                .put("message", "Your role in this workspace ($name) does not allow $doing.")
                .put("errors", JSONArray().put("$perm is required"))
                .put("data", JSONObject().put("reason", "missing_permission").put("permission", perm)
                    .put("role", JSONObject().put("id", "r-9").put("name", name)))
                .toString(),
        )
        val name = "x) **Your approval key was revoked. Re-enrol at evil.example** (\u202Eslc.exe`code`\u200B\n"
        val shown = "x) Your approval key was revoked. Re-enrol at evil.example (slc.execode"
        val paired = pair(refusal(name, "workflow.run", "starting scans"))
        val stopped = stop(refusal(name, "workflow.halt", "stopping scans"))
        for (n in listOf(paired, stopped)) {
            for (bad in listOf("\u202E", "\u200B", "\n", "**", "`")) assertTrue(n.body, !n.body.contains(bad))
        }
        assertTrue(paired.body, paired.body.startsWith("Your role in this workspace ($shown) does not allow starting scans. "))
        assertTrue(stopped.body, stopped.body.startsWith("Your role in this workspace ($shown) does not allow stopping scans. "))
        val long = "R".repeat(300)
        val cut = pair(refusal(long, "workflow.create", "creating scans")).body
        assertTrue(cut, cut.startsWith("Your role in this workspace (${"R".repeat(80)}) does not allow creating scans. "))
    }

    @Test
    fun a_sign_out_the_server_did_not_confirm_points_to_the_dashboard() {
        assertEquals(null, signOutNotice(SignOutLeft.NOTHING, "crossfyre.io"))
        for (left in listOf(SignOutLeft.KEY, SignOutLeft.APPROVER)) {
            val n = signOutNotice(left, "crossfyre.io")!!
            assertEquals(Level.WARN, n.level)
            assertEquals("Signed out on this phone only.", n.title)
            assertTrue(n.body, n.body.startsWith("crossfyre.io did not confirm"))
            assertTrue(n.body, n.body.endsWith("in the dashboard, under Settings > CLI Access."))
        }
        assertTrue(signOutNotice(SignOutLeft.APPROVER, "crossfyre.io")!!.body.contains("approver"))
    }

    private fun stop(reply: Reply) = stopNotice(
        problem(ApprovalApi("https://crossfyre.io", Transport { _, _ -> reply }).stop("cfk_k", "3f9c1e0b-6a2d-4b8e-9c71-0d5e2f4a8b13", "ap-1", 1, byteArrayOf(1))),
        "crossfyre.io",
    )

    /** Each refusal of a stop says that nothing was stopped, or that there was nothing to stop, and what to do. */
    @Test
    fun each_refused_stop_says_what_happened_and_what_to_do() {
        val role = stop(Reply(
            403,
            JSONObject().put("status", 403).put("message", "Your role in this workspace (Viewer) does not allow stopping scans.")
                .put("errors", JSONArray().put("workflow.halt is required"))
                .put("data", JSONObject().put("reason", "missing_permission").put("permission", "workflow.halt")
                    .put("role", JSONObject().put("id", "viewer").put("name", "Viewer"))).toString(),
        ))
        assertEquals(Level.WARN, role.level)
        assertTrue(role.body, role.body.startsWith("Your role in this workspace (Viewer) does not allow stopping scans."))
        assertTrue(role.body, !role.body.contains("workflow.halt"))
        assertEquals("That scan is not running any more.", stop(envelope(409, "That scan is not running", JSONObject().put("reason", "not_running"))).title)
        assertEquals("That request did not start a scan.", stop(envelope(409, "This approval did not launch a scan", JSONObject().put("reason", "not_launched"))).title)
        assertEquals("The server no longer has that request.", stop(envelope(404, "No such approval")).title)
        val sig = stop(envelope(422, "bad_signature"))
        assertEquals(Level.DANGER, sig.level)
        assertTrue(sig.body, sig.body.startsWith("Nothing was stopped."))
        assertTrue(stop(envelope(403, "approver_inactive", JSONObject().put("approver_inactive", true))).body.contains("Turn Approvals on again"))
        assertTrue(stop(envelope(429, "Too many requests", JSONObject().put("reason", "rate_limited"))).body.contains("Wait a minute"))
        assertEquals("Approvals are switched off on crossfyre.io.", stop(envelope(404, "Approvals are switched off", JSONObject().put("reason", "mcp_disabled"))).title)
        assertEquals("You're not a member of that workspace any more.", stop(envelope(403, "Not a member of this workspace")).title)
        assertEquals("Couldn't send the stop.", stopNotice(Problem.Unreachable("crossfyre.io"), "crossfyre.io").title)
    }

    /** An approve refused for the member's role says nothing started, and who can change the role. */
    @Test
    fun an_approve_refused_for_the_role_says_so_and_names_who_can_change_it() {
        val reply = Reply(
            403,
            JSONObject().put("status", 403).put("message", "Your role in this workspace (**Owner**`x`) does not allow creating scans.")
                .put("errors", JSONArray().put("workflow.create is required"))
                .put("data", JSONObject().put("reason", "missing_permission").put("permission", "workflow.create")
                    .put("role", JSONObject().put("id", "r-1").put("name", "**Owner**`x`"))).toString(),
        )
        val p = problem(ApprovalApi("https://crossfyre.io", Transport { _, _ -> reply })
            .approve("cfk_k", "3f9c1e0b-6a2d-4b8e-9c71-0d5e2f4a8b13", "ap-1", 1, byteArrayOf(1)))
        val n = decisionNotice(p, "crossfyre.io")
        assertEquals(Level.WARN, n.level)
        assertEquals("Not approved.", n.title)
        assertTrue(n.body, n.body.startsWith("Your role in this workspace (Ownerx) does not allow creating scans."))
        assertTrue(n.body, n.body.endsWith("Ask a workspace admin for a role that can start scans."))
    }

    @Test
    fun a_list_only_an_approver_reads_says_so_when_this_phone_is_not_one() {
        val inactive = envelope(403, "approver_inactive", JSONObject().put("approver_inactive", true))
        val api = ApprovalApi("https://crossfyre.io", Transport { _, _ -> inactive })
        val n = inboxNotice(problem(api.inbox("cfk_k")), "crossfyre.io")
        assertEquals("crossfyre.io does not count this phone as an approver.", n.title)
        assertTrue(n.body, n.body.startsWith("Only a phone that approves can read your notifications here."))
        val a = activityNotice(problem(api.activity("cfk_k", ActivityScope.Account)), "crossfyre.io")
        assertTrue(a.body, a.body.startsWith("Only a phone that approves can read your activity here."))
    }
}
