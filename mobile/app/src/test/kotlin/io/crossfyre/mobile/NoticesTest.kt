package io.crossfyre.mobile

import io.crossfyre.mobile.account.AccountApi
import io.crossfyre.mobile.account.Outcome
import io.crossfyre.mobile.account.Problem
import io.crossfyre.mobile.account.Reply
import io.crossfyre.mobile.account.Transport
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
}
