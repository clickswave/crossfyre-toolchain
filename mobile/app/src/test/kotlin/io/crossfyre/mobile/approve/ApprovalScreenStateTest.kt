package io.crossfyre.mobile.approve

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.time.Instant

/**
 * What the approval screen offers. Approve is the one button that matters, so
 * every reason it must not be offered is a test: a summary that does not match
 * the digest, a summary about another approval, an approval that is no longer
 * waiting, and a phone that is not an active approver.
 */
class ApprovalScreenStateTest {

    private val fixture = JSONObject(javaClass.classLoader!!.getResource("approval-sig-v1.json")!!.readText())
    private val id = fixture.getString("approval_id")
    private val text = fixture.getString("summary_json")
    private val digest = fixture.getString("digest")
    private val now = Instant.parse("2026-10-30T09:14:44Z")

    private fun pending(summary: String = text, d: String = digest, status: String = "pending", expires: String = "2026-10-30T09:22:44Z") =
        PendingApproval(id, status, Instant.parse("2026-10-30T09:12:44Z"), Instant.parse(expires), summary, d)

    @Test
    fun a_matching_pending_approval_on_an_active_phone_can_be_approved() {
        val v = approvalView(pending(), now, approverActive = true)
        assertTrue(v.checked)
        assertTrue(v.canApprove)
        assertTrue(v.canDeny)
        assertNull(v.blocked)
        assertEquals(480L, v.secondsLeft)
        assertNotNull(v.summary)
    }

    @Test
    fun a_summary_that_does_not_match_its_digest_offers_only_deny() {
        val v = approvalView(pending(summary = text.replace("app.example.com", "app.example.con")), now, approverActive = true)
        assertFalse(v.checked)
        assertFalse(v.canApprove)
        assertTrue(v.canDeny)
        assertEquals("This request could not be checked. Deny it, or open it in the dashboard.", v.blocked)
    }

    @Test
    fun a_summary_about_another_approval_offers_only_deny() {
        val other = JSONObject(text).put("id", "00000000-0000-4000-8000-000000000000").toString()
        val v = approvalView(pending(summary = other, d = ApprovalProtocol.sha256Hex(other.toByteArray())), now, approverActive = true)
        assertFalse(v.canApprove)
        assertTrue(v.canDeny)
    }

    @Test
    fun an_unreadable_summary_with_a_matching_digest_offers_only_deny() {
        val junk = "{\"v\":1}"
        val v = approvalView(pending(summary = junk, d = ApprovalProtocol.sha256Hex(junk.toByteArray())), now, approverActive = true)
        assertFalse(v.canApprove)
        assertTrue(v.canDeny)
    }

    @Test
    fun an_expired_approval_offers_nothing() {
        val v = approvalView(pending(expires = "2026-10-30T09:14:44Z"), now, approverActive = true)
        assertFalse(v.canApprove)
        assertFalse(v.canDeny)
        assertEquals(0L, v.secondsLeft)
    }

    @Test
    fun a_decided_approval_offers_nothing() {
        val v = approvalView(pending(status = "denied"), now, approverActive = true)
        assertFalse(v.canApprove)
        assertFalse(v.canDeny)
    }

    /** The fixture's summary with [edit] applied, under the digest of the new text. */
    private fun edited(edit: (JSONObject) -> Unit): PendingApproval {
        val o = JSONObject(text).also(edit).toString()
        return pending(summary = o, d = ApprovalProtocol.sha256Hex(o.toByteArray()))
    }

    @Test
    fun a_long_target_is_read_whole_and_can_be_approved() {
        // A path is what matters on a request that writes, and its tail is where it says what it does.
        val long = "https://app.example.com/api/v2/" + "a".repeat(240) + "/users/delete-all"
        val v = approvalView(edited { it.getJSONArray("targets").getJSONObject(0).put("target", long) }, now, approverActive = true)
        assertEquals(long, v.summary!!.targets[0].target)
        assertTrue(v.canApprove)
    }

    @Test
    fun a_request_the_phone_had_to_cut_to_show_offers_only_deny() {
        val cases = listOf<Pair<String, (JSONObject) -> Unit>>(
            "a target longer than any the server sends" to { o -> o.getJSONArray("targets").getJSONObject(0).put("target", "https://a.example/" + "x".repeat(5000)) },
            "a workspace name past its cap" to { o -> o.getJSONObject("workspace").put("name", "n".repeat(81)) },
            "a scope entry past its cap" to { o -> o.getJSONArray("targets").getJSONObject(0).getJSONObject("admitted_by").put("entry", "e".repeat(256)) },
            "the agent's reason past its cap" to { o -> o.put("reason", "r".repeat(201)) },
            "an option value past its cap" to { o -> o.getJSONObject("options").put("severity_min", "v".repeat(201)) },
            "more options than the screen shows" to { o -> val opts = o.getJSONObject("options"); repeat(20) { opts.put("k%02d".format(it), "v") } },
            "a target with a character the phone does not draw" to { o -> o.getJSONArray("targets").getJSONObject(0).put("target", "https://app.exa\u200Bmple.com") },
        )
        for ((name, edit) in cases) {
            val v = approvalView(edited(edit), now, approverActive = true)
            assertFalse(name, v.canApprove)
            assertTrue(name, v.canDeny)
            assertNotNull(name, v.blocked)
        }
    }

    /**
     * The signature covers the whole text, so a part the parser drops is a part
     * the person approves without seeing: a target that is not an object, a
     * section missing or of another shape, or a key the phone has no line for.
     */
    @Test
    fun a_request_with_a_part_the_phone_does_not_draw_offers_only_deny() {
        val target = { o: JSONObject -> o.getJSONArray("targets").getJSONObject(0) }
        val cases = listOf<Pair<String, (JSONObject) -> Unit>>(
            "targets as plain strings" to { o -> o.put("targets", JSONArray().put("https://prod.example.com/admin/delete-all")) },
            "an object target and a string target" to { o -> o.getJSONArray("targets").put("https://prod.example.com/admin/delete-all") },
            "a target that is a list" to { o -> o.getJSONArray("targets").put(JSONArray().put("https://prod.example.com")) },
            "targets as one string" to { o -> o.put("targets", "https://prod.example.com") },
            "no targets at all" to { o -> o.remove("targets") },
            "targets as null" to { o -> o.put("targets", JSONObject.NULL) },
            "nodes as plain strings" to { o -> o.put("nodes", JSONArray().put("fra-1").put("blr-2").put("nyc-3")) },
            "nodes as one object" to { o -> o.put("nodes", JSONObject().put("id", "n-9").put("name", "nyc-3")) },
            "no workspace" to { o -> o.remove("workspace") },
            "no requester" to { o -> o.remove("requester") },
            "a workspace that is a string" to { o -> o.put("workspace", "Acme production") },
            "options that are a string" to { o -> o.put("options", "severity_min=info") },
            "risk that is a string" to { o -> o.getJSONObject("action").put("risk", "writes") },
            "writes that is not true or false" to { o -> o.getJSONObject("action").put("writes", "yes") },
            "a scope entry that is a string" to { o -> target(o).put("admitted_by", "app.example.com") },
            "a key the summary does not have" to { o -> o.put("extra_targets", JSONArray().put("https://prod.example.com")) },
            "a key the requester does not have" to { o -> o.getJSONObject("requester").put("on_behalf_of", "mallory") },
            "a key the workspace does not have" to { o -> o.getJSONObject("workspace").put("environment", "production") },
            "a key the action does not have" to { o -> o.getJSONObject("action").put("method", "DELETE") },
            "a key a target does not have" to { o -> target(o).put("method", "DELETE") },
            "a key a scope entry does not have" to { o -> target(o).getJSONObject("admitted_by").put("expires", "yesterday") },
            "a key a node does not have" to { o -> o.getJSONArray("nodes").getJSONObject(0).put("egress", "residential") },
        )
        val approvable = cases.filter { (_, edit) ->
            val v = approvalView(edited(edit), now, approverActive = true)
            !v.checked || v.canApprove || !v.canDeny || v.blocked == null
        }.map { it.first }
        assertEquals(emptyList<String>(), approvable)
    }

    @Test
    fun the_parts_a_request_may_leave_out_still_let_it_be_approved() {
        val cases = listOf<Pair<String, (JSONObject) -> Unit>>(
            "no nodes" to { o -> o.remove("nodes") },
            "no options" to { o -> o.remove("options") },
            "no reason" to { o -> o.remove("reason") },
            "a target with no scope entry" to { o -> o.getJSONArray("targets").getJSONObject(0).remove("admitted_by") },
            "a workspace with no organization" to { o -> o.getJSONObject("workspace").remove("org") },
            "an option no other request has" to { o -> o.getJSONObject("options").put("rate_limit", 5) },
        )
        val refused = cases.filter { (_, edit) -> !approvalView(edited(edit), now, approverActive = true).canApprove }.map { it.first }
        assertEquals(emptyList<String>(), refused)
    }

    @Test
    fun a_phone_that_is_not_an_active_approver_can_deny_but_not_approve() {
        val v = approvalView(pending(), now, approverActive = false)
        assertFalse(v.canApprove)
        assertTrue(v.canDeny)
        assertTrue(v.blocked!!.contains("Turn on Approvals"))
    }
}
