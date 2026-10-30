package io.crossfyre.mobile

import io.crossfyre.mobile.approve.ActivityEvent
import io.crossfyre.mobile.approve.PendingApproval
import io.crossfyre.mobile.approve.Summary
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test

/** What the Activity tab leads with, and how its rows read. */
class ActivityStateTest {

    @Test
    fun a_qr_only_phone_is_asked_to_sign_in_and_has_no_approve_path() {
        for (state in ApproverState.values()) {
            assertEquals(ActivityHeader.SIGN_IN, activityHeader(signedIn = false, approver = state))
        }
    }

    /**
     * Turning the log on needs `/cli/activity/list` on the platform first, bound
     * to a key with an active approver, and a testkit case showing a CLI key is
     * refused. Change this test with that work, not before it.
     */
    @Test
    fun the_activity_log_stays_off_until_its_route_answers_only_a_phone() {
        assertFalse(ACTIVITY_LOG)
    }

    @Test
    fun a_signed_in_phone_leads_with_its_approver_state() {
        assertEquals(ActivityHeader.TURN_ON, activityHeader(true, ApproverState.OFF))
        assertEquals(ActivityHeader.TURN_ON, activityHeader(true, ApproverState.BROKEN))
        assertEquals(ActivityHeader.ENROLLING, activityHeader(true, ApproverState.ENROLLING))
        assertEquals(ActivityHeader.LIVE, activityHeader(true, ApproverState.ACTIVE))
    }

    /**
     * The list is kept fresh only while the phone approves, so once it stops,
     * Home's banner and the tab's badge must not keep saying an agent waits.
     */
    @Test
    fun only_a_phone_that_approves_says_an_agent_is_waiting() {
        val waiting = listOf(PendingApproval("3f9c1e0b-6a2d-4b8e-9c71-0d5e2f4a8b13", "pending", null, null, "{}", ""))
        assertEquals(waiting, waitingForYou(ApproverState.ACTIVE, waiting))
        for (state in listOf(ApproverState.BROKEN, ApproverState.OFF, ApproverState.ENROLLING)) {
            assertEquals(state.name, emptyList<PendingApproval>(), waitingForYou(state, waiting))
        }
    }

    private fun event(action: String, actor: String = "asha", kind: String = "user") = ActivityEvent(
        id = 1, at = null, org = null, team = null, workspace = null, actorKind = kind, actorName = actor,
        channel = "mcp", credentialLabel = "", credentialKind = "", action = action, outcome = "ok",
        subjectType = "", subjectName = "", detail = emptyList(),
    )

    @Test
    fun rows_read_as_sentences_and_an_unknown_action_still_reads() {
        assertEquals("asha started a scan", activityLine(event("scan.started")))
        assertEquals("asha approved an agent request", activityLine(event("approval.granted")))
        assertEquals("asha exported activity", activityLine(event("activity.exported")))
        assertEquals("asha · tunnel opened", activityLine(event("tunnel.opened")))
        assertEquals("Crossfyre started a scan", activityLine(event("scan.started", actor = "", kind = "system")))
        assertEquals("Agent", channelLabel("mcp"))
        assertEquals("", channelLabel("unknown"))
    }

    @Test
    fun the_badges_name_fleet_writes_and_active_testing() {
        val s = Summary.parse(JSONObject()
            .put("v", 1).put("id", "x")
            .put("action", JSONObject().put("label", "Replay").put("risk", JSONArray(listOf("fleet", "writes", "active", "traffic", "odd"))).put("writes", true))
            .put("nodes", JSONArray().put(JSONObject().put("id", "a").put("name", "a")).put(JSONObject().put("id", "b").put("name", "b")))
            .toString())!!
        assertEquals(listOf("Runs on 2 nodes", "Can change data on the target", "Active testing", "odd"), riskChips(s))
        assertEquals("12 Oct", shortDate("2026-10-12"))
        assertEquals("last week", shortDate("last week"))
    }
}
