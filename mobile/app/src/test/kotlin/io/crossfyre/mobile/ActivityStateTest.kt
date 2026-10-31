package io.crossfyre.mobile

import io.crossfyre.mobile.account.Problem
import io.crossfyre.mobile.account.Refusal
import io.crossfyre.mobile.approve.ActivityEvent
import io.crossfyre.mobile.approve.HistoryRow
import io.crossfyre.mobile.approve.InboxItem
import io.crossfyre.mobile.approve.InboxPage
import io.crossfyre.mobile.approve.PendingApproval
import io.crossfyre.mobile.approve.Quiet
import io.crossfyre.mobile.approve.Summary
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
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
     * The log is on because `/cli/activity/list` answers only a key whose own
     * approver is active and never exports, which the platform's live checks
     * and this app's run against it both show: a CLI key on the same account is
     * refused. The app asks for it only while this phone approves.
     */
    @Test
    fun the_activity_log_is_read_now_its_route_answers_only_a_phone() {
        assertTrue(ACTIVITY_LOG)
    }

    private val digest = "0f".repeat(32)

    private fun row(
        status: String = "approved", launch: String = "launched", wf: String = "wf-1", wfStatus: String = "running", d: String = digest,
    ) = HistoryRow("3f9c1e0b-6a2d-4b8e-9c71-0d5e2f4a8b13", status, "Launch a crawl", "Acme", null, null, "phone", "Pixel 8", launch, wf, wfStatus, d)

    @Test
    fun only_a_running_scan_that_an_approval_launched_offers_stop() {
        assertTrue(stoppable(row()))
        assertTrue(stoppable(row(wfStatus = "populating")))
        // Each fact on its own takes the button away.
        assertFalse(stoppable(row(status = "denied")))
        assertFalse(stoppable(row(status = "pending")))
        assertFalse(stoppable(row(launch = "launching")))
        assertFalse(stoppable(row(launch = "failed")))
        assertFalse(stoppable(row(wf = "")))
        assertFalse(stoppable(row(wfStatus = "stopped")))
        assertFalse(stoppable(row(wfStatus = "completed")))
        assertFalse(stoppable(row(wfStatus = "")))
        // No digest, nothing to sign: a platform that does not send it could only refuse the stop.
        assertFalse(stoppable(row(d = "")))
        assertFalse(stoppable(row(d = "0f".repeat(31))))
    }

    @Test
    fun a_notification_link_opens_only_as_a_page_on_this_server() {
        val origin = "https://crossfyre.io"
        assertEquals("https://crossfyre.io/m/approve/3f9c1e0b", notificationUrl(origin, "/m/approve/3f9c1e0b"))
        assertEquals("https://crossfyre.io/home/settings", notificationUrl("https://crossfyre.io/", "/home/settings"))
        assertEquals("http://10.0.2.2:12004/home", notificationUrl("http://10.0.2.2:12004", "/home"))
        assertNull(notificationUrl(origin, null))
        assertNull(notificationUrl(origin, ""))
        // Two slashes name another host, and so does anything that is not a path.
        assertNull(notificationUrl(origin, "//evil.example/m/approve/x"))
        assertNull(notificationUrl(origin, "https://evil.example/home"))
        assertNull(notificationUrl(origin, "javascript:alert(1)"))
        assertNull(notificationUrl(origin, "@evil.example/x"))
        assertNull(notificationUrl(origin, ".evil.example/x"))
        assertNull(notificationUrl(origin, "home/settings"))
        // On the right host but not a path: only the leading slash rule turns these away.
        assertNull(notificationUrl(origin, "?next=/home"))
        assertNull(notificationUrl(origin, "#home"))
        // Browsers read a backslash as a slash; spaces and control characters do not belong in a path.
        assertNull(notificationUrl(origin, "/\\evil.example"))
        assertNull(notificationUrl(origin, "/home settings"))
        assertNull(notificationUrl(origin, "/home\n"))
    }

    private fun item(id: String, read: Boolean = false) =
        InboxItem(id, "approval", "approval.requested", "warning", "t-$id", "", "", read, null)

    @Test
    fun the_inbox_pages_add_up_and_a_read_clears_only_its_rows() {
        var list = InboxList()
        assertFalse(list.more)
        list = list.with(InboxPage(listOf(item("a"), item("b")), total = 3, unread = 3, page = 1))
        assertTrue(list.more)
        // A row that arrived in between pushes one already shown onto the next page.
        list = list.with(InboxPage(listOf(item("b"), item("c")), total = 4, unread = 4, page = 2))
        assertEquals(listOf("a", "b", "c"), list.items.map { it.id })
        assertEquals(2, list.page)
        assertTrue(list.more)
        list = list.read(listOf("b"), unread = 3)
        assertEquals(listOf(false, true, false), list.items.map { it.read })
        assertEquals(3, list.unread)
        list = list.allRead(unread = 0)
        assertTrue(list.items.all { it.read })
        // Page 1 again starts over, with what the server has now.
        list = list.with(InboxPage(listOf(item("d")), total = 1, unread = 1, page = 1))
        assertEquals(listOf("d"), list.items.map { it.id })
        assertFalse(list.more)
    }

    @Test
    fun a_rate_limit_pauses_the_phone_for_the_wait_the_server_named() {
        val q = Quiet()
        assertTrue(q.open(0))
        q.heard(Problem.Refused(500, "x"), 0)
        q.heard(Problem.Unreachable("crossfyre.io"), 0)
        assertTrue("only a rate limit pauses", q.open(0))
        q.heard(Problem.Refused(429, "Too many requests", Refusal.RATE_LIMITED, 30), 1_000)
        assertFalse(q.open(30_999))
        assertTrue(q.open(31_000))
        // No number from the server: a minute, the platform's window.
        q.heard(Problem.Refused(429, "Too many requests", Refusal.RATE_LIMITED), 100_000)
        assertFalse(q.open(159_999))
        assertTrue(q.open(160_000))
        // A wait past ten minutes is capped there.
        q.heard(Problem.Refused(429, "Too many requests", Refusal.RATE_LIMITED, 86_400), 0)
        assertTrue(q.open(600_000))
        q.clear()
        assertTrue(q.open(0))
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
    fun each_way_a_request_was_decided_reads_as_who_or_what_did_it() {
        assertEquals("on Pixel 8", decidedBy("phone", "Pixel 8"))
        assertEquals("on a phone", decidedBy("phone", ""))
        assertEquals("in the dashboard", decidedBy("dashboard", ""))
        assertEquals("in the agent's client", decidedBy("agent_client", ""))
        // A deny sent with an account key, from a phone or a computer signed in to
        // the account: the platform names it as neither a phone nor the dashboard.
        assertEquals("from a signed-in device", decidedBy("other", ""))
        assertEquals("from a signed-in device", decidedBy("account_key", ""))
        assertEquals("by the agent", decidedBy("agent_cancel", ""))
        assertEquals("by expiry", decidedBy("expiry", ""))
        assertEquals("", decidedBy("", ""))
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
