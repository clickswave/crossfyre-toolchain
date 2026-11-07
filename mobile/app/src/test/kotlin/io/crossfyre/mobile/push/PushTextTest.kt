package io.crossfyre.mobile.push

import io.crossfyre.mobile.approve.InboxItem
import org.junit.Assert.assertEquals
import org.junit.Test

class PushTextTest {

    private fun row(title: String = "An agent is waiting for your approval", body: String = "Launch a crawl\nWorkspace: Acme", link: String = "/m/approve/x") =
        InboxItem("n1", "approval", "approval.requested", "warning", title, body, link, false, null)

    @Test
    fun an_approval_goes_on_its_own_channel_with_the_row_text() {
        val a = PushText.of("approval.requested", row(), "/m/approve/x")
        assertEquals(PushText.APPROVALS, a.channel)
        assertEquals("An agent is waiting for your approval", a.title)
        assertEquals("Launch a crawl\nWorkspace: Acme", a.text)
        assertEquals("/m/approve/x", a.link)
    }

    @Test
    fun anything_else_is_an_alert() {
        assertEquals(PushText.ALERTS, PushText.of("workflow.completed", null, "").channel)
        assertEquals(PushText.ALERTS, PushText.of("finding.critical", null, null).channel)
    }

    @Test
    fun an_unreadable_row_still_says_what_arrived_and_where_it_opens() {
        val a = PushText.of("approval.requested", null, "/m/approve/y")
        assertEquals("An agent is waiting for your approval", a.title)
        assertEquals("Open Crossfyre Mobile to see it.", a.text)
        assertEquals("/m/approve/y", a.link)
        assertEquals("A scan finished", PushText.of("workflow.completed", null, null).title)
        assertEquals("A scan found something", PushText.of("finding.any", null, null).title)
        assertEquals("Crossfyre", PushText.of("something.new", null, null).title)
    }

    @Test
    fun a_blank_row_falls_back_and_long_text_is_cut() {
        assertEquals("A scan failed", PushText.of("workflow.failed", row(title = " ", body = ""), null).title)
        assertEquals(300, PushText.of("finding.any", row(body = "x".repeat(1000)), null).text.length)
    }
}
