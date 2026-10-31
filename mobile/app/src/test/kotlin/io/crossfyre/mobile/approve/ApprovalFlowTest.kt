package io.crossfyre.mobile.approve

import io.crossfyre.mobile.account.HttpTransport
import io.crossfyre.mobile.account.Outcome
import io.crossfyre.mobile.account.Refusal
import io.crossfyre.mobile.reasonOf
import io.crossfyre.mobile.stoppable
import kotlinx.coroutines.runBlocking
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * The phone's side of the protocol end to end, over HTTP, against [FakeCloud]:
 * enrol, wait for the browser, read what is pending, sign it, and send it. The
 * keystore is replaced by a key in this JVM; the keystore itself is tested on a
 * device.
 *
 * Where a request is refused here, FakeCloud is what refuses it: an approver the
 * browser never confirmed, a revoked one, a signature over anything but the
 * digest it holds. The tests named for the fake check its copy of those rules
 * and how the phone reads each refusal. They say nothing about the platform,
 * whose routes need their own tests of the same rules, run against them.
 */
class ApprovalFlowTest {

    private val key = "cfk_" + "d".repeat(40)
    private val cloud = FakeCloud(key)
    private val api = ApprovalApi(cloud.origin, HttpTransport(2_000, 2_000))
    private val keys = SoftwareKeys()

    @After
    fun down() = cloud.close()

    private fun <T> ok(o: Outcome<T>): T = when (o) {
        is Outcome.Ok -> o.value
        is Outcome.Failed -> { fail("expected success, got ${o.problem}"); throw IllegalStateException() }
    }

    private fun summary() = JSONObject(javaClass.classLoader!!.getResource("approval-sig-v1.json")!!.readText())
        .getString("summary_json").let(::JSONObject)

    private fun enrolled(): Enrolment = runBlocking {
        val e = ok(api.enrolStart(key, "install-0001", "Pixel 8", keys.create()))
        assertEquals(EnrolState.PENDING, ok(api.enrolPoll(key, e.code)))
        cloud.confirm(e.code)
        val r = awaitEnrolment(e, { api.enrolPoll(key, it) }, { }, { 0L })
        assertEquals(Outcome.Ok(EnrolState.ACTIVE), r)
        e
    }

    private fun sign(id: String, digest: String, approverId: String, signedAt: Long = 1793345642, decision: String = "approve"): ByteArray =
        keys.signature().run { update(ApprovalProtocol.signingBytes(id, decision, digest, signedAt, approverId)); sign() }

    private fun reason(o: Outcome<*>): Refusal = reasonOf((o as Outcome.Failed).problem)

    /** Enrol, have the agent ask, approve at the fake's time, and let the fake launch it. */
    private fun approvedAndRunning(): Pair<Enrolment, FakeCloud.Pending> {
        val e = enrolled()
        val asked = cloud.request(summary())
        val p = ok(api.pending(key)).approvals.single()
        val at = cloud.now.epochSecond
        assertEquals("approved", ok(api.approve(key, p.id, e.approverId, at, sign(p.id, p.digest, e.approverId, at))))
        cloud.launch(asked)
        return e to asked
    }

    @Test
    fun the_phone_stops_the_scan_it_approved_from_its_history_row() {
        val (e, asked) = approvedAndRunning()
        val history = ok(api.history(key))
        val row = history.rows.single()
        assertTrue(stoppable(row))
        // As the app signs it: the row's digest, at the time the history answered.
        val at = history.serverTime!!.epochSecond
        assertEquals(Refusal.BAD_SIGNATURE, reason(api.stop(key, row.id, e.approverId, at, sign(row.id, row.digest, e.approverId, at))))
        assertEquals("running", asked.workflowStatus)
        val stopped = ok(api.stop(key, row.id, e.approverId, at, sign(row.id, row.digest, e.approverId, at, ApprovalProtocol.STOP)))
        assertEquals(StopAnswer.Stopped("stopped", 2), stopped)
        assertEquals("stopped", asked.workflowStatus)
        assertFalse(stoppable(ok(api.history(key)).rows.single()))
        assertEquals(Refusal.NOT_RUNNING, reason(api.stop(key, row.id, e.approverId, at, sign(row.id, row.digest, e.approverId, at, ApprovalProtocol.STOP))))
    }

    @Test
    fun a_stop_signed_by_the_phone_s_own_wrong_clock_is_handed_the_fake_s_time_and_goes_through_at_it() {
        val (e, asked) = approvedAndRunning()
        val row = ok(api.history(key)).rows.single()
        val phoneClock = cloud.now.epochSecond - 400
        val first = ok(api.stop(key, row.id, e.approverId, phoneClock, sign(row.id, row.digest, e.approverId, phoneClock, ApprovalProtocol.STOP)))
        assertEquals(StopAnswer.Stale(cloud.now), first)
        assertEquals("running", asked.workflowStatus)
        val at = (first as StopAnswer.Stale).serverTime.epochSecond
        assertTrue(ok(api.stop(key, row.id, e.approverId, at, sign(row.id, row.digest, e.approverId, at, ApprovalProtocol.STOP))) is StopAnswer.Stopped)
    }

    @Test
    fun the_fake_reads_notifications_only_to_a_phone_that_approves_and_the_phone_marks_them_read() {
        cloud.notify("An agent is waiting for your approval", "/m/approve/x")
        cloud.notify("Scan finished", null)
        assertEquals(Refusal.APPROVER_INACTIVE, reason(api.inbox(key)))
        enrolled()
        val page = ok(api.inbox(key))
        assertEquals(listOf("Scan finished", "An agent is waiting for your approval"), page.items.map { it.title })
        assertEquals(2, page.unread)
        assertEquals(InboxMarked(1, 1), ok(api.inboxRead(key, listOf(page.items[1].id))))
        assertEquals(listOf(false, true), ok(api.inbox(key)).items.map { it.read })
        assertEquals(InboxMarked(1, 0), ok(api.inboxReadAll(key)))
    }

    @Test
    fun an_enrolled_phone_approves_what_it_was_shown_and_the_server_verifies_it() {
        val e = enrolled()
        val asked = cloud.request(summary())

        val list = ok(api.pending(key))
        assertEquals(e.approverId, list.approver?.id)
        val p = list.approvals.single()
        val view = approvalView(p, list.serverTime!!, approverActive = true)
        assertTrue(view.canApprove)

        assertEquals("approved", ok(api.approve(key, p.id, e.approverId, 1793345642, sign(p.id, p.digest, e.approverId))))
        assertEquals("approved", asked.status)
        assertTrue(ok(api.pending(key)).approvals.isEmpty())
        assertEquals(Refusal.NOT_PENDING, reasonOf((api.approve(key, p.id, e.approverId, 1, sign(p.id, p.digest, e.approverId, 1)) as Outcome.Failed).problem))
    }

    @Test
    fun the_fake_refuses_a_signature_over_another_digest_and_the_phone_reads_a_bad_signature() {
        val e = enrolled()
        val asked = cloud.request(summary())
        val p = ok(api.pending(key)).approvals.single()

        val wrongDigest = sign(p.id, "0".repeat(64), e.approverId)
        assertEquals(Refusal.BAD_SIGNATURE, reasonOf((api.approve(key, p.id, e.approverId, 1793345642, wrongDigest) as Outcome.Failed).problem))
        // Signed at one time and sent as another: the bytes differ, so it fails too.
        val shifted = sign(p.id, p.digest, e.approverId, 1793345642)
        assertEquals(Refusal.BAD_SIGNATURE, reasonOf((api.approve(key, p.id, e.approverId, 1793345643, shifted) as Outcome.Failed).problem))
        assertEquals("pending", asked.status)
    }

    @Test
    fun the_fake_refuses_an_unconfirmed_phone_and_the_phone_reads_an_inactive_approver() = runBlocking {
        val e = ok(api.enrolStart(key, "install-0001", "Pixel 8", keys.create()))
        cloud.request(summary())
        val p = cloud.approvals.single()
        val r = api.approve(key, p.id, e.approverId, 1793345642, sign(p.id, p.digest, e.approverId))
        assertEquals(Refusal.APPROVER_INACTIVE, reasonOf((r as Outcome.Failed).problem))
        assertEquals("pending", p.status)
    }

    @Test
    fun a_denial_needs_no_key_and_ends_the_request() {
        enrolled()
        val asked = cloud.request(summary())
        assertEquals("denied", ok(api.deny(key, asked.id)))
        assertEquals("denied", asked.status)
        assertFalse(cloud.routes.isEmpty())
    }

    @Test
    fun the_fake_refuses_a_revoked_phone_and_the_phone_reads_an_inactive_approver() {
        val e = enrolled()
        ok(api.revoke(key, e.approverId))
        assertEquals(null, ok(api.pending(key)).approver)
        val asked = cloud.request(summary())
        val r = api.approve(key, asked.id, e.approverId, 1793345642, sign(asked.id, asked.digest, e.approverId))
        assertEquals(Refusal.APPROVER_INACTIVE, reasonOf((r as Outcome.Failed).problem))
    }
}
