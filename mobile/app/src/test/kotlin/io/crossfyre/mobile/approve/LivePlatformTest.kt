package io.crossfyre.mobile.approve

import io.crossfyre.mobile.account.HttpTransport
import io.crossfyre.mobile.account.Outcome
import io.crossfyre.mobile.account.Refusal
import io.crossfyre.mobile.notificationUrl
import io.crossfyre.mobile.reasonOf
import io.crossfyre.mobile.stoppable
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.util.concurrent.TimeUnit

/**
 * The phone's half of approvals against a running platform, through the client
 * the app uses and the bytes it signs: enrol, approve, stop the scan the
 * approval launched, read and mark the notifications, and read the activity log.
 *
 * It runs only when `CROSSFYRE_PHONE_E2E_HELPER` names an executable that stands
 * in for what is not the phone. Each call prints one JSON object on its last
 * line of output:
 *
 * - `setup`: a fresh account whose agent may launch across two nodes, as
 *   `{"origin", "key", "other_key", "workspace_id"}`. `key` is the phone's
 *   account key; `other_key` is another key of the same account, as the CLI on
 *   the host an agent runs on holds.
 * - `confirm CODE`: confirms the phone in the account's signed-in browser.
 * - `launch`: the account's agent asks for a launch that waits for the phone,
 *   as `{"approval_id"}`.
 * - `online`: marks the account's nodes online, as their heartbeats would.
 * - `cleanup`: removes the account.
 *
 * The keys stay in this process and are never printed.
 */
class LivePlatformTest {

    private val helperPath: String? = System.getenv("CROSSFYRE_PHONE_E2E_HELPER")?.takeIf { it.isNotBlank() }

    private fun helper(vararg args: String): JSONObject {
        val p = ProcessBuilder(listOf(helperPath!!) + args).redirectError(ProcessBuilder.Redirect.INHERIT).start()
        val out = p.inputStream.bufferedReader().readText()
        if (!p.waitFor(120, TimeUnit.SECONDS) || p.exitValue() != 0) fail("the helper's ${args.first()} failed")
        return JSONObject(out.trim().lines().last())
    }

    private fun <T> ok(o: Outcome<T>): T = when (o) {
        is Outcome.Ok -> o.value
        is Outcome.Failed -> { fail("expected success, got ${o.problem}"); throw IllegalStateException() }
    }

    private fun reason(o: Outcome<*>): Refusal = when (o) {
        is Outcome.Failed -> reasonOf(o.problem)
        is Outcome.Ok -> { fail("expected a refusal, got ${o.value}"); throw IllegalStateException() }
    }

    private fun elapsed(): Long = System.nanoTime() / 1_000_000

    @Test
    fun a_phone_enrols_approves_stops_and_reads_its_inbox_and_activity_on_a_running_platform() {
        assumeTrue("set CROSSFYRE_PHONE_E2E_HELPER to run against a platform", helperPath != null)
        val world = helper("setup")
        try {
            run(world)
        } finally {
            helper("cleanup")
        }
    }

    private fun run(world: JSONObject) = runBlocking {
        val origin = world.getString("origin")
        val key = world.getString("key")
        val other = world.getString("other_key")
        val workspace = ActivityScope.Workspace(world.getString("workspace_id"), "")
        val api = ApprovalApi(origin, HttpTransport())
        val keys = SoftwareKeys()

        fun signed(id: String, decision: String, digest: String, at: Long, approver: String): ByteArray =
            keys.signature().run { update(ApprovalProtocol.signingBytes(id, decision, digest, at, approver)); sign() }

        // Before this phone approves, nothing only an approver may read is answered.
        assertEquals(Refusal.APPROVER_INACTIVE, reason(api.inbox(key)))
        assertEquals(Refusal.APPROVER_INACTIVE, reason(api.activity(key, ActivityScope.Account)))

        // Enrolled, and confirmed once in the browser.
        val e = ok(api.enrolStart(key, "install-live-0001", "Pixel 8", keys.create()))
        helper("confirm", e.code)
        assertEquals(Outcome.Ok(EnrolState.ACTIVE), awaitEnrolment(e, { api.enrolPoll(key, it) }, { delay(it) }, { elapsed() }))

        // The agent asks; the phone checks what it was shown and approves it at the platform's time.
        val approvalId = helper("launch").getString("approval_id")
        val list = ok(api.pending(key))
        assertEquals(e.approverId, list.approver?.id)
        val p = list.approvals.single { it.id == approvalId }
        val view = approvalView(p, list.serverTime!!, approverActive = true)
        assertTrue(view.blocked ?: "", view.canApprove)
        val pendingClock = ServerClock(list.serverTime!!, elapsed())
        helper("online")
        val approvedAt = pendingClock.now(elapsed()).epochSecond
        val approval = signed(p.id, ApprovalProtocol.APPROVE, p.digest, approvedAt, e.approverId)
        assertEquals("approved", ok(api.approve(key, p.id, e.approverId, approvedAt, approval)))

        // The history shows the scan it launched, running, with what a stop is signed over.
        var history = ok(api.history(key))
        var row = history.rows.first { it.id == p.id }
        val until = elapsed() + 30_000
        while (!stoppable(row) && elapsed() < until) {
            delay(1_000)
            history = ok(api.history(key))
            row = history.rows.first { it.id == p.id }
        }
        assertTrue("launch ${row.launchState}, scan ${row.workflowStatus}", stoppable(row))
        assertEquals(p.digest, row.digest)
        assertNotNull(history.serverTime)
        val clock = ServerClock(history.serverTime!!, elapsed())
        fun now() = clock.now(elapsed()).epochSecond

        // Another key of the same account, the CLI's on an agent's host, gets none of it,
        // not even with this phone's own signature.
        assertEquals(Refusal.APPROVER_INACTIVE, reason(api.inbox(other)))
        assertEquals(Refusal.APPROVER_INACTIVE, reason(api.activity(other, workspace)))
        val t0 = now()
        assertEquals(
            Refusal.APPROVER_INACTIVE,
            reason(api.stop(other, row.id, e.approverId, t0, signed(row.id, ApprovalProtocol.STOP, row.digest, t0, e.approverId))),
        )

        // The signature that approved the launch does not stop it.
        assertEquals(Refusal.BAD_SIGNATURE, reason(api.stop(key, row.id, e.approverId, approvedAt, approval)))

        // Signed by a phone clock ten minutes out, it is handed the platform's time and nothing stops.
        val off = now() - 600
        val stale = ok(api.stop(key, row.id, e.approverId, off, signed(row.id, ApprovalProtocol.STOP, row.digest, off, e.approverId)))
        assertTrue("$stale", stale is StopAnswer.Stale)
        assertTrue(stoppable(ok(api.history(key)).rows.first { it.id == p.id }))

        // Signed again at that time, as the app does once, it stops.
        val again = (stale as StopAnswer.Stale).serverTime.epochSecond
        val stopped = ok(api.stop(key, row.id, e.approverId, again, signed(row.id, ApprovalProtocol.STOP, row.digest, again, e.approverId)))
        assertEquals("stopped", (stopped as StopAnswer.Stopped).workflowStatus)
        val t1 = now()
        assertEquals(
            Refusal.NOT_RUNNING,
            reason(api.stop(key, row.id, e.approverId, t1, signed(row.id, ApprovalProtocol.STOP, row.digest, t1, e.approverId))),
        )
        assertFalse(stoppable(ok(api.history(key)).rows.first { it.id == p.id }))

        // The inbox has the request. Its link opens the approval in this app, and reading it clears its dot.
        val page = ok(api.inbox(key))
        val note = page.items.first { it.eventType == "approval.requested" && it.link.endsWith(p.id) }
        assertFalse(note.read)
        assertTrue(page.unread >= 1)
        val url = notificationUrl(origin, note.link)
        assertEquals(p.id, url?.let { ApprovalIds.fromLink(it, origin) })
        assertEquals(1, ok(api.inboxRead(key, listOf(note.id))).marked)
        assertTrue(ok(api.inbox(key)).items.first { it.id == note.id }.read)
        assertEquals(0, ok(api.inboxReadAll(key)).unread)
        assertTrue(ok(api.inbox(key, unreadOnly = true)).items.isEmpty())

        // The log, read as the account: the stop is this phone's, through Mobile.
        val events = ok(api.activity(key, workspace)).events
        val halted = events.first { it.action == "scan.halted" }
        assertEquals("mobile", halted.channel)
        assertEquals("approver_device", halted.credentialKind)
        assertTrue(halted.detail.any { it.first == "approval_id" && it.second == p.id })
        assertTrue(events.map { it.action }.toString(), events.any { it.action == "approval.granted" })
        ok(api.activity(key, ActivityScope.Account))

        // Turned off, the phone reads nothing again.
        ok(api.revoke(key, e.approverId))
        assertEquals(Refusal.APPROVER_INACTIVE, reason(api.inbox(key)))
    }
}
