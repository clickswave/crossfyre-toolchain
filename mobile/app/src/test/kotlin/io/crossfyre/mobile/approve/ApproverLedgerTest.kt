package io.crossfyre.mobile.approve

import io.crossfyre.mobile.account.AccountApi
import io.crossfyre.mobile.account.AccountStore
import io.crossfyre.mobile.account.HttpTransport
import io.crossfyre.mobile.account.KeyValues
import io.crossfyre.mobile.account.Outcome
import io.crossfyre.mobile.account.Problem
import io.crossfyre.mobile.account.Sealer
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.security.KeyPairGenerator
import java.security.spec.ECGenParameterSpec

/**
 * What happens to an approver the server made for this phone when the phone
 * stops counting on it. Once a phone approves, only its signature counts, so an
 * approver left pending or active without a key on the phone would hold up every
 * request that needs one. The browser page stays open after the phone gives up,
 * and a Confirm there must not bring such an approver to life.
 */
class ApproverLedgerTest {

    private class MapValues : KeyValues {
        val map = mutableMapOf<String, String>()
        override fun get(name: String): String? = map[name]
        override fun put(name: String, value: String?) {
            if (value == null) map.remove(name) else map[name] = value
        }
    }

    private class PlainSealer : Sealer {
        override fun seal(plain: ByteArray) = plain
        override fun open(sealed: ByteArray) = sealed
    }

    private val key = "cfk_" + "e".repeat(40)
    private val cloud = FakeCloud(key)
    private val api = ApprovalApi(cloud.origin, HttpTransport(2_000, 2_000))
    private val values = MapValues()
    private val store = AccountStore(values, PlainSealer())
    private val ledger = ApproverLedger(store)
    private val spki = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair().public.encoded

    @After
    fun down() = cloud.close()

    /** A run of the enrolment with a clock that moves only when it sleeps. */
    private fun enrolNow(opened: suspend (Enrolment) -> Unit = {}): Outcome<EnrolState> = runBlocking {
        var clock = 0L
        enrol(api, key, "install-0001", "Pixel 8", spki, ledger, opened, { clock += it }, { clock })
    }

    private fun code(): String = cloud.approvers.single().code

    @Test
    fun a_wait_ended_by_a_refusal_revokes_the_approver_so_the_browser_cannot_confirm_it() {
        cloud.pollFails = 403
        val r = enrolNow()
        assertTrue(r is Outcome.Failed)
        assertEquals("revoked", cloud.approvers.single().status)
        assertFalse("a Confirm after the phone gave up made an approver with no key", cloud.confirm(code()))
        assertTrue(ledger.owed.isEmpty())
        assertNull(store.enrollingApproverId)
        assertNull(store.approverId)
    }

    @Test
    fun a_wait_that_runs_out_on_the_phone_revokes_the_approver_the_server_still_holds() {
        // The server never answers anything but pending, so the phone's own deadline ends the wait.
        cloud.enrolSeconds = 5
        assertEquals(Outcome.Ok(EnrolState.EXPIRED), enrolNow())
        assertEquals("revoked", cloud.approvers.single().status)
        assertFalse(cloud.confirm(code()))
    }

    @Test
    fun an_approver_made_for_a_key_the_phone_did_not_send_is_revoked() {
        // Whoever changed the key on the way holds the enrol code too, and could
        // send the person the confirm link.
        cloud.startFingerprint = "0000 0000 0000 0000"
        val r = enrolNow(opened = { fail("the confirmation page opened for a key that is not this phone's") })
        assertTrue(((r as Outcome.Failed).problem as Problem.Broken).text.contains("different key"))
        assertEquals("revoked", cloud.approvers.single().status)
        assertFalse(cloud.confirm(code()))
        assertTrue(ledger.owed.isEmpty())
        assertNull(store.enrollingApproverId)
        assertNull(store.approverId)
    }

    @Test
    fun an_approver_for_another_key_whose_revoke_fails_stays_owed() {
        cloud.startFingerprint = "0000 0000 0000 0000"
        cloud.revokeFails = 503
        enrolNow()
        assertEquals(setOf(cloud.approvers.single().id), ledger.owed)
        assertEquals("pending", cloud.approvers.single().status)
    }

    @Test
    fun a_confirmed_phone_becomes_the_approver_and_owes_nothing() {
        val r = enrolNow(opened = { e -> assertTrue(cloud.confirm(e.code)) })
        assertEquals(Outcome.Ok(EnrolState.ACTIVE), r)
        assertEquals(cloud.approvers.single().id, store.approverId)
        assertEquals(Spki.fingerprint(spki), store.approverFingerprint)
        assertEquals("active", cloud.approvers.single().status)
        assertNull(store.enrollingApproverId)
        assertTrue(ledger.owed.isEmpty())
    }

    @Test
    fun a_revoke_the_server_did_not_take_is_kept_and_sent_again_after_a_restart() {
        cloud.pollFails = 403
        cloud.revokeFails = 503
        enrolNow()
        val id = cloud.approvers.single().id
        assertEquals(setOf(id), ledger.owed)
        assertEquals("pending", cloud.approvers.single().status)

        // A new process, reading the same storage.
        cloud.revokeFails = null
        val again = ApproverLedger(AccountStore(values, PlainSealer()))
        assertEquals(setOf(id), again.owed)
        assertEquals(Outcome.Ok(Unit), again.settle { api.revoke(key, it) })
        assertTrue(again.owed.isEmpty())
        assertEquals("revoked", cloud.approvers.single().status)
        assertFalse(cloud.confirm(code()))
    }

    @Test
    fun an_enrolment_the_process_did_not_survive_is_revoked_at_the_next_start() {
        // The process dies while the browser page is open: the start was written down, nothing else.
        val e = (api.enrolStart(key, "install-0001", "Pixel 8", spki) as Outcome.Ok).value
        ledger.started(e.approverId)

        val next = ApproverLedger(AccountStore(values, PlainSealer()))
        assertTrue(next.abandoned())
        assertFalse("only once", next.abandoned())
        assertEquals(setOf(e.approverId), next.owed)
        next.settle { api.revoke(key, it) }
        assertFalse(cloud.confirm(e.code))
        assertTrue(next.owed.isEmpty())
    }

    @Test
    fun a_cancelled_wait_lets_the_approver_go() = runBlocking {
        val waiting = CompletableDeferred<Unit>()
        val job = launch(Dispatchers.Default) {
            enrol(api, key, "install-0001", "Pixel 8", spki, ledger, { waiting.complete(Unit) }, { delay(it) }, { System.nanoTime() / 1_000_000 })
        }
        waiting.await()
        job.cancel()
        job.join()
        val id = cloud.approvers.single().id
        assertEquals(setOf(id), ledger.owed)
        assertNull(store.enrollingApproverId)
        ledger.settle { api.revoke(key, it) }
        assertFalse(cloud.confirm(code()))
    }

    // ── sign-out ──────────────────────────────────────────────────────────

    private val account = AccountApi(cloud.origin, HttpTransport(2_000, 2_000))

    private fun signOut() = ledger.signOut({ id -> api.revoke(key, id) }, { account.logout(key) })

    /** A phone that approves as one approver, is enrolling a second, and owes a revoke for a third. */
    private fun busyPhone(): List<String> {
        enrolNow(opened = { e -> assertTrue(cloud.confirm(e.code)) })
        val enrolling = (api.enrolStart(key, "install-0001", "Pixel 8", spki) as Outcome.Ok).value.approverId
        ledger.started(enrolling)
        val owed = (api.enrolStart(key, "install-0001", "Pixel 8", spki) as Outcome.Ok).value.approverId
        ledger.letGo(owed)
        return cloud.approvers.map { it.id }
    }

    @Test
    fun signing_out_revokes_every_approver_and_then_the_key() {
        busyPhone()
        cloud.routes.clear()
        assertEquals(SignOutLeft.NOTHING, signOut())
        assertEquals(listOf("revoked", "revoked", "revoked"), cloud.approvers.map { it.status })
        assertTrue(cloud.keyRevoked)
        // A revoke sent after the logout would be refused for the key it carries.
        assertEquals("logout", cloud.routes.last())
        assertEquals(3, cloud.routes.count { it == "approver/revoke" })
        assertTrue(ledger.owed.isEmpty())
        assertNull(store.approverId)
        assertNull(store.enrollingApproverId)
    }

    @Test
    fun a_sign_out_the_server_did_not_take_says_what_it_may_still_count() {
        val ids = busyPhone()
        cloud.revokeFails = 503
        cloud.logoutFails = 503
        assertEquals(SignOutLeft.APPROVER, signOut())
        assertEquals("active", cloud.approvers.first().status)
        assertFalse(cloud.keyRevoked)
        assertEquals(ids.toSet(), ledger.owed)

        // The approvers go through on a second try, the key still does not.
        cloud.revokeFails = null
        assertEquals(SignOutLeft.KEY, signOut())
        assertEquals(listOf("revoked", "revoked", "revoked"), cloud.approvers.map { it.status })
        assertFalse(cloud.keyRevoked)
    }

    @Test
    fun a_sign_out_with_a_key_already_revoked_leaves_nothing() {
        busyPhone()
        cloud.keyRevoked = true
        assertEquals(SignOutLeft.NOTHING, signOut())
        assertTrue(ledger.owed.isEmpty())
    }

    @Test
    fun a_key_the_server_no_longer_takes_settles_everything_owed() {
        ledger.letGo("ap-1")
        ledger.letGo("ap-2")
        assertEquals(Outcome.Failed(Problem.SignedOut), ledger.settle { Outcome.Failed(Problem.SignedOut) })
        assertTrue(ledger.owed.isEmpty())
    }

    @Test
    fun letting_go_of_the_active_approver_forgets_it_and_owes_its_revoke() {
        store.approverId = "ap-1"
        store.approverFingerprint = "ab12 cd34 ef56 7890"
        ledger.letGo("ap-1")
        assertNull(store.approverId)
        assertNull(store.approverFingerprint)
        assertEquals(setOf("ap-1"), ledger.owed)
        assertEquals(Outcome.Failed(Problem.Unreachable("x")), ledger.settle { Outcome.Failed(Problem.Unreachable("x")) })
        assertEquals(setOf("ap-1"), ledger.owed)
    }
}
