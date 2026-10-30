package io.crossfyre.mobile.approve

import io.crossfyre.mobile.account.HttpTransport
import io.crossfyre.mobile.account.Outcome
import io.crossfyre.mobile.account.Refusal
import io.crossfyre.mobile.reasonOf
import kotlinx.coroutines.runBlocking
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec

/**
 * The phone's side of the protocol end to end, over HTTP, against [FakeCloud]:
 * enrol, wait for the browser, read what is pending, sign it, and have the server
 * verify the signature over its own digest. The keystore is replaced by a key in
 * this JVM; the keystore itself is tested on a device.
 */
class ApprovalFlowTest {

    /** [ApproverKeys] without a keystore, so the flow runs on the JVM. */
    private class SoftwareKeys : ApproverKeys {
        var pair: KeyPair? = null
        override fun presence() = if (pair != null) KeyPresence.PRESENT else KeyPresence.ABSENT
        override fun create(): ByteArray {
            pair = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
            return pair!!.public.encoded
        }
        override fun publicKey() = pair?.public?.encoded
        override fun signature(): Signature = Signature.getInstance("SHA256withECDSA").apply { initSign(pair!!.private) }
        override fun delete() { pair = null }
    }

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

    private fun sign(id: String, digest: String, approverId: String, signedAt: Long = 1793345642): ByteArray =
        keys.signature().run { update(ApprovalProtocol.signingBytes(id, "approve", digest, signedAt, approverId)); sign() }

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
    fun a_signature_over_anything_but_the_servers_digest_is_refused_and_changes_nothing() {
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
    fun a_phone_the_browser_never_confirmed_cannot_approve() = runBlocking {
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
    fun a_revoked_phone_is_no_longer_an_approver() {
        val e = enrolled()
        ok(api.revoke(key, e.approverId))
        assertEquals(null, ok(api.pending(key)).approver)
        val asked = cloud.request(summary())
        val r = api.approve(key, asked.id, e.approverId, 1793345642, sign(asked.id, asked.digest, e.approverId))
        assertEquals(Refusal.APPROVER_INACTIVE, reasonOf((r as Outcome.Failed).problem))
    }
}
