package io.crossfyre.mobile

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The status panel's one line of advice, in both builds.
 *
 * The Play build has no patching, so advice that sends someone to patch an app
 * sends them to a button that is not there. And a phone signed in to an account
 * renews its own session, so telling it to re-scan a QR code is wrong for it.
 */
class DiagnosisTest {

    private fun stats(
        flows: Long = 4, events: Long = 0, caRejected: Long = 0, sent: Long = 0,
        rejected: Long = 0, failed: Long = 0, quic: Long = 0,
    ) = Stats(flows, flows, caRejected, 0, events, sent, rejected, failed, quic, "", "handshake refused")

    /** Every refusal the panel can explain, with and without a patched or Flutter app in scope. */
    private fun refusals(patching: Boolean): List<Diag> = listOf(
        diagnose(true, stats(caRejected = 3), patchedInScope = false, flutterInScope = false, patching = patching, renewable = true),
        diagnose(true, stats(caRejected = 3), patchedInScope = false, flutterInScope = true, patching = patching, renewable = true),
        diagnose(true, stats(caRejected = 3), patchedInScope = patching, flutterInScope = false, patching = patching, renewable = true),
    ).map { assertNotNull(it); it!! }

    @Test
    fun without_patching_no_advice_sends_anyone_to_patch() {
        val all = refusals(patching = false) + listOfNotNull(
            diagnose(true, stats(), false, false, patching = false, renewable = true),
            diagnose(true, stats(events = 2, rejected = 1), false, false, patching = false, renewable = false),
            diagnose(true, stats(quic = 2), false, false, patching = false, renewable = true),
        )
        for (d in all) {
            val said = d.title + " " + d.body
            assertFalse("the Play build has no patching: $said", said.contains("patch", ignoreCase = true))
        }
    }

    @Test
    fun with_patching_a_refusing_app_is_still_sent_to_scope_to_be_patched() {
        val d = refusals(patching = true).first()
        assertTrue(d.body, d.body.contains("Patch", ignoreCase = true))
    }

    @Test
    fun a_refused_token_on_a_signed_in_phone_is_renewed_from_the_phone() {
        val d = diagnose(true, stats(events = 2, rejected = 1), false, false, patching = true, renewable = true)!!
        // The phone can mint itself a new token, so it is offered that, not a scanner.
        assertEquals(DiagAction.PAIR_AGAIN, d.action)
        assertFalse(d.body, d.body.contains("Scan", ignoreCase = true))
        assertTrue(d.body, d.body.contains("Pairing again", ignoreCase = true))
    }

    @Test
    fun a_refused_token_on_a_qr_pairing_needs_a_new_code() {
        val d = diagnose(true, stats(events = 2, rejected = 1), false, false, patching = true, renewable = false)!!
        assertEquals(DiagAction.SCAN_NEW_CODE, d.action)
        assertTrue(d.body, d.body.contains("Scan the new one", ignoreCase = true))
    }

    @Test
    fun a_healthy_capture_offers_the_dashboard() {
        val d = diagnose(true, stats(events = 3, sent = 3), false, false, patching = false, renewable = true)!!
        assertEquals(Level.OK, d.level)
        assertEquals(DiagAction.OPEN_DASHBOARD, d.action)
    }

    @Test
    fun an_unreachable_server_is_named() {
        val d = diagnose(true, stats(events = 3, failed = 2), false, false, patching = true, renewable = true, host = "10.0.2.2:12004")!!
        assertTrue(d.body, d.body.startsWith("10.0.2.2:12004 isn't answering"))
    }

    @Test
    fun one_dropped_quic_flow_is_counted_in_the_singular() {
        val d = diagnose(true, stats(quic = 1), false, false, patching = true, renewable = true)!!
        assertTrue(d.body, d.body.startsWith("1 QUIC flow dropped"))
    }

    @Test
    fun nothing_is_said_while_capture_is_off() {
        assertTrue(diagnose(false, stats(caRejected = 1), false, false, patching = true, renewable = true) == null)
    }
}
