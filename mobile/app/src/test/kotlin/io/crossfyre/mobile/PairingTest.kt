package io.crossfyre.mobile

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Which control planes the app will talk to.
 *
 * The Rust capture path has its own TLS stack, so the platform's cleartext ban
 * does not reach it: an http origin would ship every captured request in the
 * clear. Plain http is allowed only to a local or private address, and only by
 * a build made for a dev stack. That decision used to hang on BuildConfig.DEBUG
 * alone, which made the dev flavour's release build refuse the very server its
 * sign-in screen offers.
 */
class PairingTest {

    @Test
    fun https_is_kept_without_its_trailing_slash() {
        assertEquals("https://crossfyre.io", Pairing.normaliseApiUrl("https://crossfyre.io/", allowLocalHttp = false))
        assertEquals("https://staging.crossfyre.io", Pairing.normaliseApiUrl(" https://staging.crossfyre.io ", allowLocalHttp = false))
    }

    @Test
    fun http_to_a_dev_stack_needs_a_build_that_allows_it() {
        assertNull(Pairing.normaliseApiUrl("http://192.168.1.5:12004", allowLocalHttp = false))
        assertNull(Pairing.normaliseApiUrl("http://10.0.2.2:12004", allowLocalHttp = false))
        assertEquals("http://192.168.1.5:12004", Pairing.normaliseApiUrl("http://192.168.1.5:12004/", allowLocalHttp = true))
        assertEquals("http://10.0.2.2:12004", Pairing.normaliseApiUrl("http://10.0.2.2:12004", allowLocalHttp = true))
    }

    @Test
    fun http_to_a_public_host_is_never_allowed() {
        assertNull(Pairing.normaliseApiUrl("http://crossfyre.io", allowLocalHttp = true))
        assertNull(Pairing.normaliseApiUrl("http://172.32.0.1:12004", allowLocalHttp = true))
    }

    @Test
    fun a_name_that_starts_like_a_private_address_is_not_one() {
        // Names, not addresses: whoever owns the domain decides where they point.
        for (host in listOf("10.example.com", "192.168.evil.example", "172.16.0.example", "127.0.0.1.example")) {
            assertNull(host, Pairing.normaliseApiUrl("http://$host:12004", allowLocalHttp = true))
        }
        assertNull(Pairing.normaliseApiUrl("http://10.0.0.256:12004", allowLocalHttp = true))
        assertEquals("http://172.20.1.9:12004", Pairing.normaliseApiUrl("http://172.20.1.9:12004", allowLocalHttp = true))
        assertEquals("http://127.0.0.1:12004", Pairing.normaliseApiUrl("http://127.0.0.1:12004", allowLocalHttp = true))
        assertEquals("http://localhost:12004", Pairing.normaliseApiUrl("http://localhost:12004", allowLocalHttp = true))
    }

    @Test
    fun a_yes_to_full_requests_covers_only_the_pairing_it_was_given_for() {
        val mine = Pairing("https://crossfyre.io", "wf-mine", "cfxt_1")
        val given = FullCapturePrefs.keyOf(mine)
        assertTrue(FullCapturePrefs.covers(given, mine))
        // Pairing again renews the token, not the session.
        assertTrue(FullCapturePrefs.covers(given, mine.copy(token = "cfxt_2")))
        // Somebody else's server, by QR, even for a session id that matches.
        assertFalse(FullCapturePrefs.covers(given, Pairing("https://elsewhere.example", "wf-mine", "cfxt_1")))
        // Another session on the same server: another workspace, or a colleague's QR.
        assertFalse(FullCapturePrefs.covers(given, mine.copy(workflowId = "wf-other")))
        // No yes at all, or nothing paired.
        assertFalse(FullCapturePrefs.covers(null, mine))
        assertFalse(FullCapturePrefs.covers(given, null))
    }

    @Test
    fun credentials_and_other_schemes_are_refused() {
        assertNull(Pairing.normaliseApiUrl("https://user:pass@crossfyre.io", allowLocalHttp = true))
        assertNull(Pairing.normaliseApiUrl("javascript:alert(1)", allowLocalHttp = true))
        assertNull(Pairing.normaliseApiUrl("", allowLocalHttp = true))
    }
}
