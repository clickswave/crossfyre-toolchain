package io.crossfyre.mobile

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
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
    fun credentials_and_other_schemes_are_refused() {
        assertNull(Pairing.normaliseApiUrl("https://user:pass@crossfyre.io", allowLocalHttp = true))
        assertNull(Pairing.normaliseApiUrl("javascript:alert(1)", allowLocalHttp = true))
        assertNull(Pairing.normaliseApiUrl("", allowLocalHttp = true))
    }
}
