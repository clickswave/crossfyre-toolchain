package io.crossfyre.mobile.approve

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * A keystore that cannot be asked is not a keystore without the key. The app
 * deletes the key and revokes the approver when the key is gone, so reading a
 * failed lookup as "gone" would throw away a working approval key on an
 * ordinary resume. The real keystore's answers are tested on a device.
 */
class KeyPresenceTest {

    @Test
    fun a_keystore_that_cannot_be_read_says_unknown_rather_than_absent() {
        // There is no AndroidKeyStore provider on the JVM, so every lookup throws.
        val keys = KeystoreApproverKeys(alias = "crossfyre-approver-test", deviceSecure = { true })
        assertEquals(KeyPresence.UNKNOWN, keys.presence())
    }
}
