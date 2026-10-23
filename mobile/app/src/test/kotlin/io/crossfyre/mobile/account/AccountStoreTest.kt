package io.crossfyre.mobile.account

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.GeneralSecurityException

/**
 * What the phone keeps about the account, with the keystore replaced by a
 * stand-in. The real sealer is exercised on a device; this is the bookkeeping
 * around it: what is kept, what sign-out forgets, and what a key that can no
 * longer be opened turns into.
 */
class AccountStoreTest {

    private class MapValues : KeyValues {
        val map = mutableMapOf<String, String>()
        override fun get(name: String): String? = map[name]
        override fun put(name: String, value: String?) {
            if (value == null) map.remove(name) else map[name] = value
        }
    }

    /** Reversible, and nothing like the input, which is all a stand-in needs. */
    private class FlipSealer : Sealer {
        override fun seal(plain: ByteArray) = byteArrayOf(7) + plain.map { (it.toInt() xor 0x5A).toByte() }.reversed()
        override fun open(sealed: ByteArray): ByteArray {
            if (sealed.isEmpty() || sealed[0] != 7.toByte()) throw GeneralSecurityException("not ours")
            return sealed.drop(1).reversed().map { (it.toInt() xor 0x5A).toByte() }.toByteArray()
        }
    }

    /** A keystore key that is gone, as after a restore onto another phone. */
    private class LostKeySealer : Sealer {
        override fun seal(plain: ByteArray) = FlipSealer().seal(plain)
        override fun open(sealed: ByteArray): ByteArray = throw GeneralSecurityException("key invalidated")
    }

    private val key = "cfk_" + "0123456789abcdef".repeat(2)
    private val signedIn = SignedIn(key, AccountUser("u-1", "kew", "kew@example.com", "personal", true))

    @Test
    fun a_saved_key_comes_back_and_is_never_stored_as_typed() {
        val values = MapValues()
        val store = AccountStore(values, FlipSealer())
        store.saveSignIn(signedIn)

        assertEquals(key, store.key())
        assertEquals(StoredUser("kew", "kew@example.com"), store.user())
        values.map.values.forEach { assertFalse("stored in the clear: $it", it.contains(key)) }
        values.map.values.forEach { assertFalse("stored in the clear: $it", it.contains(key.removePrefix("cfk_"))) }
    }

    @Test
    fun signing_out_forgets_the_account_and_keeps_the_install_id() {
        val values = MapValues()
        val store = AccountStore(values, FlipSealer())
        val device = store.deviceId()
        store.saveSignIn(signedIn)
        store.saveWorkspace(ChosenWorkspace("w1", "Personal"))
        store.pairedFromAccount = true

        store.signOut()

        assertNull(store.key())
        assertNull(store.user())
        assertNull(store.workspace())
        assertFalse(store.pairedFromAccount)
        // The pairing route keys a phone's session on this id. Keeping it means
        // signing back in to the same workspace re-arms that session rather
        // than adding a second one to the list.
        assertEquals(device, store.deviceId())
    }

    @Test
    fun a_key_that_cannot_be_opened_reads_as_signed_out_and_is_dropped() {
        val values = MapValues()
        AccountStore(values, FlipSealer()).saveSignIn(signedIn)
        val store = AccountStore(values, LostKeySealer())

        assertNull(store.key())
        assertNull(store.key())
        assertFalse("the unreadable key was kept", values.map.values.any { it.length > 40 })
    }

    @Test
    fun the_install_id_is_made_once_and_is_one_the_route_accepts() {
        val values = MapValues()
        val first = AccountStore(values, FlipSealer()).deviceId()
        val again = AccountStore(values, FlipSealer()).deviceId()

        assertEquals(first, again)
        assertTrue(first, DeviceIds.isValid(first))
    }

    @Test
    fun the_chosen_workspace_is_remembered() {
        val values = MapValues()
        AccountStore(values, FlipSealer()).saveWorkspace(ChosenWorkspace("w2", "Red team"))
        val store = AccountStore(values, FlipSealer())

        assertEquals(ChosenWorkspace("w2", "Red team"), store.workspace())
        store.saveWorkspace(null)
        assertNull(store.workspace())
    }

    @Test
    fun the_server_a_dev_build_was_pointed_at_is_kept_across_sign_out() {
        val values = MapValues()
        val store = AccountStore(values, FlipSealer())
        assertNull(store.origin())
        store.saveOrigin("http://192.168.1.5:12004")
        store.saveSignIn(signedIn)
        store.signOut()

        assertNotNull(store.origin())
        assertEquals("http://192.168.1.5:12004", store.origin())
    }

    @Test
    fun the_sign_in_method_and_the_workspace_detail_are_kept_and_forgotten_with_the_account() {
        val values = MapValues()
        val store = AccountStore(values, FlipSealer())
        store.saveSignIn(SignedIn("cfk_" + "a".repeat(40), AccountUser("u-1", "meera", "meera@example.com", "personal", true)))
        store.signedInWith = "browser"
        store.saveWorkspace(ChosenWorkspace("w3", "client-app-audit", "team", "Northwind Security"))
        assertEquals("browser", store.signedInWith)
        assertEquals(ChosenWorkspace("w3", "client-app-audit", "team", "Northwind Security"), store.workspace())
        store.signOut()
        assertNull(store.signedInWith)
        assertNull(store.workspace())
        assertTrue(values.map.keys.none { it.startsWith("workspace") })
    }
}
