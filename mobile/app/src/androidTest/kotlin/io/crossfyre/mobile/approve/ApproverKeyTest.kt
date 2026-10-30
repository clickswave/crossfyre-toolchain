package io.crossfyre.mobile.approve

import android.app.KeyguardManager
import android.content.Context
import android.security.keystore.UserNotAuthenticatedException
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The approval key in the real keystore, on a device or emulator.
 *
 * The tests set and clear a PIN themselves through `locksettings`, so they need
 * a device whose lock screen they are allowed to change: an emulator, not a phone
 * in use. The unlock prompt itself is checked by hand.
 */
@RunWith(AndroidJUnit4::class)
class ApproverKeyTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context: Context = instrumentation.targetContext
    private val keyguard = context.getSystemService(KeyguardManager::class.java)
    private val keys = KeystoreApproverKeys(alias = "crossfyre-approver-test", deviceSecure = { keyguard.isDeviceSecure })

    private fun shell(cmd: String): String =
        instrumentation.uiAutomation.executeShellCommand(cmd).let { fd ->
            android.os.ParcelFileDescriptor.AutoCloseInputStream(fd).bufferedReader().use { it.readText() }
        }

    private fun lock() {
        if (!keyguard.isDeviceSecure) shell("locksettings set-pin $PIN")
        assertTrue("could not set a PIN on this device", keyguard.isDeviceSecure)
    }

    private fun unlock() {
        if (keyguard.isDeviceSecure) shell("locksettings clear --old $PIN")
        assertFalse("could not clear the PIN on this device", keyguard.isDeviceSecure)
    }

    @After
    fun down() {
        keys.delete()
        unlock()
    }

    @Test
    fun no_key_is_made_on_a_phone_without_a_screen_lock() {
        unlock()
        try {
            keys.create()
            fail("a key that needs an unlock was made on a phone with no lock")
        } catch (e: NoScreenLock) {
            assertFalse(keys.exists())
        }
    }

    @Test
    fun the_public_half_is_a_p256_key_and_the_private_half_stays_in_the_keystore() {
        lock()
        val spki = keys.create()
        assertTrue(Spki.isP256(spki))
        assertTrue(keys.exists())
        assertArrayEquals(spki, keys.publicKey())
        keys.delete()
        assertFalse(keys.exists())
    }

    /**
     * The point of the key: it does not sign for anyone who has not just unlocked
     * the phone. Built without the unlock requirement, this signs, and fails.
     */
    @Test
    fun the_key_will_not_sign_without_an_unlock() {
        lock()
        keys.create()
        val message = ApprovalProtocol.signingBytes("id", "approve", "ab".repeat(32), 1, "dev")
        val error = runCatching {
            keys.signature().run {
                update(message)
                sign()
            }
        }.exceptionOrNull() ?: return fail("the key signed with no unlock")
        val chain = generateSequence(error) { it.cause }.toList()
        assertTrue(
            "unexpected failure: $error",
            chain.any { it is UserNotAuthenticatedException || (it.message ?: "").contains("authenticat", ignoreCase = true) },
        )
    }

    private companion object {
        const val PIN = "1111"
    }
}
