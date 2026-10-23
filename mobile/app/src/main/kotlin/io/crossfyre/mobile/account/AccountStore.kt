package io.crossfyre.mobile.account

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.GeneralSecurityException
import java.security.KeyStore
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** Encrypts small secrets under a key that never leaves the platform keystore. */
interface Sealer {
    fun seal(plain: ByteArray): ByteArray

    /** Throws when the value cannot be opened, for example because the key is gone. */
    fun open(sealed: ByteArray): ByteArray
}

/** The few strings the app keeps, by name. A null value removes the name. */
interface KeyValues {
    fun get(name: String): String?
    fun put(name: String, value: String?)
}

data class StoredUser(val username: String, val email: String)

/** The workspace this phone is paired with, as much as the screens show of it. */
data class ChosenWorkspace(val id: String, val name: String, val kind: String = "", val org: String = "")

/**
 * What the phone keeps about the signed-in account.
 *
 * The account key is the one secret here. It can list every workspace the person
 * belongs to and pair any of them, so it is sealed by [Sealer] before it is
 * written, and what lands in storage is ciphertext under a key the keystore will
 * not hand out. A sealed key that no longer opens (the keystore key was wiped, or
 * the data was copied to another phone) is treated as signed out and removed, so
 * the person is asked to sign in again rather than shown an error.
 *
 * The username, email and chosen workspace are kept in the clear: they are shown
 * on screen and are not credentials. The install id and the server a dev build
 * was pointed at outlive a sign-out on purpose.
 */
class AccountStore(private val values: KeyValues, private val sealer: Sealer) {

    fun key(): String? {
        val stored = values.get(KEY) ?: return null
        return try {
            String(sealer.open(Base64.getDecoder().decode(stored)), Charsets.UTF_8)
        } catch (e: GeneralSecurityException) {
            values.put(KEY, null)
            null
        } catch (e: IllegalArgumentException) {
            values.put(KEY, null)
            null
        }
    }

    fun saveSignIn(signedIn: SignedIn) {
        val sealed = sealer.seal(signedIn.key.toByteArray(Charsets.UTF_8))
        values.put(KEY, Base64.getEncoder().encodeToString(sealed))
        values.put(USERNAME, signedIn.user.username)
        values.put(EMAIL, signedIn.user.email)
    }

    fun user(): StoredUser? {
        val name = values.get(USERNAME) ?: return null
        return StoredUser(name, values.get(EMAIL).orEmpty())
    }

    fun workspace(): ChosenWorkspace? {
        val id = values.get(WORKSPACE_ID) ?: return null
        return ChosenWorkspace(
            id, values.get(WORKSPACE_NAME).orEmpty(),
            values.get(WORKSPACE_KIND).orEmpty(), values.get(WORKSPACE_ORG).orEmpty(),
        )
    }

    fun saveWorkspace(workspace: ChosenWorkspace?) {
        values.put(WORKSPACE_ID, workspace?.id)
        values.put(WORKSPACE_NAME, workspace?.name)
        values.put(WORKSPACE_KIND, workspace?.kind?.ifEmpty { null })
        values.put(WORKSPACE_ORG, workspace?.org?.ifEmpty { null })
    }

    /** How this phone signed in: "password" or "browser", shown in Settings. */
    var signedInWith: String?
        get() = values.get(VIA)
        set(value) = values.put(VIA, value)

    /** The pairing came from the account rather than a QR code, so the phone can renew it. */
    var pairedFromAccount: Boolean
        get() = values.get(FROM_ACCOUNT) == "1"
        set(value) = values.put(FROM_ACCOUNT, if (value) "1" else null)

    /** The server a dev build was pointed at, or null for the build's own. */
    fun origin(): String? = values.get(ORIGIN)

    fun saveOrigin(origin: String) = values.put(ORIGIN, origin)

    /** This install's id, made the first time it is asked for. */
    fun deviceId(): String =
        values.get(DEVICE_ID)?.takeIf { DeviceIds.isValid(it) }
            ?: DeviceIds.fresh().also { values.put(DEVICE_ID, it) }

    /** Forget the account. The install id and the server stay. */
    fun signOut() {
        for (name in listOf(KEY, USERNAME, EMAIL, WORKSPACE_ID, WORKSPACE_NAME, WORKSPACE_KIND, WORKSPACE_ORG, FROM_ACCOUNT, VIA)) {
            values.put(name, null)
        }
    }

    private companion object {
        const val KEY = "account_key_sealed"
        const val USERNAME = "username"
        const val EMAIL = "email"
        const val WORKSPACE_ID = "workspace_id"
        const val WORKSPACE_NAME = "workspace_name"
        const val WORKSPACE_KIND = "workspace_kind"
        const val WORKSPACE_ORG = "workspace_org"
        const val FROM_ACCOUNT = "paired_from_account"
        const val ORIGIN = "origin"
        const val DEVICE_ID = "device_id"
        const val VIA = "signed_in_with"
    }
}

/** [KeyValues] in the app's private shared preferences. */
class PrefsKeyValues(context: Context, file: String = "account") : KeyValues {
    private val prefs = context.getSharedPreferences(file, Context.MODE_PRIVATE)

    override fun get(name: String): String? = prefs.getString(name, null)

    // commit, not apply: a browser approval hands the key over exactly once, so
    // it has to be on disk before anything else happens, including the process
    // being killed a moment later.
    override fun put(name: String, value: String?) {
        prefs.edit().apply { if (value == null) remove(name) else putString(name, value) }.commit()
    }
}

/**
 * AES-256-GCM under a key generated inside the Android keystore.
 *
 * The keystore generates the key and keeps it; on most phones that is secure
 * hardware, and on all of them the key material never enters this process. It
 * also picks a fresh nonce for every seal, which is stored in front of the
 * ciphertext.
 */
class KeystoreSealer(private val alias: String = "crossfyre-mobile-account") : Sealer {

    override fun seal(plain: ByteArray): ByteArray {
        val cipher = Cipher.getInstance(TRANSFORM)
        cipher.init(Cipher.ENCRYPT_MODE, existingKey() ?: newKey())
        val iv = cipher.iv
        return byteArrayOf(iv.size.toByte()) + iv + cipher.doFinal(plain)
    }

    override fun open(sealed: ByteArray): ByteArray {
        val ivLength = sealed.firstOrNull()?.toInt() ?: throw GeneralSecurityException("empty")
        if (ivLength !in 12..16 || sealed.size <= 1 + ivLength) throw GeneralSecurityException("not a sealed value")
        val key = existingKey() ?: throw GeneralSecurityException("no key to open it with")
        val cipher = Cipher.getInstance(TRANSFORM)
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(TAG_BITS, sealed, 1, ivLength))
        return cipher.doFinal(sealed, 1 + ivLength, sealed.size - 1 - ivLength)
    }

    private fun existingKey(): SecretKey? {
        val store = KeyStore.getInstance(PROVIDER).apply { load(null) }
        return store.getKey(alias, null) as? SecretKey
    }

    private fun newKey(): SecretKey {
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, PROVIDER)
        generator.init(
            KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build()
        )
        return generator.generateKey()
    }

    private companion object {
        const val PROVIDER = "AndroidKeyStore"
        const val TRANSFORM = "AES/GCM/NoPadding"
        const val TAG_BITS = 128
    }
}
