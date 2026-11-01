package io.crossfyre.mobile.approve

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.ProviderException
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.X509EncodedKeySpec

/** The phone has no screen lock, so a key that needs an unlock for every use cannot be made. */
class NoScreenLock : Exception("Set a screen lock on this phone first.")

/**
 * The key is not in the keystore any more. Android deletes a key that needs an
 * unlock when the screen lock is removed, rather than only marking it invalid.
 */
class KeyGone : Exception("No approval key on this phone.")

/**
 * Whether the approval key is in the keystore. [UNKNOWN] is a keystore that
 * could not be asked, which happens while its service restarts: nothing about
 * the key follows from it, so nothing is deleted or revoked on it.
 */
enum class KeyPresence { PRESENT, ABSENT, UNKNOWN }

/**
 * The key this phone approves with.
 *
 * It is made in the platform keystore, its private half never enters this
 * process, and the keystore refuses to sign with it unless the person has just
 * unlocked the phone: on Android 11 and later for every single signature, and on
 * Android 8 to 10 within fifteen seconds of the unlock.
 */
interface ApproverKeys {
    fun presence(): KeyPresence

    /** Make a fresh key, replacing any old one, and return its public half as SPKI DER. */
    fun create(): ByteArray

    /** The public half as SPKI DER, or null when there is no key. */
    fun publicKey(): ByteArray?

    /**
     * A signature initialised with the private key, for the unlock prompt to
     * authorise. On Android 10 and earlier this throws until the phone was
     * unlocked in the last fifteen seconds.
     */
    fun signature(): Signature

    fun delete()
}

/** Facts about a public key, which the phone and the server both state. */
object Spki {
    /** True when [der] is an X.509 SubjectPublicKeyInfo for an EC key on P-256. */
    fun isP256(der: ByteArray): Boolean = runCatching {
        val key = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(der)) as ECPublicKey
        val p = key.params
        p.curve.field.fieldSize == 256 && p.order == P256_ORDER && p.generator.affineX == P256_GX
    }.getOrDefault(false)

    /**
     * The first sixteen hex digits of the SHA-256 of the SPKI DER, in four groups
     * of four: what the phone and the confirmation page both show, so a person can
     * see that the key the browser confirms is the one this phone made.
     */
    fun fingerprint(der: ByteArray): String =
        ApprovalProtocol.sha256Hex(der).take(16).chunked(4).joinToString(" ")

    fun normalFingerprint(s: String): String = s.filter { !it.isWhitespace() }.lowercase()

    private val P256_ORDER = java.math.BigInteger("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16)
    private val P256_GX = java.math.BigInteger("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16)
}

/** [ApproverKeys] in the Android keystore. */
class KeystoreApproverKeys(
    private val alias: String = "crossfyre-approver",
    private val deviceSecure: () -> Boolean,
) : ApproverKeys {

    override fun presence(): KeyPresence = try {
        if (store().containsAlias(alias)) KeyPresence.PRESENT else KeyPresence.ABSENT
    } catch (e: Exception) {
        KeyPresence.UNKNOWN
    }

    override fun create(): ByteArray {
        // A key that needs an unlock cannot be made on a phone with nothing to
        // unlock, and the keystore's own refusal names neither the cause nor the fix.
        if (!deviceSecure()) throw NoScreenLock()
        delete()
        val pair = try {
            generate(strongBox = Build.VERSION.SDK_INT >= 28)
        } catch (e: Exception) {
            if (Build.VERSION.SDK_INT >= 28 && (e is StrongBoxUnavailableException || e is ProviderException)) {
                generate(strongBox = false)
            } else {
                throw e
            }
        }
        return pair.public.encoded
    }

    private fun generate(strongBox: Boolean): java.security.KeyPair {
        val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setUserAuthenticationRequired(true)
            .apply {
                if (Build.VERSION.SDK_INT >= 30) {
                    // Zero seconds: the keystore authorises one operation per unlock,
                    // so every approval needs its own.
                    setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL)
                } else {
                    @Suppress("DEPRECATION")
                    setUserAuthenticationValidityDurationSeconds(15)
                }
                if (strongBox && Build.VERSION.SDK_INT >= 28) setIsStrongBoxBacked(true)
            }
            .build()
        val gen = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, PROVIDER)
        gen.initialize(spec)
        return gen.generateKeyPair()
    }

    override fun publicKey(): ByteArray? = runCatching { store().getCertificate(alias)?.publicKey?.encoded }.getOrNull()

    override fun signature(): Signature {
        val key = store().getKey(alias, null) as? PrivateKey ?: throw KeyGone()
        return Signature.getInstance("SHA256withECDSA").apply { initSign(key) }
    }

    override fun delete() {
        runCatching { store().deleteEntry(alias) }
    }

    private fun store(): KeyStore = KeyStore.getInstance(PROVIDER).apply { load(null) }

    private companion object {
        const val PROVIDER = "AndroidKeyStore"
    }
}
