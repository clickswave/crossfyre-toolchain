package io.crossfyre.mobile.approve

import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec

/** [ApproverKeys] without a keystore, so a flow runs on the JVM. The keystore itself is tested on a device. */
internal class SoftwareKeys : ApproverKeys {
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
