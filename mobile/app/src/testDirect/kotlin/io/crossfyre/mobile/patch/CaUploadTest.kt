package io.crossfyre.mobile.patch

import io.crossfyre.mobile.pemFingerprint
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.security.MessageDigest
import java.util.zip.ZipFile

/** What a patch uploads as its certificate is the text it was started with. */
class CaUploadTest {

    @get:Rule
    val tmp = TemporaryFolder()

    private val der = ByteArray(300) { (it * 7).toByte() }
    private val pem = "-----BEGIN CERTIFICATE-----\n" +
        java.util.Base64.getMimeEncoder(64, "\n".toByteArray()).encodeToString(der) +
        "\n-----END CERTIFICATE-----\n"

    @Test
    fun the_upload_carries_the_certificate_it_was_handed() {
        val base = tmp.newFile("base.apk").apply { writeBytes(ByteArray(4096) { 1 }) }
        val split = tmp.newFile("config.apk").apply { writeBytes(ByteArray(512) { 2 }) }
        val upload = tmp.newFile("in.zip")

        Patcher.writeUpload(upload, listOf("base.apk" to base, "split_1.apk" to split), pem)

        ZipFile(upload).use { z ->
            assertEquals(listOf("base.apk", "split_1.apk", "ca.pem"), z.entries().toList().map { it.name })
            assertEquals(pem, z.getInputStream(z.getEntry("ca.pem")).readBytes().toString(Charsets.UTF_8))
            assertArrayEquals(base.readBytes(), z.getInputStream(z.getEntry("base.apk")).readBytes())
        }
    }

    @Test
    fun a_patch_is_recorded_against_the_certificate_it_uploads() {
        val want = MessageDigest.getInstance("SHA-256").digest(der).joinToString("") { "%02x".format(it) }
        assertEquals(want, pemFingerprint(pem))
        assertEquals("line endings do not change it", want, pemFingerprint(pem.replace("\n", "\r\n")))
        assertNull("not a certificate", pemFingerprint("ERROR: no key"))
        assertNull("empty body", pemFingerprint("-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n"))
    }
}
