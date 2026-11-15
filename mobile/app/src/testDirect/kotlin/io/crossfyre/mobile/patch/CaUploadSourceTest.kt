package io.crossfyre.mobile.patch

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * The certificate a patch uploads becomes a trust anchor in the patched app.
 * Before Android 11, an app holding storage permission can write to any app's
 * folder under Android/data, so a copy of the certificate staged there could be
 * replaced while the splits are being zipped, and the patched app would trust
 * whatever certificate was put in its place. The patch therefore carries the
 * certificate as text from start to upload and never stages it in a file.
 */
class CaUploadSourceTest {

    private fun src(path: String) = File(path).readText()

    @Test
    fun the_patch_path_does_not_stage_the_certificate_in_shared_storage() {
        val model = src("src/main/kotlin/io/crossfyre/mobile/AppModel.kt")
        val startPatch = model.substringAfter("fun startPatch(").substringBefore("\n    fun ")
        assertFalse("startPatch writes no file", Regex("""\.write(Text|Bytes)\(""").containsMatchIn(startPatch))
        assertFalse("startPatch does not stage a certificate file", startPatch.contains("ensureCaFile"))
        assertFalse(
            "nothing writes into external app storage",
            Regex("""File\(\s*ctx\.getExternalFilesDir[^\n]*\n[^\n]*\.write""").containsMatchIn(model) ||
                model.contains("ensureCaFile"),
        )
    }

    @Test
    fun the_certificate_travels_as_text_to_the_upload() {
        val feature = src("src/main/kotlin/io/crossfyre/mobile/patch/PatchFeature.kt")
        assertTrue(
            "PatchFeature.start takes the certificate as text",
            Regex("""fun start\([^)]*caPem: String""").containsMatchIn(feature),
        )
        val patcher = src("src/direct/kotlin/io/crossfyre/mobile/patch/Patcher.kt")
        assertTrue(
            "buildPatched takes the certificate as text",
            Regex("""fun buildPatched\([^)]*caPem: String""").containsMatchIn(patcher),
        )
        assertFalse("nothing reads the certificate back from a file", patcher.contains("caPem.inputStream()"))
    }
}
