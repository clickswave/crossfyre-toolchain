package io.crossfyre.mobile.patch

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * The patched build waits in the app's cache while a patch waits to be allowed
 * to install apps, and Android may clear a cache when storage runs low. Removing
 * the original then would leave the phone with neither app, so the swap goes
 * ahead only while every staged file is still there.
 */
class StagedBuildTest {

    @get:Rule
    val tmp = TemporaryFolder()

    private fun job(step: PatchStep, built: Boolean = true) =
        PatchJob("com.northwind.staff", "Northwind Staff", 22, step, built = built)

    private fun apk(name: String, bytes: Int = 64) = tmp.newFile(name).apply { writeBytes(ByteArray(bytes)) }

    @Test
    fun a_staged_build_counts_only_while_every_file_is_there_and_not_empty() {
        val base = apk("base.apk")
        val split = apk("split_config.arm64_v8a.apk")
        assertTrue(buildKept(listOf(base, split)))

        assertFalse("nothing staged", buildKept(null))
        assertFalse("an empty list", buildKept(emptyList()))
        assertFalse("an empty file", buildKept(listOf(base, apk("empty.apk", bytes = 0))))
        assertFalse("a directory is not a build", buildKept(listOf(base, tmp.newFolder("dir"))))
        split.delete()
        assertFalse("a split was cleared", buildKept(listOf(base, split)))
    }

    @Test
    fun a_cleared_build_ends_the_patch_with_the_original_installed() {
        val j = job(PatchStep.ALLOW_INSTALLS).onwards(canInstall = true, kept = false)
        assertEquals(PatchStep.FAILED, j.step)
        assertFalse("the sheet shows the result", j.running)
        val (_, why, after) = j.result()!!
        assertTrue(why, why.contains("cleared"))
        assertTrue(after, after.contains("Northwind Staff is as it was"))
    }

    @Test
    fun a_cleared_build_does_not_wait_for_the_permission_either() {
        assertEquals(PatchStep.FAILED, job(PatchStep.DOWNLOAD).onwards(canInstall = false, kept = false).step)
    }

    @Test
    fun nothing_removes_the_original_unless_the_build_is_kept() {
        for (step in PatchStep.entries) for (can in listOf(false, true)) {
            assertNotEquals("$step, canInstall=$can", PatchStep.UNINSTALL, job(step).onwards(canInstall = can, kept = false).step)
        }
    }

    @Test
    fun not_saying_whether_the_build_is_kept_never_removes_the_original() {
        assertNotEquals(PatchStep.UNINSTALL, job(PatchStep.DOWNLOAD).onwards(canInstall = true).step)
    }

    @Test
    fun before_the_build_the_staged_files_do_not_matter() {
        assertEquals(PatchStep.READ, job(PatchStep.READ, built = false).onwards(canInstall = true, kept = false).step)
    }
}
