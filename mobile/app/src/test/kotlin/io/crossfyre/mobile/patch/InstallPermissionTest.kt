package io.crossfyre.mobile.patch

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * A patch swaps the original for the patched build by removing the original
 * first. If Android then will not let Crossfyre Mobile install apps, it refuses
 * the install and the phone is left with neither, so a patch asks for that
 * permission before it starts and again before it removes anything.
 */
class InstallPermissionTest {

    private fun job(step: PatchStep, built: Boolean = false) =
        PatchJob("com.northwind.staff", "Northwind Staff", 22, step, built = built)

    @Test
    fun without_the_permission_a_patch_waits_before_reading_anything() {
        val j = job(PatchStep.READ).onwards(canInstall = false)
        assertEquals(PatchStep.ALLOW_INSTALLS, j.step)
        assertFalse(j.built)
        assertEquals("no stage has started", 0, j.stage)
        assertTrue("its sheet stays up", j.running)
        assertTrue(j.cancellable)
        assertNull(j.result())
    }

    @Test
    fun with_the_permission_a_patch_starts_reading() {
        assertEquals(PatchStep.READ, job(PatchStep.READ).onwards(canInstall = true).step)
    }

    @Test
    fun a_ready_build_keeps_the_original_when_the_permission_was_withdrawn_meanwhile() {
        // Allowed at the start, turned off while the server worked.
        val j = job(PatchStep.DOWNLOAD, built = true).onwards(canInstall = false, kept = true)
        assertEquals(PatchStep.ALLOW_INSTALLS, j.step)
        assertTrue("the patched build is kept", j.built)
        assertTrue("it can still be called off with the original in place", j.cancellable)
        assertEquals(PATCH_STAGES.size - 1, j.stage)
    }

    @Test
    fun a_ready_build_with_the_permission_goes_on_to_remove_the_original() {
        assertEquals(PatchStep.UNINSTALL, job(PatchStep.DOWNLOAD, built = true).onwards(canInstall = true, kept = true).step)
    }

    @Test
    fun coming_back_with_the_permission_carries_on_from_where_the_patch_waited() {
        val before = job(PatchStep.READ).onwards(canInstall = false)
        assertEquals(PatchStep.ALLOW_INSTALLS, before.onwards(canInstall = false).step)
        assertEquals(PatchStep.READ, before.onwards(canInstall = true).step)

        val ready = job(PatchStep.DOWNLOAD, built = true).onwards(canInstall = false, kept = true)
        assertEquals(PatchStep.ALLOW_INSTALLS, ready.onwards(canInstall = false, kept = true).step)
        assertEquals(PatchStep.UNINSTALL, ready.onwards(canInstall = true, kept = true).step)
    }

    @Test
    fun nothing_goes_on_to_remove_the_original_without_the_permission() {
        for (step in PatchStep.entries) for (built in listOf(false, true)) {
            assertNotEquals("$step, built=$built", PatchStep.UNINSTALL, job(step, built).onwards(canInstall = false, kept = true).step)
        }
    }

    @Test
    fun the_sheet_says_how_to_allow_it_and_that_the_app_is_untouched() {
        val (title, first, second) = job(PatchStep.ALLOW_INSTALLS).askToAllow()!!
        assertTrue(title, title.contains("Allow"))
        assertTrue(first, first.contains("Allow from this source"))
        assertTrue(second, second.contains("Nothing has been read or uploaded"))

        val (_, readyFirst, readySecond) = job(PatchStep.ALLOW_INSTALLS, built = true).askToAllow()!!
        assertTrue(readyFirst, readyFirst.contains("Allow from this source"))
        assertTrue(readySecond, readySecond.contains("Northwind Staff is still installed"))

        assertNull("only a waiting patch asks", job(PatchStep.SERVER).askToAllow())
    }
}
