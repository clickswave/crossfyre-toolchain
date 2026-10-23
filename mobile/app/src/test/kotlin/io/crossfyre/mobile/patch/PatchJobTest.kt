package io.crossfyre.mobile.patch

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** The patch progress sheet and its result, as a function of where the patch is. */
class PatchJobTest {

    private fun job(step: PatchStep, pct: Float = 0f, message: String? = null, fromServer: Boolean = false) =
        PatchJob("com.northwind.staff", "Northwind Staff", 22, step, pct, message, fromServer)

    @Test
    fun the_bar_moves_across_the_whole_patch_and_waits_while_the_server_works() {
        assertEquals(3f, job(PatchStep.READ).meter)
        assertEquals(5f + 0.4f * 63f, job(PatchStep.UPLOAD, 63f).meter!!, 0.001f)
        assertNull("the server says when it is done, not how far along", job(PatchStep.SERVER).meter)
        assertEquals(55f + 0.44f * 50f, job(PatchStep.DOWNLOAD, 50f).meter!!, 0.001f)
        assertEquals(99.5f, job(PatchStep.INSTALL).meter)
    }

    @Test
    fun each_step_lights_its_stage() {
        assertEquals(0, job(PatchStep.READ).stage)
        assertEquals(1, job(PatchStep.UPLOAD).stage)
        assertEquals(2, job(PatchStep.SERVER).stage)
        assertEquals(3, job(PatchStep.DOWNLOAD).stage)
        assertEquals(4, job(PatchStep.UNINSTALL).stage)
        assertEquals(4, job(PatchStep.INSTALLING).stage)
        assertEquals(PATCH_STAGES.size - 1, job(PatchStep.INSTALL).stage)
    }

    @Test
    fun cancel_is_offered_only_while_there_is_something_of_ours_to_stop() {
        assertTrue(job(PatchStep.SERVER).cancellable)
        assertTrue(job(PatchStep.DOWNLOAD).cancellable)
        assertFalse(job(PatchStep.UNINSTALL).cancellable)
        assertFalse(job(PatchStep.INSTALL).cancellable)
    }

    @Test
    fun a_running_patch_has_no_result_and_a_finished_one_does() {
        for (s in listOf(PatchStep.READ, PatchStep.SERVER, PatchStep.INSTALL, PatchStep.INSTALLING)) {
            assertTrue(job(s).running)
            assertNull(job(s).result())
        }
        for (s in listOf(PatchStep.DONE, PatchStep.FAILED, PatchStep.REJECTED, PatchStep.UNINSTALL_CANCELLED, PatchStep.INSTALL_CANCELLED)) {
            assertFalse(job(s).running)
            assertTrue(s.name, job(s).result() != null)
        }
    }

    @Test
    fun the_servers_own_sentence_leads_a_failure_and_is_marked_as_the_servers() {
        val (title, first, second) = job(PatchStep.FAILED, message = "This app checks its own signature.", fromServer = true).result()!!
        assertEquals("Patch failed", title)
        assertEquals("This app checks its own signature.", first)
        assertTrue(second, second.startsWith("That is what the server said."))
        // Our own failures are not attributed to the server.
        val (_, _, ours) = job(PatchStep.FAILED, message = "The patch took too long, so it was abandoned.").result()!!
        assertFalse(ours, ours.contains("server said"))
    }

    @Test
    fun a_refusal_after_the_original_was_removed_says_so() {
        val (title, first, _) = job(PatchStep.REJECTED).result()!!
        assertEquals("Android refused the patched build", title)
        assertTrue(first, first.contains("the original had already been removed"))
        val (_, _, untouched) = job(PatchStep.UNINSTALL_CANCELLED).result()!!
        assertEquals("Your app has not been touched.", untouched)
    }
}
