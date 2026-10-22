package io.crossfyre.mobile.patch

import android.content.ContextWrapper
import io.crossfyre.mobile.BuildConfig
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The Play build has no patch feature: not hidden, absent. These run only
 * against the Play variants, whose classpath is the one Play would ship.
 */
class PlayBuildTest {

    @Test
    fun the_play_build_says_it_cannot_patch() {
        assertFalse(BuildConfig.PATCHING)
        val f = Distribution.patchFeature(ContextWrapper(null))
        assertFalse(f.available)
        assertNull(f.job.value)
        assertEquals(0, f.patchedCount())
        assertTrue(f.stale("anything").isEmpty())
        assertEquals(PatchState.NONE, f.state("com.example", "ca"))
    }

    @Test
    fun the_code_that_rewrites_apps_is_not_on_the_classpath() {
        for (name in listOf("Patcher", "AppInspector", "Axml", "PatchPrefs", "DirectPatchFeature")) {
            val found = runCatching { Class.forName("io.crossfyre.mobile.patch.$name") }.isSuccess
            assertFalse("$name is compiled into the Play build", found)
        }
    }
}
