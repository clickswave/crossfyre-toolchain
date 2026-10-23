package io.crossfyre.mobile.patch

import io.crossfyre.mobile.BuildConfig
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** The direct build carries the patch feature, and judges a patch by certificate and by build. */
class DirectBuildTest {

    @Test
    fun the_direct_build_has_the_patch_code() {
        assertTrue(BuildConfig.PATCHING)
        Class.forName("io.crossfyre.mobile.patch.Patcher")
        Class.forName("io.crossfyre.mobile.patch.DirectPatchFeature")
    }

    @Test
    fun a_patch_is_current_only_with_this_certificate_and_our_build() {
        val rec = PatchPrefs.join("ca-1", "signer-ours")
        assertEquals(PatchState.CURRENT, PatchPrefs.judge(rec, "ca-1", "signer-ours"))
        // The certificate was reset since.
        assertEquals(PatchState.STALE, PatchPrefs.judge(rec, "ca-2", "signer-ours"))
        // The original was reinstalled over our build.
        assertEquals(PatchState.STALE, PatchPrefs.judge(rec, "ca-1", "signer-vendor"))
        // A record from before signers were kept cannot be verified.
        assertEquals(PatchState.STALE, PatchPrefs.judge("ca-1", "ca-1", "signer-ours"))
        // No certificate on the phone at all.
        assertEquals(PatchState.STALE, PatchPrefs.judge(rec, null, "signer-ours"))
        assertEquals(PatchState.NONE, PatchPrefs.judge(null, "ca-1", "signer-ours"))
    }

    @Test
    fun a_record_splits_back_into_what_was_joined() {
        assertEquals("ca" to "signer", PatchPrefs.split(PatchPrefs.join("ca", "signer")))
        assertEquals("ca" to null, PatchPrefs.split(PatchPrefs.join("ca", null)))
    }
}
