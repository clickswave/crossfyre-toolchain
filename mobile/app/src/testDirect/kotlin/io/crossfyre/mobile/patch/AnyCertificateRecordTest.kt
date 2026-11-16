package io.crossfyre.mobile.patch

import org.json.JSONObject
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** What the server says about a patched build, and how long the phone keeps saying it. */
class AnyCertificateRecordTest {

    @Test
    fun the_status_says_so_only_with_a_true_flag() {
        val done = """{"status":"done","download_url":"https://r2.example/x","sha256":"ab"}"""
        // Servers from before the field existed say nothing, which reads as false.
        assertFalse(Patcher.acceptsAnyCert(JSONObject(done)))
        assertTrue(Patcher.acceptsAnyCert(JSONObject(done).put("flutter_tls_bypassed", true)))
        assertFalse(Patcher.acceptsAnyCert(JSONObject(done).put("flutter_tls_bypassed", false)))
        assertFalse(Patcher.acceptsAnyCert(JSONObject(done).put("flutter_tls_bypassed", JSONObject.NULL)))
    }

    @Test
    fun the_offer_lasts_while_that_build_is_installed() {
        assertTrue(PatchPrefs.stillAnyCert("signer-ours", "signer-ours"))
        // The original was reinstalled over it.
        assertFalse(PatchPrefs.stillAnyCert("signer-ours", "signer-vendor"))
        // Uninstalled.
        assertFalse(PatchPrefs.stillAnyCert("signer-ours", null))
        // Never noted.
        assertFalse(PatchPrefs.stillAnyCert(null, "signer-ours"))
        // Noted without a signer: it counts while the app is installed.
        assertTrue(PatchPrefs.stillAnyCert("", "signer-anyone"))
        assertFalse(PatchPrefs.stillAnyCert("", null))
    }
}
