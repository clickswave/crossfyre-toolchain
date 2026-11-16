package io.crossfyre.mobile.patch

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * A patched build that accepts any certificate is named as one: on the result,
 * in the lists, and when capture stops with one still installed.
 */
class AnyCertificateCopyTest {

    private fun done(acceptsAnyCert: Boolean) =
        PatchJob("com.northwind.staff", "Northwind Staff", 22, PatchStep.DONE, acceptsAnyCert = acceptsAnyCert)

    @Test
    fun a_build_that_accepts_any_certificate_does_not_claim_to_trust_this_phones() {
        val (title, first, _) = done(acceptsAnyCert = true).result()!!
        assertEquals("Northwind Staff is patched", title)
        assertFalse(first, first.contains("trusts this phone's certificate"))
        assertTrue(first, first.contains("accepts any certificate"))
        assertTrue(first, first.contains("only for testing"))
        assertTrue(first, first.contains("remove it when you are done"))
    }

    @Test
    fun a_build_the_server_said_nothing_about_keeps_the_usual_line() {
        assertFalse("unset reads as false", PatchJob("p", "P", 1, PatchStep.DONE).acceptsAnyCert)
        val (_, first, _) = done(acceptsAnyCert = false).result()!!
        assertEquals("Start capture and use the app. It trusts this phone's certificate, so nothing needs installing in Android.", first)
    }

    @Test
    fun the_flag_survives_the_steps_to_the_install() {
        val built = PatchJob("p", "P", 1, PatchStep.DOWNLOAD, built = true, acceptsAnyCert = true)
        assertTrue(built.onwards(canInstall = true, kept = true).acceptsAnyCert)
        assertTrue(built.onwards(canInstall = false, kept = true).acceptsAnyCert)
    }

    @Test
    fun the_lists_name_it_too() {
        assertEquals("Patched: accepts any certificate", patchedLabel(true))
        assertEquals("Patched with this certificate", patchedLabel(false))
    }

    @Test
    fun stopping_capture_offers_to_put_the_original_back() {
        assertNull("nothing to offer", restoreOffer(emptyList()))

        val (title, first, second) = restoreOffer(listOf("Northwind Staff"))!!
        assertEquals("Put the original back?", title)
        assertTrue(first, first.startsWith("Northwind Staff is a patched build that accepts any certificate"))
        assertTrue(second, second.contains("Uninstall it"))
        assertTrue(second, second.contains("Play Store"))
        assertFalse(second, second.contains("more patched"))

        val (_, firstOfTwo, more) = restoreOffer(listOf("Northwind Staff", "Apollo"))!!
        assertTrue(firstOfTwo.startsWith("Northwind Staff "))
        assertTrue(more, more.endsWith("One more patched app is like this."))
        assertTrue(restoreOffer(listOf("a", "b", "c"))!!.third.endsWith("2 more patched apps are like this."))
    }

    @Test
    fun none_of_it_uses_an_em_dash() {
        val lines = listOfNotNull(done(true).result(), restoreOffer(listOf("A", "B")))
            .flatMap { it.toList() } + patchedLabel(true)
        for (l in lines) assertFalse(l, l.contains('\u2014'))
    }
}
