package io.crossfyre.mobile.apps

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** What reading an app's APK entries tells us, before anyone spends ten minutes on it. */
class AppFactsTest {

    @Test
    fun a_flutter_app_is_known_by_its_engine() {
        val f = Apps.factsFrom("com.northwind.field", "Northwind Field", 48L * 1024 * 1024, true,
            listOf("AndroidManifest.xml", "res/layout/a.xml", "lib/arm64-v8a/libflutter.so", "lib/arm64-v8a/libapp.so"))
        assertEquals("Flutter", f.framework)
        assertTrue(f.flutter)
        assertEquals(48, f.sizeMb)
        assertFalse(f.shielded)
        assertEquals("Flutter (own TLS), Java/OkHttp", f.stacks)
        assertEquals(listOf("libapp.so", "libflutter.so"), f.nativeLibs)
    }

    @Test
    fun a_shield_is_inferred_from_machine_named_libraries_or_missing_resources() {
        val named = Apps.factsFrom("p", "Pay", 0, true,
            listOf("res/a.xml", "lib/arm64-v8a/liba343.so", "lib/arm64-v8a/libbd33e0.so", "lib/arm64-v8a/libc7cf34.so", "lib/arm64-v8a/libhermes.so"))
        assertEquals("React Native", named.framework)
        assertEquals(3, named.shieldLibs.size)
        assertTrue(named.shielded)

        val packed = Apps.factsFrom("p", "Pay", 0, true, listOf("classes.dex", "lib/arm64-v8a/libsomething.so"))
        assertTrue(packed.packed)
        assertTrue(packed.shielded)
    }

    @Test
    fun ordinary_library_names_are_not_called_machine_named() {
        for (name in listOf("libflutter.so", "libsqlite3.so", "libcronet.so", "libc++_shared.so", "libz.so")) {
            assertFalse(name, Apps.looksMachineNamed(name))
        }
        assertTrue(Apps.looksMachineNamed("liba343.so"))
    }

    @Test
    fun cronet_is_named_as_a_second_stack() {
        val f = Apps.factsFrom("com.google.android.apps.maps", "Maps", 0, true, listOf("res/x", "lib/arm64-v8a/libcronet.129.so"))
        assertTrue(f.cronet)
        assertEquals("Cronet, Java/OkHttp", f.stacks)
    }

    @Test
    fun without_patching_the_advice_never_mentions_a_patch() {
        val flutter = Apps.factsFrom("a", "A", 0, true, listOf("res/x", "lib/x86_64/libflutter.so"))
        val plain = Apps.factsFrom("b", "B", 0, true, listOf("res/x"))
        for (f in listOf(flutter, plain)) {
            assertFalse(Apps.outlookWithoutPatching(f).contains("patch", ignoreCase = true))
        }
        assertEquals("Flutter: has its own TLS stack, so only its analytics will show", Apps.noteWithoutPatching(flutter, "a"))
        assertEquals("Ignores user certificates, so its HTTPS stays unread", Apps.noteWithoutPatching(null, "com.android.chrome"))
        assertNull(Apps.noteWithoutPatching(plain, "b"))
    }
}
