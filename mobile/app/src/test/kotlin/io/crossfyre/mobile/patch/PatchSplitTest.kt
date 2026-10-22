package io.crossfyre.mobile.patch

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * The shared code never names the classes that patch, and the shared manifest
 * never asks for what only patching needs. Both are what keep the Play build
 * free of the feature: src/direct is simply not part of it, so anything that
 * leaked into src/main would either fail that build or ship in it.
 */
class PatchSplitTest {

    // Unit tests run with the module directory as the working directory.
    private val src = File("src")

    @Test
    fun shared_code_never_names_the_patching_classes() {
        val main = File(src, "main/kotlin")
        assertTrue(main.absolutePath, main.isDirectory)
        val offenders = main.walk().filter { it.extension == "kt" }.flatMap { f ->
            f.readLines().withIndex()
                .filter { (_, l) -> Regex("\\b(Patcher|AppInspector|Axml|PatchPrefs|DirectPatchFeature)\\b").containsMatchIn(l) }
                .map { (i, l) -> "${f.relativeTo(src)}:${i + 1}: ${l.trim()}" }
        }.toList()
        assertTrue(offenders.joinToString("\n"), offenders.isEmpty())
    }

    @Test
    fun only_the_direct_manifest_asks_to_install_or_remove_apps() {
        val main = File(src, "main/AndroidManifest.xml").readText()
        for (p in listOf("REQUEST_INSTALL_PACKAGES", "REQUEST_DELETE_PACKAGES", "QUERY_ALL_PACKAGES")) {
            assertFalse("$p is in the shared manifest", main.contains("android.permission.$p"))
        }
        val direct = File(src, "direct/AndroidManifest.xml").readText()
        assertTrue(direct.contains("REQUEST_INSTALL_PACKAGES"))
        assertFalse(File(src, "play/AndroidManifest.xml").exists())
    }
}
