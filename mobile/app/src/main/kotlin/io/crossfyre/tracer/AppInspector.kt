package io.crossfyre.tracer

import android.content.Context
import android.content.pm.PackageManager
import java.util.zip.ZipFile

/**
 * What we can tell about an app before touching it.
 *
 * Two jobs, and they turn out to be the same job.
 *
 * The obvious one: an operator picking a target deserves to know what will
 * happen before spending ten minutes on a patch. "Flutter, packaged with a
 * shield, expect it to install and then refuse to start" is worth more than
 * discovering it afterwards.
 *
 * The less obvious one: the scope list was computing this per row, per frame,
 * on the main thread. Reading a certificate off disk, hashing it, querying
 * PackageManager for a signature and opening an APK's zip - for every visible
 * row, every time the list recomposed. That is why dragging the list felt like
 * it ignored you: the gesture loop was starved by disk I/O. Everything here is
 * computed once, off the main thread, and cached.
 */
data class AppInsight(
    val pkg: String,
    val label: String,
    val sizeMb: Int,
    /** Flutter / React Native / Unity / Native, by the engine it ships. */
    val framework: String,
    val flutter: Boolean,
    /** Ships Chromium's network stack, which verifies certificates its own way. */
    val cronet: Boolean,
    /** No `res/` entries: resources are relocated and unpacked at runtime. */
    val packed: Boolean,
    /** Libraries whose names look machine-generated, the mark of a shield. */
    val shieldLibs: List<String>,
    val nativeLibs: List<String>,
) {
    /** Shielding is inferred, never asserted: these are indicators, not proof. */
    val shielded: Boolean get() = packed || shieldLibs.size >= 3

    /** The one line worth reading before spending ten minutes on a patch. */
    fun outlook(patched: Boolean): String = when {
        shielded && flutter ->
            "Patching can reach its Flutter traffic, but this app checks its own integrity. " +
                "Expect it to install and then refuse to start."
        shielded ->
            "This app checks its own integrity. Expect it to install and then refuse to start."
        flutter && cronet ->
            "Flutter traffic will decrypt once patched. Anything it sends over Cronet will not."
        flutter && patched -> "Patched. Its own API and its Java traffic should both decrypt."
        flutter -> "Patch it: Flutter has its own TLS stack, so unpatched it shows only analytics."
        cronet ->
            "Ships Cronet, which verifies certificates its own way. Some traffic may not decrypt."
        patched -> "Patched. Its traffic should decrypt."
        else ->
            "Patch it if its traffic does not decrypt: unpatched apps only work when they trust " +
                "user certificates."
    }
}

object AppInspector {

    /** Read an app's APKs and report what it is. Does file I/O; never call from the UI thread. */
    fun inspect(ctx: Context, pkg: String, label: String): AppInsight {
        val paths = runCatching {
            val ai = ctx.packageManager.getApplicationInfo(pkg, 0)
            buildList {
                add(ai.sourceDir)
                ai.splitSourceDirs?.let { addAll(it) }
            }
        }.getOrDefault(emptyList())

        var bytes = 0L
        val libs = linkedSetOf<String>()
        var sawRes = false
        for (p in paths) {
            val f = java.io.File(p)
            if (f.exists()) bytes += f.length()
            runCatching {
                ZipFile(p).use { zip ->
                    val e = zip.entries()
                    while (e.hasMoreElements()) {
                        val name = e.nextElement().name
                        if (name.startsWith("res/")) sawRes = true
                        val i = name.indexOf("/lib")
                        if (name.startsWith("lib/") && name.endsWith(".so")) {
                            libs.add(name.substringAfterLast('/'))
                        } else if (i >= 0 && name.endsWith(".so")) {
                            libs.add(name.substringAfterLast('/'))
                        }
                    }
                }
            }
        }

        val flutter = libs.any { it == "libflutter.so" }
        val cronet = libs.any { it.startsWith("libcronet") }
        val framework = when {
            flutter -> "Flutter"
            libs.any { it.contains("reactnativejni") || it.startsWith("libhermes") } -> "React Native"
            libs.any { it.startsWith("libunity") || it.startsWith("libil2cpp") } -> "Unity"
            libs.any { it.startsWith("libmonodroid") } -> "Xamarin"
            else -> "Native"
        }

        return AppInsight(
            pkg = pkg,
            label = label,
            sizeMb = (bytes / 1024 / 1024).toInt(),
            framework = framework,
            flutter = flutter,
            cronet = cronet,
            // An APK with native code but no res/ at all has had its resources
            // moved somewhere only its own runtime can find. That is packing,
            // and it is why apktool cannot rebuild such an app.
            packed = paths.isNotEmpty() && !sawRes && libs.isNotEmpty(),
            shieldLibs = libs.filter { looksMachineNamed(it) },
            nativeLibs = libs.toList().sorted(),
        )
    }

    /**
     * Whether a library name looks generated rather than written by a person.
     *
     * Shielding products emit per-build names like `liba343.so`, `libbd33e0.so`,
     * `libc7cf34.so`: short, no vowel structure, mostly hex. Real libraries are
     * named after what they do. This is a heuristic and is reported as an
     * indicator, never as a verdict.
     */
    private fun looksMachineNamed(name: String): Boolean {
        val stem = name.removePrefix("lib").removeSuffix(".so")
        if (stem.length !in 3..10) return false
        if (!stem.all { it.isLetterOrDigit() }) return false
        val hexish = stem.count { it.isDigit() || it.lowercaseChar() in "abcdef" }
        // Mostly hex characters and at least one digit: "a343", "bd33e0".
        return stem.any { it.isDigit() } && hexish >= stem.length - 1
    }

    /** Every third-party app, cheapest possible query (no APK reads). */
    fun userApps(ctx: Context): List<Pair<String, String>> =
        ctx.packageManager.getInstalledApplications(0)
            .filter { it.flags and android.content.pm.ApplicationInfo.FLAG_SYSTEM == 0 && it.packageName != ctx.packageName }
            .map { it.packageName to ctx.packageManager.getApplicationLabel(it).toString() }
            .sortedBy { it.second.lowercase() }

    /** SHA-256 of the installed build's signing certificate, or null. */
    fun signerOf(ctx: Context, pkg: String): String? = runCatching {
        val info = ctx.packageManager.getPackageInfo(pkg, PackageManager.GET_SIGNING_CERTIFICATES)
        val sig = info.signingInfo?.apkContentsSigners?.firstOrNull() ?: return null
        java.security.MessageDigest.getInstance("SHA-256").digest(sig.toByteArray())
            .joinToString("") { "%02x".format(it) }
    }.getOrNull()
}
