package io.crossfyre.mobile.apps

import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import java.util.zip.ZipFile

/** An app the scope and patch lists can offer. */
data class InstalledApp(val pkg: String, val label: String)

/**
 * What we can tell about an app before touching it.
 *
 * Two jobs, and they turn out to be the same job.
 *
 * The obvious one: someone picking a target deserves to know what will happen
 * before spending ten minutes on a patch, or before wondering why an app shows
 * only its analytics. "Flutter, packaged with a shield" is worth more than
 * finding out afterwards.
 *
 * The less obvious one: the scope list used to compute this per row, per frame,
 * on the main thread, which is why dragging it felt like it ignored you.
 * Everything here is computed once, off the main thread, and cached by the
 * caller.
 *
 * Both builds read this. Only the direct build can act on it by patching, but
 * knowing an app ships its own TLS stack matters just as much on the Play build,
 * where it explains why that app's own requests never decrypt.
 */
data class AppFacts(
    val pkg: String,
    val label: String,
    val sizeMb: Int,
    /** Flutter / React Native / Unity / Xamarin / Native, by the engine it ships. */
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

    val stacks: String
        get() = buildList {
            if (flutter) add("Flutter (own TLS)")
            if (cronet) add("Cronet")
            add("Java/OkHttp")
        }.joinToString(", ")
}

object Apps {

    /**
     * Every app a person would think of as an app: the ones with a launcher
     * icon, other than the phone's own system apps and this one.
     *
     * Asked through a launcher intent, which the manifest's `<queries>` makes
     * visible, rather than through QUERY_ALL_PACKAGES. An app with no launcher
     * icon has no screen to test, so it has no place in the scope list anyway.
     * A system app that has been updated (Chrome on most phones) is kept, since
     * that is one people do test.
     */
    fun installed(ctx: Context): List<InstalledApp> {
        val pm = ctx.packageManager
        val launcher = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
        return pm.queryIntentActivities(launcher, 0)
            .mapNotNull { it.activityInfo?.applicationInfo }
            .distinctBy { it.packageName }
            .filter { it.packageName != ctx.packageName && userFacing(it) }
            .map { InstalledApp(it.packageName, pm.getApplicationLabel(it).toString()) }
            .sortedBy { it.label.lowercase() }
    }

    private fun userFacing(ai: ApplicationInfo): Boolean =
        ai.flags and ApplicationInfo.FLAG_SYSTEM == 0 ||
            ai.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP != 0 ||
            ai.packageName == "com.android.chrome"

    fun label(ctx: Context, pkg: String): String = runCatching {
        val pm = ctx.packageManager
        pm.getApplicationLabel(pm.getApplicationInfo(pkg, 0)).toString()
    }.getOrDefault(pkg)

    fun isInstalled(ctx: Context, pkg: String): Boolean =
        runCatching { ctx.packageManager.getApplicationInfo(pkg, 0); true }.getOrDefault(false)

    /** Read an app's APKs and report what it is. Does file I/O; never call from the UI thread. */
    fun read(ctx: Context, pkg: String, label: String): AppFacts {
        val paths = runCatching {
            val ai = ctx.packageManager.getApplicationInfo(pkg, 0)
            buildList {
                add(ai.sourceDir)
                ai.splitSourceDirs?.let { addAll(it) }
            }
        }.getOrDefault(emptyList())

        var bytes = 0L
        val names = mutableListOf<String>()
        for (p in paths) {
            val f = java.io.File(p)
            if (f.exists()) bytes += f.length()
            runCatching {
                ZipFile(p).use { zip ->
                    val e = zip.entries()
                    while (e.hasMoreElements()) names.add(e.nextElement().name)
                }
            }
        }
        return factsFrom(pkg, label, bytes, paths.isNotEmpty(), names)
    }

    /** The reading of [read], from the entry names alone, so it can be tested without a phone. */
    fun factsFrom(pkg: String, label: String, bytes: Long, hasApks: Boolean, entries: List<String>): AppFacts {
        val libs = linkedSetOf<String>()
        var sawRes = false
        for (name in entries) {
            if (name.startsWith("res/")) sawRes = true
            if (name.endsWith(".so") && (name.startsWith("lib/") || name.contains("/lib"))) {
                libs.add(name.substringAfterLast('/'))
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
        return AppFacts(
            pkg = pkg,
            label = label,
            sizeMb = (bytes / 1024 / 1024).toInt(),
            framework = framework,
            flutter = flutter,
            cronet = cronet,
            // An APK with native code but no res/ at all has had its resources
            // moved somewhere only its own runtime can find. That is packing,
            // and it is why such an app cannot be rebuilt.
            packed = hasApks && !sawRes && libs.isNotEmpty(),
            shieldLibs = libs.filter { looksMachineNamed(it) },
            nativeLibs = libs.toList().sorted(),
        )
    }

    /**
     * Whether a library name looks generated rather than written by a person.
     *
     * Shielding products emit per-build names like `liba343.so`, `libbd33e0.so`,
     * `libc7cf34.so`: short and mostly hex. Real libraries are named after what
     * they do. A heuristic, reported as an indicator and never as a verdict.
     */
    fun looksMachineNamed(name: String): Boolean {
        val stem = name.removePrefix("lib").removeSuffix(".so")
        if (stem.length !in 3..10) return false
        if (!stem.all { it.isLetterOrDigit() }) return false
        val hexish = stem.count { it.isDigit() || it.lowercaseChar() in "abcdef" }
        return stem.any { it.isDigit() } && hexish >= stem.length - 1
    }

    /**
     * What to expect from an app on a build that cannot patch: it decrypts only
     * if it trusts user certificates, and a Flutter app never does.
     */
    fun outlookWithoutPatching(f: AppFacts): String = when {
        f.flutter -> "Flutter has its own TLS stack and ignores Android's certificate settings, so only its analytics will show here."
        f.cronet -> "Ships Cronet, which verifies certificates its own way. Some traffic may not decrypt."
        else -> "Its traffic decrypts if it trusts user certificates. Most apps made for Android 7 or later do not."
    }

    /** The note under an app in a list on a build that cannot patch. */
    fun noteWithoutPatching(f: AppFacts?, pkg: String): String? = when {
        f?.flutter == true -> "Flutter: has its own TLS stack, so only its analytics will show"
        pkg == "com.android.chrome" -> "Ignores user certificates, so its HTTPS stays unread"
        else -> null
    }
}
