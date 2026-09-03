package io.crossfyre.tracer

import android.content.Context
import android.content.pm.PackageManager
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import java.util.zip.ZipEntry
import java.util.zip.ZipInputStream
import java.util.zip.ZipOutputStream
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Server-assisted pinning bypass. Rewriting an installed app reliably is not something a phone can do
 * on its own, so this uploads the target's packages together with the session certificate and receives
 * rewritten, re-signed, installable packages back. This class is the network half only; the caller
 * installs what comes back via PackageInstaller (needs an Activity + user confirmation).
 *
 * The rewriting itself is a hosted service and is deliberately not described here.
 */
object Patcher {

    /** A coarse progress step for the UI. `fraction` in 0..1 when known, else null (indeterminate). */
    data class Step(val label: String, val fraction: Float?)

    /**
     * Collect [pkg]'s splits, upload them for patching, and return the patched split files (in cache).
     * Throws on any failure (unreadable APK, network, server error). Runs off the main thread.
     */
    suspend fun buildPatched(
        ctx: Context,
        pkg: String,
        apiUrl: String,
        workflowId: String,
        token: String,
        caPem: File,
        progress: (Step) -> Unit
    ): List<File> = withContext(Dispatchers.IO) {
        progress(Step("Reading $pkg…", null))
        val ai = ctx.packageManager.getApplicationInfo(pkg, 0)
        val splitPaths = buildList {
            add(ai.sourceDir)
            ai.splitSourceDirs?.let { addAll(it) }
        }.map { File(it) }.filter { it.exists() }
        if (splitPaths.isEmpty()) throw IllegalStateException("Could not read $pkg's APK")

        // Zip the splits + CA into one upload (base named base.apk so the server picks it as base).
        val work = File(ctx.cacheDir, "patch").apply { deleteRecursively(); mkdirs() }
        val upload = File(work, "in.zip")
        ZipOutputStream(upload.outputStream().buffered()).use { zos ->
            splitPaths.forEachIndexed { i, f ->
                val name = if (f.absolutePath == ai.sourceDir) "base.apk" else "split_$i.apk"
                zos.putNextEntry(ZipEntry(name))
                f.inputStream().use { it.copyTo(zos) }
                zos.closeEntry()
            }
            zos.putNextEntry(ZipEntry("ca.pem"))
            caPem.inputStream().use { it.copyTo(zos) }
            zos.closeEntry()
        }

        val out = File(work, "out.zip")
        val uploadTotal = upload.length()
        // Fixed content length lets us stream with a real upload progress %.
        val conn = (URL("${apiUrl.trimEnd('/')}/api/v1/web-trace/patch").openConnection() as HttpURLConnection).apply {
            requestMethod = "POST"
            doOutput = true
            connectTimeout = 30_000
            readTimeout = 300_000 // patching a big app takes a while
            setRequestProperty("Content-Type", "application/zip")
            setRequestProperty("X-Cfx-Token", token)
            // The session this token belongs to. The proxy needs both halves to
            // verify it; it previously forwarded the token without checking it.
            setRequestProperty("X-Cfx-Workflow", workflowId)
            setFixedLengthStreamingMode(uploadTotal)
        }
        // Upload with progress (0.05 .. 0.45 of the whole flow).
        conn.outputStream.use { os ->
            upload.inputStream().use { ins ->
                val buf = ByteArray(1 shl 16)
                var sent = 0L
                var lastPct = -1
                var n = ins.read(buf)
                while (n >= 0) {
                    os.write(buf, 0, n)
                    sent += n
                    val pct = (sent * 100 / uploadTotal).toInt()
                    if (pct != lastPct) {
                        lastPct = pct
                        progress(Step("Uploading… $pct%", 0.05f + 0.40f * (sent.toFloat() / uploadTotal)))
                    }
                    n = ins.read(buf)
                }
                os.flush()
            }
        }

        progress(Step("Patching on server…", null)) // server-side; indeterminate
        val code = conn.responseCode
        if (code != 200) {
            val err = runCatching { conn.errorStream?.bufferedReader()?.readText()?.trim() }.getOrNull()
            // The server explains itself in the body, and the caller already labels this as a
            // failure, so pass the sentence through rather than wrapping it. Prefixing here as
            // well produced "Patch failed: Patch failed (HTTP 501): ...". The status code only
            // appears when there is no message to show instead of it.
            throw IllegalStateException(
                if (err.isNullOrBlank()) "the server returned HTTP $code" else err
            )
        }
        // Download with progress (0.55 .. 0.99). Content-Length is set by the proxy.
        val dlTotal = conn.contentLengthLong
        conn.inputStream.use { input ->
            out.outputStream().use { os ->
                val buf = ByteArray(1 shl 16)
                var read = 0L
                var lastPct = -1
                var n = input.read(buf)
                while (n >= 0) {
                    os.write(buf, 0, n)
                    read += n
                    if (dlTotal > 0) {
                        val pct = (read * 100 / dlTotal).toInt()
                        if (pct != lastPct) {
                            lastPct = pct
                            progress(Step("Downloading patched app… $pct%", 0.55f + 0.44f * (read.toFloat() / dlTotal)))
                        }
                    } else {
                        progress(Step("Downloading patched app…", null))
                    }
                    n = input.read(buf)
                }
            }
        }

        progress(Step("Preparing install…", null))
        val outDir = File(work, "patched").apply { mkdirs() }
        val patched = mutableListOf<File>()
        var written = 0L
        ZipInputStream(out.inputStream().buffered()).use { zis ->
            var e = zis.nextEntry
            while (e != null) {
                // Basename only: this is what keeps a `../` entry name inside outDir.
                val name = File(e.name).name
                if (patched.size >= MAX_ENTRIES) throw IllegalStateException("Patch response has too many files")
                if (!name.endsWith(".apk", ignoreCase = true)) { e = zis.nextEntry; continue }
                val dst = File(outDir, name)
                dst.outputStream().use { os ->
                    val buf = ByteArray(1 shl 16)
                    while (true) {
                        val n = zis.read(buf)
                        if (n <= 0) break
                        written += n
                        // A hostile or compromised service could otherwise fill the data partition.
                        if (written > MAX_UNPACKED) throw IllegalStateException("Patch response too large")
                        os.write(buf, 0, n)
                    }
                }
                patched.add(dst)
                e = zis.nextEntry
            }
        }
        if (patched.isEmpty()) throw IllegalStateException("Patch service returned nothing")

        // Validate before ANY of this is installed.
        //
        // Nothing here was checked: no signature, no expected signer, no package
        // name. `PackageInstaller` derives the real package from the APK's own
        // manifest (setAppPackageName is only a hint), so a hostile patch
        // endpoint chose the package name, label, icon and permissions of what
        // got installed, and the arrival of its response is what triggered
        // uninstalling the legitimate app. At minimum the returned APKs must be
        // parseable and must be the package we asked to patch.
        val pm = ctx.packageManager
        for (apk in patched) {
            val info = pm.getPackageArchiveInfo(apk.absolutePath, 0)
                ?: throw IllegalStateException("Patch service returned a file that is not an APK")
            if (info.packageName != pkg) {
                throw IllegalStateException(
                    "Patch service returned ${info.packageName}, expected $pkg"
                )
            }
        }
        patched
    }

    /** Caps on what a patch response may unpack to. */
    private const val MAX_ENTRIES = 64
    private const val MAX_UNPACKED = 2L * 1024 * 1024 * 1024

    /** Whether [pkg] is installed (so the UI can offer patch only for installed apps). */
    fun isInstalled(ctx: Context, pkg: String): Boolean =
        runCatching { ctx.packageManager.getApplicationInfo(pkg, 0); true }.getOrDefault(false)

    @Suppress("DEPRECATION")
    fun installedLabel(ctx: Context, pkg: String): String =
        runCatching {
            val ai = ctx.packageManager.getApplicationInfo(pkg, 0)
            ctx.packageManager.getApplicationLabel(ai).toString()
        }.getOrDefault(pkg)
}
