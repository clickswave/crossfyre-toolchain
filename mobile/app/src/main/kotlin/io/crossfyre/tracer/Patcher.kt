package io.crossfyre.tracer

import android.content.Context
import android.content.pm.PackageManager
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest
import org.json.JSONObject
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
        val base = apiUrl.trimEnd('/')

        // 1. Ask for a job and somewhere to put the bytes.
        //
        // The app used to POST the bundle to the control plane and hold that one
        // request open for the whole rebuild. Three things were wrong with it: an
        // edge in front of the control plane rejects bodies over ~100MB, which is
        // smaller than the apps worth patching; a rebuild takes minutes, so a
        // phone that moved between cells lost the entire upload; and every byte
        // crossed the control plane twice for no reason. Now the bytes go
        // straight to storage and only small JSON comes through here.
        progress(Step("Preparing…", 0.03f))
        val create = postJson(
            "$base/api/v1/web-trace/patch-job",
            JSONObject()
                .put("workflow_id", workflowId)
                .put("token", token)
                .put("package_name", pkg)
                .put("app_label", installedLabel(ctx, pkg))
        )
        val job = create.optJSONObject("data") ?: JSONObject()
        val jobId = job.optString("job_id", "")
        val uploadUrl = job.optString("upload_url", "")
        if (jobId.isEmpty() || uploadUrl.isEmpty()) {
            throw IllegalStateException(create.optString("message", "the server would not start a patch"))
        }

        // 2. Straight to storage, not through the control plane.
        val put = (URL(uploadUrl).openConnection() as HttpURLConnection).apply {
            requestMethod = "PUT"
            doOutput = true
            connectTimeout = 30_000
            readTimeout = 600_000
            setRequestProperty("Content-Type", "application/zip")
            setFixedLengthStreamingMode(uploadTotal)
        }
        put.outputStream.use { os ->
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
        if (put.responseCode !in 200..299) {
            throw IllegalStateException("the upload was rejected (HTTP ${put.responseCode})")
        }

        // 3. Nothing else sees the bytes, so the job only becomes work once we
        //    say they arrived.
        postJson(
            "$base/api/v1/web-trace/patch-job/uploaded",
            JSONObject().put("workflow_id", workflowId).put("token", token)
                .put("job_id", jobId).put("raw_size", uploadTotal)
        )

        // 4. Wait for the worker. Polling rather than a held connection is the
        //    point: the phone can lose signal here and pick the answer back up.
        progress(Step("Patching on server…", null))
        var downloadUrl = ""
        var expectedSha = ""
        val deadline = System.currentTimeMillis() + PATCH_WAIT_MS
        while (System.currentTimeMillis() < deadline) {
            Thread.sleep(POLL_INTERVAL_MS)
            val st = postJson(
                "$base/api/v1/web-trace/patch-job/status",
                JSONObject().put("workflow_id", workflowId).put("token", token).put("job_id", jobId)
            ).optJSONObject("data") ?: JSONObject()
            when (st.optString("status")) {
                "done" -> {
                    downloadUrl = st.optString("download_url", "")
                    expectedSha = st.optString("sha256", "")
                    break
                }
                // The server writes this for the person holding the phone.
                "failed" -> throw IllegalStateException(
                    st.optString("error", "").ifBlank { "the app could not be patched" }
                )
            }
        }
        if (downloadUrl.isEmpty()) throw IllegalStateException("the patch took too long")

        // 5. Fetch from storage, hashing as it lands.
        val get = (URL(downloadUrl).openConnection() as HttpURLConnection).apply {
            requestMethod = "GET"
            connectTimeout = 30_000
            readTimeout = 600_000
        }
        val dlTotal = get.contentLengthLong
        val digest = MessageDigest.getInstance("SHA-256")
        get.inputStream.use { input ->
            out.outputStream().use { os ->
                val buf = ByteArray(1 shl 16)
                var read = 0L
                var lastPct = -1
                var n = input.read(buf)
                while (n >= 0) {
                    os.write(buf, 0, n)
                    digest.update(buf, 0, n)
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
        // The bytes came from storage rather than from the service that made
        // them, so check they are the ones it said it produced before unpacking
        // anything. Skipped only when the server published no hash to check.
        if (expectedSha.isNotBlank()) {
            val got = digest.digest().joinToString("") { "%02x".format(it) }
            if (!got.equals(expectedSha, ignoreCase = true)) {
                throw IllegalStateException("the downloaded app did not match its checksum")
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

    /** How long to wait for a rebuild before giving up, and how often to ask. */
    private const val PATCH_WAIT_MS = 20L * 60 * 1000
    private const val POLL_INTERVAL_MS = 4000L

    /** POST JSON, read JSON back. Small bodies only: the app itself never comes
     *  through these, it goes to storage. An error body is still parsed, because
     *  that is where the server puts the sentence worth showing. */
    private fun postJson(url: String, body: JSONObject): JSONObject {
        val conn = (URL(url).openConnection() as HttpURLConnection).apply {
            requestMethod = "POST"
            doOutput = true
            connectTimeout = 30_000
            readTimeout = 60_000
            setRequestProperty("Content-Type", "application/json")
        }
        conn.outputStream.use { it.write(body.toString().toByteArray()) }
        val text = runCatching {
            (if (conn.responseCode in 200..299) conn.inputStream else conn.errorStream)
                ?.bufferedReader()?.readText()
        }.getOrNull().orEmpty()
        val parsed = runCatching { JSONObject(text) }.getOrElse { JSONObject() }
        if (conn.responseCode !in 200..299) {
            throw IllegalStateException(
                parsed.optString("message", "").ifBlank { "the server returned HTTP ${conn.responseCode}" }
            )
        }
        return parsed
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
