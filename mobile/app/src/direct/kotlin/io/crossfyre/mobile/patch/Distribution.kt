package io.crossfyre.mobile.patch

import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageInstaller
import androidx.core.content.ContextCompat
import io.crossfyre.mobile.Pairing
import io.crossfyre.mobile.apps.AppFacts
import io.crossfyre.mobile.apps.Apps
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import java.io.File
import java.io.OutputStream

/** The direct-download build, which can patch a pinned app. */
object Distribution {
    @Volatile
    private var feature: DirectPatchFeature? = null

    /** One per process: a patch outlives the screen that started it. */
    fun patchFeature(ctx: Context): PatchFeature =
        feature ?: synchronized(this) {
            feature ?: DirectPatchFeature(ctx.applicationContext).also { feature = it }
        }
}

/**
 * Patch an app: read its packages, have the server rebuild them to trust this
 * phone's certificate, then swap the installed build for the patched one.
 *
 * The swap is uninstall first, then install, because the patched build is signed
 * by a different key and Android refuses it as an update. The install is chained
 * off the uninstall's success rather than fired alongside it, so the old package
 * is definitely gone first; otherwise the install is treated as an update and
 * fails with INSTALL_FAILED_UPDATE_INCOMPATIBLE.
 */
internal class DirectPatchFeature(private val app: Context) : PatchFeature {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
    private val _job = MutableStateFlow<PatchJob?>(null)
    private val _exportable = MutableStateFlow<String?>(null)
    private var work: Job? = null
    private var pendingInstall: List<File>? = null
    private var exportFiles: List<File>? = null
    private var caForJob: String? = null

    override val available = true
    override val job: StateFlow<PatchJob?> = _job
    override val exportable: StateFlow<String?> = _exportable

    private val installAction = "${app.packageName}.INSTALL_RESULT"
    private val uninstallAction = "${app.packageName}.UNINSTALL_RESULT"

    // Handles both the uninstall and the install results.
    private val receiver = object : BroadcastReceiver() {
        override fun onReceive(c: Context, i: Intent) {
            val status = i.getIntExtra(PackageInstaller.EXTRA_STATUS, -1)
            val current = _job.value
            if (status == PackageInstaller.STATUS_PENDING_USER_ACTION) {
                // Only ever launch a handed-over Intent while a patch of ours is in
                // flight. Belt and braces with RECEIVER_NOT_EXPORTED: launching an
                // arbitrary Intent from this context is the valuable half of an
                // intent-redirection bug, so it should not be reachable at a moment
                // when no install is pending either.
                if (current == null || !current.running) return
                @Suppress("DEPRECATION")
                val confirm = i.getParcelableExtra<Intent>(Intent.EXTRA_INTENT) ?: return
                confirm.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                runCatching { app.startActivity(confirm) }
                return
            }
            if (current == null) return
            if (i.action == uninstallAction) {
                if (status == PackageInstaller.STATUS_SUCCESS) {
                    _job.update { it?.copy(step = PatchStep.INSTALL) }
                    val files = pendingInstall
                    if (files == null) {
                        _job.update { it?.copy(step = PatchStep.INSTALL_CANCELLED) }
                    } else {
                        runCatching { install(current.pkg, files) }.onFailure {
                            _job.update { j -> j?.copy(step = PatchStep.REJECTED) }
                        }
                    }
                } else {
                    _job.update { it?.copy(step = PatchStep.UNINSTALL_CANCELLED) }
                    finishWithout()
                }
            } else {
                when (status) {
                    PackageInstaller.STATUS_SUCCESS -> {
                        // Remember WHICH certificate this build trusts, and which
                        // build it is. Without both the app cannot later tell a
                        // working patch from one a certificate reset or a reinstall
                        // of the original has voided.
                        caForJob?.let { ca ->
                            PatchPrefs.record(app, current.pkg, PatchPrefs.join(ca, AppInspector.signerOf(app, current.pkg)))
                        }
                        // Hold on to what was built. The patched APK is the one
                        // artefact of the whole operation, and it used to be
                        // installed and then unreachable.
                        exportFiles = pendingInstall
                        _exportable.value = current.pkg
                        pendingInstall = null
                        _job.update { it?.copy(step = PatchStep.DONE) }
                    }
                    PackageInstaller.STATUS_FAILURE_ABORTED -> {
                        _job.update { it?.copy(step = PatchStep.INSTALL_CANCELLED) }
                        finishWithout()
                    }
                    else -> {
                        _job.update { it?.copy(step = PatchStep.REJECTED, message = i.getStringExtra(PackageInstaller.EXTRA_STATUS_MESSAGE)) }
                        finishWithout()
                    }
                }
            }
        }
    }

    init {
        // NOT_EXPORTED on every API level. minSdk is 26, and below API 33 a
        // dynamically registered receiver defaults to exported with no
        // permission, so any app could broadcast our own result action with an
        // arbitrary Intent in EXTRA_INTENT and have us launch it (intent
        // redirection). ContextCompat routes older levels through androidx's
        // signature-permission shim.
        ContextCompat.registerReceiver(
            app, receiver,
            IntentFilter(installAction).apply { addAction(uninstallAction) },
            ContextCompat.RECEIVER_NOT_EXPORTED,
        )
    }

    override fun state(pkg: String, caFingerprint: String?): PatchState =
        PatchPrefs.judge(PatchPrefs.recordFor(app, pkg), caFingerprint, AppInspector.signerOf(app, pkg))

    override fun patchedCount(): Int = PatchPrefs.all(app).size

    override fun stale(caFingerprint: String?): List<String> =
        PatchPrefs.all(app).keys.filter { state(it, caFingerprint) == PatchState.STALE }.sorted()

    override fun outlook(facts: AppFacts, patched: Boolean): String = AppInspector.outlook(facts, patched)

    override fun tidy() {
        // A patch killed mid-flight (app swiped away, process reaped) leaves its
        // staged APKs behind: tens to hundreds of megabytes with nothing left
        // that will ever read them. Nothing is patching in a new process, so
        // anything still there is debris.
        if (_job.value == null) Patcher.discardWorkspace(app)
        // Forget records of apps that are no longer installed, so the count a
        // certificate reset threatens stays honest.
        PatchPrefs.all(app).keys.forEach { if (!Apps.isInstalled(app, it)) PatchPrefs.forget(app, it) }
    }

    override fun start(pkg: String, label: String, sizeMb: Int, pairing: Pairing, ca: File, caFingerprint: String?) {
        if (_job.value?.running == true) return
        // buildPatched clears the scratch directory on entry, so anything left
        // exportable from a previous patch is about to stop existing. Drop the
        // offer now rather than letting it fail when taken up.
        exportFiles = null
        _exportable.value = null
        pendingInstall = null
        caForJob = caFingerprint
        _job.value = PatchJob(pkg, label, sizeMb, PatchStep.READ)
        work = scope.launch {
            try {
                val files = Patcher.buildPatched(app, pkg, pairing.apiUrl, pairing.workflowId, pairing.token, ca) { step ->
                    _job.update { j ->
                        if (j == null || !j.running) j
                        // Monotonic within a stage: a late report never moves the bar back.
                        else if (j.step == step.stage) j.copy(pct = maxOf(j.pct, step.pct))
                        else j.copy(step = step.stage, pct = step.pct)
                    }
                }
                pendingInstall = files
                _job.update { it?.copy(step = PatchStep.UNINSTALL, pct = 100f) }
                uninstall(pkg)
            } catch (e: CancellationException) {
                // Cancelling is a normal outcome, not a failure, and must not read
                // like one. Leave nothing half-set.
                pendingInstall = null
                Patcher.discardWorkspace(app)
                _job.value = null
                throw e
            } catch (e: Patcher.ServerSaid) {
                Patcher.discardWorkspace(app)
                _job.update { it?.copy(step = PatchStep.FAILED, message = e.message, fromServer = true) }
            } catch (e: Exception) {
                Patcher.discardWorkspace(app)
                _job.update {
                    it?.copy(
                        step = PatchStep.FAILED,
                        // e.message is null for plenty of exceptions, and "null" tells nobody anything.
                        message = e.message?.takeIf { m -> m.isNotBlank() } ?: "Something went wrong on the way to the server.",
                    )
                }
            } finally {
                work = null
            }
        }
    }

    override fun cancel() {
        work?.cancel()
    }

    override fun dismiss() {
        if (_job.value?.running != true) _job.value = null
    }

    /**
     * Save the last patched build.
     *
     * Split APKs cannot be represented as one file, so the base is exported and
     * the caller is told the rest were left behind rather than being handed a
     * file that will not install on its own.
     */
    override fun export(out: OutputStream): String {
        val files = exportFiles
        if (files.isNullOrEmpty()) return "Nothing to export yet: patch an app first."
        return runCatching {
            val base = files.maxByOrNull { it.length() }!!
            base.inputStream().use { it.copyTo(out) }
            if (files.size > 1) {
                "Exported the base APK. This app ships ${files.size} splits, so the export alone will not install: use Patch to install it here."
            } else {
                "Exported the patched APK."
            }
        }.getOrElse { "Export failed: ${it.message}" }
    }

    override fun forgetAll() {
        PatchPrefs.clear(app)
        exportFiles = null
        _exportable.value = null
    }

    private fun finishWithout() {
        pendingInstall = null
        Patcher.discardWorkspace(app)
    }

    private fun uninstall(pkg: String) {
        val flags = PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_MUTABLE
        val pi = PendingIntent.getBroadcast(app, 2, Intent(uninstallAction).setPackage(app.packageName), flags)
        app.packageManager.packageInstaller.uninstall(pkg, pi.intentSender)
    }

    private fun install(pkg: String, splits: List<File>) {
        val pi = app.packageManager.packageInstaller
        val params = PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_INSTALL)
        params.setAppPackageName(pkg)
        val sid = pi.createSession(params)
        pi.openSession(sid).use { session ->
            for (apk in splits) {
                session.openWrite(apk.name, 0, apk.length()).use { out ->
                    apk.inputStream().use { it.copyTo(out) }
                    session.fsync(out)
                }
            }
            val flags = PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_MUTABLE
            val pending = PendingIntent.getBroadcast(app, sid, Intent(installAction).setPackage(app.packageName), flags)
            session.commit(pending.intentSender)
        }
    }
}
