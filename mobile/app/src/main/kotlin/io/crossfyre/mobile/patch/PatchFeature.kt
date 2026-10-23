package io.crossfyre.mobile.patch

import io.crossfyre.mobile.Pairing
import io.crossfyre.mobile.apps.AppFacts
import kotlinx.coroutines.flow.StateFlow
import java.io.File
import java.io.OutputStream

/** Whether an app carries a patch, and whether that patch still works. */
enum class PatchState {
    /** Never patched by this phone. */
    NONE,

    /** Patched with the current certificate, and still the build we produced. */
    CURRENT,

    /**
     * Patched once, but it trusts an older certificate or is no longer the build
     * we produced (the original was reinstalled over it). It will not decrypt.
     */
    STALE,
}

/**
 * Patching a pinned app, as the rest of the app sees it.
 *
 * The direct-download build has the real thing in src/direct. The Play build has
 * none of it: its source set holds an implementation that says it is not
 * available, and neither the code that rewrites apps nor the permissions to
 * install them are compiled in. Nothing outside this interface names the classes
 * that do the work, so the two builds differ in one file each.
 */
interface PatchFeature {
    val available: Boolean

    /** The patch in progress or just finished, or null. */
    val job: StateFlow<PatchJob?>

    /** The package whose patched build can be exported, while the files exist. */
    val exportable: StateFlow<String?>

    fun state(pkg: String, caFingerprint: String?): PatchState

    /** How many apps this phone has patched, whatever their state. */
    fun patchedCount(): Int

    /** Patched apps that will not decrypt any more, by package. */
    fun stale(caFingerprint: String?): List<String>

    /** The one line worth reading before spending ten minutes on a patch. */
    fun outlook(facts: AppFacts, patched: Boolean): String

    /** Housekeeping at launch: debris from a patch that was killed, records of uninstalled apps. */
    fun tidy()

    fun start(pkg: String, label: String, sizeMb: Int, pairing: Pairing, ca: File, caFingerprint: String?)

    fun cancel()

    /** Close a finished job's result. */
    fun dismiss()

    /** Write the last patched build to [out]; returns what to tell the person. */
    fun export(out: OutputStream): String

    /** The certificate was reset, so every patch made with it is void. */
    fun forgetAll()
}

/** The stages of a patch as the progress sheet lists them. */
val PATCH_STAGES = listOf(
    "Read the app",
    "Upload",
    "Patch on the server",
    "Download the patched app",
    "Remove the original, install the patched build",
)

enum class PatchStep {
    READ, UPLOAD, SERVER, DOWNLOAD,
    /** Android's prompt to remove the original is up. */
    UNINSTALL,
    /** Android's prompt to install the patched build is up. */
    INSTALL,
    /** Confirmed, and Android is installing. */
    INSTALLING,
    DONE,
    /** Failed before anything on the phone changed. */
    FAILED,
    /** Android refused the patched build after the original was removed. */
    REJECTED,
    UNINSTALL_CANCELLED,
    INSTALL_CANCELLED,
}

/**
 * One patch, from reading the app to the result.
 *
 * @param pct progress within the current step, 0 to 100, where the step has any.
 * @param message the reason a patch failed. When [fromServer] it is the server's
 *   own sentence, written for whoever holds the phone.
 */
data class PatchJob(
    val pkg: String,
    val label: String,
    val sizeMb: Int,
    val step: PatchStep,
    val pct: Float = 0f,
    val message: String? = null,
    val fromServer: Boolean = false,
) {
    val running: Boolean get() = step.ordinal <= PatchStep.INSTALLING.ordinal

    /**
     * Cancel is offered only while there is something of ours to stop. Once
     * Android has the build, cancelling here could not undo what it is doing.
     */
    val cancellable: Boolean get() = step.ordinal <= PatchStep.DOWNLOAD.ordinal

    /** Which of [PATCH_STAGES] is under way. */
    val stage: Int
        get() = when (step) {
            PatchStep.READ -> 0
            PatchStep.UPLOAD -> 1
            PatchStep.SERVER -> 2
            PatchStep.DOWNLOAD -> 3
            else -> 4
        }

    /**
     * Where the bar sits across the whole patch, 0 to 100, or null while the
     * server works: it says when it is done, not how far along it is.
     */
    val meter: Float?
        get() = when (step) {
            PatchStep.READ -> 3f
            PatchStep.UPLOAD -> 5f + 0.40f * pct
            PatchStep.SERVER -> null
            PatchStep.DOWNLOAD -> 55f + 0.44f * pct
            else -> 99.5f
        }

    /** The line under the stage that is under way. */
    val detail: String
        get() = when (step) {
            PatchStep.READ -> "$sizeMb MB"
            PatchStep.UPLOAD -> "${pct.toInt()}%"
            PatchStep.SERVER -> "The slow part: a few minutes for a large app. The server says when it is done, not how far along it is, so the bar moves slowly here."
            PatchStep.DOWNLOAD -> "${pct.toInt()}%, checked against the server's checksum"
            PatchStep.INSTALLING -> "Installing…"
            else -> "Android asks you to confirm both. The first time, it also asks you to allow installs from Crossfyre Mobile."
        }
}

/** What a finished patch says, by outcome: title, then two lines. */
fun PatchJob.result(): Triple<String, String, String>? = when (step) {
    PatchStep.DONE -> Triple(
        "$label is patched",
        "Start capture and use the app. It trusts this phone's certificate, so nothing needs installing in Android.",
        "Sign in to it again: removing the original cleared its data.",
    )
    PatchStep.FAILED -> Triple(
        "Patch failed",
        message?.takeIf { it.isNotBlank() } ?: "The app could not be patched.",
        if (fromServer) "That is what the server said. Nothing was installed or removed, so $label is as it was."
        else "Nothing was installed or removed, so $label is as it was.",
    )
    PatchStep.REJECTED -> Triple(
        "Android refused the patched build",
        "Android's installer would not install the patched build of $label, and the original had already been removed.",
        "Patch again, or reinstall the original from where you got it.",
    )
    PatchStep.UNINSTALL_CANCELLED -> Triple(
        "Nothing was installed",
        "The original app was not removed, so the patched build could not go on.",
        "Your app has not been touched.",
    )
    PatchStep.INSTALL_CANCELLED -> Triple(
        "The patched build was not installed",
        "The original was already removed.",
        "Patch again to install it, or reinstall the original from where you got it.",
    )
    else -> null
}
