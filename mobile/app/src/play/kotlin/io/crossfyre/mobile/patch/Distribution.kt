package io.crossfyre.mobile.patch

import android.content.Context
import io.crossfyre.mobile.Pairing
import io.crossfyre.mobile.apps.AppFacts
import io.crossfyre.mobile.apps.Apps
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import java.io.File
import java.io.OutputStream

/**
 * The Google Play build. It cannot patch apps: rewriting and reinstalling
 * another app is not something a Play app may do, and REQUEST_INSTALL_PACKAGES
 * is a restricted permission. So this build ships without the code and without
 * the permission, and this is the whole of its patch feature.
 */
object Distribution {
    fun patchFeature(@Suppress("UNUSED_PARAMETER") ctx: Context): PatchFeature = NoPatching
}

private object NoPatching : PatchFeature {
    override val available = false
    override val job: StateFlow<PatchJob?> = MutableStateFlow(null)
    override val exportable: StateFlow<String?> = MutableStateFlow(null)
    override fun state(pkg: String, caFingerprint: String?) = PatchState.NONE
    override fun patchedCount() = 0
    override fun stale(caFingerprint: String?): List<String> = emptyList()
    override fun outlook(facts: AppFacts, patched: Boolean) = Apps.outlookWithoutPatching(facts)
    override fun tidy() = Unit
    override fun start(pkg: String, label: String, sizeMb: Int, pairing: Pairing, ca: File, caFingerprint: String?) = Unit
    override fun cancel() = Unit
    override fun dismiss() = Unit
    override fun export(out: OutputStream) = "This build cannot patch apps."
    override fun forgetAll() = Unit
}
