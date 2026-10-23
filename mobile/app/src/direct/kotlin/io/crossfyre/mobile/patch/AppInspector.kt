package io.crossfyre.mobile.patch

import android.content.Context
import android.content.pm.PackageManager
import io.crossfyre.mobile.apps.AppFacts

/**
 * What patching needs to know about an app beyond what it is made of: which
 * build of it is installed, and what to expect from patching it. Reading the app
 * itself lives in [io.crossfyre.mobile.apps.Apps], which both builds use.
 */
object AppInspector {

    /**
     * SHA-256 of the signing certificate of the INSTALLED build of [pkg].
     *
     * A patch is only real while the build that carries it is the one on the
     * device. Recording the package and the CA was not enough: reinstalling the
     * original app leaves both records intact, so Scope went on reporting
     * "patched and ready" about a pristine build that decrypts nothing. Every
     * patched build is re-signed by the patch service, so the signer identifies
     * our build as surely as a version would, and unlike a version it cannot be
     * reused by the vendor.
     */
    fun signerOf(ctx: Context, pkg: String): String? = runCatching {
        val info = ctx.packageManager.getPackageInfo(pkg, PackageManager.GET_SIGNING_CERTIFICATES)
        val sig = info.signingInfo?.apkContentsSigners?.firstOrNull() ?: return null
        java.security.MessageDigest.getInstance("SHA-256").digest(sig.toByteArray())
            .joinToString("") { "%02x".format(it) }
    }.getOrNull()

    /** The one line worth reading before spending ten minutes on a patch. */
    fun outlook(f: AppFacts, patched: Boolean): String = when {
        f.shielded && f.flutter ->
            "Patching can reach its Flutter traffic, but this app checks its own integrity. " +
                "Expect it to install and then refuse to start."
        f.shielded ->
            "This app checks its own integrity. Expect it to install and then refuse to start."
        f.flutter && f.cronet ->
            "Flutter traffic will decrypt once patched. Anything it sends over Cronet will not."
        f.flutter && patched -> "Patched. Its own API and its Java traffic should both decrypt."
        f.flutter -> "Patch it: Flutter has its own TLS stack, so unpatched it shows only analytics."
        f.cronet ->
            "Ships Cronet, which verifies certificates its own way. Some traffic may not decrypt."
        patched -> "Patched. Its traffic should decrypt."
        else ->
            "Patch it if its traffic does not decrypt: unpatched apps only work when they trust " +
                "user certificates."
    }
}
