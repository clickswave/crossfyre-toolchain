package io.crossfyre.mobile.patch

import android.content.Context

/**
 * Which CA each app was patched with.
 *
 * Patching embeds the CA into the app (`apk-mitm --certificate ca.pem`), so a
 * patched app trusts exactly one certificate forever. Rotate the CA and every
 * previously patched app keeps trusting the old one and fails the handshake with
 * `CertificateUnknown` the moment it is captured.
 *
 * Nothing used to record this, so nothing could tell you it had happened. The
 * app looked patched, the switch looked on, and capture produced an empty tab
 * and a TLS alert in a log nobody reads. Storing the fingerprint at patch time
 * is what lets the lists say "patch again" instead of leaving you to work it out.
 */
object PatchPrefs {
    private const val PREFS = "patches"

    /**
     * Packages whose last patch accepts any certificate, each with the signer
     * of the build we installed. Kept apart from the records above, so their
     * format stays as earlier versions wrote it and a certificate reset, which
     * clears those, leaves these: such a build accepts any certificate
     * whatever this phone's certificate is.
     */
    private const val ANY_CERT = "patches_any_cert"

    /**
     * Note whether [pkg]'s patch, just installed and signed by [signer],
     * accepts any certificate. An unknown signer is kept as empty.
     */
    fun recordAnyCert(ctx: Context, pkg: String, acceptsAnyCert: Boolean, signer: String?) {
        val e = ctx.getSharedPreferences(ANY_CERT, Context.MODE_PRIVATE).edit()
        if (acceptsAnyCert) e.putString(pkg, signer.orEmpty()) else e.remove(pkg)
        e.apply()
    }

    /** Packages whose last patch accepts any certificate, with the signer noted for each. */
    fun anyCert(ctx: Context): Map<String, String> =
        ctx.getSharedPreferences(ANY_CERT, Context.MODE_PRIVATE).all
            .mapNotNull { (k, v) -> (v as? String)?.let { k to it } }
            .toMap()

    /** Record that [pkg] was patched with the CA identified by [caFingerprint]. */
    fun record(ctx: Context, pkg: String, caFingerprint: String) {
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit().putString(pkg, caFingerprint).apply()
    }

    /** Pack a CA fingerprint and the signer of the build we produced. */
    fun join(caFingerprint: String, signer: String?): String =
        if (signer.isNullOrEmpty()) caFingerprint else "$caFingerprint|$signer"

    /** Split a stored record back into (caFingerprint, signer-or-null). */
    fun split(record: String): Pair<String, String?> {
        val i = record.indexOf('|')
        return if (i < 0) record to null else record.substring(0, i) to record.substring(i + 1)
    }

    /** The record for [pkg], or null if we never patched it. */
    fun recordFor(ctx: Context, pkg: String): String? =
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString(pkg, null)

    fun forget(ctx: Context, pkg: String) {
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().remove(pkg).apply()
        ctx.getSharedPreferences(ANY_CERT, Context.MODE_PRIVATE).edit().remove(pkg).apply()
    }

    /** Every package we have patched, whether or not it is still current. */
    fun all(ctx: Context): Map<String, String> =
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).all
            .mapNotNull { (k, v) -> (v as? String)?.let { k to it } }
            .toMap()

    /** The certificate was reset. The any-certificate notes stay; see [ANY_CERT]. */
    fun clear(ctx: Context) {
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().clear().apply()
    }

    /**
     * A record judged against the current certificate and the installed build.
     *
     * A record with no signer cannot be verified, so it does not count as
     * current. Being told to patch again once is a small price; the alternative
     * is what this replaced, where a pristine reinstall still reported "patched
     * and ready" and quietly captured nothing.
     */
    fun judge(record: String?, currentCa: String?, installedSigner: String?): PatchState {
        if (record == null) return PatchState.NONE
        val (ca, signer) = split(record)
        if (currentCa == null || ca != currentCa) return PatchState.STALE
        if (signer == null || signer != installedSigner) return PatchState.STALE
        return PatchState.CURRENT
    }

    /**
     * A build noted as accepting any certificate, signed by [noted], is still
     * what is installed. An unknown signer counts while the app is installed:
     * a warning about a build that has since been replaced costs less than
     * staying quiet about one that has not.
     */
    fun stillAnyCert(noted: String?, installedSigner: String?): Boolean =
        noted != null && installedSigner != null && (noted.isEmpty() || noted == installedSigner)
}
