package io.crossfyre.mobile

import android.content.Context

/**
 * The app's own settings and the few things it has been told once: whether the
 * account of what capture does has been read, whether Android has been asked
 * about notifications, and the chosen appearance.
 */
class AppPrefs(ctx: Context) {
    private val p = ctx.getSharedPreferences("app", Context.MODE_PRIVATE)

    /** "Before the first capture" was read and agreed to. */
    var disclosed: Boolean
        get() = p.getBoolean("disclosed", false)
        set(v) = p.edit().putBoolean("disclosed", v).apply()

    /** Android has been asked to show the capture notification, whatever it answered. */
    var notificationsAsked: Boolean
        get() = p.getBoolean("notif_asked", false)
        set(v) = p.edit().putBoolean("notif_asked", v).apply()

    var appearance: String
        get() = p.getString("appearance", "phone") ?: "phone"
        set(v) = p.edit().putString("appearance", v).apply()
}
