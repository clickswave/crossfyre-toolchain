package io.crossfyre.mobile.push

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.Uri
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import com.google.firebase.FirebaseApp
import com.google.firebase.FirebaseOptions
import com.google.firebase.messaging.FirebaseMessaging
import io.crossfyre.mobile.BuildConfig
import io.crossfyre.mobile.MainActivity
import io.crossfyre.mobile.R
import io.crossfyre.mobile.account.AccountStore
import io.crossfyre.mobile.account.HttpTransport
import io.crossfyre.mobile.account.KeystoreSealer
import io.crossfyre.mobile.account.Outcome
import io.crossfyre.mobile.account.PrefsKeyValues
import io.crossfyre.mobile.approve.ApprovalApi
import io.crossfyre.mobile.notificationUrl
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlin.coroutines.resume

/**
 * Firebase Cloud Messaging, for a phone that approves.
 *
 * A push token is made only once the phone approves, and is handed to
 * crossfyre.io with the phone's own key; turning approvals off or signing out
 * deletes it. A build without Firebase values ([start] answers false), or a
 * phone without Google Play services, gets no push, and the app asks for what
 * is waiting while it is open, as it always has.
 */
object PushSetup {
    /** Set by MainActivity's intent when a tap on a push opened it. */
    const val EXTRA_PUSHED = "io.crossfyre.mobile.PUSHED"

    @Volatile
    var available = false
        private set

    private fun options(): FirebaseOptions? {
        val values = listOf(BuildConfig.FCM_APP_ID, BuildConfig.FCM_API_KEY, BuildConfig.FCM_PROJECT_ID, BuildConfig.FCM_SENDER_ID)
        if (values.any { it.isBlank() }) return null
        return FirebaseOptions.Builder()
            .setApplicationId(BuildConfig.FCM_APP_ID)
            .setApiKey(BuildConfig.FCM_API_KEY)
            .setProjectId(BuildConfig.FCM_PROJECT_ID)
            .setGcmSenderId(BuildConfig.FCM_SENDER_ID)
            .build()
    }

    /** Start Firebase, once per process. False when this build has no push. */
    fun start(ctx: Context): Boolean {
        if (available) return true
        val o = options() ?: return false
        available = runCatching {
            if (FirebaseApp.getApps(ctx).isEmpty()) FirebaseApp.initializeApp(ctx, o)
            true
        }.getOrDefault(false)
        if (available) channels(ctx)
        return available
    }

    private suspend fun token(): String? = suspendCancellableCoroutine { c ->
        runCatching {
            FirebaseMessaging.getInstance().token.addOnCompleteListener { t ->
                c.resume(if (t.isSuccessful) t.result else null)
            }
        }.onFailure { c.resume(null) }
    }

    /**
     * Make or refresh this phone's token and give it to crossfyre.io. Null when
     * there is no push here; otherwise what the server answered, whose value says
     * whether crossfyre.io can push at all. Off the main thread.
     */
    suspend fun register(api: ApprovalApi, key: String): Outcome<Boolean>? {
        if (!available) return null
        // Firebase also refreshes a token on its own once auto-init is on, and
        // hands the new one to PushService.onNewToken.
        runCatching { FirebaseMessaging.getInstance().isAutoInitEnabled = true }
        val t = token() ?: return null
        return api.pushRegister(key, t)
    }

    /** Stop pushes to this phone: tell crossfyre.io when the key still works, and delete the token. */
    suspend fun drop(api: ApprovalApi, key: String?) {
        if (!available) return
        runCatching { FirebaseMessaging.getInstance().isAutoInitEnabled = false }
        val t = token()
        if (key != null && t != null) api.pushUnregister(key, t)
        suspendCancellableCoroutine { c ->
            runCatching {
                FirebaseMessaging.getInstance().deleteToken().addOnCompleteListener { c.resume(Unit) }
            }.onFailure { c.resume(Unit) }
        }
    }

    /** The account on this phone as the app sees it, for the service, which has no model. */
    class Account(val key: String, val origin: String)

    fun account(ctx: Context): Account? {
        val store = AccountStore(PrefsKeyValues(ctx), KeystoreSealer())
        // A phone that does not approve is never pushed; a push that arrives
        // anyway, from before it stopped, draws nothing.
        if (store.approverId == null) return null
        val key = runCatching { store.key() }.getOrNull() ?: return null
        val origin = (if (BuildConfig.ORIGIN_EDITABLE) store.origin() else null) ?: BuildConfig.DEFAULT_ORIGIN
        return Account(key, origin)
    }

    /** Short waits: Android gives a push about ten seconds before it stops the work. */
    fun api(origin: String) = ApprovalApi(origin, HttpTransport(4_000, 6_000))

    private fun channels(ctx: Context) {
        val nm = ctx.getSystemService(NotificationManager::class.java) ?: return
        nm.createNotificationChannel(
            NotificationChannel(PushText.APPROVALS, "Approvals", NotificationManager.IMPORTANCE_HIGH).apply {
                description = "An agent is waiting for you to approve or deny what it asked for."
            }
        )
        nm.createNotificationChannel(
            NotificationChannel(PushText.ALERTS, "Alerts", NotificationManager.IMPORTANCE_DEFAULT).apply {
                description = "Scans, findings, nodes and the account, as the dashboard's bell shows them."
            }
        )
    }

    /** Draw [alert]. A tap opens the app on it: an approval opens the request, anything else the Activity tab. */
    fun show(ctx: Context, origin: String, alert: Alert, id: String) {
        if (!NotificationManagerCompat.from(ctx).areNotificationsEnabled()) return
        val url = notificationUrl(origin, alert.link)
        val open = Intent(ctx, MainActivity::class.java)
            .setAction(Intent.ACTION_VIEW)
            .putExtra(EXTRA_PUSHED, true)
            .addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP)
        if (url != null) open.data = Uri.parse(url)
        val tap = PendingIntent.getActivity(
            ctx, id.hashCode(), open, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val n = NotificationCompat.Builder(ctx, alert.channel)
            .setSmallIcon(R.drawable.ic_bell)
            .setContentTitle(alert.title)
            .setContentText(alert.text)
            .setStyle(NotificationCompat.BigTextStyle().bigText(alert.text))
            .setPriority(if (alert.channel == PushText.APPROVALS) NotificationCompat.PRIORITY_HIGH else NotificationCompat.PRIORITY_DEFAULT)
            .setCategory(if (alert.channel == PushText.APPROVALS) NotificationCompat.CATEGORY_REMINDER else NotificationCompat.CATEGORY_STATUS)
            // The lock screen says that something arrived, not what.
            .setVisibility(NotificationCompat.VISIBILITY_PRIVATE)
            .setContentIntent(tap)
            .setAutoCancel(true)
            .build()
        runCatching { NotificationManagerCompat.from(ctx).notify(id, 0, n) }
    }
}
