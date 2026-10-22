package io.crossfyre.mobile

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.pm.ServiceInfo
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log

/**
 * The capture VPN. Stands up a TUN interface, scopes it to the chosen apps (or the whole device),
 * and hands the TUN fd to the native netstack which inspects flows and egresses them per the routing
 * mode. v1 routing is Normal (Direct egress); "through node" is locked.
 *
 * This scaffold establishes the TUN + foreground service + native handoff. The userspace TCP/IP +
 * TLS-MITM loop is the native M1 milestone (`cfx_mobile` / `cfx_capture`).
 */
class TracerVpnService : VpnService() {

    private var tun: ParcelFileDescriptor? = null

    companion object {
        const val ACTION_START = "io.crossfyre.mobile.START"
        const val ACTION_STOP = "io.crossfyre.mobile.STOP"
        /** Package names the scope refers to. */
        const val EXTRA_APPS = "apps"
        /** Scope mode: "all" (whole device), "only" (capture just EXTRA_APPS), "except" (capture
         * everything but EXTRA_APPS - the way to keep certificate-pinned apps like banking/dating
         * working while still capturing the rest). */
        const val EXTRA_MODE = "mode"
        const val MODE_ALL = "all"
        const val MODE_ONLY = "only"
        const val MODE_EXCEPT = "except"
        private const val TAG = "cfx-mobile"
        private const val CHANNEL = "capture"

        /** Live while the capture VPN is up. The foreground service keeps the process alive, so the UI
         *  can read this on relaunch to restore its running state after the app was closed. */
        @Volatile
        var active = false
            private set

        /**
         * Why the last start did not come up, in a sentence for the capture
         * card, or null. Cleared when a start is asked for.
         */
        @Volatile
        var failure: String? = null

        /** Wall-clock time the running capture came up, for the card's "since". */
        @Volatile
        var startedAt = 0L
            private set
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> { stop(); return START_NOT_STICKY }
            else -> start(
                intent?.getStringExtra(EXTRA_MODE) ?: MODE_ALL,
                intent?.getStringArrayExtra(EXTRA_APPS)?.toList() ?: emptyList()
            )
        }
        return START_STICKY
    }

    private val pairing get() = Pairing.load(this)

    private fun start(mode: String, apps: List<String>) {
        val pair = pairing
        if (pair == null) {
            Log.e(TAG, "no workspace pairing; scan the QR first")
            stopSelf()
            return
        }
        if (tun != null) return
        // The foreground type for a VPN, systemExempted, is only allowed to an app
        // the person has made a VPN app by accepting Android's prompt. Starting
        // without that throws, so check first and say so instead.
        if (prepare(this) != null) {
            fail("Android has not allowed the VPN connection, so capture could not start. Tap Start capture and accept Android's prompt.")
            return
        }
        if (!startForegroundCompat()) return

        val builder = Builder()
            .setSession("Crossfyre Mobile")
            .setMtu(1500)
            // A private TUN subnet; the netstack terminates flows and re-originates them (Direct
            // egress in v1), so we route everything into the interface.
            .addAddress("10.111.0.2", 32)
            .addRoute("0.0.0.0", 0)
            .addDnsServer("1.1.1.1")

        // Scope the interface. The app itself is ALWAYS excluded so our own control/egress traffic is
        // never captured or looped.
        //   only   -> allow-list: the VPN sees just these apps.
        //   except -> deny-list: the VPN sees everything but these (and us). This is how a user keeps
        //             certificate-pinned apps (banking, Hinge, etc.) working - a pinned app rejects our
        //             MITM leaf and would otherwise fail to connect while capture is on.
        //   all    -> whole device (only we are excluded).
        val effectiveMode = if (apps.isEmpty() && mode != MODE_ALL) MODE_ALL else mode
        when (effectiveMode) {
            MODE_ONLY -> for (pkg in apps) runCatching { builder.addAllowedApplication(pkg) }
            MODE_EXCEPT -> {
                runCatching { builder.addDisallowedApplication(packageName) }
                for (pkg in apps) runCatching { builder.addDisallowedApplication(pkg) }
            }
            else -> runCatching { builder.addDisallowedApplication(packageName) }
        }

        val pfd = runCatching { builder.establish() }.getOrNull()
        if (pfd == null) {
            stopForegroundCompat()
            fail("Android did not hand over the VPN interface. Another VPN app may be holding the connection: check Settings › Network & internet › VPN.")
            return
        }
        tun = pfd
        // Device-side consent for full capture. The server can ask; only this grants.
        val allowFull = FullCapturePrefs.allowed(this)
        val ok = Native.startCapture(pfd.fd, pair.apiUrl, pair.workflowId, pair.token, allowFull)
        startedAt = System.currentTimeMillis()
        active = true
        Log.i(TAG, "capture started: mode=$effectiveMode apps=${apps.joinToString().ifEmpty { "-" }} native=$ok")
    }

    private fun stop() {
        // Stopping sends the final batch that ends the session, and the ingest
        // refuses its token from then on, however the stop was asked for: from
        // the app, from the notification, or by Android revoking the VPN.
        if (active) Pairing.markEnded(this)
        active = false
        startedAt = 0L
        runCatching { Native.stopCapture() }
        runCatching { tun?.close() }
        tun = null
        stopForegroundCompat()
        stopSelf()
    }

    override fun onDestroy() {
        stop()
        super.onDestroy()
    }

    /** Android took the VPN away (another VPN app started, or the user turned it off in Settings). */
    override fun onRevoke() {
        stop()
        super.onRevoke()
    }

    private fun fail(why: String) {
        Log.e(TAG, why)
        failure = why
        stopSelf()
    }

    /** Returns false when Android refused the foreground service, having said why. */
    private fun startForegroundCompat(): Boolean {
        val nm = getSystemService(NotificationManager::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            nm.createNotificationChannel(
                NotificationChannel(CHANNEL, "Capture", NotificationManager.IMPORTANCE_LOW)
            )
        }
        // Tap opens the app; a Stop action tears down capture without opening the app.
        val piFlags = PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        val openPi = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java), piFlags
        )
        val stopPi = PendingIntent.getService(
            this, 1, Intent(this, TracerVpnService::class.java).setAction(ACTION_STOP), piFlags
        )
        val n: Notification = Notification.Builder(this, CHANNEL)
            .setContentTitle(getString(R.string.app_name))
            .setContentText("Capturing traffic for authorized testing")
            .setSmallIcon(R.drawable.ic_broadcast)
            .setOngoing(true)
            .setContentIntent(openPi)
            .addAction(Notification.Action.Builder(null, "Stop capture", stopPi).build())
            .build()
        return try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                startForeground(1, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED)
            } else {
                startForeground(1, n)
            }
            true
        } catch (e: Exception) {
            // ForegroundServiceTypeNotAllowedException on Android 14 and later, when
            // Android does not count this app as a VPN app at this moment.
            fail("Android would not run capture in the foreground (${e.javaClass.simpleName}). Tap Start capture again and accept the VPN prompt.")
            false
        }
    }

    private fun stopForegroundCompat() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            stopForeground(STOP_FOREGROUND_REMOVE)
        } else {
            @Suppress("DEPRECATION") stopForeground(true)
        }
    }
}
