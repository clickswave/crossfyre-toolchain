package io.crossfyre.mobile

import android.Manifest
import android.content.ActivityNotFoundException
import android.content.Intent
import android.graphics.Color
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import androidx.activity.ComponentActivity
import androidx.activity.SystemBarStyle
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.browser.customtabs.CustomTabsIntent
import androidx.compose.runtime.LaunchedEffect
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import io.crossfyre.mobile.ui.Appearance
import io.crossfyre.mobile.ui.AppRoot
import io.crossfyre.mobile.ui.CrossfyreTheme
import io.crossfyre.mobile.ui.isDark
import kotlinx.coroutines.launch

/**
 * The one screen of the app. It hosts the interface and does what only an
 * activity can: Android's permission and VPN prompts, the QR scanner, the
 * system's file picker, and opening other apps. Everything else lives in
 * [AppModel], so a prompt that recreates this activity loses nothing.
 */
class MainActivity : ComponentActivity() {

    private val model: AppModel by viewModels()

    private val vpnConsent =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { res ->
            model.vpnAnswered(res.resultCode == RESULT_OK)
        }

    // POST_NOTIFICATIONS has been a runtime permission since Android 13, and the
    // manifest entry alone does nothing: it has to be asked for. A foreground
    // service starts anyway, so without asking, capture ran with no notification,
    // and the notification is how a capture admits to existing and offers a Stop.
    private val notificationConsent =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) {
            // Read back from the system rather than from this argument, because
            // they disagree when the person has permanently denied it.
            model.notificationsAnswered()
        }

    private val scan = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { res ->
        if (res.resultCode == RESULT_OK) {
            res.data?.getStringExtra(ScannerActivity.EXTRA_QR)?.let { model.scanned(it) }
        }
    }

    private val caSave =
        registerForActivityResult(ActivityResultContracts.CreateDocument("application/x-x509-ca-cert")) { uri ->
            if (uri == null) return@registerForActivityResult model.certSaved(false)
            val pem = model.caPemForSaving()
            val ok = pem != null && runCatching {
                contentResolver.openOutputStream(uri)?.use { it.write(pem.toByteArray()) } != null
            }.getOrDefault(false)
            model.certSaved(ok)
        }

    private val apkSave =
        registerForActivityResult(ActivityResultContracts.CreateDocument("application/vnd.android.package-archive")) { uri ->
            if (uri == null) return@registerForActivityResult model.say("Export cancelled.", R.drawable.ic_info)
            val said = runCatching {
                contentResolver.openOutputStream(uri)?.use { model.patch.export(it) } ?: "Export failed."
            }.getOrElse { "Export failed: ${it.message}" }
            model.say(said, if (said.startsWith("Exported")) R.drawable.ic_check_circle else R.drawable.ic_warning)
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        runCatching { Native.setStorageDir(filesDir.absolutePath) }

        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                launch { model.poll() }
                model.effects.collect { handle(it) }
            }
        }

        setContent {
            val appearance = Appearance.of(model.appearance)
            val dark = isDark(appearance)
            // The bars are drawn over the app, so their icons follow the theme in
            // force, which is not always the phone's: Settings can fix it to one.
            LaunchedEffect(dark) {
                val style = if (dark) SystemBarStyle.dark(Color.TRANSPARENT)
                else SystemBarStyle.light(Color.TRANSPARENT, Color.TRANSPARENT)
                enableEdgeToEdge(statusBarStyle = style, navigationBarStyle = style)
            }
            CrossfyreTheme(appearance) { AppRoot(model) }
        }
    }

    override fun onResume() {
        super.onResume()
        model.onResumed()
    }

    private fun handle(e: Effect) {
        when (e) {
            Effect.AskNotifications -> {
                if (Build.VERSION.SDK_INT >= 33) notificationConsent.launch(Manifest.permission.POST_NOTIFICATIONS)
                else model.notificationsAnswered()
            }
            is Effect.AskVpn -> vpnConsent.launch(e.intent)
            Effect.Scan -> scan.launch(Intent(this, ScannerActivity::class.java))
            is Effect.SaveCa -> caSave.launch(e.fileName)
            is Effect.ExportApk -> apkSave.launch(e.fileName)
            is Effect.OpenUrl -> openUrl(e.url)
            Effect.NotificationSettings -> open(
                Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS).putExtra(Settings.EXTRA_APP_PACKAGE, packageName),
                Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.fromParts("package", packageName, null)),
            )
            Effect.SecuritySettings -> open(Intent(Settings.ACTION_SECURITY_SETTINGS), Intent(Settings.ACTION_SETTINGS))
        }
    }

    /**
     * A Custom Tab shares the browser's cookies, so an account already signed in
     * there approves a browser sign-in in a tap. Anything without a browser that
     * supports one falls back to a plain view intent.
     */
    private fun openUrl(url: String) {
        val uri = Uri.parse(url)
        try {
            CustomTabsIntent.Builder().setShowTitle(true).build().launchUrl(this, uri)
        } catch (e: ActivityNotFoundException) {
            runCatching { startActivity(Intent(Intent.ACTION_VIEW, uri)) }
                .onFailure { model.say("No app on this phone can open $url", R.drawable.ic_info) }
        }
    }

    private fun open(first: Intent, fallback: Intent) {
        try {
            startActivity(first)
        } catch (e: ActivityNotFoundException) {
            runCatching { startActivity(fallback) }
        }
    }
}
