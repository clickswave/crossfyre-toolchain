package io.crossfyre.mobile

import android.Manifest
import android.app.KeyguardManager
import android.content.ActivityNotFoundException
import android.content.Intent
import android.graphics.Color
import android.hardware.biometrics.BiometricManager
import android.hardware.biometrics.BiometricPrompt
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.CancellationSignal
import android.provider.Settings
import androidx.activity.ComponentActivity
import androidx.activity.SystemBarStyle
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.annotation.RequiresApi
import androidx.browser.customtabs.CustomTabsIntent
import androidx.compose.runtime.LaunchedEffect
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import io.crossfyre.mobile.push.PushSetup
import io.crossfyre.mobile.ui.Appearance
import io.crossfyre.mobile.ui.AppRoot
import io.crossfyre.mobile.ui.CrossfyreTheme
import io.crossfyre.mobile.ui.isDark
import kotlinx.coroutines.launch

/**
 * The one screen of the app. It hosts the interface and does what only an
 * activity can: Android's permission, VPN and unlock prompts, the QR scanner,
 * the system's file picker, links into the app, and opening other apps.
 * Everything else lives in [AppModel], so a prompt that recreates this activity
 * loses nothing.
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
    // Approvals and alerts arrive as notifications too, asked for once the phone
    // approves. Its answer starts nothing else, unlike the capture's.
    private val alertConsent =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) { model.alertsAnswered() }

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

    // Android 8 to 10: the lock screen's own confirmation. The key then signs for
    // fifteen seconds, which the model uses straight away.
    private val confirmCredential =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { res ->
            model.lockConfirmed(res.resultCode == RESULT_OK)
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
                // Pending approvals, asked for only while the app is in sight.
                launch { model.watchApprovals() }
                model.effects.collect { handle(it) }
            }
        }
        if (savedInstanceState == null) openFrom(intent)

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

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        openFrom(intent)
    }

    private fun openFrom(intent: Intent?) {
        if (intent?.getBooleanExtra(PushSetup.EXTRA_PUSHED, false) == true) model.openPushed(intent.dataString)
        else model.openLink(intent?.dataString)
    }

    override fun onResume() {
        super.onResume()
        model.onResumed()
    }

    private fun handle(e: Effect) {
        when (e) {
            Effect.AskAlerts -> {
                if (Build.VERSION.SDK_INT >= 33) alertConsent.launch(Manifest.permission.POST_NOTIFICATIONS)
                else model.alertsAnswered()
            }
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
            is Effect.Authenticate -> if (Build.VERSION.SDK_INT >= 30) unlockPrompt(e) else confirmLock(e)
        }
    }

    /**
     * Android 11 and later: the system prompt, holding the signature the approval
     * key will make. The keystore lets that one signature through only once the
     * person has unlocked, with a strong biometric or the screen lock.
     */
    @RequiresApi(30)
    private fun unlockPrompt(e: Effect.Authenticate) {
        val sig = model.signatureForUnlock(e.id) ?: return
        val prompt = BiometricPrompt.Builder(this)
            .setTitle(e.title)
            .setDescription(e.description)
            .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG or BiometricManager.Authenticators.DEVICE_CREDENTIAL)
            .build()
        prompt.authenticate(
            BiometricPrompt.CryptoObject(sig), CancellationSignal(), mainExecutor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    model.unlocked(e.id, result.cryptoObject?.signature ?: sig)
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence?) {
                    val cancelled = errorCode == BiometricPrompt.BIOMETRIC_ERROR_USER_CANCELED || errorCode == BiometricPrompt.BIOMETRIC_ERROR_CANCELED
                    model.unlockCancelled(e.id, if (cancelled) null else errString?.toString())
                }
            },
        )
    }

    /** Android 8 to 10: confirm the screen lock, then sign within the key's fifteen seconds. */
    private fun confirmLock(e: Effect.Authenticate) {
        val keyguard = getSystemService(KeyguardManager::class.java)
        @Suppress("DEPRECATION")
        val intent = keyguard?.createConfirmDeviceCredentialIntent(e.title, e.description)
            ?: return model.unlockCancelled(e.id, "This phone has no screen lock, so it cannot approve.")
        confirmCredential.launch(intent)
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
