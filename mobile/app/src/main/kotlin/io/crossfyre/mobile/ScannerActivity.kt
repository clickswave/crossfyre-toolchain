package io.crossfyre.mobile

import android.Manifest
import android.content.Intent
import android.net.Uri
import android.provider.Settings
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.statusBars
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import io.crossfyre.mobile.ui.Appearance
import io.crossfyre.mobile.ui.CfxButton
import io.crossfyre.mobile.ui.CfxFonts
import io.crossfyre.mobile.ui.CrossfyreTheme
import io.crossfyre.mobile.ui.Ic
import io.crossfyre.mobile.ui.IconBtn
import io.crossfyre.mobile.ui.Kind
import io.crossfyre.mobile.ui.cfx
import android.content.pm.PackageManager
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.SystemBarStyle
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.Preview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.navigationBars
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.layout.size
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.ContextCompat
import java.util.concurrent.Executors

/**
 * Portrait QR scanner (CameraX preview + ZXing's core decoder, on the phone). Replaces the zxing embedded
 * CaptureActivity, which black-previewed when locked to portrait. Returns the decoded QR string in
 * [EXTRA_QR] via a RESULT_OK activity result. Dark whatever the theme: the camera is the camera.
 */
class ScannerActivity : ComponentActivity() {
    companion object {
        const val EXTRA_QR = "qr"
        private val Light = Color(0xFFF2F1EE)
    }

    private val analysisExecutor = Executors.newSingleThreadExecutor()
    private var done = false

    /** Camera access was refused, so the screen explains instead of closing on its own. */
    private var denied by mutableStateOf(false)

    private val permission =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
            if (granted) recreate() else denied = true
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Draw behind the system bars with light icons on both: the camera is
        // dark whatever the theme.
        enableEdgeToEdge(
            statusBarStyle = SystemBarStyle.dark(android.graphics.Color.TRANSPARENT),
            navigationBarStyle = SystemBarStyle.dark(android.graphics.Color.TRANSPARENT),
        )
        val allowed = ContextCompat.checkSelfPermission(this, Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED
        if (!allowed) permission.launch(Manifest.permission.CAMERA)
        setContent {
            CrossfyreTheme(Appearance.DARK) {
                if (denied) DeniedUi() else if (allowed) ScannerUi() else Box(Modifier.fillMaxSize().background(Color(0xFF0C0C0B)))
            }
        }
    }

    override fun onResume() {
        super.onResume()
        // Back from Android settings with the camera now allowed.
        if (denied && ContextCompat.checkSelfPermission(this, Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED) recreate()
    }

    private fun onQr(value: String) {
        if (done) return
        done = true
        setResult(RESULT_OK, intent.putExtra(EXTRA_QR, value))
        finish()
    }

    @Composable
    private fun TopBar() {
        Row(
            Modifier.fillMaxWidth().windowInsetsPadding(WindowInsets.statusBars).padding(start = 4.dp, end = 16.dp, top = 4.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            IconBtn(R.drawable.ic_x, "Close", Light) { finish() }
            Text("Scan pairing code", style = TextStyle(fontFamily = CfxFonts.head, fontWeight = FontWeight.SemiBold, fontSize = 17.sp, color = Light))
        }
    }

    @Composable
    private fun DeniedUi() {
        Box(Modifier.fillMaxSize().background(Color(0xFF0C0C0B))) {
            Column(
                Modifier.fillMaxSize().padding(horizontal = 32.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp, Alignment.CenterVertically),
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                Ic(R.drawable.ic_camera_slash, 40.dp, Light)
                Text("Camera access is off", style = TextStyle(fontFamily = CfxFonts.head, fontWeight = FontWeight.SemiBold, fontSize = 19.sp, lineHeight = 26.sp, color = Light))
                Text(
                    "Allow the camera for Crossfyre Mobile in Android settings to scan a pairing code. Or sign in and pick a workspace instead.",
                    textAlign = TextAlign.Center,
                    style = TextStyle(fontFamily = CfxFonts.ui, fontSize = 14.5.sp, lineHeight = 21.sp, color = Color(0xFFC8C5BD)),
                )
                CfxButton("Open Android settings", Kind.PRIMARY) {
                    runCatching {
                        startActivity(Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.fromParts("package", packageName, null)))
                    }
                }
                CfxButton("Back", Kind.TEXT, color = Light) { finish() }
            }
            TopBar()
        }
    }

    @Composable
    private fun ScannerUi() {
        Box(Modifier.fillMaxSize().background(Color.Black)) {
            AndroidView(
                modifier = Modifier.fillMaxSize(),
                factory = { ctx ->
                    val previewView = PreviewView(ctx)
                    // TextureView-backed: renders reliably and is screenshottable (SurfaceView isn't).
                    previewView.implementationMode = PreviewView.ImplementationMode.COMPATIBLE
                    val future = ProcessCameraProvider.getInstance(ctx)
                    future.addListener({
                        val provider = future.get()
                        val preview = Preview.Builder().build().also {
                            it.setSurfaceProvider(previewView.surfaceProvider)
                        }
                        val analysis = ImageAnalysis.Builder()
                            .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                            .build()
                        analysis.setAnalyzer(analysisExecutor) { proxy ->
                            val found = runCatching { QrFrames.decode(proxy) }.getOrNull()
                            proxy.close()
                            if (found != null) runOnUiThread { onQr(found) }
                        }
                        provider.unbindAll()
                        runCatching {
                            provider.bindToLifecycle(
                                this@ScannerActivity, CameraSelector.DEFAULT_BACK_CAMERA, preview, analysis
                            )
                        }
                    }, ContextCompat.getMainExecutor(ctx))
                    previewView
                }
            )
            Finder(Modifier.align(Alignment.Center).offset(y = (-24).dp))
            TopBar()
            Column(
                Modifier.align(Alignment.BottomCenter).fillMaxWidth()
                    .windowInsetsPadding(WindowInsets.navigationBars)
                    .padding(start = 28.dp, end = 28.dp, bottom = 36.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(40.dp),
            ) {
                Text(
                    "Point the camera at the pairing code in a Web Tracer session on the dashboard.",
                    textAlign = TextAlign.Center,
                    style = TextStyle(fontFamily = CfxFonts.ui, fontSize = 15.sp, lineHeight = 22.sp, color = Light),
                )
                CfxButton("Cancel", Kind.GHOST, small = true, color = Light) { finish() }
            }
        }
    }

    /** The four corners of the viewfinder, in ember. */
    @Composable
    private fun Finder(modifier: Modifier) {
        val ember = cfx.ember
        Canvas(modifier.size(240.dp)) {
            val l = 34.dp.toPx()
            val w = 3.dp.toPx()
            val h = w / 2
            val s = size.width
            fun corner(x: Float, y: Float, dx: Float, dy: Float) {
                drawLine(ember, Offset(x, y + h * dy), Offset(x + l * dx, y + h * dy), w)
                drawLine(ember, Offset(x + h * dx, y), Offset(x + h * dx, y + l * dy), w)
            }
            corner(0f, 0f, 1f, 1f)
            corner(s, 0f, -1f, 1f)
            corner(0f, s, 1f, -1f)
            corner(s, s, -1f, -1f)
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        analysisExecutor.shutdown()
    }
}
