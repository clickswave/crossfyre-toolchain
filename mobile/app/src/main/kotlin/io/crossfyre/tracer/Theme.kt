package io.crossfyre.tracer

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp

/**
 * Crossfyre palette, mirrored from the web app design tokens (services/web_server tokens.css): a dark
 * zinc scale with a single ember accent. Kept as plain vals so non-Material surfaces (cards, the status
 * grid, the CA banner) can pull the exact same colors as the Material scheme.
 */
object Cfx {
    val ember = Color(0xFFFF6B35)
    val emberLight = Color(0xFFFF8C5A)
    val emberStrong = Color(0xFFC92800)
    val emberTint = Color(0x14FF6B35) // ~0.08 alpha
    val emberLine = Color(0x40FF6B35) // ~0.25 alpha

    val bg = Color(0xFF0A0A0B)
    val surface = Color(0xFF141416)
    val surfaceRaised = Color(0xFF18181B)
    val surfaceInput = Color(0xFF000000)

    val line = Color(0x14FFFFFF) // white 0.08
    val lineStrong = Color(0x29FFFFFF) // white 0.16

    val text = Color(0xFFFFFFFF)
    val text1 = Color(0xFFD4D4D8)
    val text2 = Color(0xFFA1A1AA)
    val text3 = Color(0xFF71717A)

    val danger = Color(0xFFEF4444)
    val dangerLight = Color(0xFFF87171)
    val dangerTint = Color(0x1AEF4444)
    val success = Color(0xFF10B981)
    val successLight = Color(0xFF34D399)
    val successTint = Color(0x1A10B981)
    val warning = Color(0xFFF59E0B)
    val warningLight = Color(0xFFFBBF24)
    val warningTint = Color(0x1AF59E0B)

    val mono = FontFamily.Monospace
}

private val CfxScheme = darkColorScheme(
    primary = Cfx.ember,
    onPrimary = Color(0xFF14100E),
    secondary = Cfx.emberLight,
    background = Cfx.bg,
    onBackground = Cfx.text1,
    surface = Cfx.surface,
    onSurface = Cfx.text1,
    surfaceVariant = Cfx.surfaceRaised,
    onSurfaceVariant = Cfx.text2,
    outline = Cfx.lineStrong,
    error = Cfx.danger,
)

private val CfxType = Typography(
    titleLarge = TextStyle(fontWeight = FontWeight.Bold, fontSize = 20.sp, letterSpacing = 1.sp),
    titleMedium = TextStyle(fontWeight = FontWeight.SemiBold, fontSize = 15.sp),
    bodyMedium = TextStyle(fontSize = 14.sp, color = Cfx.text1),
    bodySmall = TextStyle(fontSize = 12.sp, color = Cfx.text2),
    labelLarge = TextStyle(fontWeight = FontWeight.SemiBold, fontSize = 14.sp, letterSpacing = 0.5.sp),
)

@Composable
fun CrossfyreTheme(content: @Composable () -> Unit) {
    // Always dark: crossfyre is a dark-first brand.
    @Suppress("UNUSED_EXPRESSION") isSystemInDarkTheme()
    MaterialTheme(colorScheme = CfxScheme, typography = CfxType, content = content)
}
