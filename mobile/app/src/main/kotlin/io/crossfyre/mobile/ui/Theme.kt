package io.crossfyre.mobile.ui

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.Immutable
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.Font
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import io.crossfyre.mobile.R

/**
 * The Crossfyre tokens, both halves, as the dashboard defines them.
 *
 * Every colour here comes from the dashboard's tokens.css. Where the CSS mixes a
 * colour with transparent (`color-mix(in srgb, X 40%, transparent)`), the
 * result is the same colour at that alpha, which is what the `*Line` values are.
 */
@Immutable
data class CfxColors(
    val dark: Boolean,
    val ember: Color,
    val emberLight: Color,
    val emberFill: Color,
    val emberFg: Color,
    val emberStrong: Color,
    val emberTint: Color,
    val emberTintStrong: Color,
    val emberLine: Color,
    val emberLineStrong: Color,
    val text: Color,
    val text1: Color,
    val text2: Color,
    val text3: Color,
    val text4: Color,
    val skel: Color,
    val skelStrong: Color,
    val shell: Color,
    val ground: Color,
    val surfaceSolid: Color,
    val surfaceRaised: Color,
    val surface2: Color,
    val surfaceInput: Color,
    val scrim: Color,
    val line: Color,
    val lineSubtle: Color,
    val lineStrong: Color,
    val danger: Color,
    val dangerLight: Color,
    val dangerTint: Color,
    val success: Color,
    val successLight: Color,
    val successTint: Color,
    val warning: Color,
    val warningLight: Color,
    val warningTint: Color,
    val info: Color,
    val infoLight: Color,
    val infoTint: Color,
) {
    /** A semantic colour as a border, the way the CSS mixes it with transparent. */
    fun mix(c: Color, amount: Float): Color = c.copy(alpha = amount)
}

private fun tint(r: Int, g: Int, b: Int, a: Float) = Color(r, g, b, (a * 255).toInt())

val DarkCfx = CfxColors(
    dark = true,
    ember = Color(0xFFF98100),
    emberLight = Color(0xFFFFA24A),
    emberFill = Color(0xFFA85500),
    emberFg = Color(0xFFFDFCFA),
    emberStrong = Color(0xFFB35B00),
    emberTint = tint(249, 129, 0, 0.10f),
    emberTintStrong = tint(249, 129, 0, 0.18f),
    emberLine = tint(249, 129, 0, 0.28f),
    emberLineStrong = tint(249, 129, 0, 0.45f),
    text = Color(0xFFD2D0CB),
    text1 = Color(0xFFBDBAB3),
    text2 = Color(0xFFAAA69E),
    text3 = Color(0xFF9C988F),
    text4 = Color(0xFF7C786F),
    skel = tint(247, 246, 243, 0.055f),
    skelStrong = tint(247, 246, 243, 0.10f),
    shell = Color(27, 26, 24),
    ground = Color(35, 34, 32),
    surfaceSolid = Color(44, 43, 39),
    surfaceRaised = Color(52, 50, 41),
    surface2 = tint(247, 246, 243, 0.025f),
    surfaceInput = tint(0, 0, 0, 0.20f),
    scrim = tint(0, 0, 0, 0.55f),
    line = tint(247, 246, 243, 0.09f),
    lineSubtle = tint(247, 246, 243, 0.05f),
    lineStrong = tint(247, 246, 243, 0.17f),
    danger = Color(0xFFE08C7E),
    dangerLight = Color(0xFFECAA9E),
    dangerTint = tint(224, 140, 126, 0.12f),
    success = Color(0xFF7FB891),
    successLight = Color(0xFF9BC9A9),
    successTint = tint(127, 184, 145, 0.13f),
    warning = Color(0xFFD6A55E),
    warningLight = Color(0xFFE5BD84),
    warningTint = tint(214, 165, 94, 0.13f),
    info = Color(0xFF8AA9CC),
    infoLight = Color(0xFFA8C1DE),
    infoTint = tint(138, 169, 204, 0.13f),
)

val LightCfx = CfxColors(
    dark = false,
    ember = Color(0xFFA85500),
    emberLight = Color(0xFF8A4600),
    emberFill = Color(0xFFA85500),
    emberFg = Color(0xFFFDFCFA),
    emberStrong = Color(0xFF8A4600),
    emberTint = tint(168, 85, 0, 0.08f),
    emberTintStrong = tint(168, 85, 0, 0.14f),
    emberLine = tint(168, 85, 0, 0.28f),
    emberLineStrong = tint(168, 85, 0, 0.45f),
    text = Color(0xFF22201D),
    text1 = Color(0xFF3F3D38),
    text2 = Color(0xFF57544E),
    text3 = Color(0xFF67635A),
    text4 = Color(0xFF8A8880),
    skel = tint(34, 32, 29, 0.096f),
    skelStrong = tint(34, 32, 29, 0.175f),
    shell = Color(239, 237, 231),
    ground = Color(247, 246, 243),
    surfaceSolid = Color(255, 254, 251),
    surfaceRaised = Color(239, 237, 231),
    surface2 = tint(34, 32, 29, 0.035f),
    surfaceInput = tint(255, 255, 255, 0.85f),
    scrim = tint(34, 32, 29, 0.42f),
    line = tint(34, 32, 29, 0.12f),
    lineSubtle = tint(34, 32, 29, 0.07f),
    lineStrong = tint(34, 32, 29, 0.22f),
    danger = Color(0xFFA33A2E),
    dangerLight = Color(0xFF82291F),
    dangerTint = tint(163, 58, 46, 0.09f),
    success = Color(0xFF2E6B45),
    successLight = Color(0xFF1F4E31),
    successTint = tint(46, 107, 69, 0.09f),
    warning = Color(0xFF8A5A11),
    warningLight = Color(0xFF6B450A),
    warningTint = tint(138, 90, 17, 0.09f),
    info = Color(0xFF3A5F87),
    infoLight = Color(0xFF2A4767),
    infoTint = tint(58, 95, 135, 0.09f),
)

val LocalCfx = staticCompositionLocalOf { DarkCfx }

/** The palette in force, read from anywhere in the tree. */
val cfx: CfxColors @Composable get() = LocalCfx.current

/**
 * The four faces, as the dashboard applies them: Inter for the interface, Outfit
 * for headings, JetBrains Mono for anything copied out of traffic, and Orbitron
 * for the word CROSSFYRE and nothing else.
 *
 * Each weight is its own file, cut from the dashboard's variable fonts at the
 * weights the app uses. Android ignored the weight axis when a variable font was
 * loaded from resources and drew every heading at Outfit's default, Thin. All
 * four are under the SIL Open Font License, which allows bundling them.
 */
object CfxFonts {
    val ui = FontFamily(
        Font(R.font.inter_400, FontWeight.Normal),
        Font(R.font.inter_500, FontWeight.Medium),
        Font(R.font.inter_600, FontWeight.SemiBold),
        Font(R.font.inter_700, FontWeight.Bold),
    )
    val head = FontFamily(
        Font(R.font.outfit_500, FontWeight.Medium),
        Font(R.font.outfit_600, FontWeight.SemiBold),
    )
    val mono = FontFamily(
        Font(R.font.jetbrains_mono_400, FontWeight.Normal),
        Font(R.font.jetbrains_mono_500, FontWeight.Medium),
        Font(R.font.jetbrains_mono_700, FontWeight.Bold),
    )
    val brand = FontFamily(Font(R.font.orbitron_600, FontWeight.SemiBold))
}

/** How the app picks light or dark: the phone's setting, or a fixed one from Settings. */
enum class Appearance(val key: String, val label: String) {
    PHONE("phone", "Match phone"),
    DARK("dark", "Dark"),
    LIGHT("light", "Light");

    companion object {
        fun of(key: String?): Appearance = entries.firstOrNull { it.key == key } ?: PHONE
    }
}

@Composable
fun isDark(appearance: Appearance): Boolean = when (appearance) {
    Appearance.PHONE -> isSystemInDarkTheme()
    Appearance.DARK -> true
    Appearance.LIGHT -> false
}

@Composable
fun CrossfyreTheme(appearance: Appearance = Appearance.PHONE, content: @Composable () -> Unit) {
    val dark = isDark(appearance)
    val c = if (dark) DarkCfx else LightCfx
    // Material components that are used as they come (text selection, the
    // progress indicator's defaults) take their colours from here, so they agree
    // with the tokens rather than with Material's purple.
    val scheme = if (dark) {
        darkColorScheme(
            primary = c.ember, onPrimary = c.emberFg, background = c.ground, onBackground = c.text,
            surface = c.surfaceSolid, onSurface = c.text, surfaceVariant = c.surfaceRaised,
            onSurfaceVariant = c.text2, outline = c.lineStrong, error = c.danger,
        )
    } else {
        lightColorScheme(
            primary = c.ember, onPrimary = c.emberFg, background = c.ground, onBackground = c.text,
            surface = c.surfaceSolid, onSurface = c.text, surfaceVariant = c.surfaceRaised,
            onSurfaceVariant = c.text2, outline = c.lineStrong, error = c.danger,
        )
    }
    CompositionLocalProvider(LocalCfx provides c) {
        MaterialTheme(colorScheme = scheme, content = content)
    }
}
