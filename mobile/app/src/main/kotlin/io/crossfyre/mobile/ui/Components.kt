package io.crossfyre.mobile.ui

import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxScope
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.IntrinsicSize
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.RowScope
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.navigationBars
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBars
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.draw.rotate
import androidx.compose.ui.layout.layout
import androidx.compose.ui.focus.onFocusChanged
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.ColorFilter
import androidx.compose.ui.graphics.PathEffect
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.TextUnit
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.em
import androidx.compose.ui.unit.sp
import io.crossfyre.mobile.Level
import io.crossfyre.mobile.Notice
import io.crossfyre.mobile.R

// The mockups are drawn in CSS pixels and those are dp here, and font sizes in
// px are sp. Everything below is the CSS of the mockup turned into Compose.

// ── Type ─────────────────────────────────────────────────────────────────────

object T {
    @Composable fun title() = TextStyle(fontFamily = CfxFonts.head, fontWeight = FontWeight.SemiBold, fontSize = 22.sp, lineHeight = 28.sp, letterSpacing = (-0.012).em, color = cfx.text)
    @Composable fun lede() = TextStyle(fontFamily = CfxFonts.ui, fontSize = 15.sp, lineHeight = 22.sp, color = cfx.text2)
    @Composable fun body() = TextStyle(fontFamily = CfxFonts.ui, fontSize = 14.5.sp, lineHeight = 21.sp, color = cfx.text2)
    @Composable fun hint() = TextStyle(fontFamily = CfxFonts.ui, fontSize = 13.5.sp, lineHeight = 19.sp, color = cfx.text3)
    @Composable fun eyebrow() = TextStyle(fontFamily = CfxFonts.ui, fontWeight = FontWeight.Bold, fontSize = 11.sp, lineHeight = 16.sp, letterSpacing = 0.06.em, color = cfx.text3)
    @Composable fun rowTitle() = TextStyle(fontFamily = CfxFonts.ui, fontWeight = FontWeight.Medium, fontSize = 15.sp, lineHeight = 21.sp, color = cfx.text)
    @Composable fun rowSub() = TextStyle(fontFamily = CfxFonts.ui, fontSize = 13.5.sp, lineHeight = 19.sp, color = cfx.text3)
    @Composable fun mono(size: TextUnit = 13.sp) = TextStyle(fontFamily = CfxFonts.mono, fontSize = size, lineHeight = 20.sp, color = cfx.text1)
    @Composable fun head() = TextStyle(fontFamily = CfxFonts.head, fontWeight = FontWeight.SemiBold, fontSize = 17.sp, lineHeight = 24.sp, color = cfx.text)
}

/**
 * A sentence with inline code (in backticks) and strong words (in double
 * asterisks), the two marks the mockup's copy uses inside running text.
 */
@Composable
fun marked(s: String): AnnotatedString {
    val c = cfx
    return buildAnnotatedString {
        var i = 0
        while (i < s.length) {
            when {
                s.startsWith("**", i) -> {
                    val end = s.indexOf("**", i + 2).takeIf { it > 0 } ?: s.length
                    withStyle(SpanStyle(color = c.text, fontWeight = FontWeight.SemiBold)) { append(s.substring(i + 2, end)) }
                    i = end + 2
                }
                s[i] == '`' -> {
                    val end = s.indexOf('`', i + 1).takeIf { it > 0 } ?: s.length
                    withStyle(SpanStyle(fontFamily = CfxFonts.mono, fontSize = 12.5.sp, color = c.text1)) { append(s.substring(i + 1, end)) }
                    i = end + 1
                }
                else -> {
                    val next = listOf(s.indexOf("**", i), s.indexOf('`', i)).filter { it >= 0 }.minOrNull() ?: s.length
                    append(s.substring(i, next))
                    i = next
                }
            }
        }
    }
}

// ── Icons ────────────────────────────────────────────────────────────────────

@Composable
fun Ic(res: Int, size: Dp = 20.dp, tint: Color = cfx.text3, modifier: Modifier = Modifier) {
    Image(
        painter = painterResource(res),
        contentDescription = null,
        colorFilter = ColorFilter.tint(tint),
        modifier = modifier.size(size),
    )
}

/** The CSS spinner: a ring with one quarter missing, turning. */
@Composable
fun Spinner(size: Dp = 16.dp, color: Color = cfx.text2, stroke: Dp = 2.dp) {
    val t = rememberInfiniteTransition(label = "spin")
    val angle by t.animateFloat(0f, 360f, infiniteRepeatable(tween(700, easing = LinearEasing)), label = "angle")
    Canvas(Modifier.size(size).rotate(angle)) {
        val w = stroke.toPx()
        drawArc(color, startAngle = 0f, sweepAngle = 270f, useCenter = false, style = Stroke(w),
            topLeft = Offset(w / 2, w / 2), size = androidx.compose.ui.geometry.Size(this.size.width - w, this.size.height - w))
    }
}

// ── Layout pieces ────────────────────────────────────────────────────────────

/** A modifier that draws a 1dp line along the top edge, as the rows' border-top does. */
fun Modifier.topLine(color: Color, show: Boolean = true): Modifier =
    if (!show) this else drawBehind { drawLine(color, Offset(0f, 0f), Offset(size.width, 0f), 1.dp.toPx()) }

fun Modifier.bottomLine(color: Color): Modifier =
    drawBehind { drawLine(color, Offset(0f, size.height), Offset(size.width, size.height), 1.dp.toPx()) }

fun Modifier.tap(enabled: Boolean = true, role: Role = Role.Button, onClick: () -> Unit): Modifier =
    this.clickable(enabled = enabled, role = role, onClick = onClick)

@Composable
fun Eyebrow(text: String, modifier: Modifier = Modifier, color: Color = cfx.text3) {
    Text(text.uppercase(), style = T.eyebrow().copy(color = color), modifier = modifier)
}

/** An eyebrow above a list or card: `.group-label`, which tucks under the gap before it. */
@Composable
fun GroupLabel(text: String) {
    Eyebrow(text, Modifier.padding(start = 2.dp, top = 6.dp, end = 2.dp).offset(y = 0.dp))
}

@Composable
fun CfxCard(modifier: Modifier = Modifier, tight: Boolean = false, live: Boolean = false, content: @Composable ColumnScope.() -> Unit) {
    val c = cfx
    Column(
        modifier
            .fillMaxWidth()
            .background(c.surfaceSolid)
            .border(1.dp, if (live) c.emberLine else c.line)
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(if (tight) 8.dp else 12.dp),
        content = content,
    )
}

/** The bordered list. Children are rows; each draws its own top line except the first. */
@Composable
fun CfxList(modifier: Modifier = Modifier, plain: Boolean = false, content: @Composable ColumnScope.() -> Unit) {
    val c = cfx
    Column(
        modifier
            .fillMaxWidth()
            .then(if (plain) Modifier else Modifier.background(c.surfaceSolid))
            .border(1.dp, c.line),
        content = content,
    )
}

enum class Tone { NONE, OK, WARN, DANGER, INFO, ACCENT }

@Composable
fun toneColor(t: Tone): Color = when (t) {
    Tone.NONE -> cfx.text3
    Tone.OK -> cfx.success
    Tone.WARN -> cfx.warning
    Tone.DANGER -> cfx.danger
    Tone.INFO -> cfx.info
    Tone.ACCENT -> cfx.ember
}

/**
 * One row of a list: an optional leading icon or picture, a title, a secondary
 * line, a note under it, and something on the right.
 */
@Composable
fun CfxRow(
    title: String,
    modifier: Modifier = Modifier,
    first: Boolean = false,
    icon: Int? = null,
    leading: (@Composable () -> Unit)? = null,
    sub: String? = null,
    subMono: Boolean = false,
    subContent: (@Composable () -> Unit)? = null,
    note: String? = null,
    noteTone: Tone = Tone.NONE,
    value: String? = null,
    valueTone: Tone = Tone.NONE,
    trailing: (@Composable () -> Unit)? = null,
    chevron: Int? = null,
    selected: Boolean = false,
    danger: Boolean = false,
    dimTitle: Boolean = false,
    tight: Boolean = false,
    onClick: (() -> Unit)? = null,
) {
    val c = cfx
    Row(
        modifier
            .fillMaxWidth()
            .topLine(c.lineSubtle, !first)
            .then(if (selected) Modifier.background(c.emberTint) else Modifier)
            .then(if (onClick != null) Modifier.tap(onClick = onClick) else Modifier)
            .heightIn(min = 56.dp)
            .padding(horizontal = if (tight) 12.dp else 16.dp, vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        if (icon != null) Ic(icon, 22.dp, if (danger) c.danger else c.text3)
        leading?.invoke()
        Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(1.dp)) {
            Text(title, style = T.rowTitle().copy(color = when { danger -> c.danger; dimTitle -> c.text2; else -> c.text }))
            if (sub != null) {
                Text(sub, style = if (subMono) T.rowSub().copy(fontFamily = CfxFonts.mono, fontSize = 12.sp) else T.rowSub())
            }
            subContent?.invoke()
            if (note != null) {
                Text(note, style = TextStyle(fontFamily = CfxFonts.ui, fontSize = 12.5.sp, lineHeight = 18.sp, color = toneColor(noteTone)), modifier = Modifier.padding(top = 2.dp))
            }
        }
        if (value != null) {
            Text(value, style = TextStyle(fontFamily = CfxFonts.ui, fontSize = 14.sp, color = if (valueTone == Tone.NONE) c.text2 else toneColor(valueTone)), textAlign = TextAlign.End)
        }
        trailing?.invoke()
        if (chevron != null) Ic(chevron, 18.dp, c.text4)
    }
}

@Composable
fun Facts(rows: List<Pair<String, String>>, compact: Boolean = false, mono: Set<String> = emptySet(), valueColor: Map<String, Color> = emptyMap()) {
    val c = cfx
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        for ((k, v) in rows) {
            Row(horizontalArrangement = Arrangement.spacedBy(if (compact) 16.dp else 12.dp)) {
                Text(k, style = TextStyle(fontFamily = CfxFonts.ui, fontSize = 14.sp, lineHeight = 20.sp, color = c.text3),
                    modifier = if (compact) Modifier.width(IntrinsicSize.Max).widthIn(min = 56.dp) else Modifier.width(118.dp))
                val isMono = k in mono
                Text(v, style = TextStyle(
                    fontFamily = if (isMono) CfxFonts.mono else CfxFonts.ui,
                    fontSize = if (isMono) 12.5.sp else 14.sp, lineHeight = 20.sp,
                    color = valueColor[k] ?: c.text1,
                ), modifier = Modifier.weight(1f))
            }
        }
    }
}

// ── Banners and chips ────────────────────────────────────────────────────────

@Composable
fun Banner(level: Level, title: String, body: String? = null, actions: List<Pair<String, () -> Unit>> = emptyList(), modifier: Modifier = Modifier) {
    val c = cfx
    val (bg, line, fg, icon) = when (level) {
        Level.OK -> Quad(c.successTint, c.mix(c.success, 0.35f), c.successLight, R.drawable.ic_check_circle)
        Level.WARN -> Quad(c.warningTint, c.mix(c.warning, 0.35f), c.warningLight, R.drawable.ic_warning)
        Level.DANGER -> Quad(c.dangerTint, c.mix(c.danger, 0.35f), c.dangerLight, R.drawable.ic_warning_circle)
        Level.INFO -> Quad(c.infoTint, c.mix(c.info, 0.35f), c.infoLight, R.drawable.ic_info)
    }
    Row(
        modifier.fillMaxWidth().background(bg).border(1.dp, line).padding(horizontal = 14.dp, vertical = 12.dp),
        horizontalArrangement = Arrangement.spacedBy(11.dp),
    ) {
        Ic(icon, 20.dp, fg, Modifier.padding(top = 1.dp))
        Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(3.dp)) {
            Text(title, style = TextStyle(fontFamily = CfxFonts.ui, fontWeight = FontWeight.SemiBold, fontSize = 14.5.sp, lineHeight = 20.sp, color = fg))
            if (!body.isNullOrEmpty()) Text(marked(body), style = T.hint().copy(color = c.text2))
            if (actions.isNotEmpty()) {
                Row(Modifier.offset(x = (-8).dp).padding(top = 4.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    for ((label, act) in actions) CfxButton(label, Kind.TEXT, small = true, onClick = act)
                }
            }
        }
    }
}

private data class Quad<A, B, C, D>(val a: A, val b: B, val c: C, val d: D)

@Composable
fun Banner(n: Notice, actions: List<Pair<String, () -> Unit>> = emptyList()) = Banner(n.level, n.title, n.body, actions)

@Composable
fun Chip(text: String, tone: Tone = Tone.NONE, big: Boolean = false, dot: Boolean = false, modifier: Modifier = Modifier) {
    val c = cfx
    val fg = toneColor(tone)
    val bg = when (tone) {
        Tone.OK -> c.successTint
        Tone.WARN -> c.warningTint
        Tone.DANGER -> c.dangerTint
        Tone.INFO -> c.infoTint
        Tone.ACCENT -> c.emberTint
        Tone.NONE -> Color.Transparent
    }
    val border = when (tone) {
        Tone.NONE -> c.lineStrong
        Tone.ACCENT -> c.emberLine
        else -> fg.copy(alpha = 0.4f)
    }
    Row(
        modifier.clip(CircleShape).background(bg).border(1.dp, border, CircleShape)
            .padding(horizontal = if (big) 11.dp else 9.dp, vertical = if (big) 3.dp else 1.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        if (dot) Box(Modifier.size(7.dp).clip(CircleShape).background(fg))
        Text(text.uppercase(), maxLines = 1, style = TextStyle(fontFamily = CfxFonts.ui, fontWeight = FontWeight.Bold,
            fontSize = if (big) 12.sp else 11.sp, lineHeight = if (big) 19.sp else 17.6.sp, letterSpacing = 0.04.em, color = fg))
    }
}

// ── Buttons ──────────────────────────────────────────────────────────────────

enum class Kind { PRIMARY, SECONDARY, GHOST, DANGER, DANGER_TEXT, TEXT, TEXT_DIM, WARN_TEXT }

@Composable
fun CfxButton(
    text: String,
    kind: Kind = Kind.PRIMARY,
    modifier: Modifier = Modifier,
    block: Boolean = false,
    small: Boolean = false,
    icon: Int? = null,
    iconSize: Dp = 18.dp,
    busy: Boolean = false,
    enabled: Boolean = true,
    color: Color? = null,
    onClick: () -> Unit,
) {
    val c = cfx
    val (bg, border, fg) = when (kind) {
        Kind.PRIMARY -> Triple(c.emberFill, Color.Transparent, c.emberFg)
        Kind.SECONDARY -> Triple(c.surface2, c.lineStrong, c.text1)
        Kind.GHOST -> Triple(Color.Transparent, c.line, c.text2)
        Kind.DANGER -> Triple(c.danger, Color.Transparent, c.ground)
        Kind.DANGER_TEXT -> Triple(Color.Transparent, c.danger.copy(alpha = 0.4f), c.danger)
        Kind.TEXT -> Triple(Color.Transparent, Color.Transparent, c.ember)
        Kind.TEXT_DIM -> Triple(Color.Transparent, Color.Transparent, c.text2)
        Kind.WARN_TEXT -> Triple(Color.Transparent, Color.Transparent, c.warning)
    }
    val textual = kind == Kind.TEXT || kind == Kind.TEXT_DIM || kind == Kind.WARN_TEXT
    val minH = when {
        textual && small -> 36.dp
        textual -> 44.dp
        small -> 38.dp
        else -> 48.dp
    }
    val hpad = when {
        textual && small -> 6.dp
        textual -> 8.dp
        small -> 12.dp
        else -> 18.dp
    }
    // Disabled is the same colours at half strength, as the mockup's opacity, but
    // applied to the colours rather than through a layer: a layer whose alpha
    // changed from half to full left the fill undrawn.
    fun dim(x: Color) = if (enabled) x else x.copy(alpha = x.alpha * 0.5f)
    val ink = dim(color ?: fg)
    val shape = RoundedCornerShape(4.dp)
    Row(
        modifier
            .then(if (block) Modifier.fillMaxWidth() else Modifier)
            .heightIn(min = minH)
            .clip(shape)
            .background(dim(bg))
            .border(1.dp, dim(border), shape)
            .clickable(enabled = enabled && !busy, role = Role.Button, onClick = onClick)
            .padding(horizontal = hpad),
        horizontalArrangement = Arrangement.spacedBy(8.dp, Alignment.CenterHorizontally),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        if (busy) Spinner(16.dp, ink)
        else if (icon != null) Ic(icon, iconSize, ink)
        Text(
            text, maxLines = 1,
            style = TextStyle(
                fontFamily = CfxFonts.ui,
                fontWeight = if (textual) FontWeight.SemiBold else FontWeight.Bold,
                fontSize = if (small) 13.5.sp else 15.sp, lineHeight = 18.sp, color = ink,
            ),
        )
    }
}

@Composable
fun IconBtn(res: Int, label: String, tint: Color = cfx.text2, size: Dp = 22.dp, onClick: () -> Unit) {
    Box(
        Modifier.size(44.dp).clip(CircleShape).clickable(role = Role.Button, onClick = onClick).semantics { contentDescription = label },
        contentAlignment = Alignment.Center,
    ) { Ic(res, size, tint) }
}

@Composable
fun CfxSwitch(checked: Boolean, enabled: Boolean = true, label: String, onClick: () -> Unit) {
    val c = cfx
    val shape = CircleShape
    Box(
        Modifier
            .size(46.dp, 28.dp)
            .alpha(if (enabled) 1f else 0.5f)
            .clip(shape)
            .background(if (checked) c.ember else c.line)
            .border(1.dp, if (checked) c.ember else c.lineStrong, shape)
            .clickable(role = Role.Switch, onClick = onClick)
            .semantics { contentDescription = label },
    ) {
        Box(
            Modifier.offset(x = if (checked) 22.dp else 4.dp, y = 4.dp).size(18.dp).clip(CircleShape)
                .background(if (checked) c.text else c.text2)
        )
    }
}

@Composable
fun Seg(options: List<Pair<String, String>>, selected: String, onSelect: (String) -> Unit) {
    val c = cfx
    Row(
        Modifier.fillMaxWidth().clip(RoundedCornerShape(4.dp)).background(c.surfaceInput).border(1.dp, c.line, RoundedCornerShape(4.dp)).padding(4.dp),
        horizontalArrangement = Arrangement.spacedBy(4.dp),
    ) {
        for ((key, label) in options) {
            val on = key == selected
            val shape = RoundedCornerShape(3.dp)
            Box(
                Modifier.weight(1f).height(36.dp).clip(shape)
                    .background(if (on) c.emberTint else Color.Transparent)
                    .border(1.dp, if (on) c.emberLineStrong else Color.Transparent, shape)
                    .clickable(role = Role.Tab) { onSelect(key) },
                contentAlignment = Alignment.Center,
            ) {
                Text(label, maxLines = 1, style = TextStyle(fontFamily = CfxFonts.ui, fontWeight = FontWeight.SemiBold, fontSize = 13.5.sp, color = if (on) c.ember else c.text3))
            }
        }
    }
}

// ── Fields ───────────────────────────────────────────────────────────────────

@Composable
fun InputBox(
    value: String,
    onChange: (String) -> Unit,
    modifier: Modifier = Modifier,
    placeholder: String? = null,
    password: Boolean = false,
    bad: Boolean = false,
    enabled: Boolean = true,
    mono: Boolean = false,
    leading: Int? = null,
    keyboard: KeyboardOptions = KeyboardOptions.Default,
    actions: KeyboardActions = KeyboardActions.Default,
    trailing: (@Composable () -> Unit)? = null,
    label: String? = null,
) {
    val c = cfx
    var focused by remember { mutableStateOf(false) }
    val border = when {
        bad -> c.danger.copy(alpha = 0.6f)
        focused -> c.emberLineStrong
        else -> c.lineStrong
    }
    BasicTextField(
        value = value,
        onValueChange = onChange,
        enabled = enabled,
        singleLine = true,
        visualTransformation = if (password) PasswordVisualTransformation() else VisualTransformation.None,
        keyboardOptions = keyboard,
        keyboardActions = actions,
        cursorBrush = SolidColor(c.ember),
        textStyle = TextStyle(fontFamily = if (mono) CfxFonts.mono else CfxFonts.ui, fontSize = if (mono) 14.sp else 15.sp, color = c.text),
        modifier = modifier.fillMaxWidth().onFocusChanged { focused = it.isFocused }
            .then(if (label != null) Modifier.semantics { contentDescription = label } else Modifier),
        decorationBox = { inner ->
            Row(
                Modifier.fillMaxWidth().height(48.dp)
                    .then(if (focused) Modifier.border(3.dp, c.emberTint, RoundedCornerShape(6.dp)) else Modifier)
                    .padding(if (focused) 0.dp else 0.dp)
                    .clip(RoundedCornerShape(4.dp)).background(c.surfaceInput)
                    .border(1.dp, border, RoundedCornerShape(4.dp))
                    .padding(start = if (leading != null) 14.dp else 14.dp, end = if (trailing != null) 2.dp else 14.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                if (leading != null) {
                    Ic(leading, 18.dp, c.text3)
                    Spacer(Modifier.width(10.dp))
                }
                Box(Modifier.weight(1f)) {
                    if (value.isEmpty() && placeholder != null) Text(placeholder, style = TextStyle(fontFamily = CfxFonts.ui, fontSize = 15.sp, color = c.text4))
                    inner()
                }
                trailing?.invoke()
            }
        },
    )
}

@Composable
fun Field(label: String, content: @Composable () -> Unit, error: String? = null) {
    Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
        Text(label, style = TextStyle(fontFamily = CfxFonts.ui, fontWeight = FontWeight.SemiBold, fontSize = 13.sp, lineHeight = 17.sp, color = cfx.text2))
        content()
        if (error != null) Text(error, style = TextStyle(fontFamily = CfxFonts.ui, fontSize = 13.sp, color = cfx.danger))
    }
}

@Composable
fun SearchBox(value: String, onChange: (String) -> Unit, placeholder: String) {
    InputBox(
        value, onChange, placeholder = placeholder, leading = R.drawable.ic_magnifying_glass, label = placeholder,
        keyboard = KeyboardOptions(imeAction = ImeAction.Search, keyboardType = KeyboardType.Text),
    )
}

@Composable
fun Checkbox(on: Boolean) {
    val c = cfx
    val shape = RoundedCornerShape(3.dp)
    Box(
        Modifier.size(20.dp).clip(shape).background(if (on) c.emberFill else Color.Transparent).border(2.dp, if (on) c.emberFill else c.text3, shape),
        contentAlignment = Alignment.Center,
    ) { if (on) Ic(R.drawable.ic_check, 14.dp, c.emberFg) }
}

@Composable
fun Radio(on: Boolean) {
    val c = cfx
    Box(Modifier.size(20.dp).clip(CircleShape).border(2.dp, if (on) c.ember else c.text3, CircleShape), contentAlignment = Alignment.Center) {
        if (on) Box(Modifier.size(10.dp).clip(CircleShape).background(c.ember))
    }
}

// ── People and apps ──────────────────────────────────────────────────────────

@Composable
fun Avatar(initials: String?, small: Boolean = false) {
    val c = cfx
    val ghost = initials == null
    Box(
        Modifier.size(if (small) 30.dp else 38.dp).clip(CircleShape)
            .background(if (ghost) c.surface2 else c.emberTintStrong)
            .border(1.dp, if (ghost) c.lineStrong else c.emberLine, CircleShape),
        contentAlignment = Alignment.Center,
    ) {
        if (ghost) Ic(R.drawable.ic_user, 18.dp, c.text3)
        else Text(initials!!, style = TextStyle(fontFamily = CfxFonts.ui, fontWeight = FontWeight.Bold, fontSize = if (small) 11.sp else 13.sp, letterSpacing = 0.02.em, color = c.ember))
    }
}

/** Two letters for an avatar, from a username. */
fun initialsOf(name: String): String = name.filter { it.isLetterOrDigit() }.take(2).uppercase().ifEmpty { "?" }

@Composable
fun AppIcon(label: String, size: Dp = 40.dp) {
    val c = cfx
    Box(
        Modifier.size(size).clip(CircleShape).background(c.surfaceRaised).border(1.dp, c.line, CircleShape),
        contentAlignment = Alignment.Center,
    ) {
        Text(label.take(1).uppercase(), style = TextStyle(fontFamily = CfxFonts.head, fontWeight = FontWeight.SemiBold,
            fontSize = (size.value * 0.4f).sp, color = c.text2))
    }
}

// ── Empty, loading ───────────────────────────────────────────────────────────

@Composable
fun Empty(icon: Int?, title: String, body: String? = null, plain: Boolean = false, content: (@Composable () -> Unit)? = null) {
    val c = cfx
    Column(
        Modifier.fillMaxWidth()
            .then(if (plain) Modifier else Modifier.drawBehind {
                drawRect(c.lineStrong, style = Stroke(1.dp.toPx(), pathEffect = PathEffect.dashPathEffect(floatArrayOf(6f, 6f))))
            })
            .padding(horizontal = if (plain) 12.dp else 20.dp, vertical = if (plain) 32.dp else 28.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        if (icon != null) Ic(icon, 30.dp, c.text4)
        Text(title, textAlign = TextAlign.Center, style = TextStyle(fontFamily = CfxFonts.ui, fontWeight = FontWeight.SemiBold, fontSize = 15.sp, lineHeight = 21.sp, color = c.text1))
        if (body != null) Text(body, textAlign = TextAlign.Center, style = T.hint(), modifier = Modifier.widthIn(max = 280.dp))
        content?.invoke()
    }
}

@Composable
fun Skel(width: Float, height: Dp, strong: Boolean = false, round: Boolean = false, modifier: Modifier = Modifier) {
    val t = rememberInfiniteTransition(label = "pulse")
    val a by t.animateFloat(1f, 0.55f, infiniteRepeatable(tween(700), RepeatMode.Reverse), label = "a")
    Box(
        modifier.fillMaxWidth(width).height(height).alpha(a)
            .then(if (round) Modifier.clip(CircleShape) else Modifier)
            .background(if (strong) cfx.skelStrong else cfx.skel)
    )
}

@Composable
fun SkelRow(first: Boolean, iconSize: Dp = 20.dp, titleW: Float = 0.58f, subW: Float = 0.34f) {
    Row(
        Modifier.fillMaxWidth().topLine(cfx.lineSubtle, !first).padding(horizontal = 16.dp, vertical = 14.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        Box(Modifier.size(iconSize)) { Skel(1f, iconSize, strong = iconSize > 20.dp, round = true) }
        Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(7.dp)) {
            Skel(titleW, 13.dp, strong = true)
            Skel(subW, 11.dp)
        }
    }
}

@Composable
fun Authz(text: String = "Only capture apps and traffic you are authorized to test.") {
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        Ic(R.drawable.ic_shield_check, 16.dp, cfx.text3, Modifier.padding(top = 1.dp))
        Text(text, style = TextStyle(fontFamily = CfxFonts.ui, fontSize = 13.sp, lineHeight = 18.sp, color = cfx.text3))
    }
}

/** Numbered steps, the mockup's `ol.howto`. */
@Composable
fun HowTo(steps: List<String>) {
    Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
        steps.forEachIndexed { i, s ->
            Row {
                Text("${i + 1}.", style = TextStyle(fontFamily = CfxFonts.mono, fontWeight = FontWeight.Bold, fontSize = 13.sp, lineHeight = 20.sp, color = cfx.ember), modifier = Modifier.width(30.dp))
                Text(marked(s), style = TextStyle(fontFamily = CfxFonts.ui, fontSize = 14.sp, lineHeight = 20.sp, color = cfx.text2))
            }
        }
    }
}

/** A heading that opens and closes what is under it. */
@Composable
fun Toggle(text: String, open: Boolean, onClick: () -> Unit) {
    Row(
        Modifier.fillMaxWidth().heightIn(min = 32.dp).tap(onClick = onClick),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(text, modifier = Modifier.weight(1f), style = TextStyle(fontFamily = CfxFonts.ui, fontWeight = FontWeight.SemiBold, fontSize = 14.5.sp, lineHeight = 21.sp, color = cfx.text))
        Ic(if (open) R.drawable.ic_caret_up else R.drawable.ic_caret_down, 18.dp, cfx.text3)
    }
}

// ── Chrome ───────────────────────────────────────────────────────────────────

@Composable
fun Brand(size: TextUnit = 15.sp, mark: Dp = 26.dp, gap: Dp = 9.dp) {
    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(gap)) {
        Image(painterResource(R.drawable.cfx_mark), contentDescription = null, modifier = Modifier.size(mark))
        Wordmark(size)
    }
}

@Composable
fun Wordmark(size: TextUnit = 15.sp) {
    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(9.dp),
        modifier = Modifier.semantics(mergeDescendants = true) {}) {
        Text("CROSSFYRE", style = TextStyle(fontFamily = CfxFonts.brand, fontWeight = FontWeight.SemiBold, fontSize = size, letterSpacing = 0.0815.em, color = cfx.text))
        Text("Mobile", style = TextStyle(fontFamily = CfxFonts.head, fontWeight = FontWeight.SemiBold, fontSize = size, letterSpacing = (-0.01).em, color = cfx.ember))
    }
}

@Composable
fun AppBar(
    title: String = "",
    onBack: (() -> Unit)? = null,
    plain: Boolean = false,
    brand: Boolean = false,
    right: @Composable RowScope.() -> Unit = {},
) {
    val c = cfx
    Column(
        Modifier.fillMaxWidth()
            .background(if (plain) c.ground else c.shell)
            .then(if (plain) Modifier else Modifier.bottomLine(c.line))
            .windowInsetsPadding(WindowInsets.statusBars)
    ) {
        Row(
            Modifier.fillMaxWidth().height(56.dp).padding(start = if (onBack != null) 4.dp else 16.dp, end = 6.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            if (onBack != null) IconBtn(R.drawable.ic_arrow_left, "Back", c.text2, onClick = onBack)
            Box(Modifier.weight(1f)) {
                if (brand) Brand()
                else Text(title, maxLines = 1, overflow = TextOverflow.Ellipsis,
                    style = TextStyle(fontFamily = CfxFonts.head, fontWeight = FontWeight.SemiBold, fontSize = 20.sp, lineHeight = 26.sp, letterSpacing = (-0.01).em, color = c.text))
            }
            right()
        }
    }
}

data class TabSpec(val key: String, val icon: Int, val label: String, val locked: Boolean = false, val live: Boolean = false)

@Composable
fun Tabs(tabs: List<TabSpec>, current: String, onSelect: (String) -> Unit) {
    val c = cfx
    Row(
        Modifier.fillMaxWidth().background(c.shell).topLine(c.line).windowInsetsPadding(WindowInsets.navigationBars),
    ) {
        for (t in tabs) {
            val on = t.key == current
            Column(
                Modifier.weight(1f).height(64.dp)
                    .clickable(role = Role.Tab) { onSelect(t.key) }
                    .semantics { contentDescription = if (t.locked) "${t.label}, not available yet" else t.label }
                    .drawBehind {
                        if (on) {
                            val w = 28.dp.toPx()
                            drawRoundRect(c.ember, topLeft = Offset((size.width - w) / 2, -1.dp.toPx()),
                                size = androidx.compose.ui.geometry.Size(w, 3.dp.toPx()),
                                cornerRadius = androidx.compose.ui.geometry.CornerRadius(4.dp.toPx()))
                        }
                    },
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(4.dp, Alignment.CenterVertically),
            ) {
                val ink = when {
                    t.locked && on -> c.text2
                    t.locked -> c.text4
                    on -> c.text
                    else -> c.text3
                }
                Box {
                    Ic(t.icon, 24.dp, if (on && !t.locked) c.ember else ink)
                    if (t.locked) {
                        Box(Modifier.align(Alignment.BottomEnd).offset(x = 9.dp, y = 4.dp).size(14.dp).clip(CircleShape).background(c.shell), contentAlignment = Alignment.Center) {
                            Ic(R.drawable.ic_lock_simple, 10.dp, c.text4)
                        }
                    }
                    if (t.live) {
                        Box(Modifier.align(Alignment.TopEnd).offset(x = 4.dp, y = (-2).dp).size(13.dp).clip(CircleShape).background(c.shell), contentAlignment = Alignment.Center) {
                            Box(Modifier.size(9.dp).clip(CircleShape).background(c.success))
                        }
                    }
                }
                Text(t.label, style = TextStyle(fontFamily = CfxFonts.ui, fontWeight = FontWeight.SemiBold, fontSize = 11.5.sp, lineHeight = 11.5.sp, letterSpacing = 0.01.em, color = ink))
            }
        }
    }
}

/** The pinned footer of a full-screen page: `.dock`. */
@Composable
fun Dock(content: @Composable ColumnScope.() -> Unit) {
    val c = cfx
    Column(
        Modifier.fillMaxWidth().background(c.shell).topLine(c.line).windowInsetsPadding(WindowInsets.navigationBars)
            .padding(start = 16.dp, end = 16.dp, top = 12.dp, bottom = 14.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
        content = content,
    )
}

// ── Overlays ─────────────────────────────────────────────────────────────────

@Composable
fun Scrim(onClick: (() -> Unit)?) {
    Box(
        Modifier.fillMaxSize().background(cfx.scrim)
            .clickable(interactionSource = remember { MutableInteractionSource() }, indication = null, enabled = true) { onClick?.invoke() }
    )
}

/**
 * A bottom sheet, square-cornered like every panel here, over a scrim. Drawn in
 * the app's own tree rather than as a separate window, so it takes the theme and
 * the insets the rest of the screen has.
 */
@Composable
fun BoxScope.Sheet(
    title: @Composable () -> Unit,
    onDismiss: (() -> Unit)?,
    tall: Boolean = false,
    head: @Composable RowScope.() -> Unit = {},
    foot: (@Composable ColumnScope.() -> Unit)? = null,
    body: @Composable ColumnScope.() -> Unit,
) {
    val c = cfx
    Scrim(onDismiss)
    Column(
        Modifier.align(Alignment.BottomCenter).fillMaxWidth()
            .windowInsetsPadding(WindowInsets.statusBars)
            .padding(top = 56.dp)
            .then(if (tall) Modifier.fillMaxSize() else Modifier)
            .clickable(interactionSource = remember { MutableInteractionSource() }, indication = null) {}
            .background(c.surfaceSolid)
            .topLine(c.lineStrong)
            .windowInsetsPadding(WindowInsets.navigationBars)
            .imePadding()
            .padding(bottom = 22.dp),
    ) {
        Box(Modifier.padding(top = 10.dp, bottom = 2.dp).align(Alignment.CenterHorizontally).size(36.dp, 4.dp).clip(CircleShape).background(c.lineStrong))
        Row(Modifier.fillMaxWidth().padding(start = 16.dp, end = 8.dp, top = 8.dp, bottom = 10.dp), verticalAlignment = Alignment.CenterVertically) {
            Box(Modifier.weight(1f)) { title() }
            head()
        }
        Column(
            Modifier.fillMaxWidth().then(if (tall) Modifier.weight(1f) else Modifier.weight(1f, fill = false))
                .verticalScroll(rememberScrollState()).padding(start = 16.dp, end = 16.dp, top = 2.dp, bottom = 16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
            content = body,
        )
        if (foot != null) {
            Column(Modifier.fillMaxWidth().topLine(c.line).padding(start = 16.dp, end = 16.dp, top = 12.dp), verticalArrangement = Arrangement.spacedBy(8.dp), content = foot)
        }
    }
}

@Composable
fun SheetTitle(text: String) {
    Text(text, style = T.head())
}

@Composable
fun BoxScope.CfxDialog(
    title: String,
    onDismiss: (() -> Unit)?,
    actions: @Composable RowScope.() -> Unit,
    body: @Composable ColumnScope.() -> Unit,
) {
    val c = cfx
    Scrim(onDismiss)
    Column(
        Modifier.align(Alignment.Center).padding(horizontal = 22.dp).fillMaxWidth()
            .clickable(interactionSource = remember { MutableInteractionSource() }, indication = null) {}
            .background(c.surfaceSolid).border(1.dp, c.lineStrong)
            .padding(start = 20.dp, end = 20.dp, top = 20.dp, bottom = 12.dp)
            .semantics { contentDescription = title },
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text(title, style = TextStyle(fontFamily = CfxFonts.head, fontWeight = FontWeight.SemiBold, fontSize = 18.sp, lineHeight = 24.sp, color = c.text))
        Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
            androidx.compose.runtime.CompositionLocalProvider(
                androidx.compose.material3.LocalTextStyle provides TextStyle(fontFamily = CfxFonts.ui, fontSize = 14.5.sp, lineHeight = 21.sp, color = c.text2)
            ) { body() }
        }
        Row(Modifier.fillMaxWidth().offset(x = 6.dp), horizontalArrangement = Arrangement.spacedBy(4.dp, Alignment.End), content = actions)
    }
}

@Composable
fun BoxScope.Toast(text: String, icon: Int, aboveTabs: Boolean) {
    val c = cfx
    Row(
        Modifier.align(Alignment.BottomCenter)
            .windowInsetsPadding(WindowInsets.navigationBars)
            .padding(start = 16.dp, end = 16.dp, bottom = if (aboveTabs) 82.dp else 24.dp)
            .fillMaxWidth()
            .clip(RoundedCornerShape(4.dp))
            .background(c.surfaceRaised).border(1.dp, c.lineStrong, RoundedCornerShape(4.dp))
            .padding(horizontal = 14.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        Ic(icon, 20.dp, if (icon == R.drawable.ic_check_circle) c.success else c.text2)
        Text(text, style = TextStyle(fontFamily = CfxFonts.ui, fontSize = 14.sp, lineHeight = 19.sp, color = c.text))
    }
}

/** The patch meter: a thin bar, or a sliding segment while there is nothing to measure. */
@Composable
fun Meter(percent: Float?, modifier: Modifier = Modifier) {
    val c = cfx
    val t = rememberInfiniteTransition(label = "indet")
    val x by t.animateFloat(-1.1f, 3.6f, infiniteRepeatable(tween(1300)), label = "x")
    Box(
        modifier.fillMaxWidth().height(6.dp).clip(CircleShape).background(c.surfaceInput).border(1.dp, c.lineSubtle, CircleShape)
            .drawBehind {
                if (percent == null) {
                    val w = size.width * 0.3f
                    drawRect(c.ember, topLeft = Offset(w * x, 0f), size = androidx.compose.ui.geometry.Size(w, size.height))
                } else {
                    drawRect(c.ember, size = androidx.compose.ui.geometry.Size(size.width * (percent / 100f).coerceIn(0f, 1f), size.height))
                }
            }
    )
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun Wrap(content: @Composable () -> Unit) {
    FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) { content() }
}

@Composable
fun AppChip(label: String) {
    val c = cfx
    Row(
        Modifier.clip(CircleShape).border(1.dp, c.line, CircleShape).padding(start = 3.dp, end = 10.dp, top = 2.dp, bottom = 2.dp),
        verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        AppIcon(label, 20.dp)
        Text(label, style = TextStyle(fontFamily = CfxFonts.ui, fontSize = 12.5.sp, color = c.text2))
    }
}

/**
 * Pull a block into the space around it, as a negative CSS margin does: it is
 * measured as usual and then laid out [top] and [bottom] shorter, overlapping the
 * gaps on either side.
 */
fun Modifier.tuck(top: Dp = 0.dp, bottom: Dp = 0.dp): Modifier = this.then(
    Modifier.layout { measurable, constraints ->
        val p = measurable.measure(constraints)
        val t = top.roundToPx()
        val b = bottom.roundToPx()
        layout(p.width, (p.height - t - b).coerceAtLeast(0)) { p.place(0, -t) }
    }
)
