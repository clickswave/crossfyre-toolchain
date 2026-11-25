//! One palette for every tool, chosen once for the terminal it runs in.
//!
//! Colours are named for what they mean rather than what they are, so a tool
//! asks for `Tone::Good` instead of green and the whole toolchain shifts
//! together if the palette ever changes.
//!
//! There are three palettes. Where the terminal shows 24-bit colour it is
//! Crossfyre's own, in a dark and a light set picked by the terminal's
//! background. Where it does not, it is the terminal's sixteen. Under
//! `NO_COLOR` there is none, and weight alone carries the meaning.
//!
//! Ordinary text is never given a colour, so it is always the terminal's own
//! and reads on any background.

use ratatui::style::{Color, Modifier, Style};
use std::sync::OnceLock;

/// What a piece of text means, which the palette turns into a colour.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tone {
    /// Ordinary values.
    Plain,
    /// Labels, chrome, anything the eye should skip.
    Muted,
    /// Something worked: a hit, a 2xx, a finished run.
    Good,
    /// Worth a look but not a failure: a redirect, a retry, a slow host.
    Warn,
    /// Something failed, or is serious.
    Bad,
    /// Brand colour. Titles, the bar, the selected tab.
    Accent,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Palette {
    pub accent: Color,
    pub good: Color,
    pub warn: Color,
    pub bad: Color,
    pub muted: Color,
    /// Behind the selected row. `None` where the terminal has no soft
    /// background to offer, and the row is marked by weight alone.
    pub selection: Option<Color>,
}

const fn rgb(hex: u32) -> Color {
    Color::Rgb((hex >> 16) as u8, (hex >> 8) as u8, hex as u8)
}

impl Palette {
    /// Crossfyre's colours on a dark background.
    pub const DARK: Self = Self {
        accent: rgb(0xf98100),
        good: rgb(0x7fb891),
        warn: rgb(0xd6a55e),
        bad: rgb(0xe08c7e),
        muted: rgb(0x8a867d),
        selection: Some(rgb(0x2b2822)),
    };

    /// Crossfyre's colours on a light background: the same hues, darkened
    /// until they read on white.
    pub const LIGHT: Self = Self {
        accent: rgb(0xb35b00),
        good: rgb(0x2f7d4c),
        warn: rgb(0x8a6100),
        bad: rgb(0xa33a2e),
        muted: rgb(0x76726a),
        selection: Some(rgb(0xf1ebe0)),
    };

    /// The terminal's own sixteen, which follow whatever theme it has.
    pub const SIXTEEN: Self = Self {
        accent: Color::Cyan,
        good: Color::Green,
        warn: Color::Yellow,
        bad: Color::Red,
        muted: Color::DarkGray,
        selection: None,
    };

    /// No colour at all.
    pub const PLAIN: Self = Self {
        accent: Color::Reset,
        good: Color::Reset,
        warn: Color::Reset,
        bad: Color::Reset,
        muted: Color::Reset,
        selection: None,
    };

    fn colour(&self, tone: Tone) -> Option<Color> {
        match tone {
            Tone::Plain => None,
            Tone::Muted => Some(self.muted),
            Tone::Good => Some(self.good),
            Tone::Warn => Some(self.warn),
            Tone::Bad => Some(self.bad),
            Tone::Accent => Some(self.accent),
        }
    }
}

/// Whether the terminal's background is dark or light.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scheme {
    Dark,
    Light,
}

/// What the terminal said of its own colours when asked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Seen {
    pub foreground: (u8, u8, u8),
    pub background: (u8, u8, u8),
    pub scheme: Scheme,
}

/// Pick the palette.
///
/// `ask` questions the terminal and is only called when the answer is needed:
/// the question costs a round trip, and a terminal without 24-bit colour gets
/// the same sixteen whatever its background is.
pub fn choose(
    no_color: bool,
    truecolor: bool,
    forced: Option<Scheme>,
    ask: impl FnOnce() -> Option<Seen>,
) -> Palette {
    if no_color {
        return Palette::PLAIN;
    }
    if !truecolor {
        return Palette::SIXTEEN;
    }
    let of = |scheme| match scheme {
        Scheme::Dark => Palette::DARK,
        Scheme::Light => Palette::LIGHT,
    };
    if let Some(scheme) = forced {
        return of(scheme);
    }
    match ask() {
        // The row highlight is mixed from the terminal's own two colours, so it
        // sits right on a background that is neither black nor white.
        Some(seen) => Palette {
            selection: Some(mix(seen.background, seen.foreground, 0.12)),
            ..of(seen.scheme)
        },
        None => Palette::DARK,
    }
}

/// `from` moved `share` of the way to `to`.
fn mix(from: (u8, u8, u8), to: (u8, u8, u8), share: f32) -> Color {
    let part = |a: u8, b: u8| (a as f32 + (b as f32 - a as f32) * share).round() as u8;
    Color::Rgb(part(from.0, to.0), part(from.1, to.1), part(from.2, to.2))
}

/// The palette for this terminal, read from its environment and, where that
/// leaves the background open, from the terminal itself.
///
/// `NO_COLOR` turns colour off. `CROSSFYRE_THEME=light` or `dark` settles the
/// background without asking.
fn detect() -> Palette {
    let env = |name: &str| std::env::var(name).unwrap_or_default();
    let truecolor =
        matches!(env("COLORTERM").as_str(), "truecolor" | "24bit") || !env("WT_SESSION").is_empty();
    let forced = match env("CROSSFYRE_THEME").to_ascii_lowercase().as_str() {
        "light" => Some(Scheme::Light),
        "dark" => Some(Scheme::Dark),
        _ => None,
    };
    choose(!env("NO_COLOR").is_empty(), truecolor, forced, ask_terminal)
}

/// Ask the terminal for its foreground and background.
///
/// The wait is the crate's own, a second. A terminal that cannot answer says
/// so at once, since the question goes out with a second one that nearly
/// every terminal answers. The wait is for a reply that is slow, as over SSH,
/// and a shorter one would not stop that reply: it would arrive after the
/// screen was taken over and be read as keys, `g` and `/` among them.
fn ask_terminal() -> Option<Seen> {
    use terminal_colorsaurus::{QueryOptions, ThemeMode, color_palette};
    let colours = color_palette(QueryOptions::default()).ok()?;
    Some(Seen {
        foreground: colours.foreground.scale_to_8bit(),
        background: colours.background.scale_to_8bit(),
        scheme: match colours.theme_mode() {
            ThemeMode::Dark => Scheme::Dark,
            ThemeMode::Light => Scheme::Light,
        },
    })
}

static PALETTE: OnceLock<Palette> = OnceLock::new();

/// Settle the palette for this run. Called once, before the screen is taken
/// over, since asking the terminal means reading its reply from the keyboard.
pub(crate) fn init() {
    PALETTE.get_or_init(detect);
}

/// The palette in use. Before [`init`], as in a test, it is the sixteen.
pub fn palette() -> Palette {
    PALETTE.get().copied().unwrap_or(Palette::SIXTEEN)
}

/// Text in `tone`.
pub fn tone(tone: Tone) -> Style {
    paint(palette(), tone)
}

fn paint(palette: Palette, tone: Tone) -> Style {
    let style = match palette.colour(tone) {
        Some(colour) => Style::default().fg(colour),
        None => Style::default(),
    };
    // With no colour to dim with, the terminal's own dimming stands in.
    if tone == Tone::Muted && palette == Palette::PLAIN {
        style.add_modifier(Modifier::DIM)
    } else {
        style
    }
}

/// A word on a filled background, for what must be seen in a long list: a
/// severity. Reversing puts the tone behind the word and the terminal's own
/// background in front, which reads on every palette.
pub fn chip(tone: Tone) -> Style {
    self::tone(tone).add_modifier(Modifier::REVERSED | Modifier::BOLD)
}

pub fn title() -> Style {
    tone(Tone::Accent).add_modifier(Modifier::BOLD)
}

pub fn label() -> Style {
    tone(Tone::Muted)
}

pub fn value() -> Style {
    Style::default().add_modifier(Modifier::BOLD)
}

/// Borders and the rules between tabs.
pub fn border() -> Style {
    label()
}

/// The selected row.
pub fn selected() -> Style {
    let style = Style::default().add_modifier(Modifier::BOLD);
    match palette().selection {
        Some(colour) => style.bg(colour),
        None => style,
    }
}

/// A key in the footer, drawn as a key cap.
pub fn cap() -> Style {
    label().add_modifier(Modifier::REVERSED)
}

/// A tab in the results panel's border.
pub fn tab(active: bool) -> Style {
    if active {
        title().add_modifier(Modifier::UNDERLINED)
    } else {
        label()
    }
}

/// The tone of an HTTP status, by its class.
pub fn status_code(code: &str) -> Tone {
    match code.chars().next() {
        Some('2') => Tone::Good,
        Some('3') => Tone::Warn,
        Some('4') | Some('5') => Tone::Bad,
        _ => Tone::Plain,
    }
}

/// The tone of a severity.
pub fn severity(severity: &str) -> Tone {
    match severity {
        "critical" | "high" => Tone::Bad,
        "medium" => Tone::Warn,
        _ => Tone::Muted,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIGHT_TERMINAL: Seen = Seen {
        foreground: (0x20, 0x20, 0x20),
        background: (0xff, 0xff, 0xff),
        scheme: Scheme::Light,
    };

    fn never() -> Option<Seen> {
        panic!("the terminal was asked");
    }

    #[test]
    fn no_color_wins_over_everything() {
        assert_eq!(
            choose(true, true, Some(Scheme::Light), never),
            Palette::PLAIN
        );
    }

    #[test]
    fn a_terminal_without_24_bit_colour_gets_its_own_sixteen_and_is_not_asked() {
        assert_eq!(choose(false, false, None, never), Palette::SIXTEEN);
        assert_eq!(
            choose(false, false, Some(Scheme::Light), never),
            Palette::SIXTEEN
        );
    }

    #[test]
    fn a_forced_scheme_is_taken_without_asking() {
        assert_eq!(
            choose(false, true, Some(Scheme::Light), never),
            Palette::LIGHT
        );
        assert_eq!(
            choose(false, true, Some(Scheme::Dark), never),
            Palette::DARK
        );
    }

    #[test]
    fn a_light_terminal_gets_the_light_colours_and_a_highlight_mixed_from_its_own() {
        let palette = choose(false, true, None, || Some(LIGHT_TERMINAL));
        assert_eq!(palette.accent, Palette::LIGHT.accent);
        assert_eq!(palette.muted, Palette::LIGHT.muted);
        // 12% of the way from white to #202020.
        assert_eq!(palette.selection, Some(Color::Rgb(0xe4, 0xe4, 0xe4)));
    }

    #[test]
    fn a_terminal_that_does_not_answer_is_taken_for_dark() {
        assert_eq!(choose(false, true, None, || None), Palette::DARK);
    }

    #[test]
    fn ordinary_text_is_never_coloured() {
        for palette in [
            Palette::DARK,
            Palette::LIGHT,
            Palette::SIXTEEN,
            Palette::PLAIN,
        ] {
            assert_eq!(paint(palette, Tone::Plain), Style::default());
        }
    }

    #[test]
    fn without_colour_muted_text_is_dimmed() {
        assert!(
            paint(Palette::PLAIN, Tone::Muted)
                .add_modifier
                .contains(Modifier::DIM)
        );
        assert!(
            !paint(Palette::DARK, Tone::Muted)
                .add_modifier
                .contains(Modifier::DIM)
        );
    }
}
