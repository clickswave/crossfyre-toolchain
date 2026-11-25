//! Text a scanned system wrote, made fit to show.
//!
//! A page title, a banner or an error message comes from whatever was scanned,
//! and is read by a person in a terminal, or by a model in a transcript a person
//! may never see. Either way it may not carry what a terminal or a renderer acts
//! on or does not show: escape sequences, control characters, and the invisible
//! and reordering code points that let a page carry text nobody sees.

use regex::Regex;
use std::sync::LazyLock;

// CSI (colours, cursor movement), OSC (window titles, hyperlinks) terminated by BEL
// or ST, and the two-byte escapes. An OSC with no terminator falls through to the
// two-byte form, which removes the ESC and leaves the rest as visible text.
static ANSI: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[@-Z\\-_]")
        .expect("ansi pattern")
});

/// Code points that render as nothing, or reorder what is around them.
fn invisible(c: char) -> bool {
    matches!(c,
        '\u{200B}'..='\u{200F}'      // zero-width space, joiners, LRM, RLM
        | '\u{2060}'..='\u{2064}'    // word joiner and invisible operators
        | '\u{FEFF}'                 // zero-width no-break space
        | '\u{202A}'..='\u{202E}'    // bidi embeddings and overrides
        | '\u{2066}'..='\u{2069}'    // bidi isolates
        | '\u{061C}'                 // Arabic letter mark
        | '\u{180E}'                 // Mongolian vowel separator
        | '\u{00AD}'                 // soft hyphen
        | '\u{034F}'                 // combining grapheme joiner
        | '\u{115F}' | '\u{1160}' | '\u{3164}' | '\u{FFA0}' // Hangul fillers
        | '\u{FE00}'..='\u{FE0F}'    // variation selectors
        | '\u{E0100}'..='\u{E01EF}'  // variation selectors supplement
        | '\u{180B}'..='\u{180F}'    // Mongolian free variation selectors
        | '\u{2028}' | '\u{2029}'    // line and paragraph separators
        | '\u{206A}'..='\u{206F}'    // deprecated shaping and digit controls
        | '\u{FFF9}'..='\u{FFFB}'    // interlinear annotation, which some renderers hide
        | '\u{17B4}' | '\u{17B5}'    // Khmer inherent vowels, which render as nothing
        // Number signs and other prepended format characters: Arabic, Syriac,
        // Kaithi, Egyptian hieroglyph and shorthand controls, musical beams.
        | '\u{0600}'..='\u{0605}'
        | '\u{06DD}'
        | '\u{070F}'
        | '\u{0890}' | '\u{0891}'
        | '\u{08E2}'
        | '\u{110BD}' | '\u{110CD}'
        | '\u{13430}'..='\u{1343F}'
        | '\u{1BCA0}'..='\u{1BCA3}'
        | '\u{1D173}'..='\u{1D17A}'
        // Tag characters. They mirror ASCII one for one and render as nothing, which
        // makes them a way to spell out a whole sentence no person can see.
        | '\u{E0000}'..='\u{E007F}'
    )
}

/// `s` without escape sequences, control characters other than `\n` and `\t`,
/// and the invisible and reordering code points above. A `\r` goes with the
/// other control characters, which turns a CRLF into a plain newline.
pub fn strip(s: &str) -> String {
    ANSI.replace_all(s, "")
        .chars()
        .filter(|&c| !((c.is_control() && c != '\n' && c != '\t') || invisible(c)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_and_invisible_characters_are_removed() {
        let raw = "a\x1b[31mred\x1b[0m \x1b]0;title\x07b\u{202E}c\u{200B}d\u{E0041}\u{E0042}e\r\nf";
        assert_eq!(strip(raw), "ared bcde\nf");
    }

    #[test]
    fn format_and_separator_characters_go_too() {
        // Every one of these renders as nothing, breaks a line where none shows, or
        // hides the text after it in some renderer.
        for c in [
            '\u{2028}',
            '\u{2029}',
            '\u{206A}',
            '\u{206F}',
            '\u{FFF9}',
            '\u{FFFB}',
            '\u{0600}',
            '\u{06DD}',
            '\u{070F}',
            '\u{0890}',
            '\u{08E2}',
            '\u{110BD}',
            '\u{110CD}',
            '\u{13430}',
            '\u{1343F}',
            '\u{1BCA0}',
            '\u{1D173}',
            '\u{1D17A}',
            '\u{180B}',
            '\u{180F}',
            '\u{17B4}',
            '\u{17B5}',
        ] {
            assert_eq!(
                strip(&format!("a{c}b")),
                "ab",
                "U+{:04X} survived",
                c as u32
            );
        }
    }

    #[test]
    fn c1_controls_and_del_go_too() {
        assert_eq!(strip("x\u{7f}y\u{85}z\u{9b}"), "xyz");
    }
}
