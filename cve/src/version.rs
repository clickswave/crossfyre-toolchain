//! Versions as products write them, in the order their releases follow each other.

use std::cmp::Ordering;

/// A version as a banner, a header or the dataset writes it: dotted ("2.4.49"), semver
/// with a pre-release ("1.2.3-beta.1"), OpenSSH's portable releases ("8.9p1"),
/// OpenSSL's letter releases ("1.1.1w"), a build after a dash ("13.1-49.13"), Cisco's
/// interim releases in brackets ("9.16(3)23"), and any
/// of them with a distribution's build on the end ("2.4.52-1ubuntu4.3",
/// "1:8.9p1-3ubuntu0.6", "7.4.33-1+deb11u5"). A distribution's build is not ordered:
/// it only marks the version as one a distribution built, which may carry a fix the
/// upstream version does not say.
#[derive(Debug, Clone)]
pub struct Version {
    pieces: Vec<Piece>,
    distro: bool,
}

#[derive(Debug, Clone)]
enum Piece {
    /// A run of digits.
    Number(u64),
    /// A word that comes before the release it is on: alpha, beta, rc, or a semver
    /// pre-release. Its rank orders the known ones.
    Before(u8, String),
    /// A word that comes after the release it is on: OpenSSH's p in 8.9p1, OpenSSL's
    /// letter in 1.1.1w.
    After(String),
}

/// Words that come before a release, in the order they come.
const BEFORE: &[(&str, u8)] = &[
    ("dev", 0),
    ("snapshot", 0),
    ("a", 1),
    ("alpha", 1),
    ("b", 2),
    ("beta", 2),
    ("m", 3),
    ("milestone", 3),
    ("ea", 4),
    ("pre", 4),
    ("preview", 4),
    ("rc", 5),
    ("cr", 5),
];

/// Words that name the release itself, and so are not ordered.
const RELEASE: &[&str] = &["release", "final", "ga", "stable"];

impl Version {
    /// `text` as a version, or none when it holds no number.
    pub fn parse(text: &str) -> Option<Version> {
        let mut text = text.trim();
        let mut distro = false;
        // A Debian epoch, "1:", belongs to a package, not to the product.
        if let Some((epoch, rest)) = text.split_once(':')
            && !epoch.is_empty()
            && epoch.bytes().all(|b| b.is_ascii_digit())
        {
            text = rest;
            distro = true;
        }
        if let Some(rest) = text.strip_prefix(['v', 'V'])
            && rest.starts_with(|c: char| c.is_ascii_digit())
        {
            text = rest;
        }
        // The release runs to the first '-', '~', '+', space or bracket. What follows is a
        // build, a pre-release, a distribution's build or build metadata. A bracket around
        // a number, as Cisco writes 9.16(3)23, is part of the release.
        let end = text
            .char_indices()
            .find(|&(i, c)| {
                matches!(c, '-' | '~' | '+' | ' ')
                    || (c == '(' && !text[i + 1..].starts_with(|n: char| n.is_ascii_digit()))
            })
            .map_or(text.len(), |(i, _)| i);
        let (core, rest) = text.split_at(end);
        if !core.bytes().any(|b| b.is_ascii_digit()) {
            return None;
        }
        let mut pieces = pieces_of(core);
        let mut chars = rest.chars();
        if let Some(separator) = chars.next() {
            let suffix = chars.as_str();
            let dotted_number = !suffix.is_empty()
                && suffix.starts_with(|c: char| c.is_ascii_digit())
                && suffix.bytes().all(|b| b.is_ascii_digit() || b == b'.');
            if separator == '-' && dotted_number {
                // A build of the release, as NetScaler writes 13.1-49.13.
                pieces.extend(pieces_of(suffix));
            } else if distro_build(suffix) {
                distro = true;
            } else if matches!(separator, '-' | '~') && !suffix.is_empty() {
                pieces.extend(pre_release(suffix));
            }
            // After '+', a space or a bracket, anything else is metadata that orders
            // nothing.
        }
        Some(Version { pieces, distro })
    }

    /// Whether a distribution built it, as its own suffix or epoch says.
    pub fn distro(&self) -> bool {
        self.distro
    }
}

/// Whether `suffix`, what follows a version's release, is a distribution's build:
/// Debian's and Ubuntu's revisions, RPM releases, Alpine's -r.
fn distro_build(suffix: &str) -> bool {
    let s = suffix.to_ascii_lowercase();
    const MARKS: &[&str] = &[
        "ubuntu", "debian", "dfsg", "raspbian", "centos", "rhel", "redhat", "red hat", "fedora",
        "amzn", "suse", "sles", "alpine", "mageia", "freebsd",
    ];
    if MARKS.iter().any(|m| s.contains(m)) {
        return true;
    }
    // deb11u5, el7, el8_6, fc38, mga9: a mark and its release number.
    let numbered = ["deb", "el", "fc", "mga"].iter().any(|mark| {
        s.match_indices(mark).any(|(at, _)| {
            let before = s[..at].chars().next_back();
            let after = s[at + mark.len()..].chars().next();
            before.is_none_or(|c| !c.is_ascii_alphabetic())
                && after.is_some_and(|c| c.is_ascii_digit())
        })
    });
    // A Debian or RPM revision starts with its number: 1ubuntu4.3, 99.el7, 1+deb11u5.
    let revision = s.starts_with(|c: char| c.is_ascii_digit());
    // Alpine's package release: -r0.
    let alpine = s.len() > 1 && s.starts_with('r') && s[1..].bytes().all(|b| b.is_ascii_digit());
    numbered || revision || alpine
}

/// The pieces of a release: its numbers, split at dots and underscores, and the words
/// between them.
fn pieces_of(core: &str) -> Vec<Piece> {
    let mut pieces = Vec::new();
    let runs: Vec<&str> = runs(core);
    for (i, run) in runs.iter().enumerate() {
        if run.starts_with(|c: char| c.is_ascii_digit()) {
            // A number too long for u64 is no version anyone writes; it orders as the most.
            pieces.push(Piece::Number(run.parse().unwrap_or(u64::MAX)));
            continue;
        }
        let word = run.to_ascii_lowercase();
        if RELEASE.contains(&word.as_str()) {
            continue;
        }
        // A letter alone at the end is OpenSSL's next release (1.1.1w), not an alpha.
        let last_letter = word.len() == 1 && i + 1 == runs.len();
        match BEFORE.iter().find(|(w, _)| *w == word) {
            Some((_, rank)) if !last_letter => pieces.push(Piece::Before(*rank, word)),
            _ => pieces.push(Piece::After(word)),
        }
    }
    pieces
}

/// A semver pre-release's identifiers, all before the release they are on.
fn pre_release(suffix: &str) -> Vec<Piece> {
    runs(suffix)
        .into_iter()
        .map(|run| match run.parse() {
            Ok(n) => Piece::Number(n),
            Err(_) => {
                let word = run.to_ascii_lowercase();
                let rank = BEFORE
                    .iter()
                    .find(|(w, _)| *w == word)
                    .map_or(u8::MAX, |(_, rank)| *rank);
                Piece::Before(rank, word)
            }
        })
        .collect()
}

/// `text` cut into runs of digits and runs of letters; anything else separates them.
fn runs(text: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut start = None;
    let mut digits = false;
    for (i, c) in text.char_indices() {
        let kind = if c.is_ascii_digit() {
            Some(true)
        } else if c.is_ascii_alphabetic() {
            Some(false)
        } else {
            None
        };
        match (start, kind) {
            (Some(s), Some(d)) if d != digits => {
                out.push(&text[s..i]);
                start = Some(i);
                digits = d;
            }
            (Some(s), None) => {
                out.push(&text[s..i]);
                start = None;
            }
            (None, Some(d)) => {
                start = Some(i);
                digits = d;
            }
            _ => {}
        }
    }
    if let Some(s) = start {
        out.push(&text[s..]);
    }
    out
}

/// Where a piece, or the end of a version, falls at one position: a word before a
/// release, then the release itself (its end, or a 0), then a word after it, then any
/// later number.
fn key(piece: Option<&Piece>) -> (u8, u64, u8, &str) {
    match piece {
        Some(Piece::Before(rank, word)) => (0, 0, *rank, word),
        None | Some(Piece::Number(0)) => (1, 0, 0, ""),
        Some(Piece::After(word)) => (2, 0, 0, word),
        Some(Piece::Number(n)) => (3, *n, 0, ""),
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        for i in 0..self.pieces.len().max(other.pieces.len()) {
            match key(self.pieces.get(i)).cmp(&key(other.pieces.get(i))) {
                Ordering::Equal => continue,
                order => return order,
            }
        }
        Ordering::Equal
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for Version {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for Version {}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(text: &str) -> Version {
        Version::parse(text).unwrap_or_else(|| panic!("{text} is no version"))
    }

    /// Each list is in the order its releases came out.
    fn in_order(versions: &[&str]) {
        for pair in versions.windows(2) {
            assert!(v(pair[0]) < v(pair[1]), "{} before {}", pair[0], pair[1]);
            assert!(v(pair[1]) > v(pair[0]), "{} after {}", pair[1], pair[0]);
        }
    }

    #[test]
    fn dotted_versions_order_by_each_number() {
        in_order(&["2.4.5", "2.4.9", "2.4.49", "2.4.50", "2.5", "10.0"]);
        assert_eq!(v("2.4"), v("2.4.0"));
        assert_eq!(v("v1.21.0"), v("1.21"));
    }

    #[test]
    fn a_semver_pre_release_comes_before_its_release() {
        in_order(&[
            "1.2.3-alpha",
            "1.2.3-alpha.2",
            "1.2.3-beta.1",
            "1.2.3-rc.1",
            "1.2.3",
            "1.2.4-rc1",
            "1.2.4",
        ]);
        assert_eq!(v("1.2.3+build.5"), v("1.2.3"));
        in_order(&["3.12.0a1", "3.12.0b2", "3.12.0rc1", "3.12.0"]);
        assert_eq!(v("5.3.27.RELEASE"), v("5.3.27"));
    }

    #[test]
    fn openssh_portable_releases_come_after_their_release() {
        in_order(&[
            "8.5", "8.5p1", "8.5p2", "8.9p1", "9.0", "9.0p1", "9.8p1", "9.10p1",
        ]);
    }

    #[test]
    fn openssl_letter_releases_come_after_their_release() {
        in_order(&[
            "1.0.1", "1.0.1a", "1.0.1g", "1.0.2", "1.1.1", "1.1.1a", "1.1.1w", "3.0.0",
        ]);
    }

    #[test]
    fn cisco_s_interim_releases_in_brackets_are_ordered() {
        in_order(&[
            "9.16",
            "9.16(1)",
            "9.16(3)",
            "9.16(3)23",
            "9.16(4)",
            "9.17(1)",
        ]);
        assert!(!v("9.16(3)23").distro());
        assert_eq!(v("2.4.52 (Ubuntu)"), v("2.4.52"));
    }

    #[test]
    fn a_build_after_a_dash_is_ordered() {
        in_order(&[
            "13.1",
            "13.1-37.38",
            "13.1-49.12",
            "13.1-49.13",
            "13.1-49.15",
            "14.1-4.42",
        ]);
    }

    #[test]
    fn a_distribution_s_build_is_marked_and_not_ordered() {
        for (text, release) in [
            ("2.4.52-1ubuntu4.3", "2.4.52"),
            ("1:8.9p1-3ubuntu0.6", "8.9p1"),
            ("7.4.33-1+deb11u5", "7.4.33"),
            ("2.4.6-99.el7", "2.4.6"),
            ("1.24.0-r7", "1.24.0"),
            ("8.9p1 Ubuntu-3ubuntu0.6", "8.9p1"),
            ("2.4.57+dfsg", "2.4.57"),
        ] {
            assert!(v(text).distro(), "{text}");
            assert_eq!(v(text), v(release), "{text}");
        }
        for upstream in [
            "2.4.52",
            "8.9p1",
            "1.2.3-beta.1",
            "13.1-49.13",
            "1.2.3+build.5",
        ] {
            assert!(!v(upstream).distro(), "{upstream}");
        }
    }

    #[test]
    fn text_with_no_number_is_no_version() {
        for text in ["", "*", "-", "unspecified", "n/a"] {
            assert!(Version::parse(text).is_none(), "{text}");
        }
    }
}
