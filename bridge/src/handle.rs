//! The names an agent uses for exchanges and for pages: `wx_` handles and `wc_` cursors.
//!
//! An exchange id means something only inside one project, and the operator can switch
//! projects between an agent's read and its replay. So a handle carries the first ten
//! hex characters of the project's uid, and a handle from another project is refused
//! instead of reaching whatever row has that number in the one open now.
//!
//! The prefixes keep clear of the other ids an MCP client is given: `s_` and `f_` for
//! local scans and findings, and `c` with a second letter for Cloud's.
//!
//! Parsing is strict. Each value has exactly one spelling, and anything else is refused
//! rather than read as the nearest thing it might have meant.

use std::fmt;
use std::str::FromStr;

use crate::{HistoryCursor, SiteMapCursor};

pub const HANDLE_PREFIX: &str = "wx_";
pub const CURSOR_PREFIX: &str = "wc_";

/// The longest method, host and path a site map cursor carries, in bytes.
pub const SITE_MAP_CURSOR_METHOD_MAX: usize = 32;
pub const SITE_MAP_CURSOR_HOST_MAX: usize = 255;
pub const SITE_MAP_CURSOR_PATH_MAX: usize = 4096;

/// Is this a project uid: 32 lowercase hex characters.
pub fn is_project_uid(s: &str) -> bool {
    s.len() == 32 && is_lower_hex(s)
}

fn is_lower_hex(s: &str) -> bool {
    s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// The first ten characters of a project's uid.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProjectTag([u8; ProjectTag::LEN]);

impl ProjectTag {
    pub const LEN: usize = 10;

    /// The tag of a project uid, or `None` when `uid` is not one.
    pub fn of(uid: &str) -> Option<ProjectTag> {
        if !is_project_uid(uid) {
            return None;
        }
        Self::parse(&uid[..Self::LEN])
    }

    fn parse(s: &str) -> Option<ProjectTag> {
        if s.len() != Self::LEN || !is_lower_hex(s) {
            return None;
        }
        let mut b = [0u8; Self::LEN];
        b.copy_from_slice(s.as_bytes());
        Some(ProjectTag(b))
    }

    pub fn as_str(&self) -> &str {
        // Only ever built from checked lowercase hex.
        std::str::from_utf8(&self.0).unwrap_or_default()
    }

    /// Is this the tag of `uid`.
    pub fn matches(&self, uid: &str) -> bool {
        is_project_uid(uid) && uid.as_bytes()[..Self::LEN] == self.0
    }
}

impl fmt::Display for ProjectTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl fmt::Debug for ProjectTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ProjectTag({})", self.as_str())
    }
}

/// A non-negative decimal with no sign and no leading zero, at most 18 digits so it
/// always fits an `i64`.
fn decimal(s: &str) -> Option<i64> {
    if s.is_empty() || s.len() > 18 || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    if s.len() > 1 && s.starts_with('0') {
        return None;
    }
    s.parse().ok()
}

fn hex(s: &str) -> String {
    s.bytes().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str, max: usize) -> Option<String> {
    if s.is_empty() || s.len() % 2 != 0 || s.len() > max * 2 || !is_lower_hex(s) {
        return None;
    }
    let bytes: Option<Vec<u8>> = (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect();
    String::from_utf8(bytes?).ok()
}

/// One exchange in one project: `wx_<tag>_<id>`, as in `wx_3f9a0c21be_1042`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ExchangeHandle {
    pub project: ProjectTag,
    pub id: i64,
}

impl ExchangeHandle {
    /// `None` when `project_uid` is not a uid or `id` is negative.
    pub fn new(project_uid: &str, id: i64) -> Option<ExchangeHandle> {
        if id < 0 {
            return None;
        }
        Some(ExchangeHandle {
            project: ProjectTag::of(project_uid)?,
            id,
        })
    }
}

impl fmt::Display for ExchangeHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{HANDLE_PREFIX}{}_{}", self.project, self.id)
    }
}

impl FromStr for ExchangeHandle {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        let bad = || format!("{s:?} is not an exchange handle (wx_<10 hex>_<id>)");
        let rest = s.strip_prefix(HANDLE_PREFIX).ok_or_else(bad)?;
        let (tag, id) = rest.split_once('_').ok_or_else(bad)?;
        Ok(ExchangeHandle {
            project: ProjectTag::parse(tag).ok_or_else(bad)?,
            id: decimal(id).ok_or_else(bad)?,
        })
    }
}

/// Where the next page of a list starts, in one project.
///
/// - History: `wc_<tag>_<at_ms>_<id>`, as in `wc_3f9a0c21be_1798619564512_1042`.
/// - Site map: `wc_<tag>_s<method>_<host>_<path>`, each of the three as the lowercase
///   hex of its UTF-8, so a path can hold any character and still be one token.
///
/// A negative time or id is formatted but does not parse back. A project has neither.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Cursor {
    History {
        project: ProjectTag,
        at: HistoryCursor,
    },
    SiteMap {
        project: ProjectTag,
        at: SiteMapCursor,
    },
}

impl Cursor {
    pub fn project(&self) -> ProjectTag {
        match self {
            Cursor::History { project, .. } | Cursor::SiteMap { project, .. } => *project,
        }
    }
}

impl fmt::Display for Cursor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Cursor::History { project, at } => {
                write!(f, "{CURSOR_PREFIX}{project}_{}_{}", at.at_ms, at.id)
            }
            Cursor::SiteMap { project, at } => write!(
                f,
                "{CURSOR_PREFIX}{project}_s{}_{}_{}",
                hex(&at.method),
                hex(&at.host),
                hex(&at.path)
            ),
        }
    }
}

impl FromStr for Cursor {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        let bad = || format!("{s:?} is not a cursor this server gave out");
        let rest = s.strip_prefix(CURSOR_PREFIX).ok_or_else(bad)?;
        let (tag, rest) = rest.split_once('_').ok_or_else(bad)?;
        let project = ProjectTag::parse(tag).ok_or_else(bad)?;
        if let Some(rest) = rest.strip_prefix('s') {
            let mut parts = rest.split('_');
            let (Some(m), Some(h), Some(p), None) =
                (parts.next(), parts.next(), parts.next(), parts.next())
            else {
                return Err(bad());
            };
            return Ok(Cursor::SiteMap {
                project,
                at: SiteMapCursor {
                    method: unhex(m, SITE_MAP_CURSOR_METHOD_MAX).ok_or_else(bad)?,
                    host: unhex(h, SITE_MAP_CURSOR_HOST_MAX).ok_or_else(bad)?,
                    path: unhex(p, SITE_MAP_CURSOR_PATH_MAX).ok_or_else(bad)?,
                },
            });
        }
        let (at_ms, id) = rest.split_once('_').ok_or_else(bad)?;
        Ok(Cursor::History {
            project,
            at: HistoryCursor {
                at_ms: decimal(at_ms).ok_or_else(bad)?,
                id: decimal(id).ok_or_else(bad)?,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const UID: &str = "3f9a0c21be7d44c1a0e5b6f1c2d3e4f5";

    #[test]
    fn a_handle_names_its_project_and_reads_back() {
        let h = ExchangeHandle::new(UID, 1042).expect("a uid and an id");
        assert_eq!(h.to_string(), "wx_3f9a0c21be_1042");
        assert_eq!("wx_3f9a0c21be_1042".parse::<ExchangeHandle>(), Ok(h));
        assert!(h.project.matches(UID));
        assert!(!h.project.matches("3f9a0c21bf7d44c1a0e5b6f1c2d3e4f5"));
        assert_eq!(
            "wx_3f9a0c21be_0".parse::<ExchangeHandle>().map(|h| h.id),
            Ok(0)
        );
        assert_eq!(
            "wx_3f9a0c21be_999999999999999999"
                .parse::<ExchangeHandle>()
                .map(|h| h.id),
            Ok(999_999_999_999_999_999)
        );
        assert_eq!(ExchangeHandle::new(UID, -1), None);
        assert_eq!(
            ExchangeHandle::new("3F9A0C21BE7D44C1A0E5B6F1C2D3E4F5", 1),
            None
        );
        assert_eq!(ExchangeHandle::new("3f9a0c21be", 1), None);
    }

    #[test]
    fn a_handle_has_one_spelling() {
        for s in [
            "x_3f9a0c21be_1042",
            "wc_3f9a0c21be_1042",
            "WX_3f9a0c21be_1042",
            "wx_3F9A0C21BE_1042",
            "wx_3f9a0c21b_1042",
            "wx_3f9a0c21bee_1042",
            "wx_3f9a0c21bg_1042",
            "wx_3f9a0c21be_01042",
            "wx_3f9a0c21be_",
            "wx_3f9a0c21be",
            "wx_3f9a0c21be_-1",
            "wx_3f9a0c21be_+1",
            "wx_3f9a0c21be_1042 ",
            " wx_3f9a0c21be_1042",
            "wx_3f9a0c21be_1042_7",
            "wx_3f9a0c21be_1234567890123456789",
            "cs_3f9a0c21be7d44c1a0e5b6f1c2d3e4f5",
            "s_3f9a0c21be",
            "",
        ] {
            assert!(s.parse::<ExchangeHandle>().is_err(), "{s:?} was accepted");
        }
    }

    #[test]
    fn a_history_cursor_reads_back() {
        let c = Cursor::History {
            project: ProjectTag::of(UID).unwrap(),
            at: HistoryCursor {
                at_ms: 1_798_619_564_512,
                id: 1042,
            },
        };
        assert_eq!(c.to_string(), "wc_3f9a0c21be_1798619564512_1042");
        assert_eq!("wc_3f9a0c21be_1798619564512_1042".parse(), Ok(c.clone()));
        assert!(c.project().matches(UID));
    }

    #[test]
    fn a_site_map_cursor_carries_any_path_and_reads_back() {
        let project = ProjectTag::of(UID).unwrap();
        let c = Cursor::SiteMap {
            project,
            at: SiteMapCursor {
                host: "api.example.com".into(),
                path: "/a_b/ü %2F?_".into(),
                method: "GET".into(),
            },
        };
        let s = c.to_string();
        assert!(s.starts_with("wc_3f9a0c21be_s474554_"), "{s}");
        assert_eq!(s.parse::<Cursor>(), Ok(c));

        let at_limit = Cursor::SiteMap {
            project,
            at: SiteMapCursor {
                host: "h".repeat(SITE_MAP_CURSOR_HOST_MAX),
                path: "/".repeat(SITE_MAP_CURSOR_PATH_MAX),
                method: "M".repeat(SITE_MAP_CURSOR_METHOD_MAX),
            },
        };
        assert_eq!(at_limit.to_string().parse::<Cursor>(), Ok(at_limit));
        let over = Cursor::SiteMap {
            project,
            at: SiteMapCursor {
                host: "h".into(),
                path: "/".repeat(SITE_MAP_CURSOR_PATH_MAX + 1),
                method: "GET".into(),
            },
        };
        assert!(over.to_string().parse::<Cursor>().is_err());
    }

    #[test]
    fn a_cursor_has_one_spelling() {
        for s in [
            "c_3f9a0c21be_1798619564512_1042",
            "wx_3f9a0c21be_1798619564512_1042",
            "wc_3f9a0c21be_1798619564512",
            "wc_3f9a0c21be_1798619564512_1042_1",
            "wc_3f9a0c21be_01798619564512_1042",
            "wc_3f9a0c21be_1798619564512_-1",
            "wc_3f9a0c21be_s474554_68",
            "wc_3f9a0c21be_s474554_68_2f_00",
            "wc_3f9a0c21be_s_68_2f",
            "wc_3f9a0c21be_s474554_68_2F",
            "wc_3f9a0c21be_s474554_68_2",
            "wc_3f9a0c21be_s474554_68_ff",
            "wc_3f9a0c21be_s474554_68_zz",
            "wc_3f9a0c21b_1798619564512_1042",
            "",
        ] {
            assert!(s.parse::<Cursor>().is_err(), "{s:?} was accepted");
        }
    }
}
