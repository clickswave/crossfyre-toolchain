//! What an agent may change in a stored request before it is replayed.
//!
//! Changes are named, never a request typed out whole, so everything the agent did not
//! name keeps the bytes that were captured. The method cannot be edited at all: whether a
//! replay reads or writes is decided by what was captured, not by the agent.

use std::collections::HashSet;

use serde::de::{MapAccess, Visitor};
use serde::ser::SerializeMap;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Map, Value};

/// The most entries in any one of `query`, `headers`, `form` and `json`.
pub const EDIT_ENTRIES_MAX: usize = 50;
/// The longest path, name or value, in bytes.
pub const EDIT_VALUE_MAX: usize = 8 * 1024;

/// Headers the sender sets from the request it sends. Letting an edit set them would
/// let one request be framed as two.
const FIXED_HEADERS: [&str; 6] = [
    "content-length",
    "transfer-encoding",
    "connection",
    "upgrade",
    "te",
    "trailer",
];

/// `replay`'s `edits`. Every field is optional and an empty `Edits` replays the request
/// as captured.
///
/// The body is not capped here beyond the request line itself
/// ([`crate::MAX_REQUEST_LINE`]).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Edits {
    /// Replaces the request target. Starts with `/`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// A value sets the first parameter of that name, or appends one. `null` removes
    /// every parameter of that name.
    #[serde(default, skip_serializing_if = "Pairs::is_empty")]
    pub query: Pairs,
    /// As `query`, by header name, ignoring case.
    #[serde(default, skip_serializing_if = "Pairs::is_empty")]
    pub headers: Pairs,
    /// As `query`, for the fields of a form body. Refused for any other body.
    #[serde(default, skip_serializing_if = "Pairs::is_empty")]
    pub form: Pairs,
    /// Members of a body that is a JSON object, each set to the value given. Refused
    /// for any other body.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub json: Option<Map<String, Value>>,
    /// The whole body, replaced.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
}

impl Edits {
    pub fn is_empty(&self) -> bool {
        self.path.is_none()
            && self.query.is_empty()
            && self.headers.is_empty()
            && self.form.is_empty()
            && self.json.is_none()
            && self.body.is_none()
    }

    /// The protocol's limits. The server enforces these; a client can check before it
    /// sends.
    pub fn validate(&self) -> Result<(), String> {
        if let Some(p) = &self.path {
            if !p.starts_with('/') {
                return Err("path has to start with /".into());
            }
            if p.len() > EDIT_VALUE_MAX {
                return Err(format!("path is longer than {EDIT_VALUE_MAX} bytes"));
            }
            if p.bytes().any(|b| b <= b' ' || b == 0x7f) {
                return Err("path has a space or a control character in it".into());
            }
        }
        for (what, pairs) in [
            ("query", &self.query),
            ("headers", &self.headers),
            ("form", &self.form),
        ] {
            if pairs.len() > EDIT_ENTRIES_MAX {
                return Err(format!("{what} has more than {EDIT_ENTRIES_MAX} entries"));
            }
            for (k, v) in pairs.iter() {
                if k.is_empty() {
                    return Err(format!("{what} has an entry with no name"));
                }
                if k.len() > EDIT_VALUE_MAX || v.is_some_and(|v| v.len() > EDIT_VALUE_MAX) {
                    return Err(format!(
                        "{what} entry {k:?} is longer than {EDIT_VALUE_MAX} bytes"
                    ));
                }
            }
        }
        let mut seen = HashSet::new();
        for (k, v) in self.headers.iter() {
            if !k.bytes().all(is_tchar) {
                return Err(format!("{k:?} is not a header name"));
            }
            let lower = k.to_ascii_lowercase();
            if FIXED_HEADERS.contains(&lower.as_str()) || lower.starts_with("proxy-") {
                return Err(format!("{k} is set by the sender and cannot be edited"));
            }
            if !seen.insert(lower) {
                return Err(format!("the header {k} is named twice"));
            }
            if v.is_some_and(|v| v.bytes().any(|b| (b < b' ' && b != b'\t') || b == 0x7f)) {
                return Err(format!("the value for {k} has a control character in it"));
            }
        }
        if let Some(j) = &self.json {
            if j.len() > EDIT_ENTRIES_MAX {
                return Err(format!("json has more than {EDIT_ENTRIES_MAX} members"));
            }
            for (k, v) in j {
                if k.len() > EDIT_VALUE_MAX || v.to_string().len() > EDIT_VALUE_MAX {
                    return Err(format!(
                        "json member {k:?} is longer than {EDIT_VALUE_MAX} bytes"
                    ));
                }
            }
        }
        if self.body.is_some() && (!self.form.is_empty() || self.json.is_some()) {
            return Err("body replaces the whole body, so it cannot go with form or json".into());
        }
        if !self.form.is_empty() && self.json.is_some() {
            return Err("form and json cannot both apply to one body".into());
        }
        Ok(())
    }
}

/// A header name character (RFC 9110 `tchar`).
fn is_tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

/// A JSON object of names to a string or `null`, kept in the order it was written.
///
/// A name written twice is refused rather than one of the two being picked. Which one a
/// JSON reader keeps is not something two ends should have to agree on.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Pairs(pub Vec<(String, Option<String>)>);

impl Pairs {
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, Option<&str>)> {
        self.0.iter().map(|(k, v)| (k.as_str(), v.as_deref()))
    }
}

impl Serialize for Pairs {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut m = s.serialize_map(Some(self.0.len()))?;
        for (k, v) in &self.0 {
            m.serialize_entry(k, v)?;
        }
        m.end()
    }
}

impl<'de> Deserialize<'de> for Pairs {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Pairs;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("an object of names to a string or null")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> Result<Pairs, A::Error> {
                let mut out: Vec<(String, Option<String>)> = Vec::new();
                while let Some((k, v)) = a.next_entry::<String, Option<String>>()? {
                    if out.iter().any(|(seen, _)| *seen == k) {
                        return Err(serde::de::Error::custom(format!("{k:?} is named twice")));
                    }
                    out.push((k, v));
                }
                Ok(Pairs(out))
            }
        }
        d.deserialize_map(V)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn edits(json: &str) -> Edits {
        serde_json::from_str(json).expect("parses")
    }

    #[test]
    fn the_shape_in_the_protocol_parses_and_keeps_its_order() {
        let e = edits(
            r#"{"path":"/api/items/2?x=1",
                "query":{"id":"2","debug":null},
                "headers":{"x-forwarded-for":"203.0.113.9","cookie":null},
                "form":{"qty":"0"},
                "json":{"role":"admin"},
                "body":"raw replacement"}"#,
        );
        assert_eq!(
            e.query.0,
            vec![("id".into(), Some("2".into())), ("debug".into(), None)]
        );
        assert_eq!(e.headers.iter().nth(1), Some(("cookie", None)));
        // Every field at once is a shape, not a request anyone can apply: a replaced
        // body leaves no form or JSON to edit.
        assert!(e.validate().unwrap_err().contains("body"));
    }

    #[test]
    fn a_name_written_twice_is_refused() {
        let r: Result<Edits, _> = serde_json::from_str(r#"{"query":{"id":"1","id":"2"}}"#);
        assert!(r.unwrap_err().to_string().contains("named twice"));
        // Headers ignore case, so these are the same header too.
        let e = edits(r#"{"headers":{"X-Role":"a","x-role":"b"}}"#);
        assert!(e.validate().unwrap_err().contains("named twice"));
    }

    #[test]
    fn framing_headers_cannot_be_edited() {
        for h in [
            "Content-Length",
            "transfer-encoding",
            "Connection",
            "upgrade",
            "TE",
            "trailer",
            "Proxy-Authorization",
        ] {
            let e = Edits {
                headers: Pairs(vec![(h.into(), Some("x".into()))]),
                ..Edits::default()
            };
            assert!(e.validate().is_err(), "{h} was accepted");
            let e = Edits {
                headers: Pairs(vec![(h.into(), None)]),
                ..Edits::default()
            };
            assert!(e.validate().is_err(), "removing {h} was accepted");
        }
    }

    #[test]
    fn nothing_can_start_a_second_line_of_the_request() {
        let bad = [
            r#"{"path":"/a HTTP/1.1\r\nX-Injected: 1"}"#,
            r#"{"path":"/a\nb"}"#,
            r#"{"path":"api/no-slash"}"#,
            r#"{"headers":{"x-a":"1\r\nX-Injected: 1"}}"#,
            r#"{"headers":{"x a":"1"}}"#,
            r#"{"headers":{"x:a":"1"}}"#,
        ];
        for json in bad {
            assert!(edits(json).validate().is_err(), "{json} was accepted");
        }
        assert!(
            edits(r#"{"headers":{"x-a":"tab\tis fine"}}"#)
                .validate()
                .is_ok()
        );
    }

    #[test]
    fn the_limits_are_the_protocols() {
        let many = Pairs(
            (0..=EDIT_ENTRIES_MAX)
                .map(|i| (format!("p{i}"), Some("v".into())))
                .collect(),
        );
        let e = Edits {
            query: many,
            ..Edits::default()
        };
        assert!(e.validate().is_err(), "51 entries");

        let long = "x".repeat(EDIT_VALUE_MAX + 1);
        let e = Edits {
            form: Pairs(vec![("f".into(), Some(long.clone()))]),
            ..Edits::default()
        };
        assert!(e.validate().is_err(), "a value over 8 KB");
        let e = Edits {
            path: Some(format!("/{long}")),
            ..Edits::default()
        };
        assert!(e.validate().is_err(), "a path over 8 KB");

        let at = "x".repeat(EDIT_VALUE_MAX);
        let e = Edits {
            form: Pairs(vec![("f".into(), Some(at))]),
            ..Edits::default()
        };
        assert!(e.validate().is_ok(), "exactly 8 KB is allowed");
    }

    #[test]
    fn form_json_and_body_are_one_body_each() {
        assert!(
            edits(r#"{"form":{"a":"1"},"json":{"a":1}}"#)
                .validate()
                .is_err()
        );
        assert!(edits(r#"{"json":{"a":1},"body":"x"}"#).validate().is_err());
        assert!(edits(r#"{"json":{"a":1}}"#).validate().is_ok());
        assert!(edits(r#"{"body":"x"}"#).validate().is_ok());
        assert!(edits("{}").is_empty());
    }
}
