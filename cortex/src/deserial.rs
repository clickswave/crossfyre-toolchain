//! Unsafe deserialization, detected without a gadget chain.
//!
//! The usual way a scanner claims this class is to send a serialized object
//! that executes something on the way in - `ysoserial`'s URLDNS for Java, which
//! needs nothing but JRE classes and calls out to a host under the tester's
//! control. That works, and it works ONLY for Java. Ruby, PHP, Python and .NET
//! have no universal chain: every published gadget for them is assembled out of
//! classes that a particular framework happens to load, so a scanner carrying a
//! fixed payload scores zero against an application it does not already know.
//!
//! RailsGoat is the case in point. `POST /password_resets` runs
//! `Marshal.load(Base64.decode64(params[:user]))` on an unauthenticated
//! request, which is as bad as this class gets, and a Java-only scanner walks
//! past it.
//!
//! # A different question
//!
//! Executing code is not the only way to prove a deserializer ran. The parsers
//! themselves are loud: hand `Marshal.load` four arbitrary bytes and Ruby says
//! "marshal data too short". Hand them to PHP's `unserialize` and it says
//! "Error at offset 0 of 4 bytes". Those sentences exist in the response for
//! exactly one reason - the application passed our bytes to that deserializer -
//! and the payload never contains them, so there is nothing to mistake for a
//! reflection.
//!
//! So the question becomes "does this parameter reach a deserializer", which is
//! answerable in one request per site, in every language, and is the finding
//! anyway: an application that deserializes untrusted input is exploitable as
//! soon as somebody looks up which gadgets its dependencies provide.
//!
//! # Two steps, because one is not evidence
//!
//! 1. Send a value that is not valid in any of these formats, raw or
//!    base64-decoded, and see whether the answer names a deserializer that the
//!    payload did not.
//! 2. Send a minimal VALID object in whatever format step 1 named. If the
//!    complaint goes away, the application really is parsing our bytes as that
//!    format, and step 1 was not some unrelated page that always carries the
//!    word.
//!
//! Both transports are covered by one probe value: a base64 string that is
//! invalid as a serialized blob AND decodes to bytes that are invalid too, so
//! an application that decodes first and one that does not both complain.
//!
//! Nothing here attempts execution. The finding says the door is unlocked; it
//! does not walk through, and there is no chain in this file to walk through
//! with.

/// A value that is not a valid serialized object in any format below, before or
/// after base64-decoding. Deliberately unremarkable - it goes where a real
/// value goes, and an application that ignores it simply ignores it.
pub const PROBE_VALUE: &str = "Y3Jvc3NmeXJlLWRlc2VyaWFsLWNoZWNr";

/// One serialization format: how its parser complains, and the smallest valid
/// object we can hand it to make the complaint stop.
pub struct Format {
    /// Short name for the finding.
    pub name: &'static str,
    /// What to call it in prose.
    pub label: &'static str,
    /// Substrings that only this format's deserializer produces. Matched
    /// case-insensitively against the response body.
    pub errors: &'static [&'static str],
    /// A minimal valid object, base64-encoded, for the confirmation step. Sent
    /// as-is (for an application that base64-decodes) and percent-encoded from
    /// its decoded bytes is not attempted: every real transport of these blobs
    /// is base64, because the bytes are not text.
    pub valid_b64: &'static str,
    /// The same object as raw bytes, for an application that does not decode.
    pub valid_raw: &'static [u8],
}

/// The formats worth carrying: each one has a parser error that no other
/// component produces, which is what makes a single-request probe honest.
///
/// Deliberately absent: `node-serialize` and friends, whose failure mode is a
/// generic JavaScript `SyntaxError`. A signature that vague would fire on any
/// endpoint that ever parses JSON badly, and a false positive here is expensive:
/// "your application deserializes untrusted input" is a finding people act on at
/// speed.
pub const FORMATS: &[Format] = &[
    Format {
        name: "ruby_marshal",
        label: "Ruby `Marshal`",
        errors: &[
            "marshal data too short",
            "dump format error",
            "undefined class/module",
            // A prefix, because Ruby finishes this sentence three different
            // ways. RailsGoat says "marshal file format (can't be read)"; the
            // table originally carried "marshal file format version", which is
            // a real Ruby message and not the one the live target produces.
            // Checking against a running application is what caught that, and
            // it would have shipped as a silent zero otherwise.
            "marshal file format",
            // The stack frame, for an application that renders one.
            "in 'marshal.load'",
            "marshal.load'",
        ],
        // Marshal.dump(1) => "\x04\bi\x06"
        valid_b64: "BAhpBg==",
        valid_raw: b"\x04\x08i\x06",
    },
    Format {
        name: "php_unserialize",
        label: "PHP `unserialize()`",
        errors: &[
            "unserialize(): error at offset",
            "__php_incomplete_class",
            "unserialize(): unexpected end of serialized data",
        ],
        // serialize(1) => "i:1;"
        valid_b64: "aToxOw==",
        valid_raw: b"i:1;",
    },
    Format {
        name: "python_pickle",
        label: "Python `pickle`",
        errors: &[
            "unpicklingerror",
            "unpickling stack underflow",
            "pickle data was truncated",
            "invalid load key",
            "stack_global requires str",
        ],
        // pickle protocol 0 for the integer 1: "I1\n."
        valid_b64: "STEKLg==",
        valid_raw: b"I1\n.",
    },
    Format {
        name: "java_serialization",
        label: "Java `ObjectInputStream`",
        errors: &[
            "invalid stream header",
            "streamcorruptedexception",
            "java.io.objectinputstream",
            "invalid type code",
        ],
        // \xac\xed\x00\x05 t \x00\x01 x  => the String "x"
        valid_b64: "rO0ABXQAAXg=",
        valid_raw: b"\xac\xed\x00\x05t\x00\x01x",
    },
    Format {
        name: "dotnet_binaryformatter",
        label: ".NET `BinaryFormatter`",
        errors: &[
            "system.runtime.serialization.serializationexception",
            "end of stream encountered before parsing was completed",
            "binaryformatter",
            "binary stream '0' does not contain a valid binaryheader",
        ],
        // A BinaryFormatter header followed by the end-of-stream record.
        valid_b64: "AAEAAAD/////AQAAAAAAAAAL",
        valid_raw: b"\x00\x01\x00\x00\x00\xff\xff\xff\xff\x01\x00\x00\x00\x00\x00\x00\x00\x0b",
    },
    Format {
        name: "ruby_yaml",
        label: "Ruby YAML (`Psych`)",
        errors: &[
            "psych::syntaxerror",
            "psych::disallowedclass",
            "tried to load unspecified class",
            "psych::badalias",
        ],
        // "--- 1\n"
        valid_b64: "LS0tIDEK",
        valid_raw: b"--- 1\n",
    },
];

/// Which deserializer, if any, complained in this response.
///
/// Deliberately no baseline comparison. The obvious guard - "the signature must
/// not already be there for the parameter's own value" - is wrong here, and a
/// live PHP endpoint proved it: the baseline value is not a valid serialized
/// object either, so `unserialize()` complains about that too, and the guard
/// suppressed the finding on an application doing exactly the thing being looked
/// for. It also made the RailsGoat detection an accident, since that one only
/// survived because Ruby happens to word "too short" and "cannot be read"
/// differently.
///
/// A page that carries a parser's name whatever it is sent is excluded by the
/// step that follows instead: hand the deserializer something valid, and if the
/// complaint does not stop, nothing was parsing our bytes. That is the stronger
/// test, and it is the only one this needs.
pub fn accused(body: &str) -> Option<&'static Format> {
    let b = body.to_lowercase();
    FORMATS
        .iter()
        .find(|f| f.errors.iter().any(|e| b.contains(e)))
}

/// True when this response still carries the accused parser's complaint.
pub fn still_complaining(f: &Format, body: &str) -> bool {
    let b = body.to_lowercase();
    f.errors.iter().any(|e| b.contains(e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_probe_value_is_valid_in_no_format() {
        // Raw, it is ASCII that no format's header matches.
        for f in FORMATS {
            assert!(
                !PROBE_VALUE.as_bytes().starts_with(f.valid_raw),
                "{} probe value looks like a real {} blob",
                f.name,
                f.label
            );
        }
        // Decoded, it is the phrase below, which is likewise nobody's header.
        assert_eq!(
            b64_decode(PROBE_VALUE).as_deref(),
            Some(&b"crossfyre-deserial-check"[..])
        );
    }

    #[test]
    fn each_valid_blob_round_trips_to_its_raw_bytes() {
        for f in FORMATS {
            assert_eq!(
                b64_decode(f.valid_b64).as_deref(),
                Some(f.valid_raw),
                "{} valid_b64 does not decode to valid_raw",
                f.name
            );
        }
    }

    #[test]
    fn an_endpoint_that_errors_on_its_own_value_too_is_still_accused() {
        // The baseline value is not a valid serialized object either, so a real
        // deserializing endpoint complains about BOTH. Excluding that case
        // suppressed the finding on a live PHP endpoint doing precisely what
        // this looks for. What separates it from a page that always says this
        // is the confirmation step, not a baseline comparison.
        let page = "failed: unserialize(): Error at offset 0 of 24 bytes";
        assert_eq!(accused(page).unwrap().name, "php_unserialize");
    }

    #[test]
    fn formats_are_told_apart() {
        assert_eq!(
            accused("TypeError: marshal data too short").unwrap().name,
            "ruby_marshal"
        );
        assert_eq!(
            accused("java.io.StreamCorruptedException: invalid stream header")
                .unwrap()
                .name,
            "java_serialization"
        );
        assert!(accused("HTTP 500 Internal Server Error").is_none());
    }

    /// Minimal base64 decoder, tests only: the point is to check the tables in
    /// this file against themselves rather than to trust that they were typed
    /// correctly.
    fn b64_decode(s: &str) -> Option<Vec<u8>> {
        const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut acc: u32 = 0;
        let mut bits = 0;
        let mut out = Vec::new();
        for c in s.bytes() {
            if c == b'=' {
                break;
            }
            let v = A.iter().position(|&a| a == c)? as u32;
            acc = (acc << 6) | v;
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                out.push((acc >> bits) as u8);
            }
        }
        Some(out)
    }
}
