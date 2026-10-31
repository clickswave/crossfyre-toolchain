//! Every connection an engine makes toward a target goes through `transport`, which
//! names its egress. A client built any other way, or a socket opened by hand, sends
//! from this machine's own address whatever proxy the op was given, and nothing at
//! run time would say so.
//!
//! So this reads the engines' sources and fails on any such line outside a short
//! list of places that are not target traffic. The list holds exact counts, so a
//! second client in a file that is allowed one still fails. Naming an egress
//! outright is caught the same way: an engine's op takes the egress the daemon read
//! off the request, and `Inherit` or `Direct` written into op code would drop it.
//!
//! Test code (`#[cfg(test)]` items) and comments are not read.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

const ENGINES: &[&str] = &[
    "plessor/src",
    "ambulo/src",
    "voyage/src",
    "toolmark/src",
    "doorward/src",
];

const PATTERNS: &[&str] = &[
    "reqwest::Client::builder(",
    "reqwest::Client::new(",
    "reqwest::ClientBuilder::new(",
    "reqwest::get(",
    "wreq::Client",
    "TcpStream::connect(",
    "Egress::Inherit",
    "Egress::Direct",
];

/// (file, pattern, how many, why it is not target traffic or not an op's egress)
const ALLOWED: &[(&str, &str, usize, &str)] = &[
    (
        "plessor/src/lib.rs",
        "TcpStream::connect(",
        1,
        "the command line talking to its own daemon on loopback",
    ),
    (
        "plessor/src/solver.rs",
        "reqwest::Client::builder(",
        1,
        "the operator's own challenge solver, which is not the target",
    ),
    (
        "plessor/src/solver.rs",
        "Egress::Inherit",
        1,
        "the solver is told the environment's proxy only for an op that inherits it",
    ),
    (
        "ambulo/src/main.rs",
        "TcpStream::connect(",
        3,
        "the command line talking to its own daemon on loopback",
    ),
    (
        "ambulo/src/main.rs",
        "Egress::Inherit",
        1,
        "the daemon's default scan settings; each op sets its own egress",
    ),
    (
        "ambulo/src/daemon.rs",
        "Egress::Inherit",
        3,
        "the shared probe clients serve only requests that came without a wrapper",
    ),
    (
        "ambulo/src/browser.rs",
        "TcpStream::connect(",
        1,
        "the DevTools socket of the browser this process started, on loopback",
    ),
    (
        "voyage/src/main.rs",
        "TcpStream::connect(",
        4,
        "the command line talking to its own daemon on loopback",
    ),
    (
        "voyage/src/main.rs",
        "Egress::Inherit",
        1,
        "origin discovery run from the command line, which inherits",
    ),
    (
        "toolmark/src/main.rs",
        "TcpStream::connect(",
        1,
        "the command line talking to its own daemon on loopback",
    ),
    (
        "doorward/src/main.rs",
        "TcpStream::connect(",
        3,
        "the command line talking to its own daemon on loopback",
    ),
    (
        "doorward/src/scanner.rs",
        "TcpStream::connect(",
        1,
        "a connect scan is the measurement; the daemon refuses a proxied op",
    ),
];

fn workspace() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .to_path_buf()
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            rust_files(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

/// The lines of `src` that are not test code, with their numbers. A `#[cfg(test)]`
/// item is skipped to the brace that closes it, counting braces outside string and
/// character literals and comments.
fn non_test_lines(src: &str) -> Vec<(usize, &str)> {
    let lines: Vec<&str> = src.lines().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        if lines[i].trim_start().starts_with("#[cfg(test)]") {
            i = end_of_item(&lines, i + 1);
            continue;
        }
        out.push((i + 1, lines[i]));
        i += 1;
    }
    out
}

/// The index of the line after the item that starts at `from`.
fn end_of_item(lines: &[&str], from: usize) -> usize {
    let mut depth = 0i32;
    let mut opened = false;
    let mut in_str = false;
    let mut in_block_comment = false;
    for (n, line) in lines.iter().enumerate().skip(from) {
        let b = line.as_bytes();
        let mut k = 0;
        while k < b.len() {
            let c = b[k];
            if in_block_comment {
                if c == b'*' && b.get(k + 1) == Some(&b'/') {
                    in_block_comment = false;
                    k += 1;
                }
            } else if in_str {
                if c == b'\\' {
                    k += 1;
                } else if c == b'"' {
                    in_str = false;
                }
            } else if c == b'/' && b.get(k + 1) == Some(&b'/') {
                break;
            } else if c == b'/' && b.get(k + 1) == Some(&b'*') {
                in_block_comment = true;
                k += 1;
            } else if c == b'"' {
                in_str = true;
            } else if c == b'\'' && b.get(k + 2) == Some(&b'\'') {
                // A character literal such as '{'.
                k += 2;
            } else if c == b'{' {
                depth += 1;
                opened = true;
            } else if c == b'}' {
                depth -= 1;
            } else if c == b';' && !opened && depth == 0 {
                return n + 1;
            }
            k += 1;
        }
        if opened && depth == 0 {
            return n + 1;
        }
    }
    lines.len()
}

#[test]
fn engine_code_opens_no_connection_except_through_transport() {
    let root = workspace();
    let mut files = Vec::new();
    for dir in ENGINES {
        rust_files(&root.join(dir), &mut files);
    }
    assert!(files.len() > 40, "the engines' sources were not found");
    files.sort();

    let mut found: BTreeMap<(String, &str), Vec<usize>> = BTreeMap::new();
    for f in &files {
        let rel = f
            .strip_prefix(&root)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        let src = std::fs::read_to_string(f).unwrap();
        for (n, line) in non_test_lines(&src) {
            if line.trim_start().starts_with("//") {
                continue;
            }
            for p in PATTERNS {
                if line.contains(p) {
                    found.entry((rel.clone(), *p)).or_default().push(n);
                }
            }
        }
    }

    let mut wrong = Vec::new();
    for ((file, pattern), at) in &found {
        let allowed = ALLOWED
            .iter()
            .find(|(f, p, _, _)| f == file && p == pattern)
            .map_or(0, |a| a.2);
        if at.len() != allowed {
            wrong.push(format!(
                "{file}: `{pattern}` {} time(s) at line(s) {at:?}, {allowed} allowed",
                at.len()
            ));
        }
    }
    for (file, pattern, n, _) in ALLOWED {
        if !found.contains_key(&(file.to_string(), *pattern)) {
            wrong.push(format!(
                "{file}: `{pattern}` is allowed {n} time(s) and no longer appears; \
                 take it off the list"
            ));
        }
    }
    assert!(
        wrong.is_empty(),
        "engine code that sends around `transport`, or names an egress instead of \
         taking the op's:\n  {}\n\nBuild the client with transport::build_client or \
         open the connection with transport::dial, passing the op's egress.",
        wrong.join("\n  ")
    );
}

#[test]
fn test_code_and_comments_are_not_read() {
    let src = "fn a() {}\n\
               #[cfg(test)]\n\
               mod tests {\n\
                   fn b() { let s = \"}\"; let c = '{'; TcpStream::connect(x); }\n\
               }\n\
               fn c() { TcpStream::connect(y); }\n";
    let kept: Vec<usize> = non_test_lines(src).iter().map(|(n, _)| *n).collect();
    assert_eq!(kept, [1, 6]);
    let one_line = "#[cfg(test)]\nuse x::y;\nfn z() {}\n";
    let kept: Vec<usize> = non_test_lines(one_line).iter().map(|(n, _)| *n).collect();
    assert_eq!(kept, [3]);
}
