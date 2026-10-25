//! Colour is for a person at a terminal. Output that goes to a file or a pipe, and
//! output for someone who set NO_COLOR, carries none of the escape codes.

use std::process::{Command, Stdio};

/// `crossfyre extension install` with no name: usage, coloured, and nothing changed.
fn usage(no_color: Option<&str>) -> String {
    let dir = std::env::temp_dir().join(format!("crossfyre-colour-{}", std::process::id()));
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_crossfyre"));
    cmd.arg("--data-dir")
        .arg(&dir)
        .args(["extension", "install"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env_remove("NO_COLOR");
    if let Some(v) = no_color {
        cmd.env("NO_COLOR", v);
    }
    let out = cmd.output().expect("runs");
    let _ = std::fs::remove_dir_all(&dir);
    assert!(out.status.success(), "{out:?}");
    String::from_utf8(out.stdout).expect("utf-8")
}

#[test]
fn output_to_a_pipe_has_no_escape_codes() {
    let text = usage(None);
    assert!(text.contains("crossfyre extension install"), "{text}");
    assert!(
        !text.contains('\x1b'),
        "escape codes in piped output: {text:?}"
    );
}

#[test]
fn no_color_has_no_escape_codes_either() {
    assert!(!usage(Some("1")).contains('\x1b'));
}
