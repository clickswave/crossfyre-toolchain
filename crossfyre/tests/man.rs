//! `crossfyre man` prints a roff man page for the CLI.

use std::process::Command;

#[test]
fn man_page_names_crossfyre_and_its_subcommands() {
    let out = Command::new(env!("CARGO_BIN_EXE_crossfyre"))
        .arg("man")
        .output()
        .expect("runs");
    assert!(out.status.success(), "{out:?}");
    let text = String::from_utf8(out.stdout).expect("utf-8");
    // clap_mangen emits two `.ie`/`.el` quote-setup lines before the title.
    let title = text
        .lines()
        .find(|line| !line.starts_with(".ie") && !line.starts_with(".el"))
        .expect("has a title line");
    assert!(title.starts_with(".TH crossfyre "), "{title}");
    for sub in ["extension", "node", "completions"] {
        assert!(text.contains(sub), "{sub} missing from: {text}");
    }
}

/// `crossfyre man | head` closes the pipe early, which is not a failure of the command.
#[test]
fn a_reader_that_stops_early_is_not_an_error() {
    let (reader, writer) = std::io::pipe().expect("pipe");
    drop(reader);
    let out = Command::new(env!("CARGO_BIN_EXE_crossfyre"))
        .arg("man")
        .stdout(writer)
        .stderr(std::process::Stdio::piped())
        .output()
        .expect("runs");
    assert!(out.status.success(), "{out:?}");
    assert!(
        out.stderr.is_empty(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn man_is_hidden_from_help() {
    let out = Command::new(env!("CARGO_BIN_EXE_crossfyre"))
        .arg("--help")
        .output()
        .expect("runs");
    assert!(out.status.success(), "{out:?}");
    let text = String::from_utf8(out.stdout).expect("utf-8");
    assert!(
        !text
            .lines()
            .any(|line| line.trim_start().starts_with("man ")),
        "man shows in --help: {text}"
    );
}
