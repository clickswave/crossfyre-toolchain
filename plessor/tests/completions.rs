//! `plessor completions bash` prints a script that completes the subcommands.

use std::process::{Command, Stdio};

#[test]
fn bash_completions_name_the_subcommands() {
    let out = Command::new(env!("CARGO_BIN_EXE_plessor"))
        .args(["completions", "bash"])
        .output()
        .expect("runs");
    assert!(out.status.success(), "{out:?}");
    let text = String::from_utf8(out.stdout).expect("utf-8");
    for sub in ["inject", "exec"] {
        assert!(text.contains(sub), "{sub} missing from: {text}");
    }
}

/// `plessor completions bash | head -3` closes the pipe after three lines. That is the reader
/// being done, and the command used to panic on the next write and exit 101. The pipe here
/// is closed before the command starts, so its first write fails, whatever size the script
/// is.
#[test]
fn a_reader_that_stops_early_is_not_an_error_for_any_shell() {
    for shell in ["bash", "elvish", "fish", "powershell", "zsh"] {
        let (reader, writer) = std::io::pipe().expect("pipe");
        drop(reader);
        let out = Command::new(env!("CARGO_BIN_EXE_plessor"))
            .args(["completions", shell])
            .stdout(writer)
            .stderr(Stdio::piped())
            .output()
            .expect("runs");
        assert!(out.status.success(), "{shell}: {out:?}");
        assert!(
            out.stderr.is_empty(),
            "{shell}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}
