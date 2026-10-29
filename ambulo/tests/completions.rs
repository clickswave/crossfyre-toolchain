//! `ambulo completions bash` prints a script that completes the subcommands.

use std::process::Command;

#[test]
fn bash_completions_name_the_subcommands() {
    let out = Command::new(env!("CARGO_BIN_EXE_ambulo"))
        .args(["completions", "bash"])
        .output()
        .expect("runs");
    assert!(out.status.success(), "{out:?}");
    let text = String::from_utf8(out.stdout).expect("utf-8");
    for sub in ["scan", "exec"] {
        assert!(text.contains(sub), "{sub} missing from: {text}");
    }
}
