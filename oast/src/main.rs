//! Standalone `oast` server binary: reads config from the environment and runs.
//! (Self-hosters usually go through `crossfyre oast serve`, which runs the same
//! server in-process; this binary is for systemd units and container images.)
//!
//! It takes no arguments. `--version` and `--help` answer and exit, as every other
//! binary in the toolchain does; anything else used to start the server, which on a
//! system that lets anyone listen on port 53 ran until something killed it.

const HELP: &str = "\
oast: the out-of-band interaction server.

Usage: oast

Configured through the environment: OAST_DOMAIN, OAST_PUBLIC_IP, OAST_DNS_ADDR,
OAST_HTTP_ADDR, OAST_HTTPS_ADDR, OAST_POLL_ADDR, OAST_TLS_CERT, OAST_TLS_KEY,
OAST_TLS_CERTS, OAST_ACME_TXT_FILE and OAST_TTL_SECS. Most people run it as
`crossfyre oast serve`.

Options:
  -h, --help     Print this and exit
  -V, --version  Print the version and exit";

/// What the arguments ask for: None to run the server, or the text to print and the
/// exit status to leave with.
fn answer(args: &[String]) -> Option<(String, i32)> {
    match args.first().map(String::as_str) {
        None => None,
        Some("-V" | "--version") => Some((format!("oast {}", env!("CARGO_PKG_VERSION")), 0)),
        Some("-h" | "--help") => Some((HELP.to_string(), 0)),
        Some(other) => Some((format!("oast: unexpected argument {other:?}\n\n{HELP}"), 2)),
    }
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let Some((text, code)) = answer(&args) {
        if code == 0 {
            println!("{text}");
        } else {
            eprintln!("{text}");
        }
        std::process::exit(code);
    }
    oast::run(oast::Config::from_env()).await;
}

#[cfg(test)]
mod tests {
    use super::answer;

    fn args(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn no_arguments_runs_the_server() {
        assert!(answer(&[]).is_none());
    }

    #[test]
    fn version_and_help_answer_and_exit() {
        let (text, code) = answer(&args(&["--version"])).expect("an answer");
        assert_eq!(
            (text.as_str(), code),
            (concat!("oast ", env!("CARGO_PKG_VERSION")), 0)
        );
        assert_eq!(answer(&args(&["-V"])).map(|a| a.1), Some(0));
        assert_eq!(answer(&args(&["--help"])).map(|a| a.1), Some(0));
    }

    #[test]
    fn anything_else_is_refused_rather_than_starting_the_server() {
        assert_eq!(answer(&args(&["serve"])).map(|a| a.1), Some(2));
    }
}
