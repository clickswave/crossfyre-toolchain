//! The lines `crossfyre node init` ends with: what is running and what is not, and for
//! each thing that is not, the one command that starts it.

use crate::toolchain::ui::{arrow, check, cross, done, end, error, hint, row, section};

/// How `node init` left the node service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NodeService {
    Running,
    /// Not running: it could not be installed, or it did not stay up.
    Stopped,
    /// Not installed, as `--no-service` asked.
    Skipped,
}

/// An engine or the database, which `node init` starts besides the node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Part {
    pub name: String,
    pub running: bool,
    /// The command that starts it when it is not running.
    pub start: String,
}

/// What `node init` left running.
pub(crate) struct Summary {
    pub node: NodeService,
    pub parts: Vec<Part>,
}

/// The command that starts the node when its service is not running.
const NODE_UP: &str = "crossfyre node up";

/// The command that starts engine `name` when it is not running: `extension install`
/// when it is not installed, or forced when it is installed without a service; `daemon`,
/// its own daemon command, where nothing runs services; and otherwise its service,
/// through `extension start`.
pub(crate) fn engine_start(
    name: &str,
    installed: bool,
    registered: bool,
    daemon: Option<String>,
) -> String {
    match (installed, daemon) {
        (false, _) => format!("crossfyre extension install {name}"),
        (true, Some(daemon)) => daemon,
        (true, None) if !registered => format!("crossfyre extension install --force {name}"),
        (true, None) => format!("crossfyre extension start {name}"),
    }
}

impl Summary {
    /// Whether `node init` exits zero: everything it started is running, and the node is
    /// too, unless `--no-service` left it to be started by hand.
    pub fn succeeded(&self) -> bool {
        self.node != NodeService::Stopped && self.down().is_empty()
    }

    /// The parts that are not running, by name.
    fn down(&self) -> Vec<&str> {
        self.parts
            .iter()
            .filter(|p| !p.running)
            .map(|p| p.name.as_str())
            .collect()
    }

    /// One row for the node and one for each part: running, or not running and the
    /// command that starts it.
    pub fn rows(&self) -> Vec<String> {
        let node = ("node", self.node == NodeService::Running, NODE_UP);
        std::iter::once(node)
            .chain(
                self.parts
                    .iter()
                    .map(|p| (p.name.as_str(), p.running, p.start.as_str())),
            )
            .map(|(name, running, start)| {
                let line = if running {
                    row(&check(), name, "running", "")
                } else {
                    row(
                        &cross(),
                        name,
                        "not running",
                        &format!("{} {start}", arrow()),
                    )
                };
                line.trim_end().to_string()
            })
            .collect()
    }

    /// The line under the rows.
    pub fn verdict(&self) -> String {
        let down = self.down();
        let (rest, verb) = match down.as_slice() {
            [] => (String::new(), ""),
            [one] => (one.to_string(), "is"),
            [first @ .., last] => (format!("{} and {last}", first.join(", ")), "are"),
        };
        match (self.node, down.is_empty()) {
            (NodeService::Stopped, _) => "Node not running".to_string(),
            (NodeService::Running, true) => "Node ready".to_string(),
            (NodeService::Running, false) => format!("Node running, but {rest} {verb} not"),
            (NodeService::Skipped, true) => "Node not started (--no-service)".to_string(),
            (NodeService::Skipped, false) => {
                format!("Node not started (--no-service), and {rest} {verb} not running")
            }
        }
    }

    pub fn print(&self) {
        section("Status");
        for line in self.rows() {
            println!("{line}");
        }
        end();
        let verdict = self.verdict();
        if !self.succeeded() {
            error(&verdict);
        } else if self.node == NodeService::Running {
            done(&verdict);
            hint("Run `crossfyre node status` to see it running.");
        } else {
            hint(&verdict);
        }
        end();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `s` without its colour, as a file or a pipe gets it.
    fn plain(s: &str) -> String {
        let mut out = String::new();
        let mut chars = s.chars();
        while let Some(c) = chars.next() {
            if c == '\x1b' {
                chars.by_ref().find(|&c| c == 'm');
            } else {
                out.push(c);
            }
        }
        out
    }

    fn rows(s: &Summary) -> Vec<String> {
        s.rows().iter().map(|r| plain(r)).collect()
    }

    fn part(name: &str, running: bool, start: &str) -> Part {
        Part {
            name: name.to_string(),
            running,
            start: start.to_string(),
        }
    }

    #[test]
    fn a_running_node_with_everything_up_is_ready() {
        let s = Summary {
            node: NodeService::Running,
            parts: vec![
                part("voyage", true, "crossfyre extension start voyage"),
                part("database", true, "crossfyre db up"),
            ],
        };
        assert_eq!(s.verdict(), "Node ready");
        assert!(s.succeeded());
    }

    /// The node is online, but it cannot do the work it was given, so init fails and
    /// says what is down.
    #[test]
    fn whatever_did_not_start_is_named_with_its_command_and_init_fails() {
        let s = Summary {
            node: NodeService::Running,
            parts: vec![
                part("voyage", true, "crossfyre extension start voyage"),
                part("doorward", false, "crossfyre extension start doorward"),
                part("database", false, "crossfyre db up"),
            ],
        };
        assert_eq!(
            rows(&s),
            [
                "    \u{2713} node       running",
                "    \u{2713} voyage     running",
                "    \u{2717} doorward   not running   \u{203a} crossfyre extension start doorward",
                "    \u{2717} database   not running   \u{203a} crossfyre db up",
            ]
        );
        assert_eq!(
            s.verdict(),
            "Node running, but doorward and database are not"
        );
        assert!(!s.succeeded());

        let one = Summary {
            node: NodeService::Running,
            parts: vec![part("database", false, "crossfyre db up")],
        };
        assert_eq!(one.verdict(), "Node running, but database is not");
        assert!(!one.succeeded());
    }

    /// --no-service leaves the node to be started by hand, which is no failure, but
    /// what init did start still has to run.
    #[test]
    fn without_the_node_service_init_fails_only_on_what_it_started() {
        let skipped = |running| Summary {
            node: NodeService::Skipped,
            parts: vec![
                part("voyage", running, "crossfyre extension start voyage"),
                part("toolmark", running, "crossfyre extension start toolmark"),
                part("database", running, "crossfyre db up"),
            ],
        };
        assert_eq!(skipped(true).verdict(), "Node not started (--no-service)");
        assert!(skipped(true).succeeded());
        assert_eq!(
            skipped(false).verdict(),
            "Node not started (--no-service), and voyage, toolmark and database are not running"
        );
        assert!(!skipped(false).succeeded());
    }

    #[test]
    fn a_node_whose_service_is_not_running_is_not_ready_and_init_fails() {
        let s = Summary {
            node: NodeService::Stopped,
            parts: vec![part("voyage", false, "crossfyre extension start voyage")],
        };
        assert_eq!(
            rows(&s),
            [
                "    \u{2717} node       not running   \u{203a} crossfyre node up",
                "    \u{2717} voyage     not running   \u{203a} crossfyre extension start voyage",
            ]
        );
        assert_eq!(s.verdict(), "Node not running");
        assert!(!s.succeeded());
    }

    #[test]
    fn an_engine_is_started_by_what_will_start_it_here() {
        let daemon = || Some("/opt/crossfyre/bin/voyage --daemon --port 4442".to_string());
        assert_eq!(
            engine_start("voyage", true, true, None),
            "crossfyre extension start voyage"
        );
        assert_eq!(
            engine_start("voyage", true, false, None),
            "crossfyre extension install --force voyage"
        );
        assert_eq!(
            engine_start("voyage", false, false, None),
            "crossfyre extension install voyage"
        );
        // Without a service manager its service cannot run, and neither can the command
        // that would start it: the daemon is started by hand.
        assert_eq!(
            engine_start("voyage", true, true, daemon()),
            "/opt/crossfyre/bin/voyage --daemon --port 4442"
        );
        assert_eq!(
            engine_start("voyage", false, false, daemon()),
            "crossfyre extension install voyage"
        );
    }

    /// `--no-service` asked for the node to be left to the person, so init has done what
    /// it was asked and says how to start it.
    #[test]
    fn a_node_left_out_with_no_service_says_how_to_start_it_and_init_succeeds() {
        let s = Summary {
            node: NodeService::Skipped,
            parts: Vec::new(),
        };
        assert_eq!(
            rows(&s),
            ["    \u{2717} node       not running   \u{203a} crossfyre node up"]
        );
        assert_eq!(s.verdict(), "Node not started (--no-service)");
        assert!(s.succeeded());
    }
}
