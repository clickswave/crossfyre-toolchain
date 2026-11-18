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

impl Summary {
    /// Whether `node init` exits zero: the node is running, or `--no-service` left it to
    /// be started by hand.
    pub fn succeeded(&self) -> bool {
        self.node != NodeService::Stopped
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
    pub fn verdict(&self) -> &'static str {
        match self.node {
            NodeService::Running => "Node ready",
            NodeService::Stopped => "Node not running",
            NodeService::Skipped => "Node not started (--no-service)",
        }
    }

    pub fn print(&self) {
        section("Status");
        for line in self.rows() {
            println!("{line}");
        }
        end();
        match self.node {
            NodeService::Running => {
                done(self.verdict());
                hint("Run `crossfyre node status` to see it running.");
            }
            NodeService::Stopped => error(self.verdict()),
            NodeService::Skipped => hint(self.verdict()),
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
    fn a_running_node_is_ready_and_whatever_did_not_start_is_named_with_its_command() {
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
        assert_eq!(s.verdict(), "Node ready");
        assert!(s.succeeded());
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
