//! Asking a person before traffic goes out.
//!
//! The scope file is the gate. This is a second, softer check on top of it, because
//! a client can be set to answer these questions on its own. Its value is the moment
//! a person reads the list of destinations and says yes, once per server process.
//!
//! Write actions are different. They can change or destroy data on the target, so
//! they need `allow_writes` in the file AND a yes each time (or once per host for a
//! single request, the way an intercepting proxy asks), and a client that cannot ask
//! is refused rather than waved through.

use crate::core::{Reason, Refusal};
use crate::peer::{Answer, ClientPeer};
use crate::scope_file::LoadedScope;
use crate::untrusted;
use std::collections::HashSet;
use std::sync::Mutex;
use std::time::Duration;

/// How long a person has to answer.
pub(crate) const ASK_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScopeAnswer {
    Unasked,
    /// Said yes in a form.
    Elicited,
    /// The client cannot show a form, so the file is the statement.
    File,
    /// Said no. Latched for the life of the process, so a model retrying in a loop
    /// cannot turn one refusal into a stream of questions. A question dismissed or
    /// left unanswered is not a no, and is asked again on the next call.
    Declined,
}

pub(crate) struct Confirmations {
    scope: tokio::sync::Mutex<ScopeAnswer>,
    write_hosts: Mutex<HashSet<String>>,
}

/// A write action waiting for a yes.
pub(crate) struct WriteAsk {
    /// `host:port` when the answer is remembered per destination for this process;
    /// `None` when every call asks again.
    pub remember: Option<String>,
    pub message: String,
}

impl Confirmations {
    pub(crate) fn new() -> Self {
        Confirmations {
            scope: tokio::sync::Mutex::new(ScopeAnswer::Unasked),
            write_hosts: Mutex::new(HashSet::new()),
        }
    }

    /// The once-per-process confirmation of the whole scope. Returns how it was given,
    /// for the audit: `elicited` or `file`.
    ///
    /// Concurrent first calls wait on the lock, so a person sees one question.
    pub(crate) async fn scope(
        &self,
        peer: &dyn ClientPeer,
        scope: &LoadedScope,
    ) -> Result<&'static str, Refusal> {
        let mut state = self.scope.lock().await;
        match *state {
            ScopeAnswer::Elicited => return Ok("elicited"),
            ScopeAnswer::File => return Ok("file"),
            ScopeAnswer::Declined => {
                return Err(Refusal::new(
                    Reason::Declined,
                    "Sending traffic was declined in this session. Restart the MCP server to \
                     be asked again.",
                ));
            }
            ScopeAnswer::Unasked => {}
        }
        if !peer.can_elicit_form() {
            *state = ScopeAnswer::File;
            return Ok("file");
        }
        let mut shown: Vec<String> = scope
            .entries
            .iter()
            .take(50)
            .map(|e| untrusted::clean(e, 200))
            .collect();
        if scope.entries.len() > 50 {
            shown.push(format!("+{} more", scope.entries.len() - 50));
        }
        let message = format!(
            "crossfyre mcp is about to send traffic. The scope file {} (sha256 {}) lists: {}. \
             Confirm that you are authorised to test every destination on this list.",
            scope.path.display(),
            scope.short_sha(),
            shown.join(", ")
        );
        match peer
            .confirm(
                message,
                "authorized",
                "I am authorised to test everything on this list",
            )
            .await
        {
            Answer::Yes => {
                *state = ScopeAnswer::Elicited;
                Ok("elicited")
            }
            Answer::No => {
                *state = ScopeAnswer::Declined;
                Err(Refusal::new(
                    Reason::Declined,
                    "The person did not confirm they are authorised to test the destinations \
                     in the scope file, so nothing was sent. Later traffic in this session is \
                     refused without asking; restart the MCP server to be asked again.",
                ))
            }
            Answer::Dismissed => Err(not_answered()),
        }
    }

    /// A yes for one write action. Needs a client that can ask.
    pub(crate) async fn write(&self, peer: &dyn ClientPeer, ask: WriteAsk) -> Result<(), Refusal> {
        if let Some(key) = &ask.remember
            && self.write_hosts.lock().is_ok_and(|s| s.contains(key))
        {
            return Ok(());
        }
        if !peer.can_elicit_form() {
            return Err(Refusal::new(
                Reason::NotConfirmed,
                "This client cannot show the confirmation that write actions need, so the \
                 request was not sent. Use a read-only method or a client that supports \
                 elicitation.",
            ));
        }
        match peer
            .confirm(ask.message, "allow", "Allow this write action")
            .await
        {
            Answer::Yes => {
                if let (Some(key), Ok(mut s)) = (ask.remember, self.write_hosts.lock()) {
                    s.insert(key);
                }
                Ok(())
            }
            Answer::No => Err(Refusal::new(
                Reason::Declined,
                "The write action was not confirmed, so nothing was sent.",
            )),
            Answer::Dismissed => Err(not_answered()),
        }
    }
}

fn not_answered() -> Refusal {
    Refusal::new(
        Reason::NotConfirmed,
        "The confirmation was dismissed or not answered in time, so nothing was sent. The next \
         call that sends traffic asks again.",
    )
}
