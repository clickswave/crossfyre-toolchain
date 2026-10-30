//! What the server needs from the client on the other end of a call.
//!
//! Kept small so the tests can stand in for a client without speaking the protocol: a
//! label for the audit, whether it can show a form, asking a yes or no question, and
//! reporting progress. The Cloud backend adds telling the client its tool list changed,
//! with a default that does nothing.

use crate::guard::BoxFut;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Answer {
    /// Accepted with the box ticked.
    Yes,
    /// Declined, or accepted with the box unticked: a person said no.
    No,
    /// Dismissed, not answered in time, or the question could not be asked. Nobody
    /// said yes, and nobody said no either.
    Dismissed,
}

pub(crate) trait ClientPeer: Send + Sync {
    /// The client's own name and version. Unverified: any client can say anything.
    fn label(&self) -> String;
    /// The client said it can show a form to a person.
    fn can_elicit_form(&self) -> bool;
    /// Ask a person one yes or no question, as one required boolean `field`.
    fn confirm<'a>(
        &'a self,
        message: String,
        field: &'static str,
        title: &'static str,
    ) -> BoxFut<'a, Answer>;
    /// Report progress on the current call, if the client asked for it.
    fn progress<'a>(&'a self, done: f64, total: Option<f64>, message: &'a str) -> BoxFut<'a, ()>;

    /// Tell the client the tool list changed, as a backend comes or goes.
    fn tool_list_changed<'a>(&'a self) -> BoxFut<'a, ()> {
        Box::pin(async {})
    }
}
