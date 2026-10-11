pub fn user_agent(user_agents: Option<Vec<String>>) -> String {
    // An explicit list is the caller's choice; take the first deterministically
    // (per-request UA flapping over a fixed TLS fingerprint is itself a bot
    // tell). Otherwise present a coherent browser identity from the adaptive
    // layer instead of the old UUID-as-UA, which was an obvious tell.
    if let Some(agents) = user_agents
        && !agents.is_empty()
    {
        return agents[0].clone();
    }
    adaptive::identity::resolve(&adaptive::identity::Mode::Evasive, None).user_agent
}
