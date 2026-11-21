pub fn user_agent() -> String {
    // Present a coherent, current browser identity from the adaptive layer rather
    // than a random pick per call: per-request UA flapping over a fixed TLS
    // fingerprint is itself a bot tell, and a hard-coded list drifts out of date.
    // The profile catalogue + rotation live in the pacing module.
    adaptive::identity::resolve(&adaptive::identity::Mode::Evasive, None).user_agent
}
