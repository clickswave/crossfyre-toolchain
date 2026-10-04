//! The point of the library target: another crate can reach these.
//!
//! This lives as an integration test because an integration test compiles against the
//! crate the way a dependent would, so a module that is `pub` but whose signature leaks
//! a private type fails here rather than in whichever consumer tries first.

#[test]
fn byte_exact_sending_is_reachable() {
    // The primitive a Repeater needs. Normalising a request is correct for a client and
    // wrong for a tool whose job is to send malformed ones.
    let (tls, host, port, path) =
        cortex::rawhttp::split_url("https://example.test:8443/a/../b").expect("parse");
    assert!(tls);
    assert_eq!(host, "example.test");
    assert_eq!(port, 8443);
    assert_eq!(
        path, "/a/../b",
        "the dot segment survives, which is the whole reason this exists"
    );
}

#[test]
fn host_scope_is_reachable() {
    // Three host-scope implementations exist in this product and two of them disagree
    // about whether a wildcard admits the apex. A credential's host scope is an
    // authorisation boundary, so that is a defect rather than a style difference. This
    // pins what THIS one does, so the other two can be moved onto it deliberately.
    let (scope, bad) = cortex::scope::parse(&["*.example.com".to_string()]);
    assert!(bad.is_empty(), "the entry parses: {bad:?}");

    assert!(
        scope.admits("api.example.com", Some(443)),
        "a subdomain is in"
    );
    assert!(
        !scope.admits("example.com", Some(443)),
        "and the apex is NOT. This is the answer the other two implementations have to \
         be reconciled against, and it is the stricter of the two, which is the right \
         direction for something that is an authorisation boundary."
    );
    assert!(
        !scope.admits("evil-example.com", Some(443)),
        "and a plain ends_with would have admitted this one"
    );
}
