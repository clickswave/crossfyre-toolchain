//! With a release key and a data key compiled in, as a release is built, a module the
//! data key signed is refused and one the release key signed is not: the data key cannot
//! make an engine run code.
//!
//! The keys are read when this is built, so it runs only in a build given throwaway ones,
//! which the build tests make, passing the secret halves' paths in
//! CFX_TEST_RELEASE_SECKEY and CFX_TEST_DATA_SECKEY.

mod common;
use base64::Engine as _;
use cfx_pacing::{Limits, open, release_keys};
use common::*;

fn secret_from(var: &str) -> ed25519_dalek::SigningKey {
    let path = std::env::var(var).unwrap_or_else(|_| panic!("{var} names no key file"));
    let text = std::fs::read_to_string(path).expect("the key file reads");
    let seed = base64::engine::general_purpose::STANDARD
        .decode(text.trim())
        .expect("the seed decodes");
    ed25519_dalek::SigningKey::from_bytes(&seed.try_into().expect("a 32-byte seed"))
}

#[test]
#[ignore = "needs throwaway keys compiled in"]
fn with_keys_compiled_in_a_module_the_data_key_signed_is_refused() {
    let release = secret_from("CFX_TEST_RELEASE_SECKEY");
    let data = secret_from("CFX_TEST_DATA_SECKEY");
    let compiled = release_keys();
    assert_eq!(compiled, vec![public(&release).as_str()]);
    assert!(!compiled.contains(&public(&data).as_str()));

    let folder = Folder::new("compiled-keys");
    let bytes = module(&Spec::default());
    let path = folder.put(&bytes, Some(&sign(&data, &bytes)));
    let why = open(&path, &exe(), &compiled, Limits::default())
        .err()
        .expect("a module the data key signed was accepted");
    assert!(why.contains("not signed by a release key"), "{why}");

    folder.put(&bytes, Some(&sign(&release, &bytes)));
    assert!(open(&path, &exe(), &compiled, Limits::default()).is_ok());
}
