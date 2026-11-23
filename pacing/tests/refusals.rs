//! A module that fails a check is never used, and says why: signed by the data key or by
//! nobody, edited after it was signed, importing from its host, of another interface,
//! writable by others, or in a build that carries no release key. One that runs past its
//! budget gives no answer.

mod common;
use cfx_pacing::{Limits, Loaded, Module, open};
use common::*;

fn refused(path: &std::path::Path, keys: &[&str]) -> String {
    match open(path, &exe(), keys, Limits::default()) {
        Ok(_) => panic!("{} was accepted", path.display()),
        Err(why) => why,
    }
}

#[test]
fn a_module_signed_by_the_data_key_is_refused() {
    let folder = Folder::new("data-key");
    let bytes = module(&Spec::default());
    let release = public(&release_key());
    let path = folder.put(&bytes, Some(&sign(&data_key(), &bytes)));
    assert!(refused(&path, &[&release]).contains("not signed by a release key"));
    // The same module, signed by the release key, is accepted.
    folder.put(&bytes, Some(&sign(&release_key(), &bytes)));
    assert!(open(&path, &exe(), &[&release], Limits::default()).is_ok());
}

#[test]
fn an_edited_unsigned_or_unkeyed_module_is_refused() {
    let folder = Folder::new("edited");
    let bytes = module(&Spec::default());
    let sig = sign(&release_key(), &bytes);
    let release = public(&release_key());
    let mut edited = bytes.clone();
    let last = edited.len() - 1;
    edited[last] ^= 1;
    let path = folder.put(&edited, Some(&sig));
    assert!(refused(&path, &[&release]).contains("not signed by a release key"));
    folder.put(&bytes, None);
    assert!(refused(&path, &[&release]).contains("no signature"));
    folder.put(&bytes, Some(&sig));
    assert!(refused(&path, &[]).contains("carries no release key"));
}

#[test]
fn a_module_that_imports_or_speaks_another_interface_is_refused() {
    let folder = Folder::new("shape");
    let release = public(&release_key());
    for (spec, why) in [
        (
            Spec {
                import: true,
                ..Spec::default()
            },
            "imports from its host",
        ),
        (
            Spec {
                interface: 2,
                ..Spec::default()
            },
            "implements interface 2",
        ),
    ] {
        let bytes = module(&spec);
        let path = folder.put(&bytes, Some(&sign(&release_key(), &bytes)));
        let got = refused(&path, &[&release]);
        assert!(got.contains(why), "{got}");
    }
}

#[cfg(unix)]
#[test]
fn a_module_others_can_write_is_refused() {
    use std::os::unix::fs::PermissionsExt;
    let folder = Folder::new("mode");
    let bytes = module(&Spec::default());
    let path = folder.put(&bytes, Some(&sign(&release_key(), &bytes)));
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o664)).unwrap();
    assert!(refused(&path, &[&public(&release_key())]).contains("writable by group or others"));
}

#[test]
fn a_module_that_runs_past_its_budget_gives_no_answer() {
    use adaptive::backend::Backend;
    let looping = Module::new(
        &module(&Spec {
            spin: true,
            ..Spec::default()
        }),
        Limits {
            fuel_per_call: 100_000,
            ..Limits::default()
        },
    )
    .unwrap();
    assert_eq!(looping.call("congestion.decide", b"{}"), None);
    let answering = Module::new(&module(&Spec::default()), Limits::default()).unwrap();
    assert_eq!(
        answering.call("congestion.decide", b"{}").as_deref(),
        Some(&b"{}"[..])
    );
}

#[test]
fn without_a_module_the_baseline_answers_and_says_why() {
    let folder = Folder::new("none");
    let got = cfx_pacing::load_from(
        &folder.0.join(cfx_pacing::MODULE),
        &exe(),
        &[&public(&release_key())],
        Limits::default(),
    );
    assert_eq!(got, Loaded::Baseline("no module is installed".into()));
    assert_eq!(got.say(), "pacing: baseline (no module is installed)");
}
