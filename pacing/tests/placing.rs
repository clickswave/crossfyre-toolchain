//! An install puts a module where engines look, only after checking it as they do, and
//! leaves nothing behind when it would not be loaded.

mod common;
use cfx_pacing::{Limits, MODULE, SIG_SUFFIX, install, open};
use common::*;

fn files(folder: &Folder) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(&folder.0)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

#[test]
fn a_signed_module_is_placed_beside_the_binaries_and_opens_from_there() {
    let folder = Folder::new("place");
    let release = public(&release_key());
    let old = module(&Spec {
        answer: "{\"old\": 1}".into(),
        ..Spec::default()
    });
    install(
        &folder.0,
        &exe(),
        &old,
        &sign(&release_key(), &old),
        &[&release],
        Limits::default(),
    )
    .unwrap();
    let bytes = module(&Spec::default());
    let sig = sign(&release_key(), &bytes);
    let path = install(
        &folder.0,
        &exe(),
        &bytes,
        &format!("{sig}\n"),
        &[&release],
        Limits::default(),
    )
    .unwrap();
    assert_eq!(path, folder.0.join(MODULE));
    assert_eq!(
        std::fs::read(&path).unwrap(),
        bytes,
        "the new module replaced the old"
    );
    let sig_path = folder.0.join(format!("{MODULE}{SIG_SUFFIX}"));
    assert_eq!(std::fs::read_to_string(&sig_path).unwrap(), sig);
    assert_eq!(
        files(&folder),
        [MODULE.to_string(), format!("{MODULE}{SIG_SUFFIX}")]
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for p in [&path, &sig_path] {
            assert_eq!(
                std::fs::metadata(p).unwrap().permissions().mode() & 0o777,
                0o644
            );
        }
    }
    assert!(open(&path, &exe(), &[&release], Limits::default()).is_ok());
}

#[test]
fn a_module_an_engine_would_refuse_leaves_the_installed_one_in_place() {
    let folder = Folder::new("refuse");
    let release = public(&release_key());
    let good = module(&Spec::default());
    let good_sig = sign(&release_key(), &good);
    let path = install(
        &folder.0,
        &exe(),
        &good,
        &good_sig,
        &[&release],
        Limits::default(),
    )
    .unwrap();
    let other = module(&Spec {
        answer: "{\"other\": 1}".into(),
        ..Spec::default()
    });
    let by_data = install(
        &folder.0,
        &exe(),
        &other,
        &sign(&data_key(), &other),
        &[&release],
        Limits::default(),
    );
    assert!(by_data.unwrap_err().contains("not signed by a release key"));
    let importing = module(&Spec {
        import: true,
        ..Spec::default()
    });
    let sig = sign(&release_key(), &importing);
    let got = install(
        &folder.0,
        &exe(),
        &importing,
        &sig,
        &[&release],
        Limits::default(),
    );
    assert!(got.unwrap_err().contains("imports from its host"));
    assert_eq!(std::fs::read(&path).unwrap(), good);
    let sig_path = folder.0.join(format!("{MODULE}{SIG_SUFFIX}"));
    assert_eq!(std::fs::read_to_string(sig_path).unwrap(), good_sig);
    assert_eq!(files(&folder).len(), 2, "{:?}", files(&folder));
    assert!(open(&path, &exe(), &[&release], Limits::default()).is_ok());
}

#[cfg(unix)]
#[test]
fn a_folder_others_can_write_is_left_as_it_was() {
    use std::os::unix::fs::PermissionsExt;
    let folder = Folder::new("open-folder");
    std::fs::set_permissions(&folder.0, std::fs::Permissions::from_mode(0o775)).unwrap();
    let bytes = module(&Spec::default());
    let got = install(
        &folder.0,
        &exe(),
        &bytes,
        &sign(&release_key(), &bytes),
        &[&public(&release_key())],
        Limits::default(),
    );
    assert!(got.unwrap_err().contains("writable by group or others"));
    assert!(files(&folder).is_empty(), "{:?}", files(&folder));
}
