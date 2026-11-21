//! A module signed by a release key is installed, the engine says its version, and the
//! adaptive crate's answers come from it, held to the caller's bounds.

mod common;
use adaptive::backend::{Pacing, pacing};
use adaptive::congestion::{Estimator, Limits, Window, decide};
use common::*;

#[test]
fn a_signed_module_is_installed_and_answers_within_the_bounds() {
    let folder = Folder::new("install");
    let bytes = module(&Spec {
        answer: r#"{"srtt_us": 1500.0, "rttvar_us": 300.0, "warmup": false,
                    "concurrency": 1000000, "timeout_ms": 0, "retries": 99}"#
            .into(),
        ..Spec::default()
    });
    let path = folder.put(&bytes, Some(&sign(&release_key(), &bytes)));
    assert_eq!(pacing(), Pacing::Baseline);
    let got = cfx_pacing::load_from(
        &path,
        &exe(),
        &[&public(&release_key())],
        cfx_pacing::Limits::default(),
    );
    assert_eq!(got, cfx_pacing::Loaded::Module("test 1".into()));
    assert_eq!(got.say(), "pacing: module test 1");
    assert_eq!(pacing(), Pacing::Module("test 1".into()));

    let limits = Limits::default();
    let mut est = Estimator::warmup(1000);
    let w = Window {
        sent: 10,
        lost: 0,
        delivered: 10,
        retried: 0,
        recovered: 0,
        rtt_sum_us: 10_000,
    };
    let d = decide(&mut est, 16, &w, None, &limits);
    assert_eq!(
        (d.concurrency, d.timeout_ms, d.retries),
        (limits.conc_ceil, limits.timeout_floor_ms, limits.retry_ceil)
    );
    assert_eq!((est.srtt_us, est.rttvar_us), (1500.0, 300.0));
}
