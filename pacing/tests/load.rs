//! An engine's own load: once per process, from beside its executable, and said the
//! same way every time it is asked.

#[test]
fn load_looks_once_beside_the_executable_and_says_the_same_after() {
    let first = cfx_pacing::load();
    let exe = std::env::current_exe().unwrap();
    let beside = exe.parent().unwrap().join(cfx_pacing::MODULE);
    assert!(!beside.exists(), "{} is there", beside.display());
    assert_eq!(first.label(), "baseline (no module is installed)");
    assert_eq!(first.say(), "pacing: baseline (no module is installed)");
    assert!(std::ptr::eq(first, cfx_pacing::load()));
}
