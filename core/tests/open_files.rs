//! The node raises its limit on open descriptors when it starts. It runs in a process
//! of its own here, because it lowers the limit first.
#![cfg(unix)]

use cfx_core::os::{OPEN_FILES_WANTED, open_file_limit, raise_open_file_limit};

#[test]
#[allow(clippy::unnecessary_cast)]
fn the_node_raises_its_descriptor_limit_as_far_as_the_hard_limit() {
    let mut rl = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut rl) }, 0);
    let hard = rl.rlim_max as u64;
    // What a service is usually started with, or less.
    let low = hard.min(256);
    rl.rlim_cur = low as libc::rlim_t;
    assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &rl) }, 0);
    assert_eq!(open_file_limit(), Some(low));

    let mut want = hard.min(OPEN_FILES_WANTED);
    if cfg!(target_os = "macos") {
        want = want.min(10240);
    }
    let raised = raise_open_file_limit().expect("raised");
    assert_eq!(raised, Some((low, want)));
    assert_eq!(open_file_limit(), Some(want));

    // Already there: nothing changes.
    assert_eq!(raise_open_file_limit().unwrap(), Some((want, want)));
}
