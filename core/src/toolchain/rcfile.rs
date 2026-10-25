// The PATH line the installer used to write into a person's shell startup files.
//
// Up to 0.1.32 the installer put /opt/crossfyre/bin at the front of PATH, under a
// "# Added by the Crossfyre installer" comment. That directory holds the node agent,
// which is called `node`, so on a machine with Node.js every new shell found the agent
// first. The installer now appends the directory instead, and this rewrites a line an
// older installer wrote, from `crossfyre update` and `crossfyre node init` when a person
// runs them. The node daemon never calls it: it runs as root under the service manager,
// and a file in somebody's home is not its to edit unasked.
//
// The file is edited where it is. A ~/.bashrc that is a symlink into a dotfiles
// repository stays a symlink, and the file it points at keeps its owner and mode,
// because the new line is the old one with its two halves swapped, the same length,
// written over it in place.

use std::path::{Path, PathBuf};

/// The comment the installer writes above its PATH line.
pub const MARKER: &str = "# Added by the Crossfyre installer";

/// The line an older installer wrote and the line that replaces it: for bash and zsh,
/// then for fish.
const REWRITES: [(&str, &str); 2] = [
    (
        "export PATH=\"/opt/crossfyre/bin:$PATH\"",
        "export PATH=\"$PATH:/opt/crossfyre/bin\"",
    ),
    (
        "set -gx PATH /opt/crossfyre/bin $PATH",
        "set -gx PATH $PATH /opt/crossfyre/bin",
    ),
];

// The rewrite goes over the old bytes, so each pair has to be the same length.
const _: () = {
    assert!(REWRITES[0].0.len() == REWRITES[0].1.len());
    assert!(REWRITES[1].0.len() == REWRITES[1].1.len());
};

/// Where in `text` an old PATH line sits directly under the marker, and what replaces
/// it there. A line anywhere else is the person's own and is not listed.
fn edits(text: &[u8]) -> Vec<(usize, &'static str)> {
    let mut out = Vec::new();
    let mut under_marker = false;
    let mut at = 0;
    for line in text.split_inclusive(|b| *b == b'\n') {
        let content = line.strip_suffix(b"\n").unwrap_or(line);
        let content = content.strip_suffix(b"\r").unwrap_or(content);
        if under_marker
            && let Some((_, new)) = REWRITES.iter().find(|(old, _)| content == old.as_bytes())
        {
            out.push((at, *new));
        }
        under_marker = content == MARKER.as_bytes();
        at += line.len();
    }
    out
}

/// Rewrite the installer's old PATH line in the file at `path`, through any symlinks.
/// `Ok(true)` when the file changed. A missing file is left alone, and so is one owned
/// by anyone but `owner` when that is given: under sudo this runs as root, and the file
/// has to be the invoking user's own.
pub fn rewrite(path: &Path, owner: Option<u32>) -> std::io::Result<bool> {
    let real = match std::fs::canonicalize(path) {
        Ok(p) => p,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e),
    };
    #[cfg(unix)]
    if let Some(uid) = owner {
        use std::os::unix::fs::MetadataExt;
        if std::fs::metadata(&real)?.uid() != uid {
            return Ok(false);
        }
    }
    #[cfg(not(unix))]
    let _ = owner;
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&real)?;
    let mut text = Vec::new();
    std::io::Read::read_to_end(&mut file, &mut text)?;
    let found = edits(&text);
    if found.is_empty() {
        return Ok(false);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileExt;
        for (at, new) in &found {
            file.write_all_at(new.as_bytes(), *at as u64)?;
        }
    }
    #[cfg(windows)]
    for (at, new) in &found {
        use std::os::windows::fs::FileExt;
        let mut done = 0;
        while done < new.len() {
            done += file.seek_write(&new.as_bytes()[done..], (*at + done) as u64)?;
        }
    }
    file.sync_all()?;
    Ok(true)
}

/// The shell startup files the installer writes its PATH line into, under `home`. The
/// old line only ever went into these three, from the Linux installer. On macOS and
/// Windows there is nothing to rewrite: an installer there appends the bin directory to
/// PATH from the start (on Windows, to the user's PATH in the registry), for the same
/// reason.
fn rc_files(home: &Path) -> [PathBuf; 3] {
    [
        home.join(".bashrc"),
        home.join(".zshrc"),
        home.join(".config/fish/config.fish"),
    ]
}

/// Rewrite the installer's old PATH line in the invoking user's shell startup files,
/// saying so for each file changed. Once rewritten there is nothing left to match, so
/// each file is reported once. For `crossfyre update` and `crossfyre node init` only.
pub fn fix_for_invoking_user() {
    let (home, owner) = match super::sudo_user::sudo_user_info() {
        Some((uid, _, home, _)) => (home, Some(uid)),
        None => match dirs::home_dir() {
            Some(home) => (home, None),
            None => return,
        },
    };
    for rc in rc_files(&home) {
        let shown = match rc.strip_prefix(&home) {
            Ok(rel) => format!("~/{}", rel.display()),
            Err(_) => rc.display().to_string(),
        };
        match rewrite(&rc, owner) {
            Ok(true) => println!(
                "[+] {shown} now adds /opt/crossfyre/bin at the end of PATH rather than the \
                 front, so the Crossfyre node agent no longer hides Node.js. New shells pick \
                 it up."
            ),
            Ok(false) => {}
            Err(e) => eprintln!("[!] could not update the PATH line in {shown}: {e}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    const OLD_BASHRC: &str = "alias ll='ls -l'\n\n# Added by the Crossfyre installer\nexport PATH=\"/opt/crossfyre/bin:$PATH\"\n";
    const NEW_BASHRC: &str = "alias ll='ls -l'\n\n# Added by the Crossfyre installer\nexport PATH=\"$PATH:/opt/crossfyre/bin\"\n";

    #[test]
    fn only_a_line_under_the_marker_is_the_installers() {
        assert_eq!(edits(OLD_BASHRC.as_bytes()).len(), 1);
        assert!(edits(NEW_BASHRC.as_bytes()).is_empty(), "already appended");
        let own = "export PATH=\"/opt/crossfyre/bin:$PATH\"\n";
        assert!(edits(own.as_bytes()).is_empty(), "the person's own line");
        let fish = "# Added by the Crossfyre installer\nset -gx PATH /opt/crossfyre/bin $PATH\n";
        let found = edits(fish.as_bytes());
        assert_eq!(found, [(35, "set -gx PATH $PATH /opt/crossfyre/bin")]);
        let crlf =
            "# Added by the Crossfyre installer\r\nexport PATH=\"/opt/crossfyre/bin:$PATH\"\r\n";
        assert_eq!(edits(crlf.as_bytes()).len(), 1);
        let no_newline =
            "# Added by the Crossfyre installer\nexport PATH=\"/opt/crossfyre/bin:$PATH\"";
        assert_eq!(edits(no_newline.as_bytes()).len(), 1);
    }

    #[test]
    fn the_line_is_rewritten_and_the_rest_of_the_file_is_not() {
        let dir = tempfile::tempdir().expect("scratch");
        let rc = dir.path().join(".bashrc");
        fs::write(&rc, OLD_BASHRC).expect("write");
        assert!(rewrite(&rc, None).expect("rewrites"));
        assert_eq!(fs::read_to_string(&rc).expect("read"), NEW_BASHRC);
        assert!(
            !rewrite(&rc, None).expect("reads"),
            "nothing to do the second time"
        );
        assert!(!rewrite(&dir.path().join("absent"), None).expect("a missing file is fine"));
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_rc_file_stays_a_symlink_and_keeps_its_owner_and_mode() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let dir = tempfile::tempdir().expect("scratch");
        let dotfiles = dir.path().join("dotfiles");
        let home = dir.path().join("home");
        fs::create_dir_all(&dotfiles).expect("dotfiles");
        fs::create_dir_all(&home).expect("home");
        let target = dotfiles.join("bashrc");
        fs::write(&target, OLD_BASHRC).expect("write");
        fs::set_permissions(&target, fs::Permissions::from_mode(0o640)).expect("chmod");
        let before = fs::metadata(&target).expect("meta");
        let link = home.join(".bashrc");
        std::os::unix::fs::symlink(&target, &link).expect("link");

        assert!(rewrite(&link, None).expect("rewrites"));

        assert!(
            fs::symlink_metadata(&link)
                .expect("meta")
                .file_type()
                .is_symlink(),
            "the link is still a link"
        );
        assert_eq!(fs::read_link(&link).expect("link"), target);
        assert_eq!(fs::read_to_string(&target).expect("read"), NEW_BASHRC);
        let after = fs::metadata(&target).expect("meta");
        assert_eq!(after.mode() & 0o7777, 0o640, "mode kept");
        assert_eq!(
            (after.uid(), after.gid()),
            (before.uid(), before.gid()),
            "owner kept"
        );
        assert_eq!(after.ino(), before.ino(), "the same file, written in place");
    }

    #[cfg(unix)]
    #[test]
    fn a_file_owned_by_someone_else_is_left_alone() {
        use std::os::unix::fs::MetadataExt;
        let dir = tempfile::tempdir().expect("scratch");
        let rc = dir.path().join(".bashrc");
        fs::write(&rc, OLD_BASHRC).expect("write");
        let mine = fs::metadata(&rc).expect("meta").uid();
        assert!(!rewrite(&rc, Some(mine.wrapping_add(1))).expect("reads"));
        assert_eq!(fs::read_to_string(&rc).expect("read"), OLD_BASHRC);
        assert!(rewrite(&rc, Some(mine)).expect("rewrites"));
    }
}
