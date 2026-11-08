//! The CPython a Linux release carries beside cfx-script, and the only one it runs.
//!
//! A Linux build linked the libpython of the machine that built it, by its versioned
//! name, so it started only where exactly that Python's shared library was installed.
//! A release built with the `bundled-python` feature comes with a CPython in a folder
//! called `python` beside the binary instead:
//!
//! ```text
//! cfx-script
//! python/lib/libpython3.X.so.1.0
//! python/lib/python3.X/...        the standard library
//! ```
//!
//! The binary names `$ORIGIN/python/lib` as its DT_RPATH (see build.rs), so the loader
//! finds libpython there before it looks anywhere else. Before Python starts, `start`
//! checks that the libpython in this process is that one and that the standard library
//! is beside it, then starts the interpreter with `python` as its home. When either is
//! missing it refuses to run, rather than fall back to a Python the host may have: a
//! libpython of the same name from elsewhere would pair this build with another
//! build's standard library.
//!
//! The interpreter ignores the PYTHON* variables in the environment and the user's
//! site-packages. They belong to the host's own Python, of whatever version, and a
//! PYTHONPATH meant for that one would put its packages in front of the standard
//! library here.

use pyo3::ffi;
use std::ffi::{CStr, CString, OsStr};
use std::mem::MaybeUninit;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

#[cfg(any(not(target_os = "linux"), feature = "abi3"))]
compile_error!(
    "bundled-python is for Linux builds against a full libpython: it starts Python through \
     PyConfig, which the stable ABI does not have"
);

/// The folder beside the binary that holds the Python.
pub const DIR: &str = "python";

/// Start the Python beside this binary, or say why it cannot be started. Called once,
/// before anything else touches Python, and after fd 1 has been moved (`take_stdout`),
/// since Python wraps fd 1 as it starts. On success the interpreter is running and the
/// GIL is released, as pyo3 leaves it when it starts Python itself, so `Python::attach`
/// finds it running and uses it.
pub fn start() -> Result<(), String> {
    let exe = std::env::current_exe()
        .map_err(|e| format!("cfx-script cannot tell where it is installed ({e})"))?;
    let home = exe
        .parent()
        .map(|dir| dir.join(DIR))
        .ok_or_else(|| format!("{} is in no directory", exe.display()))?;
    let lib = home.join("lib");
    let loaded = loaded_libpython()?;
    let version = check_loaded(&loaded, &lib)?;
    let stdlib = lib.join(format!("python{version}"));
    if !stdlib.join("os.py").is_file() {
        return Err(missing(
            &home,
            &format!("{} holds no standard library", stdlib.display()),
        ));
    }
    // SAFETY: Python has not been started in this process: this is the first thing
    // main does with it, and pyo3 starts it only when it is not running.
    unsafe { initialize(&home) }
}

/// What to say when the Python beside the binary is not all there.
fn missing(home: &Path, what: &str) -> String {
    format!(
        "cfx-script runs .cfx scripts with the Python in {}, and {what}. `crossfyre update \
         --force` installs cfx-script again with its Python.",
        home.display()
    )
}

/// Every libpython mapped into this process, by the path the kernel gives for it.
fn loaded_libpython() -> Result<Vec<PathBuf>, String> {
    let maps = std::fs::read("/proc/self/maps")
        .map_err(|e| format!("cfx-script cannot read /proc/self/maps ({e})"))?;
    let mut found: Vec<PathBuf> = maps
        .split(|b| *b == b'\n')
        .filter_map(|line| {
            let path = Path::new(OsStr::from_bytes(
                &line[line.iter().position(|b| *b == b'/')?..],
            ));
            path.file_name()?
                .as_bytes()
                .starts_with(b"libpython")
                .then(|| path.to_path_buf())
        })
        .collect();
    found.sort();
    found.dedup();
    Ok(found)
}

/// The Python version of the one libpython in `loaded`, `3.13` from
/// `libpython3.13.so.1.0`, when it is the one in `lib`. Anything else is refused: no
/// libpython, more than one, or one from somewhere else.
fn check_loaded(loaded: &[PathBuf], lib: &Path) -> Result<String, String> {
    let home = lib.parent().unwrap_or(lib);
    let [one] = loaded else {
        let names: Vec<String> = loaded.iter().map(|p| p.display().to_string()).collect();
        return Err(if names.is_empty() {
            missing(home, "no libpython is loaded")
        } else {
            missing(
                home,
                &format!("more than one libpython is loaded: {}", names.join(", ")),
            )
        });
    };
    let beside = std::fs::canonicalize(lib).ok();
    if beside.is_none() || one.parent() != beside.as_deref() {
        return Err(missing(
            home,
            &format!(
                "the libpython loaded is {}, not the one in {}",
                one.display(),
                lib.display()
            ),
        ));
    }
    let name = one.file_name().map(OsStr::as_bytes).unwrap_or_default();
    let version = name
        .strip_prefix(b"libpython")
        .and_then(|rest| {
            rest.split(|b| *b == b'.')
                .take(2)
                .collect::<Vec<_>>()
                .try_into()
                .ok()
        })
        .and_then(|[major, minor]: [&[u8]; 2]| {
            let digits = |s: &[u8]| !s.is_empty() && s.iter().all(u8::is_ascii_digit);
            (digits(major) && digits(minor)).then(|| {
                format!(
                    "{}.{}",
                    String::from_utf8_lossy(major),
                    String::from_utf8_lossy(minor)
                )
            })
        });
    version.ok_or_else(|| {
        missing(
            home,
            &format!("{} is not named for a Python version", one.display()),
        )
    })
}

/// Start the interpreter with `home` as its prefix.
///
/// sys.executable is left for Python to find on PATH, as it was when pyo3 started
/// Python: the folder carries no interpreter binary of its own, since the one in the
/// upstream build links all of libpython in again.
///
/// # Safety
/// Python must not be running in this process yet.
unsafe fn initialize(home: &Path) -> Result<(), String> {
    let mut config = MaybeUninit::<ffi::PyConfig>::uninit();
    let config = config.as_mut_ptr();
    // SAFETY: PyConfig_InitPythonConfig fills in the whole struct, and every pointer
    // below is into it. The fields are set before the first PyConfig_Set* call, which
    // preinitialises Python from them. PyConfig_Clear frees what the Set* calls
    // allocated, whether or not Python started.
    unsafe {
        ffi::PyConfig_InitPythonConfig(config);
        (*config).use_environment = 0;
        (*config).user_site_directory = 0;
        // As pyo3 starts Python: SIGINT keeps its default action, so the node can stop
        // a script the way it stops any process.
        (*config).install_signal_handlers = 0;
        // A release's Python has no lib-dynload: nothing it carries is built as a
        // separate module. `start` has checked the standard library itself.
        (*config).pathconfig_warnings = 0;
        let result = set_path(config, &raw mut (*config).home, home)
            .and_then(|()| status(ffi::Py_InitializeFromConfig(config)));
        ffi::PyConfig_Clear(config);
        result?;
        ffi::PyEval_SaveThread();
    }
    Ok(())
}

/// Set a string field of `config` to `path`, decoded the way Python decodes paths.
///
/// # Safety
/// `config` is initialised and `field` is one of its string fields.
unsafe fn set_path(
    config: *mut ffi::PyConfig,
    field: *mut *mut libc::wchar_t,
    path: &Path,
) -> Result<(), String> {
    let bytes = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| format!("{} has a NUL byte in it", path.display()))?;
    // SAFETY: as the caller promises, and `bytes` outlives the call, which copies it.
    status(unsafe { ffi::PyConfig_SetBytesString(config, field, bytes.as_ptr()) })
}

/// Ok, or what a PyStatus that is an error or an exit says.
fn status(status: ffi::PyStatus) -> Result<(), String> {
    // SAFETY: PyStatus_Exception reads the struct it is given and nothing else.
    if unsafe { ffi::PyStatus_Exception(status) } == 0 {
        return Ok(());
    }
    let text = |p: *const libc::c_char| {
        // SAFETY: a PyStatus's strings are static C strings or null.
        (!p.is_null()).then(|| unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned())
    };
    let what = match (text(status.func), text(status.err_msg)) {
        (Some(func), Some(msg)) => format!("{func}: {msg}"),
        (None, Some(msg)) => msg,
        _ => format!("it exited with status {}", status.exitcode),
    };
    Err(format!("cfx-script could not start Python: {what}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lib_dir() -> (tempfile_free::Dir, PathBuf) {
        let dir = tempfile_free::Dir::new();
        let lib = dir.0.join("python").join("lib");
        std::fs::create_dir_all(&lib).unwrap();
        let lib = std::fs::canonicalize(lib).unwrap();
        (dir, lib)
    }

    #[test]
    fn the_libpython_beside_the_binary_gives_its_version() {
        let (_dir, lib) = lib_dir();
        let loaded = [lib.join("libpython3.13.so.1.0")];
        assert_eq!(check_loaded(&loaded, &lib).unwrap(), "3.13");
    }

    #[test]
    fn a_libpython_from_elsewhere_is_refused_and_named() {
        let (_dir, lib) = lib_dir();
        let loaded = [PathBuf::from(
            "/usr/lib/x86_64-linux-gnu/libpython3.13.so.1.0",
        )];
        let why = check_loaded(&loaded, &lib).unwrap_err();
        assert!(
            why.contains("/usr/lib/x86_64-linux-gnu/libpython3.13.so.1.0"),
            "{why}"
        );
        assert!(why.contains("crossfyre update --force"), "{why}");
    }

    #[test]
    fn no_libpython_or_two_of_them_is_refused() {
        let (_dir, lib) = lib_dir();
        assert!(
            check_loaded(&[], &lib)
                .unwrap_err()
                .contains("no libpython")
        );
        let two = [
            lib.join("libpython3.13.so.1.0"),
            PathBuf::from("/usr/lib/libpython3.11.so.1.0"),
        ];
        assert!(
            check_loaded(&two, &lib)
                .unwrap_err()
                .contains("more than one")
        );
    }

    #[test]
    fn a_missing_lib_folder_is_refused() {
        let (dir, _) = lib_dir();
        let gone = dir.0.join("elsewhere").join("lib");
        let loaded = [gone.join("libpython3.13.so.1.0")];
        assert!(check_loaded(&loaded, &gone).is_err());
    }

    #[test]
    fn a_libpython_not_named_for_a_version_is_refused() {
        let (_dir, lib) = lib_dir();
        let loaded = [lib.join("libpython3.so")];
        assert!(
            check_loaded(&loaded, &lib)
                .unwrap_err()
                .contains("not named for a Python version")
        );
    }

    /// A directory removed when dropped, without a crate for it.
    mod tempfile_free {
        pub struct Dir(pub std::path::PathBuf);
        impl Dir {
            pub fn new() -> Self {
                use std::sync::atomic::{AtomicUsize, Ordering};
                static N: AtomicUsize = AtomicUsize::new(0);
                let path = std::env::temp_dir().join(format!(
                    "cfx-script-bundled-{}-{}",
                    std::process::id(),
                    N.fetch_add(1, Ordering::Relaxed)
                ));
                std::fs::create_dir_all(&path).unwrap();
                Dir(path)
            }
        }
        impl Drop for Dir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
    }
}
