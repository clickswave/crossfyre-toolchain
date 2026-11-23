//! The pacing module: found beside the binaries, checked, and installed as the `adaptive`
//! crate's backend for the rest of the process. Without one, or with one that fails a
//! check, the baseline answers, and the engine says which.
//!
//! A module is code, so it has to carry a signature by a release key, the key that signs
//! the binaries' manifest, and never the data key, which vouches only for templates and
//! CVE data. On Unix it is also believed only under the rule `packaging.json` is: the file
//! and its directory owned by root or by whoever owns the executable, and writable by
//! nobody else.
//!
//! It runs in an interpreter, imports nothing from its host, and each call it answers has
//! a budget of work and memory: a module that loops, or asks for more, gives no answer, and
//! the baseline's is used for that call.

use adaptive::backend::{Backend, INTERFACE};
use base64::Engine as _;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

/// The module's file name beside the binaries, and its signature's beside it.
pub const MODULE: &str = "pacing.wasm";
pub const SIG_SUFFIX: &str = ".sig";

const RELEASE_KEY: Option<&str> = option_env!("CROSSFYRE_MANIFEST_PUBKEY");
const RELEASE_KEY_NEXT: Option<&str> = option_env!("CROSSFYRE_MANIFEST_PUBKEY_NEXT");

/// The keys a module's signature is checked with: the release keys this build carries.
pub fn release_keys() -> Vec<&'static str> {
    [RELEASE_KEY, RELEASE_KEY_NEXT]
        .into_iter()
        .flatten()
        .filter(|k| !k.trim().is_empty())
        .collect()
}

/// What answers the adaptive crate's calls after [`load`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Loaded {
    /// A module, by its version.
    Module(String),
    /// The baseline, and why no module is used.
    Baseline(String),
}

impl Loaded {
    /// As an engine's `capabilities` answer gives it: `module <version>`, or
    /// `baseline (<why>)`.
    pub fn label(&self) -> String {
        match self {
            Loaded::Module(v) => format!("module {v}"),
            Loaded::Baseline(why) => format!("baseline ({why})"),
        }
    }

    /// The line an engine says it in.
    pub fn say(&self) -> String {
        format!("pacing: {}", self.label())
    }
}

/// What one call of a module may use.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Instructions, roughly: wasmi's fuel.
    pub fuel_per_call: u64,
    pub memory_bytes: usize,
    /// The longest answer read back.
    pub answer_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            fuel_per_call: 50_000_000,
            memory_bytes: 32 << 20,
            answer_bytes: 1 << 20,
        }
    }
}

/// Load the module beside the running executable, with this build's release keys, and
/// install it. An engine calls this first thing; the first call looks, and every call
/// after gives what it found.
pub fn load() -> &'static Loaded {
    static LOADED: OnceLock<Loaded> = OnceLock::new();
    LOADED.get_or_init(|| {
        let exe = match std::env::current_exe().and_then(std::fs::canonicalize) {
            Ok(exe) => exe,
            Err(e) => return Loaded::Baseline(format!("the executable cannot be found: {e}")),
        };
        let dir = exe.parent().map(Path::to_path_buf).unwrap_or_default();
        load_from(&dir.join(MODULE), &exe, &release_keys(), Limits::default())
    })
}

/// Load the module at `path` for the executable at `exe`, checked with `keys`, and
/// install it. When a module answers already, that one is said.
pub fn load_from(path: &Path, exe: &Path, keys: &[&str], limits: Limits) -> Loaded {
    if let adaptive::backend::Pacing::Module(v) = adaptive::backend::pacing() {
        return Loaded::Module(v);
    }
    match open(path, exe, keys, limits) {
        Ok(module) => {
            let version = module.version.clone();
            if adaptive::backend::install(Box::new(module)) {
                Loaded::Module(version)
            } else {
                Loaded::Baseline("a module is installed already".into())
            }
        }
        Err(why) => Loaded::Baseline(why),
    }
}

/// The module at `path`, checked: present, believed, signed by one of `keys`, and a
/// module of this interface that imports nothing.
pub fn open(path: &Path, exe: &Path, keys: &[&str], limits: Limits) -> Result<Module, String> {
    if !path.exists() {
        return Err("no module is installed".into());
    }
    trust(path, exe)?;
    let bytes = std::fs::read(path).map_err(|e| format!("the module cannot be read: {e}"))?;
    let sig_path = PathBuf::from(format!("{}{SIG_SUFFIX}", path.display()));
    let sig = std::fs::read_to_string(&sig_path)
        .map_err(|_| "the module has no signature beside it".to_string())?;
    verify(keys, &bytes, sig.trim())?;
    Module::new(&bytes, limits)
}

/// Put a module and its signature in `dir`, the binaries' folder, as an install does:
/// checked first as an engine checks it (signed by one of `keys`, of this interface,
/// importing nothing), each file written beside its place and renamed over it, readable
/// by all and writable by its owner only, and then opened from there for the engine at
/// `exe` under the trust rule. Nothing is written when a check before writing fails;
/// both files are taken away again when the last one does.
pub fn install(
    dir: &Path,
    exe: &Path,
    bytes: &[u8],
    sig: &str,
    keys: &[&str],
    limits: Limits,
) -> Result<PathBuf, String> {
    verify(keys, bytes, sig.trim())?;
    Module::new(bytes, limits)?;
    let path = dir.join(MODULE);
    let sig_path = dir.join(format!("{MODULE}{SIG_SUFFIX}"));
    // The signature first: an engine starting between the two renames finds the new
    // signature over the old module, refuses it, and runs the baseline.
    write_over(&sig_path, sig.trim().as_bytes())?;
    write_over(&path, bytes)?;
    if let Err(why) = open(&path, exe, keys, limits) {
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&sig_path);
        return Err(format!(
            "an engine would not load it from {}: {why}",
            dir.display()
        ));
    }
    Ok(path)
}

/// Write `bytes` beside `path` and rename them over it, readable by all and writable by
/// the owner only.
fn write_over(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let new = PathBuf::from(format!("{}.new", path.display()));
    let written = std::fs::write(&new, bytes).and_then(|()| {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&new, std::fs::Permissions::from_mode(0o644))?;
        }
        std::fs::rename(&new, path)
    });
    written.map_err(|e| {
        let _ = std::fs::remove_file(&new);
        format!("{}: {e}", path.display())
    })
}

/// Whether `sig` is one of `keys`' signatures of `bytes`.
pub fn verify(keys: &[&str], bytes: &[u8], sig: &str) -> Result<(), String> {
    if keys.is_empty() {
        return Err("this build carries no release key, so no module can be checked".into());
    }
    let b64 = base64::engine::general_purpose::STANDARD;
    let sig = b64
        .decode(sig)
        .ok()
        .and_then(|s| <[u8; 64]>::try_from(s.as_slice()).ok())
        .map(|s| ed25519_dalek::Signature::from_bytes(&s))
        .ok_or("the module's signature does not read")?;
    for key in keys {
        let Some(vk) = b64
            .decode(key.trim())
            .ok()
            .and_then(|k| <[u8; 32]>::try_from(k.as_slice()).ok())
            .and_then(|k| ed25519_dalek::VerifyingKey::from_bytes(&k).ok())
        else {
            continue;
        };
        if vk.verify_strict(bytes, &sig).is_ok() {
            return Ok(());
        }
    }
    Err("the module is not signed by a release key".into())
}

/// The owner and mode rule `packaging.json` is read under: the file where its symlinks
/// lead, the directory holding it and the one holding the name looked up, each owned by
/// root or by whoever owns the executable, and none writable by group or others.
#[cfg(unix)]
fn trust(path: &Path, exe: &Path) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    let exe_owner = std::fs::metadata(exe)
        .map_err(|e| format!("the executable cannot be read: {e}"))?
        .uid();
    let real =
        std::fs::canonicalize(path).map_err(|e| format!("the module cannot be resolved: {e}"))?;
    let mut checked = vec![real.clone()];
    for dir in [real.parent(), path.parent()].into_iter().flatten() {
        if !checked.iter().any(|c| c == dir) {
            checked.push(dir.to_path_buf());
        }
    }
    for p in &checked {
        let meta = std::fs::metadata(p).map_err(|e| format!("{}: {e}", p.display()))?;
        if meta.uid() != 0 && meta.uid() != exe_owner {
            return Err(format!(
                "{} belongs to uid {}, which is neither root nor the owner of the executable",
                p.display(),
                meta.uid()
            ));
        }
        if meta.mode() & 0o022 != 0 {
            return Err(format!("{} is writable by group or others", p.display()));
        }
    }
    if !std::fs::metadata(&real)
        .map(|m| m.is_file())
        .unwrap_or(false)
    {
        return Err("the module is not a regular file".into());
    }
    Ok(())
}

/// Windows has no owner and mode rule here: whoever can write the binaries' folder can
/// replace the binaries in it too, so the module's signature is what is checked.
#[cfg(not(unix))]
fn trust(_path: &Path, _exe: &Path) -> Result<(), String> {
    Ok(())
}

struct Held {
    limits: wasmi::StoreLimits,
}

struct Live {
    store: wasmi::Store<Held>,
    memory: wasmi::Memory,
    alloc: wasmi::TypedFunc<i32, i32>,
    call: wasmi::TypedFunc<(i32, i32, i32, i32), i64>,
}

/// A checked module, instantiated, answering one call at a time.
pub struct Module {
    version: String,
    limits: Limits,
    live: Mutex<Live>,
}

impl Module {
    /// Instantiate `bytes`, a module of this interface that imports nothing.
    pub fn new(bytes: &[u8], limits: Limits) -> Result<Module, String> {
        let mut config = wasmi::Config::default();
        config.consume_fuel(true);
        let engine = wasmi::Engine::new(&config);
        let module = wasmi::Module::new(&engine, bytes)
            .map_err(|e| format!("the module does not read: {e}"))?;
        if module.imports().len() > 0 {
            return Err("the module imports from its host, which a module may not".into());
        }
        let held = Held {
            limits: wasmi::StoreLimitsBuilder::new()
                .memory_size(limits.memory_bytes)
                .build(),
        };
        let mut store = wasmi::Store::new(&engine, held);
        store.limiter(|h| &mut h.limits);
        store
            .set_fuel(limits.fuel_per_call)
            .map_err(|e| e.to_string())?;
        let instance = wasmi::Linker::<Held>::new(&engine)
            .instantiate_and_start(&mut store, &module)
            .map_err(|e| format!("the module does not start: {e}"))?;
        let func = |name: &str| format!("the module has no {name} of the interface");
        let interface = instance
            .get_typed_func::<(), i32>(&store, "cfx_interface")
            .map_err(|_| func("cfx_interface"))?
            .call(&mut store, ())
            .map_err(|e| e.to_string())?;
        if interface != INTERFACE as i32 {
            return Err(format!(
                "the module implements interface {interface}, and this engine speaks {INTERFACE}"
            ));
        }
        let memory = instance
            .get_memory(&store, "memory")
            .ok_or_else(|| func("memory"))?;
        let alloc = instance
            .get_typed_func::<i32, i32>(&store, "cfx_alloc")
            .map_err(|_| func("cfx_alloc"))?;
        let call = instance
            .get_typed_func::<(i32, i32, i32, i32), i64>(&store, "cfx_call")
            .map_err(|_| func("cfx_call"))?;
        let version = instance
            .get_typed_func::<(), i64>(&store, "cfx_version")
            .map_err(|_| func("cfx_version"))?
            .call(&mut store, ())
            .map_err(|e| e.to_string())
            .and_then(|at| read(&store, &memory, at, 64))
            .ok()
            .and_then(|v| String::from_utf8(v).ok())
            .filter(|v| !v.is_empty() && v.chars().all(|c| c.is_ascii_graphic() || c == ' '))
            .ok_or("the module's version does not read")?;
        Ok(Module {
            version,
            limits,
            live: Mutex::new(Live {
                store,
                memory,
                alloc,
                call,
            }),
        })
    }
}

/// The bytes at `at`, an answer's place as the interface gives it: where in the upper 32
/// bits and how long in the lower, at most `max` long.
fn read(
    store: &wasmi::Store<Held>,
    memory: &wasmi::Memory,
    at: i64,
    max: usize,
) -> Result<Vec<u8>, String> {
    if at < 0 {
        return Err("no answer".into());
    }
    let (ptr, len) = (
        (at as u64 >> 32) as usize,
        (at as u64 & 0xffff_ffff) as usize,
    );
    if len > max {
        return Err("the answer is too long".into());
    }
    let mut out = vec![0u8; len];
    memory
        .read(store, ptr, &mut out)
        .map_err(|e| e.to_string())?;
    Ok(out)
}

impl Backend for Module {
    fn version(&self) -> &str {
        &self.version
    }

    fn call(&self, op: &str, input: &[u8]) -> Option<Vec<u8>> {
        let mut live = self.live.lock().ok()?;
        let Live {
            store,
            memory,
            alloc,
            call,
        } = &mut *live;
        store.set_fuel(self.limits.fuel_per_call).ok()?;
        let mut place = |bytes: &[u8]| -> Option<i32> {
            let at = alloc
                .call(&mut *store, i32::try_from(bytes.len()).ok()?)
                .ok()?;
            memory
                .write(&mut *store, usize::try_from(at).ok()?, bytes)
                .ok()?;
            Some(at)
        };
        let op_at = place(op.as_bytes())?;
        let in_at = place(input)?;
        let answer = call
            .call(
                &mut *store,
                (op_at, op.len() as i32, in_at, input.len() as i32),
            )
            .ok()?;
        read(store, memory, answer, self.limits.answer_bytes).ok()
    }
}
