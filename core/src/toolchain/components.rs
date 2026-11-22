//! The closed components: plessor-authz, the pacing module and the egress helper. They
//! come with a Crossfyre plan that includes them, after login, rather than with the
//! release, and are installed beside the open binaries.
//!
//! Crossfyre answers an account's key, or a node's, with a manifest of every component,
//! signed by the release key as the release manifest is, and the components that key's
//! plan includes; it serves a component's files only to a key whose plan includes it.
//! Each file is checked against the manifest's SHA-256 before it is placed, and the pacing
//! module also against its own signature, by [`cfx_pacing::install`].
//!
//! Nothing here runs when a component runs: no token, no check, no count of machines. A
//! key whose plan no longer includes a component keeps what is installed, and it stops
//! being updated; when Crossfyre cannot be reached, what is installed keeps working and
//! only downloads wait.
//!
//! The components go out with texts of their own, the licence they are under and the
//! notices of what they compile in, which the manifest names under `texts` and which are
//! installed in `licences/` beside the binaries with the first component.

use super::install::{Artifact, Component};
use crate::api::SendApi;
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

/// The components manifest: each component's version and files, and the texts every
/// component goes out with, by the name each is installed under.
#[derive(serde::Deserialize, Debug)]
struct Manifest {
    components: HashMap<String, Component>,
    #[serde(default)]
    texts: BTreeMap<String, Artifact>,
}

/// The closed components, as Crossfyre names them.
pub const COMPONENTS: [&str; 3] = ["plessor-authz", "pacing", "egress"];

/// The key components are asked for with, and where.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Credentials {
    pub api_url: String,
    pub key: String,
}

/// The account's key from `crossfyre login`, or else the key of a node `node init` set
/// up here.
pub fn credentials(data_dir: &Path) -> Option<Credentials> {
    if let Some(a) = crate::auth::load_account(data_dir) {
        return Some(Credentials {
            api_url: a.api_url,
            key: a.api_key,
        });
    }
    let mut configs: Vec<PathBuf> = std::fs::read_dir(crate::nodes_dir(data_dir))
        .ok()?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "toml"))
        .collect();
    configs.sort();
    configs.into_iter().find_map(|p| {
        let c = crate::load_node_config(&p).ok()?;
        Some(Credentials {
            api_url: c.api_url.clone(),
            key: c.api_key.clone(),
        })
    })
}

/// What Crossfyre answered: the plan, the components it includes, and the manifest.
pub struct Offer {
    pub plan: Option<String>,
    pub included: Vec<String>,
    manifest: Manifest,
}

impl Offer {
    pub fn includes(&self, component: &str) -> bool {
        self.included.iter().any(|c| c == component)
    }

    /// The version Crossfyre has of `component`.
    pub fn version(&self, component: &str) -> Option<&str> {
        self.manifest
            .components
            .get(component)
            .map(|c| c.version.as_str())
    }

    /// `component`'s file for this host: its platform's, or the one for any.
    fn artifact(&self, component: &str) -> Result<&Artifact, String> {
        let c = self
            .manifest
            .components
            .get(component)
            .ok_or_else(|| format!("Crossfyre has no {component}"))?;
        c.artifacts
            .get(&super::install::platform_key())
            .or_else(|| c.artifacts.get("any"))
            .ok_or_else(|| {
                format!(
                    "{component} is not built for {}",
                    super::install::platform_key()
                )
            })
    }
}

/// Why components could not be had.
#[derive(Debug, PartialEq, Eq)]
pub enum Unavailable {
    /// Crossfyre could not be reached, or answered as though it could not.
    Unreachable(String),
    /// It does not take the key.
    NotLoggedIn(String),
    /// It answered, and said no.
    Refused(String),
}

impl std::fmt::Display for Unavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Unavailable::Unreachable(why)
            | Unavailable::NotLoggedIn(why)
            | Unavailable::Refused(why) => f.write_str(why),
        }
    }
}

/// `e`, and when Crossfyre no longer takes the session `creds` came from, what that did to
/// this machine's policy.
fn with_session_end(data_dir: &Path, creds: &Credentials, e: &Unavailable) -> String {
    let ended = matches!(e, Unavailable::NotLoggedIn(_))
        .then(|| crate::policy::session_ended(data_dir, &creds.key))
        .flatten();
    match ended {
        Some(line) => format!("{e}\n{line}"),
        None => e.to_string(),
    }
}

fn endpoint(api_url: &str, path: &str) -> String {
    format!("{}/api/v1/cli/{path}", api_url.trim_end_matches('/'))
}

/// The message in a refusal's body, or its status.
async fn refusal(resp: reqwest::Response) -> String {
    let status = resp.status();
    let body: serde_json::Value = resp.json().await.unwrap_or_default();
    body["errors"][0]
        .as_str()
        .or_else(|| body["message"].as_str())
        .map(str::to_string)
        .unwrap_or_else(|| format!("Crossfyre answered {status}"))
}

/// Ask Crossfyre which components `creds` may have, with the signed manifest.
pub async fn offer(client: &reqwest::Client, creds: &Credentials) -> Result<Offer, Unavailable> {
    let resp = client
        .post(endpoint(&creds.api_url, "components"))
        .json(&serde_json::json!({ "api_key": creds.key }))
        .send_api()
        .await
        .map_err(|e| Unavailable::Unreachable(format!("Crossfyre could not be reached: {e}")))?;
    let status = resp.status();
    if status.is_server_error() {
        return Err(Unavailable::Unreachable(refusal(resp).await));
    }
    if status == reqwest::StatusCode::UNAUTHORIZED {
        return Err(Unavailable::NotLoggedIn(refusal(resp).await));
    }
    if !status.is_success() {
        return Err(Unavailable::Refused(refusal(resp).await));
    }
    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| Unavailable::Unreachable(format!("Crossfyre's answer did not read: {e}")))?;
    let data = &body["data"];
    let text = data["manifest"]
        .as_str()
        .ok_or_else(|| Unavailable::Refused("Crossfyre sent no components manifest".into()))?;
    // The manifest as the build host signed it, checked as the release manifest is: in
    // a build that carries a release key, one it did not sign is not believed.
    if super::release_sig::required() {
        let sig = data["signature"].as_str().ok_or_else(|| {
            Unavailable::Refused("the components manifest came without a signature".into())
        })?;
        super::release_sig::verify(text.as_bytes(), sig)
            .map_err(|e| Unavailable::Refused(format!("the components manifest {e}")))?;
    }
    let manifest: Manifest = serde_json::from_str(text)
        .map_err(|e| Unavailable::Refused(format!("the components manifest does not read: {e}")))?;
    let included = data["included"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|c| c.as_str())
                .filter(|c| COMPONENTS.contains(c))
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    Ok(Offer {
        plan: data["plan"].as_str().map(str::to_string),
        included,
        manifest,
    })
}

async fn download(
    client: &reqwest::Client,
    creds: &Credentials,
    component: &str,
    file: &str,
) -> Result<Vec<u8>, String> {
    let resp = client
        .post(endpoint(&creds.api_url, "components/download"))
        .json(&serde_json::json!({ "api_key": creds.key, "component": component, "file": file }))
        .send_api()
        .await
        .map_err(|e| format!("Crossfyre could not be reached: {e}"))?;
    if !resp.status().is_success() {
        return Err(refusal(resp).await);
    }
    Ok(resp
        .bytes()
        .await
        .map_err(|e| format!("{file} did not arrive whole: {e}"))?
        .to_vec())
}

/// Where components go: the binaries' folder, and whether an engine's daemon is
/// registered with the service manager as it is placed (never in a test).
#[derive(Clone, Debug)]
pub struct Here {
    pub bin: PathBuf,
    pub services: bool,
}

impl Here {
    /// This host's binaries' folder.
    pub fn this_host() -> Here {
        Here {
            bin: super::config::get_bin_dir(),
            services: true,
        }
    }

    /// Where a component is installed: the file engines and the node run or load, and
    /// the sidecar recording its version.
    pub fn placed(&self, component: &str) -> (PathBuf, PathBuf) {
        let file = match component {
            "pacing" => self.bin.join(cfx_pacing::MODULE),
            "egress" => self.bin.join(format!(
                "{}{}",
                crate::egress::HELPER,
                std::env::consts::EXE_SUFFIX
            )),
            other => self.bin.join(super::config::file_name(other)),
        };
        (file, self.bin.join(format!("{component}.version")))
    }

    /// Where the components' texts go.
    pub fn licences(&self) -> PathBuf {
        self.bin.join("licences")
    }

    /// Every file a component puts here besides an engine's (plessor-authz is one, and
    /// goes as engines go): the pacing module, its signature, the helper, and each one's
    /// version.
    pub fn component_files(&self) -> Vec<PathBuf> {
        let mut out = Vec::new();
        for component in COMPONENTS
            .into_iter()
            .filter(|c| super::engine(c).is_none())
        {
            let (file, sidecar) = self.placed(component);
            if component == "pacing" {
                out.push(PathBuf::from(format!(
                    "{}{}",
                    file.display(),
                    cfx_pacing::SIG_SUFFIX
                )));
            }
            out.extend([file, sidecar]);
        }
        out
    }
}

/// The version of `component` installed `here`, None when it is not.
pub fn installed_version(here: &Here, component: &str) -> Option<String> {
    let (file, sidecar) = here.placed(component);
    if !file.exists() {
        return None;
    }
    Some(
        std::fs::read_to_string(sidecar)
            .map(|v| v.trim().to_string())
            .unwrap_or_else(|_| "unknown".into()),
    )
}

/// Install `component` from `offer`, replacing what is installed, and give its version.
/// The keys a pacing module is checked against are `keys`, this build's release keys
/// outside tests.
pub async fn install(
    client: &reqwest::Client,
    creds: &Credentials,
    offer: &Offer,
    component: &str,
    keys: &[&str],
    here: &Here,
) -> Result<String, String> {
    if !offer.includes(component) {
        return Err(format!(
            "{component} comes with a Crossfyre plan that includes it, and this account's \
             plan does not."
        ));
    }
    let version = offer
        .version(component)
        .ok_or_else(|| format!("Crossfyre has no {component}"))?
        .to_string();
    let artifact = offer.artifact(component)?;
    let bin = &here.bin;
    if !super::install::can_write_in(bin) {
        return Err(format!(
            "{} cannot be written to, so {component} cannot be put beside the binaries. \
             Run this as the binaries' owner.",
            bin.display()
        ));
    }
    // Its licence and notices are fetched and checked before it, and written as it is
    // placed, so nothing is written for a component that does not check out.
    let texts = fetch_texts(client, creds, offer, component, here).await?;
    let bytes = download(client, creds, component, &artifact.file).await?;
    super::install::verify_artifact_bytes(artifact, &bytes)?;
    let (file, sidecar) = here.placed(component);
    match component {
        "pacing" => {
            let sig_file = artifact
                .sig
                .as_deref()
                .ok_or("the manifest names no signature for the pacing module")?;
            let sig = download(client, creds, component, sig_file).await?;
            let sig = String::from_utf8(sig).map_err(|_| "the module's signature does not read")?;
            let exe = std::env::current_exe().map_err(|e| e.to_string())?;
            cfx_pacing::install(bin, &exe, &bytes, &sig, keys, cfx_pacing::Limits::default())?;
            write_texts(here, &texts)?;
        }
        _ => {
            let staged = tempfile::NamedTempFile::new().map_err(|e| e.to_string())?;
            std::fs::write(staged.path(), &bytes).map_err(|e| e.to_string())?;
            let engine = here.services && super::engine(component).is_some();
            let was_running = engine && super::config::is_extension_installed(component);
            if was_running {
                super::service::try_stop(component);
            }
            super::install::place_binary(staged.path(), &file).map_err(|e| e.to_string())?;
            write_texts(here, &texts)?;
            std::fs::write(&sidecar, &version)
                .map_err(|e| format!("{}: {e}", sidecar.display()))?;
            if engine {
                // Its daemon runs as every engine's does: a unit of the service manager,
                // or the node's supervisor where none runs.
                if super::service::user_manager_started() {
                    super::service::create_service_file(component).map_err(|e| e.to_string())?;
                    if was_running {
                        let _ = super::service::start(component);
                    }
                } else {
                    super::service::say_node_up_runs_engines();
                }
            }
            return Ok(version);
        }
    }
    std::fs::write(&sidecar, &version).map_err(|e| format!("{}: {e}", sidecar.display()))?;
    Ok(version)
}

/// The texts the manifest names that `licences/` here does not hold as the manifest has
/// them, each fetched with `component`, which the plan includes, and checked against the
/// manifest. A manifest that names none is refused: a component does not go out without
/// its licence.
async fn fetch_texts(
    client: &reqwest::Client,
    creds: &Credentials,
    offer: &Offer,
    component: &str,
    here: &Here,
) -> Result<Vec<(PathBuf, Vec<u8>)>, String> {
    if offer.manifest.texts.is_empty() {
        return Err("the components manifest names no licence for them".into());
    }
    let mut out = Vec::new();
    for (name, artifact) in &offer.manifest.texts {
        let plain = Path::new(name)
            .file_name()
            .is_some_and(|f| f == name.as_str());
        if !plain || name.starts_with('.') {
            return Err(format!("the components manifest names a text as {name}"));
        }
        let dest = here.licences().join(name);
        let current = std::fs::read(&dest)
            .is_ok_and(|b| super::install::verify_artifact_bytes(artifact, &b).is_ok());
        if !current {
            let bytes = download(client, creds, component, &artifact.file).await?;
            super::install::verify_artifact_bytes(artifact, &bytes)?;
            out.push((dest, bytes));
        }
    }
    Ok(out)
}

/// Write what [`fetch_texts`] gave, each by a rename.
fn write_texts(here: &Here, texts: &[(PathBuf, Vec<u8>)]) -> Result<(), String> {
    let dir = here.licences();
    std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    for (dest, bytes) in texts {
        let staged = dest.with_extension("new");
        std::fs::write(&staged, bytes).map_err(|e| format!("{}: {e}", staged.display()))?;
        std::fs::rename(&staged, dest).map_err(|e| format!("{}: {e}", dest.display()))?;
    }
    Ok(())
}

/// What became of one component in [`bring_current`].
#[derive(Debug, PartialEq, Eq)]
pub enum Kept {
    /// Installed or updated, to this version.
    Installed(String),
    /// Already this version.
    Current(String),
    /// Kept as it is, at this version: the plan no longer includes it.
    NoLongerIncluded(String),
    Failed(String),
}

/// Bring the components in `which` current: each one installed here that the plan still
/// includes is updated when Crossfyre has another version, and with `install_missing`,
/// each one the plan includes and is not here is installed. One the plan no longer
/// includes is kept as it is.
pub async fn bring_current(
    client: &reqwest::Client,
    creds: &Credentials,
    offer: &Offer,
    which: &[&'static str],
    install_missing: bool,
    keys: &[&str],
    here: &Here,
) -> Vec<(&'static str, Kept)> {
    let mut out = Vec::new();
    for &component in which {
        let have = installed_version(here, component);
        let kept = match (&have, offer.includes(component)) {
            (None, false) => continue,
            (None, true) if !install_missing => continue,
            (Some(v), false) => Kept::NoLongerIncluded(v.clone()),
            (Some(v), true) if offer.version(component) == Some(v.as_str()) => {
                Kept::Current(v.clone())
            }
            _ => match install(client, creds, offer, component, keys, here).await {
                Ok(v) => Kept::Installed(v),
                Err(why) => Kept::Failed(why),
            },
        };
        out.push((component, kept));
    }
    out
}

/// Say what [`bring_current`] did, a line each.
pub fn say(results: &[(&'static str, Kept)]) {
    use super::ui::*;
    for (component, kept) in results {
        match kept {
            Kept::Installed(v) => ok(&format!("{component} {v} installed")),
            Kept::Current(v) => ok(&format!("{component} {v} is current")),
            Kept::NoLongerIncluded(v) => warn(&format!(
                "{component} {v} is kept as it is: the plan no longer includes it, so it is \
                 not updated"
            )),
            Kept::Failed(why) => fail(&format!("{component}: {why}")),
        }
    }
}

/// The components an update target names: `components` for all of them, or one by name.
pub fn asked_for(target: &str) -> Option<Vec<&'static str>> {
    if target == "components" {
        return Some(COMPONENTS.to_vec());
    }
    COMPONENTS.iter().find(|c| **c == target).map(|c| vec![*c])
}

/// `crossfyre update`'s rows for the components in `which`: each installed one brought
/// current with the plan of `creds`, and with `install_missing`, each the plan includes
/// installed. Nothing is said when none is here and none is asked for. Crossfyre out of
/// reach is no failure: what is installed keeps working.
pub async fn update_step(
    data_dir: &Path,
    creds: Option<&Credentials>,
    which: &[&'static str],
    install_missing: bool,
    out: &mut super::install::Updated,
) {
    use super::ui::*;
    let here = Here::this_host();
    if !install_missing && !which.iter().any(|c| installed_version(&here, c).is_some()) {
        return;
    }
    let Some(creds) = creds else {
        println!(
            "{}",
            row(
                &dot(),
                "components",
                "",
                &dim("sign in with `crossfyre login` to install or update them")
            )
        );
        out.skipped += 1;
        return;
    };
    let client = crate::api::client();
    let offer = match offer(&client, creds).await {
        Ok(o) => o,
        Err(Unavailable::Unreachable(why)) => {
            println!(
                "{}",
                row(
                    &dot(),
                    "components",
                    "",
                    &dim(&format!("{why}; what is installed keeps working"))
                )
            );
            out.skipped += 1;
            return;
        }
        Err(e @ (Unavailable::NotLoggedIn(_) | Unavailable::Refused(_))) => {
            let why = with_session_end(data_dir, creds, &e);
            println!(
                "{}",
                row(&bang(), "components", "", &format!("{YELLOW}{why}{RESET}"))
            );
            out.failed += 1;
            return;
        }
    };
    let keys = cfx_pacing::release_keys();
    for (component, kept) in
        bring_current(&client, creds, &offer, which, install_missing, &keys, &here).await
    {
        let line = match &kept {
            Kept::Installed(v) => {
                out.changed += 1;
                row(
                    &check(),
                    component,
                    &format!("v{v}"),
                    &format!("{GREEN}installed{RESET}"),
                )
            }
            Kept::Current(v) => {
                out.current += 1;
                row(&check(), component, &format!("v{v}"), &dim("up to date"))
            }
            Kept::NoLongerIncluded(v) => {
                out.skipped += 1;
                row(
                    &dot(),
                    component,
                    &format!("v{v}"),
                    &dim("kept: the plan no longer includes it, so it is not updated"),
                )
            }
            Kept::Failed(why) => {
                out.failed += 1;
                row(
                    &bang(),
                    component,
                    "",
                    &format!("{YELLOW}failed{RESET} {}", dim(why)),
                )
            }
        };
        println!("{line}");
    }
}

/// `crossfyre extension install` of a closed engine: from Crossfyre, with the plan of
/// the key in `data_dir`.
pub async fn install_closed(component: &str, data_dir: &Path) -> Result<String, String> {
    let creds = credentials(data_dir).ok_or_else(|| {
        format!(
            "{component} comes with a Crossfyre plan that includes it. Sign in with              `crossfyre login`, then install it with `crossfyre update {component}`."
        )
    })?;
    let client = crate::api::client();
    let offer = offer(&client, &creds)
        .await
        .map_err(|e| with_session_end(data_dir, &creds, &e))?;
    let keys = cfx_pacing::release_keys();
    install(
        &client,
        &creds,
        &offer,
        component,
        &keys,
        &Here::this_host(),
    )
    .await
}

/// After `crossfyre login`: the components the plan includes that are not here, and with
/// `ask`, an offer to install them now. Quiet when there are none, or when Crossfyre
/// cannot say: the login itself went through.
pub async fn after_login(creds: &Credentials, ask: bool) {
    use super::ui::*;
    let client = crate::api::client();
    let Ok(offer) = offer(&client, creds).await else {
        return;
    };
    let here = Here::this_host();
    let missing: Vec<&'static str> = COMPONENTS
        .into_iter()
        .filter(|c| offer.includes(c) && installed_version(&here, c).is_none())
        .collect();
    if missing.is_empty() {
        return;
    }
    section("Components");
    field("Your plan includes", &missing.join(", "));
    let yes = ask
        && dialoguer::Confirm::new()
            .with_prompt("Install them now?")
            .default(true)
            .interact()
            .unwrap_or(false);
    if yes {
        let keys = cfx_pacing::release_keys();
        say(&bring_current(&client, creds, &offer, &missing, true, &keys, &here).await);
    } else {
        hint("Install them with `crossfyre update components`.");
    }
}

/// For `crossfyre status`: each component, with its version, or why it is not here.
pub fn rows(here: &Here) -> Vec<(&'static str, String)> {
    COMPONENTS
        .iter()
        .map(|c| {
            (
                *c,
                installed_version(here, c).unwrap_or_else(|| super::NEEDS_A_PLAN.to_string()),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests;
