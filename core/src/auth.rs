//! Account authentication for the `crossfyre` CLI (`crossfyre login`).
//!
//! Three methods all converge on the CLI holding a revocable *account API key*
//! (the `account_api_keys` table server-side), persisted to `<data_dir>/auth.toml`:
//!   - `--api-key <key>`              -> verify the pasted key
//!   - `--username <u> --password <p>`-> exchange credentials for a fresh key
//!   - no flags                       -> browser device-authorization flow
//!
//! With a session, `crossfyre node init` provisions a node server-side (no manual
//! node-key paste). Flags `--agree-tos` and `--no-prompt` make the flow
//! scriptable; mismatched/missing flags error rather than silently prompting.

use serde::{Deserialize, Serialize};
use std::io::IsTerminal;
use std::path::{Path, PathBuf};

/// The default control-plane origin. The CLI talks to web_server's public
/// `/api/v1/*` proxy (which injects the backend auth header), so this is the
/// public site origin, not api_switch directly. Override with `--api-url`.
///
/// Baked at build time per env (crossfyre_build sets CROSSFYRE_API_URL): a dev
/// build points at the local web (http://localhost:12004), staging at
/// staging.crossfyre.io, prod at crossfyre.io. Defaults to prod when unset.
pub const DEFAULT_API_URL: &str = match option_env!("CROSSFYRE_API_URL") {
    Some(u) => u,
    None => "https://crossfyre.io",
};

/// A short legal notice shown before the first login unless `--agree-tos`.
const TOS_NOTICE: &str = "\
  Crossfyre is an offensive security platform for AUTHORIZED penetration
  testing and security research only. By logging in you agree to the Terms of
  Service (https://crossfyre.io/terms) and Acceptable Use Policy, and confirm
  you are authorized to test the targets you operate against. Unauthorized use
  is illegal and strictly prohibited.";

/// Persisted account session. Stored at `<data_dir>/auth.toml`.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Account {
    /// Control-plane origin this session authenticates against.
    pub api_url: String,
    /// Account API key (`cfk_...`) the CLI presents for account-scoped calls.
    pub api_key: String,
    pub user_id: String,
    pub username: String,
    pub email: String,
}

pub fn account_path(data_dir: &Path) -> PathBuf {
    data_dir.join("auth.toml")
}

pub fn load_account(data_dir: &Path) -> Option<Account> {
    let raw = std::fs::read_to_string(account_path(data_dir)).ok()?;
    toml::from_str(&raw).ok()
}

pub fn save_account(data_dir: &Path, account: &Account) -> Result<(), Box<dyn std::error::Error>> {
    if !data_dir.exists() {
        std::fs::create_dir_all(data_dir)?;
    }
    let path = account_path(data_dir);
    // The mode goes on a fresh file BEFORE the key does. Writing and then chmodding, which
    // is what this did, leaves a window in which the credential exists at the process
    // umask, and a key that leaked during it has leaked.
    //
    // Worth being honest about what the tests below can and cannot say. Neither observes
    // that window: it is a race, it is gone by the time anything can stat the file, and
    // the old code reached the same final mode. They guard the two things that ARE
    // observable, which is that the mode is set at all and that a short write leaves none
    // of a long one. `fs::write` truncated for free; `OpenOptions` does not, so the
    // explicit truncate guards a hazard this approach introduced rather than one it
    // removed. The argument for the change is structural rather than empirical.
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&path)?;
        f.write_all(toml::to_string(account)?.as_bytes())?;
        f.flush()?;
    }
    #[cfg(not(unix))]
    std::fs::write(&path, toml::to_string(account)?)?;
    // Hand ownership back to the invoking user if we ran under sudo.
    crate::toolchain::sudo_user::chown_to_invoking_user(&path);
    Ok(())
}

pub fn clear_account(data_dir: &Path) -> bool {
    std::fs::remove_file(account_path(data_dir)).is_ok()
}

// ---- small environment helpers ----------------------------------------

fn hostname() -> String {
    std::env::var("HOSTNAME")
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(|| {
            std::process::Command::new("hostname")
                .output()
                .ok()
                .and_then(|o| String::from_utf8(o.stdout).ok())
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        })
        .unwrap_or_else(|| "unknown".to_string())
}

fn os_label() -> String {
    format!("{} ({})", std::env::consts::OS, std::env::consts::ARCH)
}

fn cli_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

fn spawn_quiet(cmd: &str, args: &[&str]) -> bool {
    std::process::Command::new(cmd)
        .args(args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .is_ok()
}

/// Best-effort: open `url` in the operator's browser. Never fatal.
///
/// On Linux under `sudo`, root has no GUI session, so `xdg-open` as root does
/// nothing. Re-launch it as the invoking user ($SUDO_USER), preserving the
/// display/session env vars so it lands in their actual desktop session.
fn open_browser(url: &str) -> bool {
    if cfg!(target_os = "macos") {
        return spawn_quiet("open", &[url]);
    }
    if cfg!(target_os = "windows") {
        return spawn_quiet("cmd", &["/C", "start", "", url]);
    }
    #[cfg(unix)]
    {
        let euid = unsafe { libc::geteuid() };
        if euid == 0
            && let Ok(user) = std::env::var("SUDO_USER")
            && !user.is_empty()
            && user != "root"
            && spawn_quiet(
                "sudo",
                &[
                    "-u",
                    &user,
                    "--preserve-env=DISPLAY,XDG_RUNTIME_DIR,DBUS_SESSION_BUS_ADDRESS,WAYLAND_DISPLAY,XAUTHORITY",
                    "xdg-open",
                    url,
                ],
            )
        {
            return true;
        }
    }
    spawn_quiet("xdg-open", &[url])
}

// ---- login orchestration -----------------------------------------------

#[derive(Clone, Copy, PartialEq)]
enum Method {
    ApiKey,
    Password,
    Browser,
}

/// Inputs gathered from the CLI flags (shared by `login` and `init`).
pub struct LoginFlags {
    pub api_key: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub api_url: String,
    pub agree_tos: bool,
    pub no_prompt: bool,
}

/// Resolve which method to use from the flags, erroring on mismatched or
/// missing combinations (especially under `--no-prompt`). May prompt for a
/// missing half of a username/password pair when interactive.
fn resolve_method(flags: &mut LoginFlags) -> Result<Method, String> {
    let has_key = flags
        .api_key
        .as_deref()
        .map(|s| !s.is_empty())
        .unwrap_or(false);
    let has_user = flags
        .username
        .as_deref()
        .map(|s| !s.is_empty())
        .unwrap_or(false);
    let has_pass = flags
        .password
        .as_deref()
        .map(|s| !s.is_empty())
        .unwrap_or(false);

    if has_key && (has_user || has_pass) {
        return Err(
            "Choose one login method: either --api-key, or --username/--password (not both)."
                .into(),
        );
    }

    if has_key {
        return Ok(Method::ApiKey);
    }

    if has_user || has_pass {
        // A credential pair: fill the missing half interactively, else error.
        if !has_user {
            if flags.no_prompt {
                return Err(
                    "--password was given without --username (and --no-prompt is set).".into(),
                );
            }
            let u: String = dialoguer::Input::new()
                .with_prompt("Username or email")
                .interact_text()
                .map_err(|e| e.to_string())?;
            flags.username = Some(u);
        }
        if !has_pass {
            if flags.no_prompt {
                return Err(
                    "--username was given without --password (and --no-prompt is set).".into(),
                );
            }
            let p = dialoguer::Password::new()
                .with_prompt("Password")
                .interact()
                .map_err(|e| e.to_string())?;
            flags.password = Some(p);
        }
        return Ok(Method::Password);
    }

    // No method flags at all.
    if flags.no_prompt {
        return Err("No login method specified. Pass --api-key, or --username/--password, in non-interactive mode.".into());
    }
    if !std::io::stdin().is_terminal() {
        // Can't run an interactive picker or browser flow without a TTY.
        return Err("No login method specified and no terminal available. Pass --api-key or --username/--password.".into());
    }

    // Interactive: let the operator choose.
    let choices = [
        "Browser (open crossfyre.io to approve)",
        "API key",
        "Username & password",
    ];
    let pick = dialoguer::Select::new()
        .with_prompt("How would you like to log in?")
        .items(choices)
        .default(0)
        .interact()
        .map_err(|e| e.to_string())?;
    match pick {
        1 => {
            let k: String = dialoguer::Input::new()
                .with_prompt("Account API key")
                .interact_text()
                .map_err(|e| e.to_string())?;
            flags.api_key = Some(k);
            Ok(Method::ApiKey)
        }
        2 => {
            let u: String = dialoguer::Input::new()
                .with_prompt("Username or email")
                .interact_text()
                .map_err(|e| e.to_string())?;
            let p = dialoguer::Password::new()
                .with_prompt("Password")
                .interact()
                .map_err(|e| e.to_string())?;
            flags.username = Some(u);
            flags.password = Some(p);
            Ok(Method::Password)
        }
        _ => Ok(Method::Browser),
    }
}

/// Enforce ToS acceptance. Returns Err with a message if it can't be obtained.
fn require_tos(flags: &LoginFlags) -> Result<(), String> {
    use crate::toolchain::ui::*;
    if flags.agree_tos {
        return Ok(());
    }
    if flags.no_prompt {
        return Err(
            "You must pass --agree-tos to accept the Terms of Service in non-interactive mode."
                .into(),
        );
    }
    println!();
    section("Terms of Service");
    println!("{}", dim(TOS_NOTICE));
    println!();
    let ok = dialoguer::Confirm::new()
        .with_prompt("Do you accept the Terms of Service?")
        .default(false)
        .interact()
        .map_err(|e| e.to_string())?;
    if ok {
        Ok(())
    } else {
        Err("Terms of Service not accepted.".into())
    }
}

/// Run the full login flow and persist the resulting session. Returns the
/// authenticated Account. Shared by the `login` command and `init`.
pub async fn perform_login(
    data_dir: &Path,
    mut flags: LoginFlags,
) -> Result<Account, Box<dyn std::error::Error>> {
    let method =
        resolve_method(&mut flags).map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
    require_tos(&flags).map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;

    let client = reqwest::Client::new();
    let api_url = flags.api_url.trim_end_matches('/').to_string();

    let (api_key, user) = match method {
        Method::ApiKey => {
            let key = flags.api_key.clone().unwrap();
            let user = verify_key(&client, &api_url, &key).await?;
            (key, user)
        }
        Method::Password => {
            let username = flags.username.clone().unwrap();
            let password = flags.password.clone().unwrap();
            password_login(&client, &api_url, &username, &password).await?
        }
        Method::Browser => browser_login(&client, &api_url).await?,
    };

    let account = Account {
        api_url,
        api_key,
        user_id: user.0,
        username: user.1,
        email: user.2,
    };
    // The server hands the key over exactly once: the first poll that collects it nulls
    // the stored copy and marks the row collected. So a failure here is not "try again",
    // it is a key that has been issued and is now gone, and the message has to say that
    // rather than leaving somebody to retry a login the server believes already happened.
    save_account(data_dir, &account).map_err(|e| -> Box<dyn std::error::Error> {
        format!(
            "Signed in, but the session could not be saved to {}: {e}\n\
             The key issued for this login cannot be handed over a second time, so it is \
             gone. Fix whatever stopped the write and sign in again.",
            account_path(data_dir).display()
        )
        .into()
    })?;
    Ok(account)
}

/// (user_id, username, email) extracted from a `{ data: { user: {...} } }` body.
type UserTriple = (String, String, String);

fn user_from_data(body: &serde_json::Value) -> Result<UserTriple, Box<dyn std::error::Error>> {
    let u = &body["data"]["user"];
    let id = u["id"]
        .as_str()
        .ok_or("login response missing user id")?
        .to_string();
    let username = u["username"].as_str().unwrap_or("").to_string();
    let email = u["email"].as_str().unwrap_or("").to_string();
    Ok((id, username, email))
}

fn body_message(body: &serde_json::Value) -> String {
    body["message"]
        .as_str()
        .unwrap_or("Login failed")
        .to_string()
}

async fn verify_key(
    client: &reqwest::Client,
    api_url: &str,
    key: &str,
) -> Result<UserTriple, Box<dyn std::error::Error>> {
    let res = client
        .post(format!("{api_url}/api/v1/cli/verify-key"))
        .json(&serde_json::json!({ "api_key": key }))
        .send()
        .await?;
    let ok = res.status().is_success();
    let body: serde_json::Value = res.json().await.unwrap_or(serde_json::json!({}));
    if !ok {
        return Err(body_message(&body).into());
    }
    user_from_data(&body)
}

async fn password_login(
    client: &reqwest::Client,
    api_url: &str,
    identifier: &str,
    password: &str,
) -> Result<(String, UserTriple), Box<dyn std::error::Error>> {
    let res = client
        .post(format!("{api_url}/api/v1/cli/login"))
        .json(&serde_json::json!({
            "identifier": identifier,
            "password": password,
            "key_name": hostname(),
        }))
        .send()
        .await?;
    let ok = res.status().is_success();
    let body: serde_json::Value = res.json().await.unwrap_or(serde_json::json!({}));
    if !ok {
        return Err(body_message(&body).into());
    }
    let api_key = body["data"]["api_key"]
        .as_str()
        .ok_or("login response missing api_key")?
        .to_string();
    let user = user_from_data(&body)?;
    Ok((api_key, user))
}

async fn browser_login(
    client: &reqwest::Client,
    api_url: &str,
) -> Result<(String, UserTriple), Box<dyn std::error::Error>> {
    // 1. Start the device flow.
    let res = client
        .post(format!("{api_url}/api/v1/cli/device/start"))
        .json(&serde_json::json!({
            "client_info": { "hostname": hostname(), "os": os_label(), "version": cli_version() }
        }))
        .send()
        .await?;
    if !res.status().is_success() {
        let body: serde_json::Value = res.json().await.unwrap_or(serde_json::json!({}));
        return Err(body_message(&body).into());
    }
    let body: serde_json::Value = res.json().await?;
    let d = &body["data"];
    let device_code = d["device_code"]
        .as_str()
        .ok_or("device start: missing device_code")?
        .to_string();
    let verify_uri = d["verification_uri_complete"]
        .as_str()
        .or_else(|| d["verification_uri"].as_str())
        .unwrap_or("https://crossfyre.io/device")
        .to_string();
    let interval = d["interval"].as_u64().unwrap_or(3).max(1);
    let expires_in = d["expires_in"].as_u64().unwrap_or(600);

    use crate::toolchain::ui::*;
    section("Browser");
    step("Approve this device to finish signing in.");
    field("link", &verify_uri);
    if open_browser(&verify_uri) {
        hint("Opened your browser; if nothing happened, open the link above.");
    }
    working("Waiting for approval\u{2026}");

    // 2. Poll until approved / denied / expired / timeout.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(expires_in);
    // A transient failure is not an answer. The device code is minted once and is only
    // usable from this loop, so dropping out on one refused connection throws away a login
    // the operator has already approved, and the browser tab then says it worked. Counted
    // rather than unbounded: a control plane that is actually down should be said so
    // rather than polled at for ten minutes.
    const GIVE_UP_AFTER: u32 = 5;
    let mut consecutive_failures: u32 = 0;
    // Polled first, slept second. The other order charges a full interval for an approval
    // that had already happened before the first request went out, which on the common
    // path is the whole of the wait the operator sees.
    loop {
        if std::time::Instant::now() > deadline {
            return Err("Login timed out before it was approved.".into());
        }

        let answer = client
            .post(format!("{api_url}/api/v1/cli/device/poll"))
            .json(&serde_json::json!({ "device_code": device_code }))
            .send()
            .await;

        let body = match answer {
            Ok(res) => {
                consecutive_failures = 0;
                res.json::<serde_json::Value>()
                    .await
                    .unwrap_or(serde_json::json!({}))
            }
            Err(e) => {
                consecutive_failures += 1;
                if consecutive_failures >= GIVE_UP_AFTER {
                    return Err(format!(
                        "Could not reach {api_url} to finish signing in, after \
                         {GIVE_UP_AFTER} attempts: {e}"
                    )
                    .into());
                }
                tokio::time::sleep(std::time::Duration::from_secs(interval)).await;
                continue;
            }
        };

        let status = body["data"]["status"].as_str().unwrap_or("");
        match status {
            "approved" => {
                let api_key = body["data"]["api_key"]
                    .as_str()
                    .ok_or("approval missing api_key")?
                    .to_string();
                let user = user_from_data(&body)?;
                return Ok((api_key, user));
            }
            "denied" => return Err("Login was denied in the browser.".into()),
            "expired" => return Err("Login request expired. Run `crossfyre login` again.".into()),
            "unknown" => return Err("Login request was not found.".into()),
            // The server says "error" for its own 500. Treated as pending it polls for the
            // full ten minutes against something that is broken and saying so, and the
            // operator watches a spinner rather than reading the reason.
            "error" => {
                consecutive_failures += 1;
                if consecutive_failures >= GIVE_UP_AFTER {
                    return Err(format!(
                        "{api_url} answered with an error {GIVE_UP_AFTER} times while \
                         finishing the login. Try again in a moment."
                    )
                    .into());
                }
                tokio::time::sleep(std::time::Duration::from_secs(interval)).await;
            }
            _ => {
                // Pending, which is the ordinary case: wait and ask again.
                tokio::time::sleep(std::time::Duration::from_secs(interval)).await;
            }
        }
    }
}

// ---- node provisioning (used by `init`) --------------------------------

/// Authenticate an existing dashboard-created node by its `cfx_...` key
/// (legacy `crossfyre node init --node-key` path). Returns the authorize-node body.
pub async fn authorize_existing_node(
    client: &reqwest::Client,
    api_url: &str,
    node_key: &str,
    force: bool,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let res = client
        .post(format!(
            "{}/api/v1/authorize-node",
            api_url.trim_end_matches('/')
        ))
        .json(&serde_json::json!({ "api_key": node_key, "force": force }))
        .send()
        .await?;
    if !res.status().is_success() {
        return Err("Invalid node API key or server error.".into());
    }
    Ok(res.json().await?)
}

/// Provision a brand-new node for the logged-in account. Returns a body shaped
/// like authorize-node (node_id, nats_*, extensions, ...) plus `api_key` (the
/// node's enrolment key, which the caller persists for daemon refresh).
// Used by `crossfyre node init` when no node key is supplied and a session
// exists. The server claims the account's oldest never-online node or creates
// one, so a first-run install needs only the account key.
pub async fn provision_node(
    client: &reqwest::Client,
    account: &Account,
    name: Option<&str>,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let res = client
        .post(format!(
            "{}/api/v1/cli/node/provision",
            account.api_url.trim_end_matches('/')
        ))
        .json(&serde_json::json!({
            "api_key": account.api_key,
            "hostname": hostname(),
            "name": name,
        }))
        .send()
        .await?;
    let ok = res.status().is_success();
    let body: serde_json::Value = res.json().await.unwrap_or(serde_json::json!({}));
    if !ok {
        return Err(body_message(&body).into());
    }
    Ok(body["data"].clone())
}

/// `crossfyre node list`: fetch the account's node fleet (scoped to its team)
/// with live online/offline status. Returns the `nodes` array.
pub async fn list_nodes(
    client: &reqwest::Client,
    account: &Account,
) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    let res = client
        .post(format!(
            "{}/api/v1/cli/node/list",
            account.api_url.trim_end_matches('/')
        ))
        .json(&serde_json::json!({ "api_key": account.api_key }))
        .send()
        .await?;
    let ok = res.status().is_success();
    let body: serde_json::Value = res.json().await.unwrap_or(serde_json::json!({}));
    if !ok {
        return Err(body_message(&body).into());
    }
    Ok(body["data"]["nodes"]
        .as_array()
        .cloned()
        .unwrap_or_default())
}

// ---- command entrypoints -----------------------------------------------

/// `crossfyre login`
pub async fn run_login(
    data_dir: &Path,
    flags: LoginFlags,
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::toolchain::ui::*;
    let host = flags
        .api_url
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_end_matches('/')
        .to_string();
    title("Crossfyre login", &host);

    let account = perform_login(data_dir, flags).await?;

    let who = if account.username.is_empty() {
        &account.user_id
    } else {
        &account.username
    };
    section("Session");
    field("account", &format!("{} <{}>", who, account.email));
    field("file", &account_path(data_dir).display().to_string());
    end();
    done(&format!("Signed in as {who}"));
    hint("Next: register this host with `crossfyre node init`.");
    end();
    Ok(())
}

/// `crossfyre logout`
///
/// Extensions must not run without an account session, so logging out stops and
/// disables every installed extension daemon (so none keep running or restart on
/// boot). Logging back in lets you start them again. Best-effort; failures to
/// stop a unit are ignored.
pub fn run_logout(data_dir: &Path) {
    use crate::toolchain::ui::*;
    title("Crossfyre logout", "");

    // Logout only clears the account session. It deliberately leaves the engine
    // daemons running: they're free, local, and don't use the account (they
    // install from the public manifest and can run scripts with `crossfyre run`,
    // no control plane). Tearing them down here would couple the free tools to
    // the login state, which is exactly what we don't want. De-enrolling a node
    // is a separate, explicit action (`crossfyre node remove`).

    if clear_account(data_dir) {
        done("Signed out");
        hint(&format!("Removed {}.", account_path(data_dir).display()));
    } else {
        warn("Not logged in.");
    }
    end();
}

/// Ensure there is an account session, logging in inline if needed. Honors the
/// same flags as `login`. Retained for the account-provisioning flow (see
/// `provision_node`); not used by the current key-based `node init`.
#[allow(dead_code)]
pub async fn ensure_logged_in(
    data_dir: &Path,
    flags: LoginFlags,
) -> Result<Account, Box<dyn std::error::Error>> {
    use crate::toolchain::ui::*;
    if let Some(existing) = load_account(data_dir) {
        let who = if existing.username.is_empty() {
            &existing.user_id
        } else {
            &existing.username
        };
        ok(&format!("Using saved login for {who}."));
        return Ok(existing);
    }
    step("Not logged in yet; signing in first.");
    perform_login(data_dir, flags).await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The account file is owner-only.
    ///
    /// It holds a revocable account API key. This asserts the mode that ends up on the
    /// file and nothing about the window between creating it and setting that mode, which
    /// is the thing the implementation was changed to close: the window is a race and is
    /// over before anything here could look. Dropping the mode entirely is what this
    /// catches, and that is worth catching on its own.
    #[cfg(unix)]
    #[test]
    fn the_account_file_is_created_private_rather_than_made_private() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!(
            "cfx-auth-mode-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let account = Account {
            api_url: "https://example.test".into(),
            api_key: "cfk_secret".into(),
            user_id: "u1".into(),
            username: "someone".into(),
            email: "someone@example.test".into(),
        };
        save_account(&dir, &account).expect("save");

        let mode = std::fs::metadata(account_path(&dir))
            .expect("stat")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "the key file is owner-only, got {mode:o}");

        // And it round trips, because a mode fix that broke the write would pass the
        // assertion above and lose the session.
        assert_eq!(load_account(&dir).as_ref(), Some(&account));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Writing a shorter account over a longer one leaves nothing of the longer one.
    ///
    /// This guards a hazard the current implementation has and the previous one did not.
    /// `fs::write` truncates; `OpenOptions::write` does not, so without the explicit
    /// truncate the tail of a previous key survives past the end of the new document.
    /// TOML still parses, because the leftovers sit after the last newline, and the file
    /// quietly holds a fragment of a credential that was supposed to be gone.
    #[cfg(unix)]
    #[test]
    fn a_shorter_account_does_not_leave_the_tail_of_a_longer_one() {
        let dir = std::env::temp_dir().join(format!(
            "cfx-auth-trunc-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let long = Account {
            api_url: "https://example.test".into(),
            api_key: "cfk_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            user_id: "user-with-a-long-identifier".into(),
            username: "somebody-with-a-long-name".into(),
            email: "somebody-with-a-long-name@example.test".into(),
        };
        save_account(&dir, &long).expect("save long");

        let short = Account {
            api_url: "https://e.test".into(),
            api_key: "cfk_b".into(),
            user_id: "u".into(),
            username: "s".into(),
            email: "s@e.test".into(),
        };
        save_account(&dir, &short).expect("save short");

        let raw = std::fs::read_to_string(account_path(&dir)).expect("read");
        assert!(
            !raw.contains("cfk_aaaa"),
            "the old key survived the overwrite:\n{raw}"
        );
        assert_eq!(load_account(&dir).as_ref(), Some(&short));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
