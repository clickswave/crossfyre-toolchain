//! The Crossfyre command-line interface. Management + lifecycle commands.
//! Node lifecycle is delegated to the separate `node` worker binary (the OS
//! service execs `node supervise`; `crossfyre node up/down` manage that service).
use cfx_core::toolchain::ui::*;
use clap::{CommandFactory, Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    name = "crossfyre",
    about = "Install and run the Crossfyre scan engines, and enrol this machine as a node",
    version
)]
struct Cli {
    /// Use another config directory, the one that holds `nodes.d` and
    /// `config.toml`. The default is the one the engines read, `~/.config/crossfyre`
    /// on Linux, of the user who ran the command, so `sudo` keeps using your home and
    /// not root's. Give a path to keep a separate set of nodes, for example
    /// `--data-dir ~/.config/crossfyre-lab`.
    #[arg(long, global = true, value_name = "PATH")]
    data_dir: Option<std::path::PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Sign in to your Crossfyre account.
    ///
    /// Signed in, `node init` enrols this machine with no key copied by hand.
    /// Three ways:
    ///
    ///   crossfyre login                                 opens the browser to approve
    ///   crossfyre login --api-key <key>
    ///   crossfyre login --username <u> --password <p>
    ///
    /// The session is saved to <data-dir>/auth.toml.
    #[command(verbatim_doc_comment)]
    Login {
        /// Log in with an account API key (from Settings -> CLI Access)
        #[arg(long)]
        api_key: Option<String>,

        /// Username or email (use with --password)
        #[arg(long)]
        username: Option<String>,

        /// Password (use with --username)
        #[arg(long)]
        password: Option<String>,

        /// Crossfyre's API address
        #[arg(long, default_value = cfx_core::auth::DEFAULT_API_URL)]
        api_url: String,

        /// Accept the Terms of Service without an interactive prompt
        #[arg(long)]
        agree_tos: bool,

        /// Never prompt; require everything via flags (fails on missing/mismatched flags)
        #[arg(long)]
        no_prompt: bool,
    },

    /// Log out: remove the saved account session (auth.toml).
    Logout,

    /// Manage Crossfyre nodes: register this host (`node init`), see your fleet
    /// (`node list`), bring nodes online (`node up` / `node down`), or check the
    /// local daemons (`node status`). All node commands live under here.
    Node {
        #[command(subcommand)]
        action: NodeAction,
    },

    /// Manage toolchain extensions (ambulo, voyage, doorward, toolmark, plessor):
    /// list, install, remove, update, and control their daemons. All extension
    /// commands live under here.
    #[command(alias = "ext")]
    Extension {
        #[command(subcommand)]
        action: ExtensionAction,
    },

    /// Run and manage your OWN OAST server (out-of-band interaction server) so you
    /// can use a bring-your-own OAST endpoint on your own domain instead of the
    /// managed pool. `setup` installs it as a service and gets wildcard TLS;
    /// `serve` runs the server; `status` shows its state.
    Oast {
        #[command(subcommand)]
        action: OastAction,
    },

    /// Run a .cfx script on this machine. No account and no Crossfyre server needed.
    /// Targets are type:value pairs, e.g. `crossfyre run test.cfx domain:example.com`.
    Run {
        script: String,

        #[arg(trailing_var_arg = true)]
        targets: Vec<String>,
    },

    /// Web Tracer: capture the sites you browse into a `web_trace` session's asset graph.
    /// Runs a local intercepting proxy (default; needs only a browser) and points a launched browser
    /// at it, or use `--method keylog` for SSLKEYLOGFILE + packet capture. Each request is reduced to
    /// a redacted shape and streamed to Crossfyre. Create the session in the dashboard
    /// (Command Center -> New Web Tracer) and paste the `--workflow-id`/`--token` it prints.
    Trace {
        /// The web_trace workflow id (from the dashboard session).
        #[arg(long)]
        workflow_id: String,

        /// The one-time session token (`cfxt_…`) shown when the session was created.
        #[arg(long)]
        token: String,

        /// Crossfyre's API address.
        #[arg(long, default_value = cfx_core::auth::DEFAULT_API_URL)]
        api_url: String,

        /// Capture interface (`any` on Linux; a named iface elsewhere).
        #[arg(long, default_value = "any")]
        interface: String,

        /// Launch this browser with SSLKEYLOGFILE set (chrome/chromium/firefox/edge). Omit to
        /// point your own already-configured browser instead.
        #[arg(long)]
        browser: Option<String>,

        /// Only capture URLs containing this substring (keep out-of-scope hosts out).
        #[arg(long)]
        scope: Option<String>,

        /// Flush a batch once this many shapes are buffered.
        #[arg(long, default_value_t = 25)]
        batch_size: usize,

        /// Flush at least this often (seconds), even below the batch size.
        #[arg(long, default_value_t = 5)]
        flush_secs: u64,

        /// Capture method: `proxy` (local MITM proxy, needs only a browser - default) or `keylog`
        /// (SSLKEYLOGFILE + packet capture, needs Wireshark).
        #[arg(long, default_value = "proxy")]
        method: String,

        /// Local port for the intercepting proxy. Default 0 = OS-assigned free port (the
        /// tool prints the one it picked); set a fixed port if you drive your own browser.
        #[arg(long, default_value_t = 0)]
        proxy_port: u16,

        /// Seed the session auth you browse with (cookies, bearer/API-key headers) into the
        /// saved credentials (Arsenal, then Credentials in the dashboard) as encrypted, host-scoped
        /// credentials, ready for authenticated scans
        /// and authz testing. Off by default; only the hosts you actually visit are captured.
        #[arg(long)]
        seed_credentials: bool,
    },

    /// Update from the release manifest: `self`, an extension name, or `all`
    /// (default: self + every installed extension). For a single extension you
    /// can also use `crossfyre extension update <name>`.
    Update {
        target: Option<String>,
        /// Re-download and reinstall even when the installed version already
        /// matches the manifest. Use this when a binary is present but wrong:
        /// a corrupted download, a hand-copied dev build, or a republished
        /// release that kept its version number.
        #[arg(long)]
        force: bool,
    },

    /// Show a full overview of the local node daemons, extensions and database.
    /// (For one area, use `crossfyre node status` or `crossfyre extension list`.)
    Status,

    /// The database the engines keep their state in: the local one crossfyre makes and
    /// runs as you, or one you run yourself.
    Db {
        #[command(subcommand)]
        command: cfx_core::DbCommands,
    },

    /// Check the environment for common problems.
    Doctor,

    /// Remove Crossfyre services, extensions, binaries and the local database
    /// from this host.
    Uninstall {
        /// Also remove the config root (node registrations included)
        #[arg(long, conflicts_with = "keep_data")]
        purge: bool,
        /// Stop the local database and keep it, with the scan state in it
        #[arg(long)]
        keep_data: bool,
        /// Do not ask first (for scripts, such as a package's removal script)
        #[arg(long, short = 'y')]
        yes: bool,
    },
    /// Serve the installed engines to an MCP client over stdio. Tools refuse
    /// destinations that a scope file you write does not list; the server reads it at
    /// start and never changes it.
    #[command(args_conflicts_with_subcommands = true)]
    Mcp {
        #[command(subcommand)]
        command: Option<McpCommand>,

        /// The scope file. Defaults to `<data-dir>/mcp/scope.toml`.
        #[arg(long, value_name = "PATH")]
        scope_file: Option<std::path::PathBuf>,

        /// Return secrets found in responses and evidence unmasked. The audit log is
        /// masked either way.
        #[arg(long)]
        no_redact: bool,

        /// The workbench_* tools: `auto` lists them while a Crossfyre Workbench with
        /// Agent access on answers, `always` lists them even when none does (for a
        /// client that never rereads the tool list), `off` reaches no Workbench.
        #[arg(long, value_enum, default_value_t = WorkbenchArg::Auto, value_name = "MODE")]
        workbench: WorkbenchArg,

        /// The Cloud key file. Defaults to `<data-dir>/mcp/cloud.toml`, written by
        /// `crossfyre mcp cloud login`.
        #[arg(long, value_name = "PATH", conflicts_with = "no_cloud")]
        cloud_file: Option<std::path::PathBuf>,

        /// Serve without the Cloud tools, whatever key is set up.
        #[arg(long)]
        no_cloud: bool,
    },

    /// Print a shell completion script to stdout, for example:
    ///   crossfyre completions bash > ~/.local/share/bash-completion/completions/crossfyre
    Completions {
        /// The shell to generate completions for
        shell: clap_complete::Shell,
    },
    /// Print the crossfyre man page (roff) to stdout, for example:
    ///   crossfyre man > crossfyre.1
    #[command(hide = true)]
    Man,
}

/// `crossfyre mcp --workbench`.
#[derive(clap::ValueEnum, Clone, Copy, Debug)]
enum WorkbenchArg {
    Auto,
    Always,
    Off,
}

/// Where a running Workbench says how to reach it: `$CROSSFYRE_WORKBENCH_DIR`, or the
/// Workbench's own data directory.
fn workbench_dir() -> Option<std::path::PathBuf> {
    match std::env::var_os("CROSSFYRE_WORKBENCH_DIR") {
        Some(d) if !d.is_empty() => Some(std::path::PathBuf::from(d)),
        _ => dirs::data_dir().map(|d| d.join("io.crossfyre.workbench")),
    }
}

#[derive(Subcommand, Debug)]
enum McpCommand {
    /// Connect `crossfyre mcp` to a Crossfyre Cloud workspace with an MCP key
    #[command(subcommand)]
    Cloud(CloudCommand),
}

#[derive(Subcommand, Debug)]
enum CloudCommand {
    /// Check an MCP key with the platform and save it for `crossfyre mcp`. The key is
    /// read from a hidden prompt, or from stdin when that is not a terminal; never
    /// from the command line.
    Login {
        /// Crossfyre's API address. Defaults to the one `crossfyre login` saved, and
        /// otherwise to the build's default.
        #[arg(long)]
        api_url: Option<String>,
        /// Where to save the key. Defaults to `<data-dir>/mcp/cloud.toml`.
        #[arg(long, value_name = "PATH")]
        cloud_file: Option<std::path::PathBuf>,
    },
    /// Show what the platform says about the saved key
    Status {
        #[arg(long, value_name = "PATH")]
        cloud_file: Option<std::path::PathBuf>,
    },
    /// Remove the saved key
    Logout {
        /// Revoke the key on the platform first
        #[arg(long)]
        revoke: bool,
        #[arg(long, value_name = "PATH")]
        cloud_file: Option<std::path::PathBuf>,
    },
}

#[derive(Subcommand, Debug)]
enum NodeAction {
    /// Enrol this machine as a Crossfyre node. Signed in with `crossfyre login`,
    /// it takes the oldest node on your account that has not come online yet and
    /// asks for no key. Without a session it needs that node's API key from the
    /// dashboard: pass it with `--node-key`, or paste it when asked. Enrolment
    /// writes `nodes.d/<node-id>.toml`, installs the node's engines, sets up the
    /// database and installs the node service.
    Init {
        /// Force-disconnect an already-running instance and take over
        #[arg(long)]
        force: bool,

        // Why the session comes first: taking the build default first meant `login`
        // and `node init` could disagree. Logging in to a local instance and then
        // enrolling sent the node key to whatever the binary was compiled against,
        // which for a plain build is production.
        /// Crossfyre's API address. Defaults to the one this data directory is
        /// signed in to, and otherwise to the build's default.
        #[arg(long)]
        api_url: Option<String>,

        /// Skip installing the node OS service (run `crossfyre node up` manually)
        #[arg(long)]
        no_service: bool,

        /// The node's API key, from the dashboard. Not needed when signed in.
        /// Without it and without a session, you are asked to paste it (unless
        /// --no-prompt).
        #[arg(long)]
        node_key: Option<String>,

        /// Never prompt; require the node key via --node-key (fails if missing).
        #[arg(long)]
        no_prompt: bool,
    },

    /// Remove a registered node from this host: deletes its `nodes.d/<id>.toml`
    /// (and pid/network files). `--inactive` removes every locally-registered
    /// node the server no longer knows about (deleted in the dashboard).
    Remove {
        /// Node id (or unique prefix) to remove. Omit with --inactive or --all.
        node_id: Option<String>,

        /// Remove all nodes the server reports as unknown/deleted.
        #[arg(long)]
        inactive: bool,

        /// Remove every node registered on this host (clean slate).
        #[arg(long)]
        all: bool,
    },

    /// List the nodes on your account, as Crossfyre sees them, with live online/offline
    /// status. (This is the server view; for the local daemons on this host use
    /// `crossfyre node status`.)
    List {
        /// Print raw JSON instead of a table.
        #[arg(long)]
        json: bool,
    },

    /// Show the node daemons registered on THIS host and whether each is running.
    Status,

    /// Bring all nodes online: start the node supervisor service (background).
    /// Falls back to a foreground supervisor when no OS service is installed.
    Up {
        /// Force-disconnect already-running instances and take over
        #[arg(long)]
        force: bool,
    },

    /// Take all nodes offline: stop the node supervisor service.
    Down,

    /// Restart the node supervisor service.
    Restart,

    /// Enable the node supervisor service (start on boot).
    Enable,

    /// Disable the node supervisor service (don't start on boot).
    Disable,
}

#[derive(Subcommand, Debug)]
enum OastAction {
    /// Install the OAST server as a systemd service (cf-oast) on this machine for your domain, then obtain
    /// a wildcard TLS cert (ACME DNS-01) and print the DNS-delegation records to add.
    /// Re-run after adding the records to finish TLS. Needs root, which it asks sudo for.
    Setup {
        /// The delegated zone callbacks arrive on, e.g. oob.example.com
        #[arg(long)]
        domain: String,
        /// This box's public IP (auto-detected if omitted)
        #[arg(long)]
        public_ip: Option<String>,
        /// ACME account email (required to obtain wildcard TLS)
        #[arg(long)]
        email: Option<String>,
        /// Install HTTP + DNS only; skip the TLS step for now
        #[arg(long)]
        no_tls: bool,
    },

    /// Run the OAST server in the foreground. With no flags it reads OAST_* from the
    /// environment (this is what the systemd unit runs); flags override for manual runs.
    Serve {
        /// Callback domain pool (comma-separated). Omit to read OAST_DOMAIN from env.
        #[arg(long)]
        domain: Option<String>,
        /// Public IP the DNS responder answers with (A record)
        #[arg(long)]
        public_ip: Option<String>,
        /// TLS certificate (fullchain PEM) to serve HTTPS on 443
        #[arg(long)]
        tls_cert: Option<String>,
        /// TLS private key (PEM)
        #[arg(long)]
        tls_key: Option<String>,
    },

    /// Show the local OAST server's status (service + domain + TLS).
    Status,
}

#[derive(Subcommand, Debug)]
enum ExtensionAction {
    /// List extensions with install state and daemon health.
    List,
    /// Install an extension (ambulo, voyage, doorward, toolmark, plessor, all):
    /// download, verify against the release manifest, enable and start its daemon.
    Install {
        name: Option<String>,
        /// Force reinstall even if already installed
        #[arg(short, long)]
        force: bool,
    },
    /// Remove an extension (stop service, delete binary).
    Remove { name: Option<String> },
    /// Update an extension from the release manifest.
    Update {
        name: Option<String>,
        /// Re-download even if the installed version already matches.
        #[arg(long)]
        force: bool,
    },
    /// Start an extension daemon.
    Start { name: String },
    /// Stop an extension daemon.
    Stop { name: String },
    /// Restart an extension daemon.
    Restart { name: String },
    /// Enable an extension daemon (start on boot).
    Enable { name: String },
    /// Disable an extension daemon (don't start on boot).
    Disable { name: String },
    /// Run an extension's daemon as its service (the launchd agent or scheduled task
    /// runs this).
    #[cfg(not(target_os = "linux"))]
    #[command(hide = true)]
    Host { name: String },
}

/// The `node` worker to run in the foreground: the one built beside this binary, for a
/// build run from a checkout, and otherwise the installed one. Never one from beside a
/// packaged CLI or from PATH, where `node` is Node.js on most machines that have either.
fn node_worker() -> Option<std::path::PathBuf> {
    let beside = if cfx_core::toolchain::packaging::current().is_some() {
        None
    } else {
        std::env::current_exe()
            .ok()
            .and_then(|p| {
                p.parent()
                    .map(|d| d.join(cfx_core::toolchain::config::file_name("node")))
            })
            .filter(|p| p.exists())
    };
    beside.or_else(|| Some(cfx_core::toolchain::service::node_binary()).filter(|p| p.exists()))
}

/// Run the `node` worker's supervisor in the foreground (fallback for hosts
/// with no OS service).
fn exec_node_supervise(
    base: &std::path::Path,
    force: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let node = node_worker().ok_or_else(|| {
        format!(
            "the node worker is not installed at {}; run `{}`",
            cfx_core::toolchain::service::node_binary().display(),
            cfx_core::os::elevated("crossfyre node init")
        )
    })?;
    let mut cmd = std::process::Command::new(node);
    cmd.arg("supervise").arg("--data-dir").arg(base);
    if force {
        cmd.arg("--force");
    }
    if !cmd.status()?.success() {
        return Err("node supervise exited with an error".into());
    }
    Ok(())
}

// An error is printed as the sentence it is. Returned from `main`, Rust prints it
// in debug form: in quotes, with any line break shown as a backslash and an n.
fn main() -> std::process::ExitCode {
    cfx_core::api::name_client("crossfyre", env!("CARGO_PKG_VERSION"));
    let outcome = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(Box::<dyn std::error::Error>::from)
        .and_then(|rt| rt.block_on(run()));
    match outcome {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("Error: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    // Run by a user, a command that needs root runs again through sudo.
    #[cfg(unix)]
    if !cfx_core::os::is_elevated()
        && let Some(command) = needs_root(
            &cli.command,
            &cfx_core::toolchain::install::may_replace_binaries,
        )
    {
        cfx_core::os::rerun_as_root(command);
    }
    let base = cfx_core::resolve_data_dir(cli.data_dir.as_deref())?;
    // Make --data-dir mean what it says: config.toml lives under the same root
    // as nodes.d and auth.toml, so an isolated node set gets its own database
    // and its own engine ports rather than quietly sharing the global ones.
    cfx_core::toolchain::config::set_toolchain_dir(base.clone());
    // Named in the User-Agent of requests to the release origin.
    cfx_core::toolchain::release_http::set_version(env!("CARGO_PKG_VERSION"));

    // No account gate here on purpose. The engines are free, and every command
    // that isn't node enrolment is either local or served from the PUBLIC
    // release manifest (bins.crossfyre.io): `extension` install/manage,
    // `update`, `status`, `db` (the local database) and `run` (a .cfx script
    // with no control plane) never touch the account session, so forcing a login
    // to install or use them is friction with nothing behind it.
    //
    // Auth still happens where it's genuinely needed, inside the command that
    // needs it: `node init` enrols this host against your account (and logs in
    // inline if needed), and `node list`/`node remove` hit the authed API and
    // self-handle a missing session with their own tailored message. `login`/
    // `logout` manage the session for those.

    match cli.command {
        Commands::Login {
            api_key,
            username,
            password,
            api_url,
            agree_tos,
            no_prompt,
        } => {
            cfx_core::auth::run_login(
                &base,
                cfx_core::auth::LoginFlags {
                    api_key,
                    username,
                    password,
                    api_url,
                    agree_tos,
                    no_prompt,
                    cli_version: env!("CARGO_PKG_VERSION").to_string(),
                },
            )
            .await?;
        }
        Commands::Logout => {
            cfx_core::auth::run_logout(&base);
        }
        Commands::Node { action } => match action {
            NodeAction::Init {
                force,
                api_url,
                no_service,
                node_key,
                no_prompt,
            } => {
                // Explicit flag wins; then the session saved in this data
                // directory; then the build default.
                let api_url = api_url
                    .or_else(|| cfx_core::auth::load_account(&base).map(|a| a.api_url))
                    .unwrap_or_else(|| cfx_core::auth::DEFAULT_API_URL.to_string());
                cfx_core::run_init(
                    force,
                    &api_url,
                    &base,
                    no_service,
                    node_key,
                    no_prompt,
                    env!("CARGO_PKG_VERSION"),
                )
                .await?;
            }
            NodeAction::Remove {
                node_id,
                inactive,
                all,
            } => {
                cfx_core::run_node_remove(&base, node_id, inactive, all).await?;
            }
            NodeAction::List { json } => {
                cfx_core::run_node_list(&base, json).await?;
            }
            NodeAction::Status => {
                cfx_core::toolchain::status::nodes(&base)?;
            }
            NodeAction::Up { force } => {
                if cfx_core::toolchain::service::node_service_exists() {
                    cfx_core::toolchain::service::start(cfx_core::toolchain::service::NODE_TARGET)?;
                    ok("Node supervisor started.");
                    hint("Run `crossfyre node status` to see the daemons.");
                } else {
                    // No OS service (e.g. `node init --no-service`, or non-Linux):
                    // run the supervisor in the foreground instead.
                    step(
                        "No node service installed; running the supervisor in the foreground (Ctrl-C to stop).",
                    );
                    exec_node_supervise(&base, force)?;
                }
            }
            NodeAction::Down => {
                if cfx_core::toolchain::service::node_service_exists() {
                    cfx_core::toolchain::service::stop(cfx_core::toolchain::service::NODE_TARGET)?;
                    ok("Node supervisor stopped.");
                } else {
                    warn("No node service installed; nothing to stop.");
                    hint("If a foreground `node up` is running, press Ctrl-C there.");
                }
            }
            NodeAction::Restart => {
                cfx_core::toolchain::service::restart(cfx_core::toolchain::service::NODE_TARGET)?;
            }
            NodeAction::Enable => {
                cfx_core::toolchain::service::enable(cfx_core::toolchain::service::NODE_TARGET)?;
            }
            NodeAction::Disable => {
                cfx_core::toolchain::service::disable(cfx_core::toolchain::service::NODE_TARGET)?;
            }
        },
        Commands::Extension { action } => match action {
            ExtensionAction::List => cfx_core::toolchain::status::extensions()?,
            ExtensionAction::Install { name, force } => match name.as_deref() {
                Some(ext) => {
                    let writer =
                        cfx_core::toolchain::install::Writer::cli(env!("CARGO_PKG_VERSION"));
                    cfx_core::toolchain::install::install_and_start(ext, force, writer).await?;
                }
                None => cfx_core::toolchain::print_extension_usage("install"),
            },
            ExtensionAction::Remove { name } => match name.as_deref() {
                Some(ext) => cfx_core::toolchain::install::remove(ext)?,
                None => cfx_core::toolchain::print_extension_usage("remove"),
            },
            ExtensionAction::Update { name, force } => {
                let updated = cfx_core::toolchain::install::update(
                    name.as_deref(),
                    env!("CARGO_PKG_VERSION"),
                    force,
                )
                .await?;
                if !updated.succeeded() {
                    std::process::exit(1);
                }
            }
            ExtensionAction::Start { name } => cfx_core::toolchain::service::start(&name)?,
            ExtensionAction::Stop { name } => cfx_core::toolchain::service::stop(&name)?,
            ExtensionAction::Restart { name } => cfx_core::toolchain::service::restart(&name)?,
            ExtensionAction::Enable { name } => cfx_core::toolchain::service::enable(&name)?,
            ExtensionAction::Disable { name } => cfx_core::toolchain::service::disable(&name)?,
            #[cfg(not(target_os = "linux"))]
            ExtensionAction::Host { name } => cfx_core::toolchain::service::host(&name)?,
        },
        Commands::Oast { action } => match action {
            OastAction::Setup {
                domain,
                public_ip,
                email,
                no_tls,
            } => {
                cfx_core::toolchain::oast::setup(cfx_core::toolchain::oast::SetupOpts {
                    domain,
                    public_ip,
                    email,
                    no_tls,
                })
                .await?;
            }
            OastAction::Serve {
                domain,
                public_ip,
                tls_cert,
                tls_key,
            } => {
                // Flags override; with none, read the full config from the environment
                // (the systemd unit sets OAST_* via EnvironmentFile).
                let cfg = match domain {
                    Some(d) => {
                        let domains: Vec<String> = d
                            .split(',')
                            .map(|x| x.trim().trim_matches('.').to_ascii_lowercase())
                            .filter(|x| !x.is_empty())
                            .collect();
                        let ip = public_ip
                            .as_deref()
                            .and_then(oast::parse_ipv4)
                            .unwrap_or([127, 0, 0, 1]);
                        let mut c = oast::Config::new(domains, ip);
                        c.tls_cert = tls_cert;
                        c.tls_key = tls_key;
                        c
                    }
                    None => oast::Config::from_env(),
                };
                oast::run(cfg).await;
            }
            OastAction::Status => {
                cfx_core::toolchain::oast::status()?;
            }
        },
        Commands::Run { script, targets } => {
            cfx_core::run_script(&script, &targets).await?;
        }
        Commands::Trace {
            workflow_id,
            token,
            api_url,
            interface,
            browser,
            scope,
            batch_size,
            flush_secs,
            method,
            proxy_port,
            seed_credentials,
        } => {
            let method = match method.to_lowercase().as_str() {
                "keylog" | "packet" | "pcap" => cfx_core::toolchain::trace::CaptureMethod::Keylog,
                _ => cfx_core::toolchain::trace::CaptureMethod::Proxy,
            };
            cfx_core::toolchain::trace::run(cfx_core::toolchain::trace::TraceConfig {
                api_url,
                workflow_id,
                token,
                method,
                proxy_port,
                interface,
                browser,
                host_filter: scope,
                batch_size,
                flush_secs,
                seed_credentials,
            })
            .await?;
        }
        Commands::Update { target, force } => {
            let updated = cfx_core::toolchain::install::update(
                target.as_deref(),
                env!("CARGO_PKG_VERSION"),
                force,
            )
            .await?;
            if updated.restart && cfx_core::toolchain::service::node_service_exists() {
                step("Restarting the node service to pick up the new binary...");
                let _ = cfx_core::toolchain::service::restart(
                    cfx_core::toolchain::service::NODE_TARGET,
                );
            }
            // A component that needed an update and did not get one fails the command,
            // after the restart that whatever did update needs.
            if !updated.succeeded() {
                std::process::exit(1);
            }
        }
        Commands::Status => {
            cfx_core::toolchain::status::overview(&base)?;
        }
        Commands::Db { command } => {
            cfx_core::toolchain::db::run(&command).await?;
        }
        Commands::Doctor => {
            cfx_core::toolchain::doctor::run(&base).await?;
        }
        Commands::Uninstall {
            purge,
            keep_data,
            yes,
        } => {
            cfx_core::toolchain::uninstall::run(
                cfx_core::toolchain::uninstall::Scope { purge, keep_data },
                yes,
            )?;
        }
        Commands::Mcp {
            command: Some(McpCommand::Cloud(cloud)),
            ..
        } => {
            mcp_cloud(&base, cloud).await;
        }
        Commands::Mcp {
            command: None,
            scope_file,
            no_redact,
            workbench,
            cloud_file,
            no_cloud,
        } => {
            // Stdout is the protocol from here on, so nothing on this path may print
            // to it: no ui helpers, no status output. Diagnostics go to stderr.
            use cfx_core::toolchain::config;
            let engines = cfx_core::toolchain::ENGINES
                .iter()
                .map(|e| cfx_mcp::EngineInfo {
                    name: e.name.to_string(),
                    port: config::engine_port(e.name),
                    installed: config::is_extension_installed(e.name),
                })
                .collect();
            let opts = cfx_mcp::Options {
                scope_file,
                default_dir: base.join("mcp"),
                engines,
                // The port only, to say whether the database is up; never the password.
                postgres_port: config::load_config().ok().map(|c| c.postgres.port),
                version: env!("CARGO_PKG_VERSION").to_string(),
                redact: !no_redact,
                workbench_dir: workbench_dir(),
                workbench: match workbench {
                    WorkbenchArg::Auto => cfx_mcp::WorkbenchMode::Auto,
                    WorkbenchArg::Always => cfx_mcp::WorkbenchMode::Always,
                    WorkbenchArg::Off => cfx_mcp::WorkbenchMode::Off,
                },
                cloud_file,
                no_cloud,
            };
            match cfx_mcp::serve(opts).await {
                // Exit here rather than returning: a read of stdin still parked on the
                // runtime's blocking pool would hold up its shutdown after a Ctrl-C.
                Ok(()) => std::process::exit(0),
                Err(e) => {
                    eprintln!("crossfyre mcp: {e}");
                    std::process::exit(2);
                }
            }
        }
        Commands::Completions { shell } => {
            let mut script = Vec::new();
            clap_complete::generate(shell, &mut Cli::command(), "crossfyre", &mut script);
            print_all(&script)?;
        }
        Commands::Man => {
            let mut page = Vec::new();
            clap_mangen::Man::new(Cli::command()).render(&mut page)?;
            print_all(&page)?;
        }
    }

    Ok(())
}

/// The command as a person names it, as `node init`, when it needs root on Linux and
/// macOS, where it then runs itself again through sudo. The node service, the node's
/// configs (which only root may change, and which `node remove` reads and deletes),
/// uninstall and the OAST service always need it. `update` and the commands that install
/// or remove an engine need it when this user may not replace what is in the bin
/// directory, as in the installer's /opt/crossfyre/bin: `binaries_writable` says.
#[cfg(unix)]
fn needs_root(command: &Commands, binaries_writable: &dyn Fn() -> bool) -> Option<&'static str> {
    match command {
        Commands::Node { action } => match action {
            NodeAction::Init { .. } => Some("node init"),
            NodeAction::Up { .. } => Some("node up"),
            NodeAction::Down => Some("node down"),
            NodeAction::Restart => Some("node restart"),
            NodeAction::Enable => Some("node enable"),
            NodeAction::Disable => Some("node disable"),
            NodeAction::Remove {
                node_id,
                inactive,
                all,
            } if node_id.is_some() || *inactive || *all => Some("node remove"),
            NodeAction::Remove { .. } | NodeAction::List { .. } | NodeAction::Status => None,
        },
        Commands::Uninstall { .. } => Some("uninstall"),
        Commands::Oast {
            action: OastAction::Setup { .. },
        } if cfg!(target_os = "linux") => Some("oast setup"),
        Commands::Update { .. } if !binaries_writable() => Some("update"),
        Commands::Extension { action } => match action {
            ExtensionAction::Install { name: Some(_), .. } if !binaries_writable() => {
                Some("extension install")
            }
            ExtensionAction::Remove { name: Some(_) } if !binaries_writable() => {
                Some("extension remove")
            }
            ExtensionAction::Update { .. } if !binaries_writable() => Some("extension update"),
            _ => None,
        },
        _ => None,
    }
}

/// Write `bytes` to stdout. A reader that stops early, as `head` does, closes the pipe,
/// and that is not an error: the rest was not wanted. clap_complete panics on any failed
/// write, so what it generates is kept in memory and written from here.
fn print_all(bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut out = std::io::stdout().lock();
    match out.write_all(bytes).and_then(|()| out.flush()) {
        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
        done => done,
    }
}

/// The key, from a hidden prompt at a terminal or one line of stdin otherwise.
fn read_mcp_key() -> std::io::Result<String> {
    use std::io::IsTerminal;
    if std::io::stdin().is_terminal() {
        dialoguer::Password::new()
            .with_prompt("MCP key (cfm_...)")
            .interact()
            .map_err(std::io::Error::other)
    } else {
        let mut line = String::new();
        std::io::stdin().read_line(&mut line)?;
        Ok(line.trim().to_string())
    }
}

/// `crossfyre mcp cloud ...`. These print to the terminal; they never run while the
/// server is serving, where stdout is the protocol.
async fn mcp_cloud(base: &std::path::Path, cmd: CloudCommand) {
    let at = |cloud_file| cfx_mcp::CloudCommand {
        default_dir: base.join("mcp"),
        cloud_file,
        version: env!("CARGO_PKG_VERSION").to_string(),
    };
    let done = match cmd {
        CloudCommand::Login {
            api_url,
            cloud_file,
        } => {
            let api_url = api_url
                .or_else(|| cfx_core::auth::load_account(base).map(|a| a.api_url))
                .unwrap_or_else(|| cfx_core::auth::DEFAULT_API_URL.to_string());
            match read_mcp_key() {
                Ok(key) => cfx_mcp::cloud_login(&at(cloud_file), &api_url, &key).await,
                Err(e) => Err(format!("could not read the key: {e}")),
            }
        }
        CloudCommand::Status { cloud_file } => cfx_mcp::cloud_status(&at(cloud_file)).await,
        CloudCommand::Logout { revoke, cloud_file } => {
            cfx_mcp::cloud_logout(&at(cloud_file), revoke).await
        }
    };
    match done {
        Ok(lines) => {
            for l in lines {
                println!("{l}");
            }
        }
        Err(e) => {
            eprintln!("crossfyre mcp cloud: {e}");
            std::process::exit(1);
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    fn root_for(args: &[&str], binaries_writable: bool) -> Option<&'static str> {
        let cli = Cli::try_parse_from(std::iter::once("crossfyre").chain(args.iter().copied()))
            .expect("parses");
        needs_root(&cli.command, &|| binaries_writable)
    }

    #[test]
    fn the_node_s_service_and_configs_and_uninstall_always_need_root() {
        for (args, name) in [
            (&["node", "init"][..], "node init"),
            (
                &["node", "init", "--no-service", "--node-key", "k"],
                "node init",
            ),
            (&["node", "up"], "node up"),
            (&["node", "up", "--force"], "node up"),
            (&["node", "down"], "node down"),
            (&["node", "restart"], "node restart"),
            (&["node", "enable"], "node enable"),
            (&["node", "disable"], "node disable"),
            (&["node", "remove", "0b7f5d0e"], "node remove"),
            (&["node", "remove", "--inactive"], "node remove"),
            (&["node", "remove", "--all"], "node remove"),
            (&["uninstall", "--yes"], "uninstall"),
            (&["uninstall", "--purge"], "uninstall"),
        ] {
            for writable in [false, true] {
                assert_eq!(root_for(args, writable), Some(name), "{args:?}");
            }
        }
    }

    #[test]
    fn replacing_binaries_needs_root_only_where_this_user_may_not_write_them() {
        for (args, name) in [
            (&["update"][..], "update"),
            (&["update", "self"], "update"),
            (&["update", "voyage", "--force"], "update"),
            (&["extension", "install", "voyage"], "extension install"),
            (&["extension", "remove", "voyage"], "extension remove"),
            (&["extension", "update"], "extension update"),
            (&["extension", "update", "voyage"], "extension update"),
        ] {
            assert_eq!(root_for(args, false), Some(name), "{args:?}");
            assert_eq!(root_for(args, true), None, "{args:?}");
        }
    }

    #[test]
    fn the_oast_service_needs_root_where_it_can_be_set_up() {
        let args = ["oast", "setup", "--domain", "oob.example.com"];
        let want = cfg!(target_os = "linux").then_some("oast setup");
        assert_eq!(root_for(&args, true), want);
    }

    /// Engines are the user's own services, and the rest reads or talks to the
    /// account, so none of it asks for root.
    #[test]
    fn everything_else_runs_as_the_user() {
        for args in [
            &["login"][..],
            &["logout"],
            &["status"],
            &["doctor"],
            &["node", "status"],
            &["node", "list"],
            &["node", "remove"],
            &["extension", "list"],
            &["extension", "install"],
            &["extension", "remove"],
            &["extension", "start", "voyage"],
            &["extension", "stop", "voyage"],
            &["extension", "restart", "voyage"],
            &["extension", "enable", "voyage"],
            &["extension", "disable", "voyage"],
            &["oast", "status"],
            &["oast", "serve", "--domain", "oob.example.com"],
            &["db", "up"],
            &["mcp"],
            &["run", "x.cfx", "domain:example.com"],
            &["completions", "bash"],
        ] {
            for writable in [false, true] {
                assert_eq!(root_for(args, writable), None, "{args:?}");
            }
        }
    }
}
