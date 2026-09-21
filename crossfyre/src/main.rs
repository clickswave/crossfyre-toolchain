//! The Crossfyre command-line interface. Management + lifecycle commands.
//! Node lifecycle is delegated to the separate `node` worker binary (the OS
//! service execs `node supervise`; `crossfyre node up/down` manage that service).
use cfx_core::toolchain::ui::*;
use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    name = "crossfyre",
    about = "Crossfyre node and toolchain CLI",
    version
)]
struct Cli {
    /// Override the crossfyre config root (the directory that holds
    /// `nodes.d` and `config.toml`). Defaults to `$XDG_CONFIG_HOME/crossfyre`
    /// of the *invoking* user (so `sudo` keeps using your home, not `/root`).
    /// Pass an explicit path to run an isolated set of nodes:
    /// `--data-dir ~/.config/cfx-htb`.
    #[arg(long, global = true, value_name = "PATH")]
    data_dir: Option<std::path::PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Log in to your Crossfyre account so the CLI can act on your behalf
    /// (e.g. provision nodes during `node init`). Three methods:
    ///   crossfyre login --api-key <key>
    ///   crossfyre login --username <u> --password <p>
    ///   crossfyre login                 (opens the browser to approve)
    /// The session is saved to <data-dir>/auth.toml.
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

        /// Control-plane origin
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

    /// Manage toolchain extensions (mach, voyage, pulse): list, install, remove,
    /// update, and control their daemons. All extension commands live under here.
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

    /// Run a .cfx script locally, no control plane required.
    /// Targets are type:value pairs, e.g. `crossfyre run test.cfx domain:example.com`.
    Run {
        script: String,

        #[arg(trailing_var_arg = true)]
        targets: Vec<String>,
    },

    /// Web Tracer: capture the sites you browse into a `web_trace` session's asset graph.
    /// Runs a local intercepting proxy (default; needs only a browser) and points a launched browser
    /// at it, or use `--method keylog` for SSLKEYLOGFILE + packet capture. Each request is reduced to
    /// a redacted shape and streamed to the control plane. Create the session in the dashboard
    /// (Command Center -> New Web Tracer) and paste the `--workflow-id`/`--token` it prints.
    Trace {
        /// The web_trace workflow id (from the dashboard session).
        #[arg(long)]
        workflow_id: String,

        /// The one-time session token (`cfxt_…`) shown when the session was created.
        #[arg(long)]
        token: String,

        /// Control-plane origin.
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

        /// Local port for the intercepting proxy (Method 2). Default 0 = OS-assigned free port (the
        /// tool prints the one it picked); set a fixed port if you drive your own browser.
        #[arg(long, default_value_t = 0)]
        proxy_port: u16,

        /// Seed the session auth you browse with (cookies, bearer/API-key headers) into the
        /// Credentials arsenal as encrypted, host-scoped credentials, ready for authenticated scans
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
    /// (Use `crossfyre node status`, `crossfyre extension list` or
    /// `crossfyre db status` for a single area.)
    Status,

    /// Manage the toolchain Postgres container.
    Db {
        #[command(subcommand)]
        command: cfx_core::DbCommands,
    },

    /// Check the environment for common problems.
    Doctor,

    /// Remove Crossfyre services, extensions, binaries and the database
    /// container from this host.
    Uninstall {
        /// Also remove the config root (node registrations included)
        #[arg(long)]
        purge: bool,
    },
}

#[derive(Subcommand, Debug)]
enum NodeAction {
    /// Register this host as a Crossfyre node using a node API key created in
    /// the dashboard (Nodes -> create a node). Pass it with `--node-key`, or
    /// run interactively and you'll be prompted to paste it. Enrolment writes
    /// `nodes.d/<node-id>.toml`, installs the node's selected extensions,
    /// provisions the database, and installs the node OS service.
    Init {
        /// Force-disconnect an already-running instance and take over
        #[arg(long)]
        force: bool,

        /// API base URL for the Crossfyre control plane.
        ///
        /// Defaults to the control plane this data directory is already signed
        /// in to, and only then to the build's default. Taking the build default
        /// first meant `login` and `node init` could disagree: logging in to a
        /// local instance and then enrolling sent the node key to whatever the
        /// binary was compiled against, which for a plain build is production.
        #[arg(long)]
        api_url: Option<String>,

        /// Skip installing the node OS service (run `crossfyre node up` manually)
        #[arg(long)]
        no_service: bool,

        /// The node API key (from the dashboard). If omitted, you're prompted
        /// to paste it (unless --no-prompt).
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

    /// List your node fleet from the control plane, with live online/offline
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
    /// Install cf_oast as a systemd service on THIS box for your domain, then obtain
    /// a wildcard TLS cert (ACME DNS-01) and print the DNS-delegation records to add.
    /// Re-run after adding the records to finish TLS. Needs root (sudo).
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
    /// Install an extension (mach, voyage, pulse, all): download, verify against
    /// the release manifest, enable and start its daemon.
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
}

/// Run the `node` worker's supervisor in the foreground (fallback for hosts
/// with no OS service). Finds the `node` binary next to this one, else on PATH.
fn exec_node_supervise(
    base: &std::path::Path,
    force: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let node = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("node")))
        .filter(|p| p.exists())
        .unwrap_or_else(|| std::path::PathBuf::from("node"));
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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(run())
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let base = cfx_core::resolve_data_dir(cli.data_dir.as_deref())?;
    // Make --data-dir mean what it says: config.toml lives under the same root
    // as nodes.d and auth.toml, so an isolated node set gets its own database
    // and its own engine ports rather than quietly sharing the global ones.
    cfx_core::toolchain::config::set_toolchain_dir(base.clone());

    // No account gate here on purpose. The engines are free, and every command
    // that isn't node enrolment is either local or served from the PUBLIC
    // release manifest (bins.crossfyre.io): `extension` install/manage,
    // `update`, `status`, `db` (the local container) and `run` (a .cfx script
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
                cfx_core::run_init(force, &api_url, &base, no_service, node_key, no_prompt).await?;
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
                    if force {
                        cfx_core::toolchain::install::install(ext, true).await?;
                        for e in cfx_core::toolchain::resolve_extensions(ext)? {
                            cfx_core::toolchain::service::enable(e)?;
                            cfx_core::toolchain::service::start(e)?;
                        }
                    } else {
                        cfx_core::toolchain::install::install_and_start(ext).await?;
                    }
                }
                None => cfx_core::toolchain::print_extension_usage("install"),
            },
            ExtensionAction::Remove { name } => match name.as_deref() {
                Some(ext) => cfx_core::toolchain::install::remove(ext)?,
                None => cfx_core::toolchain::print_extension_usage("remove"),
            },
            ExtensionAction::Update { name, force } => {
                cfx_core::toolchain::install::update(
                    name.as_deref(),
                    env!("CARGO_PKG_VERSION"),
                    force,
                )
                .await?;
            }
            ExtensionAction::Start { name } => cfx_core::toolchain::service::start(&name)?,
            ExtensionAction::Stop { name } => cfx_core::toolchain::service::stop(&name)?,
            ExtensionAction::Restart { name } => cfx_core::toolchain::service::restart(&name)?,
            ExtensionAction::Enable { name } => cfx_core::toolchain::service::enable(&name)?,
            ExtensionAction::Disable { name } => cfx_core::toolchain::service::disable(&name)?,
        },
        Commands::Oast { action } => match action {
            OastAction::Setup {
                domain,
                public_ip,
                email,
                no_tls,
            } => {
                let exe = std::env::current_exe()?;
                cfx_core::toolchain::oast::setup(
                    &exe,
                    cfx_core::toolchain::oast::SetupOpts {
                        domain,
                        public_ip,
                        email,
                        no_tls,
                    },
                )
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
            let self_updated = cfx_core::toolchain::install::update(
                target.as_deref(),
                env!("CARGO_PKG_VERSION"),
                force,
            )
            .await?;
            if self_updated && cfx_core::toolchain::service::node_service_exists() {
                step("Restarting the node service to pick up the new binary...");
                let _ = cfx_core::toolchain::service::restart(
                    cfx_core::toolchain::service::NODE_TARGET,
                );
            }
        }
        Commands::Status => {
            cfx_core::toolchain::status::overview(&base)?;
        }
        Commands::Db { command } => {
            cfx_core::toolchain::db::run(&command)?;
        }
        Commands::Doctor => {
            cfx_core::toolchain::doctor::run(&base).await?;
        }
        Commands::Uninstall { purge } => {
            cfx_core::toolchain::uninstall::run(purge)?;
        }
    }

    Ok(())
}
