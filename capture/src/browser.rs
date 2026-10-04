//! Launching a browser that is already pointed at the proxy and already trusts the CA.
//!
//! The alternative is a page of instructions, and the instructions are where people give
//! up: find the proxy settings, find the certificate import dialog, know that Firefox has
//! its own trust store, know that Chromium bypasses loopback unless told not to. All of
//! that is knowable and none of it is interesting.
//!
//! Every detail here is carried over from `core/src/toolchain/trace_proxy.rs`, which has
//! been doing this since 2026-08-20 and learned each one the hard way. The two that look
//! like trivia and are not:
//!
//! - **`network.proxy.allow_hijacking_localhost`** and
//!   **`--proxy-bypass-list=<-loopback>`**. Both families bypass the proxy for loopback by
//!   default, so without these a `http://localhost` target never reaches the capture at
//!   all, and the symptom is an empty history while the site plainly works.
//! - **Firefox ignores Chromium's flags entirely.** Passing `--proxy-server` to Firefox is
//!   silently accepted and does nothing, which is why pointing `--browser firefox` at a
//!   proxy captured nothing for a while.
//!
//! The profile is a throwaway directory per launch, so none of this touches the browser
//! the operator actually uses.

use std::path::{Path, PathBuf};

/// Which family a browser belongs to, which decides everything about how it is launched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    Firefox,
    Chromium,
}

/// A browser found on this machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Browser {
    /// What to show: `firefox`, `chromium`, `google-chrome`.
    pub name: String,
    pub binary: PathBuf,
    pub family: Family,
}

/// Candidates in the order they are offered. Firefox first because its CA can be trusted
/// outright, so it is the one that works without weakening anything.
const CANDIDATES: &[(&str, Family)] = &[
    ("firefox", Family::Firefox),
    ("firefox-esr", Family::Firefox),
    ("chromium", Family::Chromium),
    ("chromium-browser", Family::Chromium),
    ("google-chrome-stable", Family::Chromium),
    ("google-chrome", Family::Chromium),
    ("brave-browser", Family::Chromium),
    ("brave", Family::Chromium),
    ("microsoft-edge", Family::Chromium),
];

/// Browsers present on this machine, in the order they should be offered.
pub fn installed() -> Vec<Browser> {
    let mut out = Vec::new();
    for (name, family) in CANDIDATES {
        if let Some(binary) = which(name) {
            // Several names often resolve to the same binary (chromium and
            // chromium-browser, chrome and google-chrome-stable). Offering one browser
            // three times under different names is not a choice, it is noise.
            if out.iter().any(|b: &Browser| b.binary == binary) {
                continue;
            }
            out.push(Browser {
                name: (*name).to_string(),
                binary,
                family: *family,
            });
        }
    }
    out
}

impl Browser {
    /// A browser the caller has already located, named on a command line rather than
    /// chosen from a list.
    ///
    /// The family is inferred from the binary's name, which is what decides whether this
    /// launch speaks prefs or flags. Anything not recognisably Firefox is treated as
    /// Chromium, because that is the larger family and the flags it takes are ignored by
    /// most things that are neither.
    pub fn at(binary: impl Into<PathBuf>) -> Self {
        let binary = binary.into();
        let name = binary
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| binary.display().to_string());
        let family = if name.to_ascii_lowercase().contains("firefox") {
            Family::Firefox
        } else {
            Family::Chromium
        };
        Self {
            name,
            binary,
            family,
        }
    }
}

/// Resolve a command name on PATH. No shell, so a name cannot become an invocation.
fn which(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(name))
        .find(|p| p.is_file())
}

/// What a launch needs.
pub struct Launch<'a> {
    pub browser: &'a Browser,
    /// The proxy to point at, on loopback.
    pub proxy_port: u16,
    /// The CA certificate file, for the families whose trust store can be pre-loaded.
    pub ca_pem: &'a Path,
    /// A throwaway profile directory. Created if absent and never shared with the
    /// operator's real profile.
    pub profile: &'a Path,
    /// Where to open. `about:blank` keeps the capture to what the operator then does.
    pub start_url: &'a str,
}

/// How the certificate ended up being trusted, which the caller has to be able to say.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trust {
    /// Installed into this profile's own store. Certificate checking is fully intact.
    Installed,
    /// Certificate checking is OFF in this throwaway profile.
    ///
    /// Chromium on Linux reads the user's shared NSS database rather than its
    /// `--user-data-dir`, so a certificate cannot be put somewhere that affects only this
    /// profile without touching the operator's real one. The alternative to this flag is
    /// writing our CA into their system trust store, which is a far bigger thing to do to
    /// somebody's machine than loosening one disposable profile.
    ///
    /// The caller has to tell the operator, because in this window nothing's certificate
    /// is checked, not just ours.
    CheckingDisabled,
    /// Neither was possible: `certutil` is absent for a Firefox launch.
    None,
}

/// Prepare the profile and return the arguments to run with.
///
/// Separate from spawning so the arguments can be asserted in a test without launching a
/// browser, which is the part that is easy to get silently wrong.
pub fn prepare(l: &Launch<'_>) -> std::io::Result<Prepared> {
    std::fs::create_dir_all(l.profile)?;
    let env = launch_env(l.browser.family);
    match l.browser.family {
        Family::Firefox => {
            let trust = if trust_ca_in_profile(l.profile, l.ca_pem) {
                Trust::Installed
            } else {
                Trust::None
            };
            std::fs::write(l.profile.join("user.js"), firefox_prefs(l.proxy_port))?;
            Ok(Prepared {
                args: vec![
                    "--no-remote".into(),
                    "--profile".into(),
                    l.profile.display().to_string(),
                    l.start_url.into(),
                ],
                env,
                trust,
            })
        }
        Family::Chromium => {
            seed_chromium_prefs(l.profile)?;
            Ok(Prepared {
                args: chromium_args(l),
                env,
                trust: Trust::CheckingDisabled,
            })
        }
    }
}

/// Everything needed to spawn, in one value.
///
/// The environment is in here rather than left to the caller because forgetting it is
/// invisible and expensive: `MOZ_REMOTE_SETTINGS_DEVTOOLS` is the difference between four
/// captures for a page and twenty-eight, and nothing about a launch without it looks
/// wrong. A caller that spawns from this struct cannot leave it out.
pub struct Prepared {
    pub args: Vec<String>,
    pub env: &'static [(&'static str, &'static str)],
    pub trust: Trust,
}

/// Launch it. The child is returned so the caller can decide whether to wait on it.
pub fn launch(l: &Launch<'_>) -> std::io::Result<(std::process::Child, Trust)> {
    let p = prepare(l)?;
    let mut cmd = std::process::Command::new(&l.browser.binary);
    cmd.args(&p.args);
    for (k, v) in p.env {
        cmd.env(k, v);
    }
    let child = cmd
        // A browser's console output is not the operator's problem and would bury the
        // capture log.
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()?;
    Ok((child, p.trust))
}

/// Pre-trust the CA in a Firefox profile's own NSS store, so nothing has to be imported
/// by hand.
///
/// A throwaway profile starts with an empty trust store, which is why a persistent CA on
/// its own was not enough: the profile, not the CA, is the thing being discarded.
/// Best-effort, returning false when `certutil` (from nss) is not installed.
pub fn trust_ca_in_profile(profile: &Path, ca_pem: &Path) -> bool {
    use std::process::Command;
    let db = format!("sql:{}", profile.display());
    // A fresh profile has no NSS database yet. A no-op where one exists.
    let _ = Command::new("certutil")
        .args(["-N", "-d", &db, "--empty-password"])
        .output();
    Command::new("certutil")
        .args(["-A", "-n", "Crossfyre Workbench CA", "-t", "C,,", "-i"])
        .arg(ca_pem)
        .args(["-d", &db])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Chromium's arguments.
fn chromium_args(l: &Launch<'_>) -> Vec<String> {
    let mut args = vec![
        format!("--proxy-server=127.0.0.1:{}", l.proxy_port),
        // Without this a http://localhost target never reaches the proxy.
        "--proxy-bypass-list=<-loopback>".to_string(),
        format!("--user-data-dir={}", l.profile.display()),
        // See `Trust::CheckingDisabled`.
        "--ignore-certificate-errors".to_string(),
    ];
    args.extend(QUIET.iter().map(|s| (*s).to_string()));
    args.push(l.start_url.to_string());
    args
}

/// Flags that stop the browser's own background traffic from filling the capture.
///
/// Safebrowsing, optimisation hints, account sync, component and dictionary downloads, the
/// new-tab page's promotions, GCM, metrics. Without them the first screen of any capture
/// is the browser phoning home rather than the operator's browsing, which is the same
/// reason an embedded testing browser is quiet.
const QUIET: &[&str] = &[
    "--no-first-run",
    "--no-default-browser-check",
    "--disable-background-networking",
    "--disable-component-update",
    "--disable-sync",
    "--disable-domain-reliability",
    "--disable-client-side-phishing-detection",
    "--safebrowsing-disable-auto-update",
    "--disable-default-apps",
    "--disable-breakpad",
    "--metrics-recording-only",
    "--no-pings",
    "--no-service-autorun",
    "--password-store=basic",
    "--use-mock-keychain",
    "--disable-component-extensions-with-background-pages",
    "--disable-search-engine-choice-screen",
    "--disable-features=OptimizationHints,OptimizationGuideModelDownloading,Translate,MediaRouter,\
DialMediaRouteProvider,InterestFeedContentSuggestions,CalculateNativeWinOcclusion,\
AutofillServerCommunication,CertificateTransparencyComponentUpdater",
];

/// Firefox's profile preferences.
///
/// The proxy ones are the point; the rest are the same silencing the Chromium flags do.
/// `security.enterprise_roots.enabled` is there so a CA installed in the system store is
/// also honoured, for an operator who prefers that to a per-profile import.
fn firefox_prefs(port: u16) -> String {
    let mut s = format!(
        "user_pref(\"network.proxy.type\", 1);\n\
         user_pref(\"network.proxy.http\", \"127.0.0.1\");\n\
         user_pref(\"network.proxy.http_port\", {port});\n\
         user_pref(\"network.proxy.ssl\", \"127.0.0.1\");\n\
         user_pref(\"network.proxy.ssl_port\", {port});\n\
         user_pref(\"network.proxy.allow_hijacking_localhost\", true);\n\
         user_pref(\"network.proxy.no_proxies_on\", \"\");\n\
         user_pref(\"security.enterprise_roots.enabled\", true);\n"
    );
    for quiet in FIREFOX_QUIET {
        s.push_str(quiet);
        s.push('\n');
    }
    s
}

/// Hosts a browser talks to on its own account, which are not the operator's browsing.
///
/// Measured rather than guessed: a single launch of Firefox pointed at one page produced
/// 28 captures, 26 of them these. The preferences below are supposed to prevent that and
/// demonstrably do not, because several of them take a URL and an empty string is not a
/// URL, so the component falls back to its built-in default. Rather than keep guessing at
/// a pref list that changes every release, the window filters these out of the VIEW and
/// says how many it hid. Nothing is dropped: they are in the project, and a target that
/// happens to be one of these is one toggle away.
pub const VENDOR_NOISE: &[&str] = &[
    "firefox.settings.services.mozilla.com",
    "incoming.telemetry.mozilla.org",
    "aus5.mozilla.org",
    "ads.mozilla.org",
    "ads-img.mozilla.org",
    "contile.services.mozilla.com",
    "push.services.mozilla.com",
    "normandy.cdn.mozilla.net",
    "shavar.services.mozilla.com",
    "content-signature-2.cdn.mozilla.net",
    "prod.ohttp-gateway.prod.webservices.mozgcp.net",
    "mozilla-ohttp.fastly-edge.com",
    "ciscobinary.openh264.org",
    "detectportal.firefox.com",
    "update.googleapis.com",
    "clients2.google.com",
    "clientservices.googleapis.com",
    "optimizationguide-pa.googleapis.com",
    "safebrowsing.googleapis.com",
    "edge.microsoft.com",
    "config.edge.skype.com",
];

const FIREFOX_QUIET: &[&str] = &[
    "user_pref(\"browser.shell.checkDefaultBrowser\", false);",
    "user_pref(\"network.captive-portal-service.enabled\", false);",
    "user_pref(\"network.connectivity-service.enabled\", false);",
    "user_pref(\"captivedetect.canonicalURL\", \"\");",
    // These take a URL. An empty string is not one, so the component ignores it and
    // uses its built-in default, which is why setting them to "" silenced nothing. A
    // syntactically valid address that cannot be reached does stop them.
    "user_pref(\"services.settings.server\", \"http://localhost.invalid/v1\");",
    "user_pref(\"browser.safebrowsing.malware.enabled\", false);",
    "user_pref(\"browser.safebrowsing.phishing.enabled\", false);",
    "user_pref(\"browser.safebrowsing.downloads.enabled\", false);",
    "user_pref(\"browser.safebrowsing.provider.google4.updateURL\", \"\");",
    "user_pref(\"browser.safebrowsing.provider.mozilla.updateURL\", \"\");",
    "user_pref(\"extensions.blocklist.enabled\", false);",
    "user_pref(\"app.update.enabled\", false);",
    "user_pref(\"app.update.auto\", false);",
    "user_pref(\"browser.region.network.url\", \"\");",
    "user_pref(\"browser.region.update.enabled\", false);",
    "user_pref(\"browser.discovery.enabled\", false);",
    "user_pref(\"browser.ping-centre.telemetry\", false);",
    "user_pref(\"browser.newtabpage.activity-stream.feeds.telemetry\", false);",
    "user_pref(\"browser.newtabpage.activity-stream.telemetry\", false);",
    "user_pref(\"browser.newtabpage.activity-stream.feeds.snippets\", false);",
    "user_pref(\"browser.newtabpage.activity-stream.feeds.section.topstories\", false);",
    "user_pref(\"browser.newtabpage.activity-stream.default.sites\", \"\");",
    "user_pref(\"dom.push.enabled\", false);",
    "user_pref(\"extensions.getAddons.cache.enabled\", false);",
    "user_pref(\"extensions.systemAddon.update.enabled\", false);",
    "user_pref(\"network.prefetch-next\", false);",
    "user_pref(\"datareporting.healthreport.uploadEnabled\", false);",
    "user_pref(\"datareporting.policy.dataSubmissionEnabled\", false);",
    "user_pref(\"toolkit.telemetry.enabled\", false);",
    "user_pref(\"toolkit.telemetry.unified\", false);",
    "user_pref(\"toolkit.telemetry.archive.enabled\", false);",
    "user_pref(\"toolkit.telemetry.server\", \"http://localhost.invalid\");",
    "user_pref(\"app.update.url\", \"http://localhost.invalid/update.xml\");",
    "user_pref(\"media.gmp-manager.url\", \"http://localhost.invalid/gmds.xml\");",
    "user_pref(\"browser.newtabpage.activity-stream.showSponsored\", false);",
    "user_pref(\"browser.newtabpage.activity-stream.showSponsoredTopSites\", false);",
    "user_pref(\"browser.contentblocking.report.hide_vpn_banner\", true);",
    "user_pref(\"network.dns.disablePrefetch\", true);",
    "user_pref(\"app.normandy.enabled\", false);",
    "user_pref(\"app.normandy.first_run\", false);",
    "user_pref(\"app.shield.optoutstudies.enabled\", false);",
    "user_pref(\"browser.aboutwelcome.enabled\", false);",
    "user_pref(\"browser.startup.homepage_override.mstone\", \"ignore\");",
    // Address-bar suggestions are not only noise. On a default profile every character
    // typed into the bar goes to the search engine, so an operator typing an internal
    // hostname publishes it before they have pressed Return, and the capture shows it
    // happening. Speculative connect is the same problem one step earlier: it opens a
    // connection to whatever the bar autocompleted to.
    "user_pref(\"browser.search.suggest.enabled\", false);",
    "user_pref(\"browser.urlbar.suggest.searches\", false);",
    "user_pref(\"browser.urlbar.suggest.quicksuggest.sponsored\", false);",
    "user_pref(\"browser.urlbar.suggest.quicksuggest.nonsponsored\", false);",
    "user_pref(\"browser.urlbar.speculativeConnect.enabled\", false);",
    "user_pref(\"browser.urlbar.quicksuggest.enabled\", false);",
    "user_pref(\"browser.fixup.alternate.enabled\", false);",
    // The codec and DRM plugins fetch themselves on first run, which is two more hosts in
    // the capture before the operator has browsed anywhere. Pointing gmp-manager at an
    // unreachable address was not enough on its own.
    "user_pref(\"media.gmp-provider.enabled\", false);",
    "user_pref(\"media.gmp.install.enabled\", false);",
    "user_pref(\"media.gmp-gmpopenh264.enabled\", false);",
    "user_pref(\"media.gmp-widevinecdm.enabled\", false);",
    "user_pref(\"media.gmp-widevinecdm.visible\", false);",
];

/// Settings a browser will not take from its profile.
///
/// `services.settings.server` is read through a guard: on a release build Firefox ignores
/// the pref entirely unless this variable says otherwise, and uses the compiled-in
/// address. That is why pointing it somewhere unreachable silenced nothing, and why a
/// launch that visited one local page spent sixteen of its twenty-one captures talking to
/// firefox.settings.services.mozilla.com.
fn launch_env(family: Family) -> &'static [(&'static str, &'static str)] {
    match family {
        Family::Firefox => &[("MOZ_REMOTE_SETTINGS_DEVTOOLS", "1")],
        Family::Chromium => &[],
    }
}

/// Chromium keeps the same setting in the profile rather than on the command line, and
/// reads this file at startup, so seeding it before the first launch is the only way in.
/// Writing it over an existing profile would throw away the operator's own settings, so
/// this only ever creates.
fn seed_chromium_prefs(profile: &Path) -> std::io::Result<()> {
    let dir = profile.join("Default");
    let file = dir.join("Preferences");
    if file.exists() {
        return Ok(());
    }
    std::fs::create_dir_all(&dir)?;
    std::fs::write(
        &file,
        r#"{"search":{"suggest_enabled":false},"alternate_error_pages":{"enabled":false},"safebrowsing":{"enabled":false},"credentials_enable_service":false,"profile":{"password_manager_enabled":false}}"#,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn browser(family: Family) -> Browser {
        Browser {
            name: "test".into(),
            binary: PathBuf::from("/bin/true"),
            family,
        }
    }

    #[test]
    fn chromium_is_told_not_to_bypass_loopback() {
        // The one flag whose absence is invisible: without it a http://localhost target
        // never reaches the proxy and the history stays empty while the site works.
        let b = browser(Family::Chromium);
        let l = Launch {
            browser: &b,
            proxy_port: 8080,
            ca_pem: Path::new("/tmp/ca.pem"),
            profile: Path::new("/tmp/p"),
            start_url: "about:blank",
        };
        let args = chromium_args(&l);
        assert!(args.contains(&"--proxy-bypass-list=<-loopback>".to_string()));
        assert!(args.contains(&"--proxy-server=127.0.0.1:8080".to_string()));
        assert!(args.contains(&"--user-data-dir=/tmp/p".to_string()));
        assert_eq!(args.last().unwrap(), "about:blank", "the url goes last");
        assert!(
            args.iter().any(|a| a.starts_with("--disable-features=")),
            "the quiet flags are there, or the capture opens full of Google"
        );
    }

    #[test]
    fn firefox_carries_the_variable_its_prefs_depend_on() {
        // `services.settings.server` is read only when this says it may, on a release
        // build. Without it the pref is ignored and the compiled-in address is used, so
        // the setting silently does nothing and one page of browsing produced
        // twenty-eight captures. It is returned with the arguments for that reason.
        let env = launch_env(Family::Firefox);
        assert!(
            env.iter()
                .any(|(k, v)| *k == "MOZ_REMOTE_SETTINGS_DEVTOOLS" && *v == "1"),
            "got: {env:?}"
        );
        assert!(launch_env(Family::Chromium).is_empty());
    }

    #[test]
    fn firefox_is_told_the_same_thing_in_its_own_language() {
        // Firefox ignores Chromium's flags entirely, which is why this is prefs and not
        // arguments, and why passing the wrong family's settings captures nothing.
        let prefs = firefox_prefs(9999);
        assert!(prefs.contains("user_pref(\"network.proxy.type\", 1);"));
        assert!(prefs.contains("user_pref(\"network.proxy.http_port\", 9999);"));
        assert!(prefs.contains("user_pref(\"network.proxy.ssl_port\", 9999);"));
        assert!(
            prefs.contains("allow_hijacking_localhost\", true"),
            "the loopback equivalent"
        );
        assert!(prefs.contains("toolkit.telemetry.enabled\", false"));
        // Not the empty string. These take a URL, so "" is not one, the component falls
        // back to its built-in default and the pref silences nothing while looking as
        // though it did. The CLI's tracer shipped that version for weeks.
        for pref in [
            "services.settings.server",
            "toolkit.telemetry.server",
            "app.update.url",
            "media.gmp-manager.url",
        ] {
            assert!(
                !prefs.contains(&format!("{pref}\", \"\")")),
                "{pref} is set to the empty string, which does nothing"
            );
            assert!(prefs.contains(pref), "{pref} is not set at all");
        }
        // Every line is a complete pref, or Firefox discards the rest of the file.
        for line in prefs.lines().filter(|l| !l.trim().is_empty()) {
            assert!(
                line.starts_with("user_pref(") && line.ends_with(");"),
                "malformed pref line: {line}"
            );
        }
    }

    #[test]
    fn a_chromium_launch_says_that_checking_is_off() {
        // It has to be reported, not assumed: in that profile NOTHING's certificate is
        // checked, not only ours, and the operator is the one who has to know.
        let b = browser(Family::Chromium);
        let dir = std::env::temp_dir().join(format!("cfx-br-{}", std::process::id()));
        let l = Launch {
            browser: &b,
            proxy_port: 8080,
            ca_pem: Path::new("/nonexistent.pem"),
            profile: &dir,
            start_url: "about:blank",
        };
        let p = prepare(&l).expect("prepare");
        assert_eq!(p.trust, Trust::CheckingDisabled);
        // And the environment travels with the arguments, so a caller spawning from this
        // cannot leave out the one variable that decides whether the capture is readable.
        assert!(
            p.env.is_empty(),
            "chromium needs nothing here, unlike firefox"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn neither_family_sends_the_address_bar_to_a_search_engine() {
        // Measured: a launch that only visited one local page still produced a request to
        // www.google.com/complete/search, because typing the hostname into the bar sent it
        // there a character at a time. On a pentest profile that publishes the name of an
        // internal host before the operator has pressed Return.
        let prefs = firefox_prefs(8080);
        assert!(prefs.contains("browser.search.suggest.enabled\", false"));
        assert!(prefs.contains("browser.urlbar.suggest.searches\", false"));

        let dir = std::env::temp_dir().join(format!("cfx-br-sug-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        seed_chromium_prefs(&dir).expect("seed");
        let seeded =
            std::fs::read_to_string(dir.join("Default").join("Preferences")).expect("read");
        assert!(seeded.contains("\"suggest_enabled\":false"));

        // And seeding never overwrites: the second launch of a profile the operator has
        // been using would otherwise throw away everything they had set in it.
        std::fs::write(dir.join("Default").join("Preferences"), "{\"mine\":true}").expect("write");
        seed_chromium_prefs(&dir).expect("seed again");
        let after = std::fs::read_to_string(dir.join("Default").join("Preferences")).expect("read");
        assert_eq!(after, "{\"mine\":true}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_browser_named_on_a_command_line_gets_the_right_family() {
        // The CLI takes `--browser <name>` and resolves it to a path, so the family has
        // to come from the path. Getting it wrong is silent: Firefox accepts Chromium's
        // flags and ignores them, so the browser opens, works, and captures nothing.
        assert_eq!(Browser::at("/usr/bin/firefox").family, Family::Firefox);
        assert_eq!(Browser::at("/usr/bin/firefox-esr").family, Family::Firefox);
        assert_eq!(Browser::at("/opt/Firefox/firefox").family, Family::Firefox);
        assert_eq!(Browser::at("/usr/bin/chromium").family, Family::Chromium);
        assert_eq!(
            Browser::at("/usr/bin/google-chrome-stable").family,
            Family::Chromium
        );
        assert_eq!(
            Browser::at("/usr/bin/brave-browser").family,
            Family::Chromium
        );
        // And the name is the binary's, not the whole path, because it is shown.
        assert_eq!(Browser::at("/usr/bin/chromium").name, "chromium");
    }

    #[test]
    fn the_same_binary_is_not_offered_twice_under_two_names() {
        // chromium and chromium-browser, chrome and google-chrome-stable: several names
        // commonly resolve to one binary, and three entries for one browser is noise
        // rather than a choice.
        let found = installed();
        let mut bins: Vec<_> = found.iter().map(|b| &b.binary).collect();
        let before = bins.len();
        bins.sort();
        bins.dedup();
        assert_eq!(before, bins.len(), "a binary appears twice: {found:?}");
    }
}
