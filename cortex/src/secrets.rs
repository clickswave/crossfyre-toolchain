//! What a file read is actually worth.
//!
//! `/etc/passwd` proves path traversal and is worth nothing to an attacker: it
//! lists account names on a box they cannot log into. The reason traversal is a
//! critical finding is the file NEXT to it - the application's own configuration
//! - and that is a different request, which nothing was making.
//!
//! So a confirmed file read is followed by a short, bounded look for the config
//! files that carry credentials. Reaching one turns "this parameter builds a
//! path" into "the database password, the signing key and the cloud credentials
//! are readable by anyone with a URL", which is the difference between a ticket
//! that waits for the next sprint and one that pages somebody.
//!
//! # What is recorded, and what is not
//!
//! The key NAMES that appeared, never their values. The response body arrives
//! either way - there is no asking for half a file - but what goes into a
//! findings database, an export, a screenshot in a report and an email
//! attachment is a decision, and putting a live database password in all five is
//! not a service to anyone. The evidence needed is that the file was readable
//! and what class of secret it holds. That is what is kept.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

/// A configuration file worth one request, and how to know it when it arrives.
pub struct SecretFile {
    pub label: &'static str,
    /// Path relative to wherever the vulnerable script sits.
    pub path: &'static str,
    /// Key names this file carries. Two or more must appear before we believe
    /// it: `password` on its own is a word that turns up on login pages.
    pub keys: &'static [&'static str],
}

/// Deliberately short. Every entry costs a request per depth on a target that
/// already has a confirmed traversal, and a list of two hundred filenames is a
/// content-discovery wordlist wearing a chain's clothes.
pub const SECRET_FILES: &[SecretFile] = &[
    SecretFile {
        label: "environment file (.env)",
        path: ".env",
        keys: &[
            "DB_PASSWORD",
            "DB_USERNAME",
            "APP_KEY",
            "SECRET_KEY_BASE",
            "AWS_SECRET_ACCESS_KEY",
            "DATABASE_URL",
        ],
    },
    SecretFile {
        label: "Rails database configuration",
        path: "config/database.yml",
        keys: &["adapter:", "password:", "database:", "username:"],
    },
    SecretFile {
        label: "Rails secrets",
        path: "config/secrets.yml",
        keys: &["secret_key_base", "production:"],
    },
    SecretFile {
        label: "WordPress configuration",
        path: "wp-config.php",
        keys: &["DB_PASSWORD", "DB_NAME", "AUTH_KEY", "SECURE_AUTH_KEY"],
    },
    SecretFile {
        label: "Spring application properties",
        path: "application.properties",
        keys: &["spring.datasource.password", "spring.datasource.url"],
    },
    SecretFile {
        label: ".NET application settings",
        path: "appsettings.json",
        keys: &["ConnectionStrings", "DefaultConnection"],
    },
];

/// How many parent directories to walk up looking for the application root.
///
/// A config file sits beside the code, not at `/`, and the traversal that
/// reached `/etc/passwd` says nothing about how deep the script is. Three is
/// enough for the usual layouts and keeps the whole escalation under twenty
/// requests.
pub const DEPTHS: usize = 3;

/// At least this many of a file's key names must appear before it counts.
pub const KEY_HITS: usize = 2;

/// Escalation results already computed, keyed by host + parameter.
///
/// Mutillidae answers on a dozen values of one routing parameter, and every one
/// of them confirms the same file read through the same `page` parameter. The
/// finding is deduplicated on the way out, but the eighteen requests this
/// escalation costs were being spent once per URL before anything could
/// deduplicate them - so twelve identical answers cost two hundred requests to
/// produce, and eleven of them were discarded.
///
/// Keyed by parameter rather than by host because two parameters can sit in
/// scripts at different depths, and the recorded path should be the one that
/// actually worked.
static REACHED: OnceLock<Mutex<HashMap<String, Vec<serde_json::Value>>>> = OnceLock::new();

/// The cached escalation for this (host, param), if one has been done.
pub fn cached_reach(key: &str) -> Option<Vec<serde_json::Value>> {
    let m = REACHED.get_or_init(|| Mutex::new(HashMap::new()));
    let g = m.lock().unwrap_or_else(|e| e.into_inner());
    g.get(key).cloned()
}

pub fn remember_reach(key: &str, out: &[serde_json::Value]) {
    let m = REACHED.get_or_init(|| Mutex::new(HashMap::new()));
    let mut g = m.lock().unwrap_or_else(|e| e.into_inner());
    g.insert(key.to_string(), out.to_vec());
}

/// Which of this file's key names are present in a response body.
///
/// Case-sensitive for the SHOUTED constants (`DB_PASSWORD`) and
/// case-insensitive for the YAML/properties keys, because that is how each is
/// actually written and a case-blind match on `password:` would hit any page
/// with a login form on it.
pub fn keys_present(f: &SecretFile, body: &str) -> Vec<&'static str> {
    f.keys
        .iter()
        .copied()
        .filter(|k| {
            if k.chars().any(|c| c.is_ascii_uppercase()) {
                body.contains(k)
            } else {
                body.to_lowercase().contains(&k.to_lowercase())
            }
        })
        .collect()
}

/// Did this response carry the file we asked for?
pub fn is_the_file(f: &SecretFile, body: &str, baseline: &str) -> Option<Vec<&'static str>> {
    let hits = keys_present(f, body);
    if hits.len() < KEY_HITS {
        return None;
    }
    // Keys already on the endpoint's ordinary answer are the endpoint's, not
    // the file's.
    let base = keys_present(f, baseline);
    let new: Vec<&'static str> = hits.into_iter().filter(|k| !base.contains(k)).collect();
    (new.len() >= KEY_HITS).then_some(new)
}

/// The traversal prefix that reached `/etc/passwd`, reused to reach the
/// application's own files.
///
/// `../../../../etc/passwd` climbs to the filesystem root and the config file is
/// not there, so the prefix alone is not what is wanted; what it establishes is
/// that `../` is not being filtered and in which spelling. That spelling is what
/// comes back here, to be applied one, two and three levels up.
pub fn traversal_style(payload: &str) -> Option<&'static str> {
    if payload.contains("..%2f") {
        Some("..%2f")
    } else if payload.contains("....//") {
        Some("....//")
    } else if payload.contains("..\\") {
        Some("..\\")
    } else if payload.contains("../") {
        Some("../")
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env_file() -> &'static SecretFile {
        &SECRET_FILES[0]
    }

    #[test]
    fn a_dotenv_is_recognised_by_more_than_one_key() {
        let body = "APP_ENV=production\nAPP_KEY=base64:abc\nDB_PASSWORD=hunter2\n";
        let hits = is_the_file(env_file(), body, "").unwrap();
        assert!(hits.contains(&"APP_KEY"));
        assert!(hits.contains(&"DB_PASSWORD"));
    }

    #[test]
    fn one_key_is_not_a_file() {
        // A page that merely mentions DB_PASSWORD in prose.
        assert!(is_the_file(env_file(), "set DB_PASSWORD in your environment", "").is_none());
    }

    #[test]
    fn keys_already_on_the_page_do_not_count() {
        let page = "APP_KEY=x DB_PASSWORD=y";
        // Same content in the baseline: the endpoint always says this, so the
        // traversal did not produce it.
        assert!(is_the_file(env_file(), page, page).is_none());
    }

    #[test]
    fn a_login_page_is_not_a_rails_database_config() {
        let rails = &SECRET_FILES[1];
        let login = "<label>Password:</label><input name=username>";
        assert!(is_the_file(rails, login, "").is_none());
        let real = "production:\n  adapter: postgresql\n  database: app\n  password: s3cr3t\n";
        assert!(is_the_file(rails, real, "").is_some());
    }

    #[test]
    fn the_spelling_that_worked_is_the_one_reused() {
        assert_eq!(traversal_style("..%2f..%2fetc%2fpasswd"), Some("..%2f"));
        assert_eq!(traversal_style("....//....//etc/passwd"), Some("....//"));
        assert_eq!(traversal_style("../../etc/passwd"), Some("../"));
        assert_eq!(traversal_style("..\\..\\windows\\win.ini"), Some("..\\"));
        // An absolute path establishes no traversal spelling to reuse.
        assert_eq!(traversal_style("/etc/passwd"), None);
    }
}
