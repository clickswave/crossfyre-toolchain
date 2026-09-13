//! Dangling-CNAME / subdomain-takeover detection.
//!
//! A takeover happens when a host still points at a third-party service that no
//! longer serves it: `blog.example.com` CNAMEs to a Heroku app that was deleted,
//! so anyone who registers that app name now serves content on `example.com`.
//!
//! Two independent signals, in descending order of confidence:
//!
//!   1. **The CNAME target does not resolve at all** (NXDOMAIN). This is proof on
//!      its own, no HTTP needed and no service fingerprint needed: the record
//!      points into nothing. It is also the case most checkers miss, because they
//!      only match against a service list and give up when the provider is not on
//!      it. We report it whether or not we recognise the provider.
//!
//!   2. **The service answers with its "this host is unclaimed" page.** The target
//!      resolves, so signal 1 is silent, but the provider is serving a known
//!      not-configured response. This needs both a CNAME match and a body match:
//!      matching on the body alone produces false positives on any site that
//!      happens to quote the string.
//!
//! `Status` records what a match actually means today, which is the part that
//! rots. Many providers added domain verification precisely to kill this class,
//! so a matching fingerprint on one of those is a misconfiguration to clean up
//! rather than a live takeover. Reporting those as critical is how a checker
//! loses the reader's trust, so they are graded separately.
//!
//! Fingerprints go stale as providers change their 404 pages. `Status::EdgeCase`
//! and the body strings both need periodic review; a stale entry produces a
//! confident wrong answer, which is worse than no answer.

use std::collections::HashSet;

use hickory_resolver::TokioResolver;
use hickory_resolver::proto::rr::{RData, RecordType};

/// What a fingerprint match means in practice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// The name can be registered by anyone, so a match is a live takeover.
    Vulnerable,
    /// The provider requires ownership verification, or claiming needs a paid
    /// plan or a same-account condition. The dangling record is still wrong and
    /// worth fixing, but it is usually not directly claimable by a stranger.
    EdgeCase,
    /// Known-not-claimable. Kept so a match is reported as tidy-up rather than
    /// silently dropped, and so nobody re-adds it as vulnerable later.
    NotVulnerable,
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Vulnerable => "vulnerable",
            Status::EdgeCase => "edge_case",
            Status::NotVulnerable => "not_vulnerable",
        }
    }
}

pub struct Fingerprint {
    /// Provider name, as shown to a human.
    pub service: &'static str,
    /// CNAME suffixes that indicate this provider.
    pub cnames: &'static [&'static str],
    /// Body substrings the provider serves for a host it does not recognise.
    /// Empty means the provider is detected by NXDOMAIN alone.
    pub bodies: &'static [&'static str],
    /// Whether an NXDOMAIN on the CNAME target is expected for this provider
    /// when the resource is gone. Informational: an NXDOMAIN is reported for
    /// any provider, known or not, so `check` never reads this.
    ///
    /// It is not decoration. The corpus test asserts every fingerprint has at
    /// least one usable signal (`nxdomain || !bodies.is_empty()`), which catches
    /// an entry that would otherwise sit in the table and never match anything.
    /// Only the test reads it, hence the allow: clippy is right that the shipped
    /// binary does not.
    #[allow(dead_code)]
    pub nxdomain: bool,
    pub status: Status,
}

/// Provider fingerprints, derived from the public can-i-take-over-xyz corpus and
/// the providers we see most often in real subdomain sets.
///
/// Ordered roughly by how often each shows up rather than alphabetically, since
/// matching stops at the first hit and the common cases should be cheap.
pub const FINGERPRINTS: &[Fingerprint] = &[
    Fingerprint {
        service: "AWS S3",
        cnames: &[
            "s3.amazonaws.com",
            "s3-website",
            "s3.dualstack",
            "amazonaws.com",
        ],
        bodies: &["NoSuchBucket", "The specified bucket does not exist"],
        nxdomain: false,
        status: Status::Vulnerable,
    },
    Fingerprint {
        service: "AWS Elastic Beanstalk",
        cnames: &["elasticbeanstalk.com"],
        bodies: &[],
        nxdomain: true,
        status: Status::Vulnerable,
    },
    Fingerprint {
        service: "AWS CloudFront",
        cnames: &["cloudfront.net"],
        bodies: &["ERROR: The request could not be satisfied"],
        nxdomain: false,
        status: Status::EdgeCase,
    },
    Fingerprint {
        service: "Heroku",
        cnames: &["herokuapp.com", "herokudns.com", "herokussl.com"],
        bodies: &["No such app", "herokucdn.com/error-pages/no-such-app.html"],
        nxdomain: false,
        status: Status::Vulnerable,
    },
    Fingerprint {
        service: "GitHub Pages",
        cnames: &["github.io", "github.map.fastly.net"],
        bodies: &[
            "There isn't a GitHub Pages site here.",
            "For root URLs (like http://example.com/) you must provide an index.html file",
        ],
        nxdomain: false,
        status: Status::EdgeCase,
    },
    Fingerprint {
        service: "Microsoft Azure",
        cnames: &[
            "cloudapp.net",
            "cloudapp.azure.com",
            "azurewebsites.net",
            "blob.core.windows.net",
            "azure-api.net",
            "azurehdinsight.net",
            "azureedge.net",
            "azurecontainer.io",
            "redis.cache.windows.net",
            "servicebus.windows.net",
            "visualstudio.com",
            "trafficmanager.net",
        ],
        bodies: &[],
        nxdomain: true,
        status: Status::Vulnerable,
    },
    Fingerprint {
        service: "Shopify",
        cnames: &["myshopify.com"],
        bodies: &[
            "Sorry, this shop is currently unavailable.",
            "Only one step left!",
        ],
        nxdomain: false,
        status: Status::EdgeCase,
    },
    Fingerprint {
        service: "Fastly",
        cnames: &["fastly.net"],
        bodies: &["Fastly error: unknown domain"],
        nxdomain: false,
        status: Status::EdgeCase,
    },
    Fingerprint {
        service: "Netlify",
        cnames: &["netlify.app", "netlify.com", "netlifyglobalcdn.com"],
        bodies: &["Not Found - Request ID"],
        nxdomain: false,
        status: Status::EdgeCase,
    },
    Fingerprint {
        service: "Vercel",
        cnames: &["vercel-dns.com", "vercel.app", "vercel-dns-016.com"],
        bodies: &[
            "The deployment could not be found on Vercel",
            "DEPLOYMENT_NOT_FOUND",
        ],
        nxdomain: false,
        status: Status::EdgeCase,
    },
    Fingerprint {
        service: "Pantheon",
        cnames: &["pantheonsite.io", "pantheon.io"],
        bodies: &["The gods are wise, but do not know of the site which you seek."],
        nxdomain: false,
        status: Status::Vulnerable,
    },
    Fingerprint {
        service: "Tumblr",
        cnames: &["domains.tumblr.com", "tumblr.com"],
        bodies: &[
            "Whatever you were looking for doesn't currently exist at this address.",
            "There's nothing here.",
        ],
        nxdomain: false,
        status: Status::Vulnerable,
    },
    Fingerprint {
        service: "WordPress.com",
        cnames: &["wordpress.com"],
        bodies: &["Do you want to register"],
        nxdomain: false,
        status: Status::Vulnerable,
    },
    Fingerprint {
        service: "Ghost",
        cnames: &["ghost.io"],
        bodies: &[
            "The thing you were looking for is no longer here, or never was",
            "Domain error",
        ],
        nxdomain: false,
        status: Status::Vulnerable,
    },
    Fingerprint {
        service: "Bitbucket",
        cnames: &["bitbucket.io"],
        bodies: &["Repository not found"],
        nxdomain: false,
        status: Status::Vulnerable,
    },
    Fingerprint {
        service: "Surge.sh",
        cnames: &["surge.sh"],
        bodies: &["project not found"],
        nxdomain: false,
        status: Status::Vulnerable,
    },
    Fingerprint {
        service: "Intercom",
        cnames: &["custom.intercom.help", "intercom.help"],
        bodies: &[
            "This page is reserved for artistic dogs.",
            "Uh oh. That page doesn't exist.",
        ],
        nxdomain: false,
        status: Status::Vulnerable,
    },
    Fingerprint {
        service: "Webflow",
        cnames: &["proxy-ssl.webflow.com", "proxy.webflow.com", "webflow.io"],
        bodies: &["The page you are looking for doesn't exist or has been moved."],
        nxdomain: false,
        status: Status::EdgeCase,
    },
    Fingerprint {
        service: "Help Scout",
        cnames: &["helpscoutdocs.com"],
        bodies: &["No settings were found for this company:"],
        nxdomain: false,
        status: Status::Vulnerable,
    },
    Fingerprint {
        service: "Helpjuice",
        cnames: &["helpjuice.com"],
        bodies: &["We could not find what you're looking for."],
        nxdomain: false,
        status: Status::Vulnerable,
    },
    Fingerprint {
        service: "Readme.io",
        cnames: &["readme.io", "readmessl.com"],
        bodies: &["Project doesnt exist... yet!"],
        nxdomain: false,
        status: Status::Vulnerable,
    },
    Fingerprint {
        service: "UserVoice",
        cnames: &["uservoice.com"],
        bodies: &["This UserVoice subdomain is currently available!"],
        nxdomain: false,
        status: Status::Vulnerable,
    },
    Fingerprint {
        service: "Campaign Monitor",
        cnames: &["createsend.com", "createsend.net"],
        bodies: &["Trying to access your account?", "double-check the URL"],
        nxdomain: false,
        status: Status::Vulnerable,
    },
    Fingerprint {
        service: "Acquia",
        cnames: &["acquia-sites.com", "acquia-test.co"],
        bodies: &[
            "The site you are looking for could not be found.",
            "If you are an Acquia Cloud customer",
        ],
        nxdomain: false,
        status: Status::Vulnerable,
    },
    Fingerprint {
        service: "Teamwork",
        cnames: &["teamwork.com"],
        bodies: &["Oops - We didn't find your site."],
        nxdomain: false,
        status: Status::Vulnerable,
    },
    Fingerprint {
        service: "Canny",
        cnames: &["canny.io"],
        bodies: &["Company Not Found"],
        nxdomain: false,
        status: Status::Vulnerable,
    },
    Fingerprint {
        service: "Frontify",
        cnames: &["frontify.com"],
        bodies: &["404 - Page not found"],
        nxdomain: false,
        status: Status::Vulnerable,
    },
    Fingerprint {
        service: "Gemfury",
        cnames: &["furyns.com"],
        bodies: &["404: This page could not be found."],
        nxdomain: false,
        status: Status::Vulnerable,
    },
    Fingerprint {
        service: "GetResponse",
        cnames: &["gr8.com"],
        bodies: &["With GetResponse Landing Pages, lead generation has never been easier"],
        nxdomain: false,
        status: Status::Vulnerable,
    },
    Fingerprint {
        service: "Hatena Blog",
        cnames: &["hatenablog.com"],
        bodies: &["404 Blog is not found"],
        nxdomain: false,
        status: Status::Vulnerable,
    },
    Fingerprint {
        service: "Kinsta",
        cnames: &["kinsta.cloud"],
        bodies: &["No Site For Domain"],
        nxdomain: false,
        status: Status::Vulnerable,
    },
    Fingerprint {
        service: "LaunchRock",
        cnames: &["launchrock.com"],
        bodies: &["It looks like you may have taken a wrong turn somewhere"],
        nxdomain: false,
        status: Status::Vulnerable,
    },
    Fingerprint {
        service: "ngrok",
        cnames: &["ngrok.io", "ngrok.app"],
        bodies: &["ngrok.io not found", "Tunnel not found"],
        nxdomain: false,
        status: Status::Vulnerable,
    },
    Fingerprint {
        service: "Read the Docs",
        cnames: &["readthedocs.io", "readthedocs.org"],
        bodies: &["unknown to Read the Docs"],
        nxdomain: false,
        status: Status::Vulnerable,
    },
    Fingerprint {
        service: "Smartling",
        cnames: &["smartling.com"],
        bodies: &["Domain is not configured"],
        nxdomain: false,
        status: Status::Vulnerable,
    },
    Fingerprint {
        service: "Strikingly",
        cnames: &["s.strikinglydns.com", "strikinglydns.com"],
        bodies: &["But if you're looking to build your own website"],
        nxdomain: false,
        status: Status::Vulnerable,
    },
    Fingerprint {
        service: "Uberflip",
        cnames: &["read.uberflip.com"],
        bodies: &["The URL you've accessed does not provide a hub."],
        nxdomain: false,
        status: Status::Vulnerable,
    },
    Fingerprint {
        service: "Wishpond",
        cnames: &["wishpond.com"],
        bodies: &["https://www.wishpond.com/404?utm_campaign=404_page"],
        nxdomain: false,
        status: Status::Vulnerable,
    },
    Fingerprint {
        service: "Aftership",
        cnames: &["aftership.com"],
        bodies: &[
            "Oops.</h2><p class=\"text-muted text-tight\">The page you're looking for doesn't exist.",
        ],
        nxdomain: false,
        status: Status::Vulnerable,
    },
    Fingerprint {
        service: "Big Cartel",
        cnames: &["bigcartel.com"],
        bodies: &[
            "<h1>Oops! We could&#8217;t find that page.</h1>",
            "Oops! We couldn",
        ],
        nxdomain: false,
        status: Status::Vulnerable,
    },
    Fingerprint {
        service: "FeedPress",
        cnames: &["redirect.feedpress.me"],
        bodies: &["The feed has not been found."],
        nxdomain: false,
        status: Status::Vulnerable,
    },
    Fingerprint {
        service: "Flywheel",
        cnames: &["flywheelsites.com", "flywheelstaging.com"],
        bodies: &["We're sorry, you've landed on a page that is hosted by Flywheel"],
        nxdomain: false,
        status: Status::Vulnerable,
    },
    Fingerprint {
        service: "HubSpot",
        cnames: &["hubspot.net", "hs-sites.com", "hubspotusercontent.com"],
        bodies: &["does not exist in our system", "Domain not found"],
        nxdomain: false,
        status: Status::EdgeCase,
    },
    Fingerprint {
        service: "JetBrains YouTrack",
        cnames: &["myjetbrains.com"],
        bodies: &["is not a registered InCloud YouTrack"],
        nxdomain: false,
        status: Status::Vulnerable,
    },
    Fingerprint {
        service: "Short.io",
        cnames: &["cname.short.io", "short.io"],
        bodies: &["Link does not exist"],
        nxdomain: false,
        status: Status::Vulnerable,
    },
    Fingerprint {
        service: "SmugMug",
        cnames: &["domains.smugmug.com"],
        bodies: &[],
        nxdomain: true,
        status: Status::Vulnerable,
    },
    Fingerprint {
        service: "Vend",
        cnames: &["vendecommerce.com"],
        bodies: &["Looks like you've traveled too far into cyberspace."],
        nxdomain: false,
        status: Status::Vulnerable,
    },
    Fingerprint {
        service: "Thinkific",
        cnames: &["thinkific.com"],
        bodies: &["You may have mistyped the address or the page may have moved."],
        nxdomain: false,
        status: Status::Vulnerable,
    },
    Fingerprint {
        service: "Simplebooklet",
        cnames: &["simplebooklet.com"],
        bodies: &["We can't find this <a href=\"https://simplebooklet.com"],
        nxdomain: false,
        status: Status::Vulnerable,
    },
    Fingerprint {
        service: "Aha!",
        cnames: &["ideas.aha.io"],
        bodies: &["There is no portal here ... sending you back to Aha!"],
        nxdomain: false,
        status: Status::Vulnerable,
    },
    Fingerprint {
        service: "AnnounceKit",
        cnames: &["cname.announcekit.app"],
        bodies: &["Error 404 - AnnounceKit"],
        nxdomain: false,
        status: Status::Vulnerable,
    },
    Fingerprint {
        service: "Instapage",
        cnames: &["pageserve.co", "secure.pageserve.co"],
        bodies: &["Look like you're lost"],
        nxdomain: false,
        status: Status::Vulnerable,
    },
    Fingerprint {
        service: "GitBook",
        cnames: &["gitbook.io", "gitbook.com"],
        bodies: &["If you need specifics, here's the error"],
        nxdomain: false,
        status: Status::Vulnerable,
    },
    Fingerprint {
        service: "Statuspage",
        cnames: &["statuspage.io"],
        bodies: &["You are being <a href=\"https://www.statuspage.io\">redirected"],
        nxdomain: false,
        status: Status::EdgeCase,
    },
    Fingerprint {
        service: "Unbounce",
        cnames: &["unbouncepages.com"],
        bodies: &["The requested URL was not found on this server."],
        nxdomain: false,
        status: Status::EdgeCase,
    },
    Fingerprint {
        service: "Tilda",
        cnames: &["tilda.ws", "tilda.cc"],
        bodies: &["Please renew your subscription"],
        nxdomain: false,
        status: Status::EdgeCase,
    },
    Fingerprint {
        service: "Wix",
        cnames: &["wixdns.net", "wix.com"],
        bodies: &["Error ConnectYourDomain occurred"],
        nxdomain: false,
        status: Status::EdgeCase,
    },
    Fingerprint {
        service: "Mashery",
        cnames: &["mashery.com"],
        bodies: &["Unrecognized domain"],
        nxdomain: false,
        status: Status::EdgeCase,
    },
    Fingerprint {
        service: "Discourse",
        cnames: &["hosted-by-discourse.com"],
        bodies: &["This Discourse server is not configured for that hostname"],
        nxdomain: false,
        status: Status::EdgeCase,
    },
    Fingerprint {
        service: "Zendesk",
        cnames: &["zendesk.com"],
        bodies: &["Help Center Closed"],
        nxdomain: false,
        status: Status::NotVulnerable,
    },
    Fingerprint {
        service: "Squarespace",
        cnames: &["squarespace.com"],
        bodies: &["Website Expired"],
        nxdomain: false,
        status: Status::NotVulnerable,
    },
    Fingerprint {
        service: "Fly.io",
        cnames: &["fly.dev"],
        bodies: &[],
        nxdomain: true,
        status: Status::EdgeCase,
    },
    Fingerprint {
        service: "Render",
        cnames: &["onrender.com"],
        bodies: &[],
        nxdomain: true,
        status: Status::EdgeCase,
    },
    Fingerprint {
        service: "Cargo Collective",
        cnames: &["cargocollective.com"],
        bodies: &["<title>404 &mdash; File not found</title>"],
        nxdomain: false,
        status: Status::Vulnerable,
    },
    Fingerprint {
        service: "Worksites",
        cnames: &["worksites.net"],
        bodies: &["Hello! Sorry, but the website you&rsquo;re looking for doesn&rsquo;t exist."],
        nxdomain: false,
        status: Status::Vulnerable,
    },
    Fingerprint {
        service: "Agile CRM",
        cnames: &["agilecrm.com"],
        bodies: &["Sorry, this page is no longer available."],
        nxdomain: false,
        status: Status::Vulnerable,
    },
];

/// What the check concluded for one host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// The CNAME target does not resolve. Proof on its own.
    DanglingNxdomain,
    /// A known provider is serving its unclaimed-host page.
    UnclaimedService,
    /// Points at a known provider and the provider is serving it normally.
    Claimed,
    /// No CNAME, or a CNAME that resolves and matches nothing interesting.
    Clean,
}

impl Verdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Verdict::DanglingNxdomain => "dangling_nxdomain",
            Verdict::UnclaimedService => "unclaimed_service",
            Verdict::Claimed => "claimed",
            Verdict::Clean => "clean",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Report {
    pub host: String,
    /// The CNAME chain we walked, in order. Empty when the host has no CNAME.
    pub chain: Vec<String>,
    pub verdict: Verdict,
    /// Provider name when a fingerprint matched.
    pub service: Option<&'static str>,
    /// Claimability of the matched provider.
    pub status: Option<Status>,
    /// Human-readable reason, safe to show a stranger.
    pub detail: String,
}

impl Report {
    /// Severity for the asset graph / findings feed.
    ///
    /// An NXDOMAIN dangling record is high whether or not we know the provider,
    /// because the record itself is the defect. A fingerprint match is graded by
    /// what the provider actually allows today.
    pub fn severity(&self) -> &'static str {
        match (self.verdict, self.status) {
            (Verdict::DanglingNxdomain, _) => "high",
            (Verdict::UnclaimedService, Some(Status::Vulnerable)) => "high",
            (Verdict::UnclaimedService, Some(Status::EdgeCase)) => "medium",
            (Verdict::UnclaimedService, _) => "low",
            _ => "info",
        }
    }

    pub fn is_finding(&self) -> bool {
        matches!(
            self.verdict,
            Verdict::DanglingNxdomain | Verdict::UnclaimedService
        )
    }
}

/// Match a CNAME target against the fingerprint list.
fn fingerprint_for(target: &str) -> Option<&'static Fingerprint> {
    let t = target.trim_end_matches('.').to_lowercase();
    FINGERPRINTS.iter().find(|fp| {
        fp.cnames
            .iter()
            .any(|c| t == *c || t.ends_with(&format!(".{c}")))
    })
}

/// Walk the CNAME chain for `host`, following at most `MAX_HOPS` links.
///
/// Bounded because a CNAME loop is a thing that exists in the wild and an
/// unbounded walk on a stranger's zone is a self-inflicted hang.
const MAX_HOPS: usize = 8;

async fn cname_chain(resolver: &TokioResolver, host: &str) -> Vec<String> {
    let mut chain = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut current = host.to_string();

    for _ in 0..MAX_HOPS {
        let lookup = match resolver.lookup(current.clone(), RecordType::CNAME).await {
            Ok(l) => l,
            Err(_) => break,
        };
        let Some(next) = lookup.answers().iter().find_map(|r| match &r.data {
            RData::CNAME(c) => Some(c.0.to_utf8()),
            _ => None,
        }) else {
            break;
        };
        let next = next.trim_end_matches('.').to_lowercase();
        if next.is_empty() || !seen.insert(next.clone()) {
            break;
        }
        chain.push(next.clone());
        current = next;
    }
    chain
}

/// Does `name` resolve to an address at all?
///
/// Distinguishing "no A/AAAA record" from "the name does not exist" matters:
/// only the second is a dangling record. hickory reports both as errors, so we
/// ask for the specific NXDOMAIN condition rather than treating any lookup
/// failure as proof, which would flag every host behind a timing-out resolver.
async fn is_nxdomain(resolver: &TokioResolver, name: &str) -> bool {
    match resolver.lookup_ip(name).await {
        Ok(_) => false,
        // `is_nx_domain` is specifically ResponseCode::NXDomain, not "the lookup
        // failed". A timeout, SERVFAIL or a NOERROR-with-no-A answer all return
        // Err here and none of them mean the name is gone.
        Err(e) => e.is_nx_domain(),
    }
}

/// Check one host for a takeover-shaped misconfiguration.
///
/// `fetch` is the HTTP body fetcher, injected so the caller owns the client
/// (and therefore the egress identity and timeouts). It should return the body
/// of `https://host/` (falling back to http) or None on any failure.
pub async fn check<F, Fut>(resolver: &TokioResolver, host: &str, fetch: F) -> Report
where
    F: FnOnce(String) -> Fut,
    Fut: std::future::Future<Output = Option<String>>,
{
    let host = host.trim().trim_end_matches('.').to_lowercase();
    let chain = cname_chain(resolver, &host).await;

    let Some(final_target) = chain.last().cloned() else {
        return Report {
            host,
            chain,
            verdict: Verdict::Clean,
            service: None,
            status: None,
            detail: "No CNAME record. Nothing to dangle.".to_string(),
        };
    };

    let fp = fingerprint_for(&final_target);

    // Signal 1: the chain ends in a name that does not exist. Proof regardless
    // of whether we recognise the provider, which is the point of checking it
    // before the fingerprint match rather than after.
    if is_nxdomain(resolver, &final_target).await {
        let detail = match fp {
            Some(f) => format!(
                "{host} points at {final_target} ({}), and that name no longer exists. \
                 Whoever registers it next serves content on {host}.",
                f.service
            ),
            None => format!(
                "{host} points at {final_target}, and that name no longer exists. \
                 If the provider lets anyone register it, they serve content on {host}."
            ),
        };
        return Report {
            host,
            chain,
            verdict: Verdict::DanglingNxdomain,
            service: fp.map(|f| f.service),
            status: fp.map(|f| f.status),
            detail,
        };
    }

    // Signal 2: a known provider serving its unclaimed-host page. Requires the
    // CNAME match too; body-only matching false-positives on any page that
    // happens to quote the string.
    let Some(f) = fp else {
        return Report {
            host,
            chain,
            verdict: Verdict::Clean,
            service: None,
            status: None,
            detail: format!("Points at {final_target}, which resolves. No known takeover pattern."),
        };
    };

    if !f.bodies.is_empty()
        && let Some(body) = fetch(host.clone()).await
        && let Some(hit) = f.bodies.iter().find(|b| body.contains(**b))
    {
        return Report {
            host: host.clone(),
            chain,
            verdict: Verdict::UnclaimedService,
            service: Some(f.service),
            status: Some(f.status),
            detail: match f.status {
                Status::Vulnerable => format!(
                    "{} is serving its \"not configured\" page for {host} (matched: {hit}). \
                     The resource was deleted but the DNS record still points at it.",
                    f.service
                ),
                Status::EdgeCase => format!(
                    "{} is serving its \"not configured\" page for {host} (matched: {hit}). \
                     {} requires domain verification before a host can be claimed, so this is a \
                     stale record to clean up rather than an open takeover.",
                    f.service, f.service
                ),
                Status::NotVulnerable => format!(
                    "{} is serving its \"not configured\" page for {host}. \
                     {} does not allow a stranger to claim the host, so this is untidy rather \
                     than dangerous.",
                    f.service, f.service
                ),
            },
        };
    }

    Report {
        host,
        chain,
        verdict: Verdict::Claimed,
        service: Some(f.service),
        status: Some(f.status),
        detail: format!("Points at {} and is being served normally.", f.service),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cname_suffix_match_is_boundary_aware() {
        // Exact host and a real subdomain both match.
        assert!(fingerprint_for("myapp.herokuapp.com").is_some());
        assert!(fingerprint_for("herokuapp.com").is_some());
        // A domain that merely ENDS with the string must not match, or
        // `evilherokuapp.com` would be fingerprinted as Heroku.
        assert!(fingerprint_for("evilherokuapp.com").is_none());
        assert!(fingerprint_for("notgithub.io").is_none());
    }

    #[test]
    fn trailing_dot_and_case_are_normalised() {
        assert!(fingerprint_for("MyApp.HerokuApp.Com.").is_some());
    }

    #[test]
    fn every_fingerprint_is_usable() {
        for f in FINGERPRINTS {
            assert!(!f.service.is_empty(), "fingerprint with no service name");
            assert!(!f.cnames.is_empty(), "{}: no cname patterns", f.service);
            // A fingerprint with neither an NXDOMAIN expectation nor body
            // strings can never fire, so it is dead weight that reads as
            // coverage. Catch it here rather than in a silent no-op scan.
            assert!(
                f.nxdomain || !f.bodies.is_empty(),
                "{}: no nxdomain flag and no body strings, so it can never match",
                f.service
            );
            for c in f.cnames {
                assert!(
                    !c.starts_with('.'),
                    "{}: cname '{c}' should not start with a dot",
                    f.service
                );
                assert!(
                    !c.ends_with('.'),
                    "{}: cname '{c}' should not end with a dot",
                    f.service
                );
            }
        }
    }

    #[test]
    fn severity_grades_by_claimability_not_just_match() {
        let base = Report {
            host: "x.example.com".into(),
            chain: vec!["y.herokuapp.com".into()],
            verdict: Verdict::UnclaimedService,
            service: Some("Heroku"),
            status: Some(Status::Vulnerable),
            detail: String::new(),
        };
        assert_eq!(base.severity(), "high");

        let edge = Report {
            status: Some(Status::EdgeCase),
            ..base.clone()
        };
        assert_eq!(edge.severity(), "medium");

        // An NXDOMAIN dangle is high even with no provider identified: the
        // record pointing into nothing is itself the defect.
        let nx = Report {
            verdict: Verdict::DanglingNxdomain,
            service: None,
            status: None,
            ..base.clone()
        };
        assert_eq!(nx.severity(), "high");

        let clean = Report {
            verdict: Verdict::Clean,
            ..base.clone()
        };
        assert_eq!(clean.severity(), "info");
        assert!(!clean.is_finding());
    }
}
