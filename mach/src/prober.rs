use crate::libs::cli_args;
use crate::libs::mach_db::Work;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use reqwest::header::{AUTHORIZATION, COOKIE, HeaderMap, HeaderName, HeaderValue};
use transport::Client;

#[derive(Debug)]
pub struct Prober {
    config: cli_args::Args,
    client: Client,
    /// Wildcard/soft-404 baseline learned at calibration time. When a target answers
    /// "success" for paths that cannot exist (an SPA serving index.html for everything,
    /// a catch-all 200 error page), every wordlist entry would otherwise be a false
    /// "found". If set, a probe whose status + body size match this baseline is demoted
    /// to not_found. `None` = the target 404s honestly, so no suppression happens.
    soft404: Option<Soft404>,
}

#[derive(Debug, Clone)]
struct Soft404 {
    status: u16,
    len_lo: i64,
    len_hi: i64,
}

#[derive(Debug)]
pub struct Response {
    pub status: u16,
    pub headers: Option<Vec<String>>,
    pub headers_length: i64,
    pub body: Option<Vec<u8>>,
    pub body_length: i64,
    /// Where the request actually landed. Equal to the requested URL for a direct
    /// hit; when redirects were followed it is the final destination, so the node
    /// can show "requested -> final" instead of a bare redirect finding.
    pub final_url: String,
}

#[derive(Debug)]
pub struct ProbeResult {
    pub status: String,
    pub response: Response,
}

#[derive(Debug)]
pub enum ProbeError {
    UnsupportedMethod(String),
    RequestFailed(String),
}

impl std::fmt::Display for ProbeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProbeError::UnsupportedMethod(method) => {
                write!(f, "Unsupported HTTP method: {method}")
            }
            ProbeError::RequestFailed(err) => write!(f, "Request failed: {err}"),
        }
    }
}

impl Prober {
    pub async fn new(config: &cli_args::Args) -> Result<Self, String> {
        let policy = if config.follow_redirects {
            if config.follow_redirects_depth == 0 {
                transport::Redirect::Limited(usize::MAX) // effectively unlimited
            } else {
                transport::Redirect::Limited(config.follow_redirects_depth as usize)
            }
        } else {
            transport::Redirect::None
        };

        let user_agent = if config.random_user_agent_scan {
            crate::libs::rng::user_agent(None)
        } else {
            config.user_agent.clone()
        };

        let mut headers_map = HeaderMap::new();

        for header in &config.headers {
            if let Some((key, value)) = header.split_once(':') {
                let header_name = HeaderName::from_bytes(key.trim().as_bytes())
                    .map_err(|e| format!("Invalid header name '{key}': {e}"))?;
                let header_value = HeaderValue::from_str(value.trim())
                    .map_err(|e| format!("Invalid header value '{value}': {e}"))?;
                headers_map.insert(header_name, header_value);
            } else {
                return Err(format!(
                    "Invalid header format '{header}'. Use 'Key: Value'"
                ));
            }
        }

        // --- Build Cookie header from config.cookies ---
        if !config.cookies.is_empty() {
            let cookie_string = config
                .cookies
                .iter()
                .filter_map(|c| c.split_once(':'))
                .map(|(k, v)| format!("{}={}", k.trim(), v.trim()))
                .collect::<Vec<_>>()
                .join("; ");

            headers_map.insert(
                COOKIE,
                HeaderValue::from_str(&cookie_string)
                    .map_err(|e| format!("Invalid cookie header: {e}"))?,
            );
        }

        // --- Add Basic Auth if configured ---
        if !config.basic_auth.is_empty() {
            if let Some((username, password)) = config.basic_auth.split_once(':') {
                let credentials = format!("{username}:{password}"); // password may be empty
                let encoded = STANDARD.encode(credentials);
                let value = format!("Basic {encoded}");
                headers_map.insert(
                    AUTHORIZATION,
                    HeaderValue::from_str(&value)
                        .map_err(|e| format!("Invalid basic auth header: {e}"))?,
                );
            } else {
                return Err(format!(
                    "Invalid basic_auth format '{}'. Use 'username:password'",
                    config.basic_auth
                ));
            }
        }

        // Content-discovery client via the transport layer. Config headers/cookies
        // are app headers (always sent); the impersonate backend emulates a real
        // browser fingerprint from the UA family. No timeout, matching the prior
        // bare client. accept_invalid_certs stays false as before.
        // Attribution token (Identify posture) survives emulation as an app header.
        if let Some(token) = &config.identify {
            if let Ok(val) = transport::HeaderValue::from_str(token) {
                headers_map.insert(transport::HeaderName::from_static("x-bug-bounty"), val);
            }
        }
        let reqwest_client = transport::build_client(transport::ClientConfig {
            timeout: None,
            redirect: policy,
            accept_invalid_certs: false,
            cookie_store: config.store_cookies,
            user_agent: Some(user_agent),
            browser_headers: transport::HeaderMap::new(),
            extra_headers: headers_map,
            emulate: config.evasive,
            resolve: Vec::new(),
            ..Default::default()
        })
        .map_err(|e| format!("Failed to create HTTP client: {e}"))?;

        Ok(Self {
            config: config.clone(),
            client: reqwest_client,
            soft404: None,
        })
    }

    /// Probe a few paths that almost certainly do not exist. If the target answers with a
    /// "success" status and a stable body size for them, it wildcards (soft-404s), and we record
    /// that baseline so real probes matching it are not reported as findings. Only engages when at
    /// least two synthetic probes agree on the same success status with a tight body-length spread,
    /// so an honest 404 target (or one with genuinely varied pages) is left untouched.
    pub async fn calibrate(&mut self) {
        let bases = self.config.url.clone();
        let Some(base) = bases.first() else { return };
        let b = base.trim_end_matches('/');
        let synthetic = [
            "cfx404probe-zqx1w9",
            "this-path-should-not-exist-8f3a2b",
            "wildcard-calibration-5m7k",
        ];
        let mut hits: Vec<(u16, i64)> = Vec::new();
        for p in synthetic {
            let work = Work {
                url: format!("{b}/{p}"),
                entry_id: -1,
                method: "get".to_string(),
            };
            if let Ok(res) = self.probe_url(&work, false).await {
                if res.status == "found" {
                    hits.push((res.response.status, res.response.body_length));
                }
            }
        }
        // Need >=2 agreeing on the same success status.
        if hits.len() < 2 {
            return;
        }
        let status = hits[0].0;
        if !hits.iter().all(|(s, _)| *s == status) {
            return;
        }
        let lens: Vec<i64> = hits.iter().map(|(_, l)| *l).collect();
        let lo = *lens.iter().min().unwrap();
        let hi = *lens.iter().max().unwrap();
        // Require a tight spread; a widely varying "not found" page is not a reliable oracle and we
        // would rather report a few extra hits than silently swallow real endpoints of varied size.
        if hi - lo > 512 {
            return;
        }
        // Small margin absorbs the length difference from the reflected path itself.
        let margin = 128;
        self.soft404 = Some(Soft404 {
            status,
            len_lo: lo - margin,
            len_hi: hi + margin,
        });
        eprintln!(
            "[mach] soft-404 wildcard detected (status={status}, body ~{lo}-{hi}B); suppressing matching probes"
        );
    }

    pub async fn probe_url(
        &self,
        work: &Work,
        random_agent: bool,
    ) -> Result<ProbeResult, ProbeError> {
        let url = &work.url;
        let method = &work.method;

        // Build the request
        let mut request_builder = match method.as_str() {
            "get" => self.client.get(url),
            "post" => self.client.post(url),
            "put" => self.client.put(url),
            "delete" => self.client.delete(url),
            "head" => self.client.head(url),
            other => {
                return Err(ProbeError::UnsupportedMethod(format!(
                    "Unsupported HTTP method: {other}"
                )));
            }
        };

        if random_agent {
            // If random_user_agent_scan is true, set a random user agent
            let user_agent = crate::libs::rng::user_agent(None);
            request_builder = request_builder.header(reqwest::header::USER_AGENT, user_agent)
        }

        // Send the request
        let response = request_builder.send().await;

        let valid_response = match response {
            Ok(resp) => resp,
            Err(e) => {
                return Err(ProbeError::RequestFailed(format!(
                    "Failed to send request: {e}"
                )));
            }
        };

        let response_status = valid_response.status().as_u16();
        // The URL the response came from. With redirects followed this is the
        // final hop; captured before the body is consumed below.
        let final_url = valid_response.url().to_string();

        let mut probe_status = match &self.config.success_status_codes.contains(&response_status) {
            true => "found",
            false => "not_found",
        }
        .to_string();

        // headers format --> Name: Value
        let (headers, headers_length) = match &self.config.save_response_headers {
            true => {
                let headers = valid_response
                    .headers()
                    .iter()
                    .map(|(name, value)| {
                        format!("{}: {}", name.as_str(), value.to_str().unwrap_or(""))
                    })
                    .collect::<Vec<String>>();
                let headers_length = headers.len();
                (Some(headers), headers_length as i64)
            }
            false => {
                let headers_length = valid_response.headers().len();

                dbg!(headers_length);
                (None, headers_length as i64)
            }
        };
        // if save_response_body is true, we need to get body as bytes anyway but,
        // if its false, check for content length first
        // if content length is present, we can skip reading the body
        let (body, body_length) = match self.config.save_response_body {
            true => {
                let valid_body = valid_response.bytes().await;
                match valid_body {
                    Ok(bytes) => (Some(bytes.to_vec()), bytes.len() as i64),
                    Err(_) => (None, 0),
                }
            }
            false => {
                let content_length = valid_response.content_length();
                match content_length {
                    Some(len) => (None, len as i64),
                    None => {
                        let valid_body = valid_response.bytes().await;
                        match valid_body {
                            Ok(bytes) => (None, bytes.len() as i64),
                            Err(_) => (None, 0),
                        }
                    }
                }
            }
        };

        // Demote a "found" that matches the learned soft-404 wildcard (same success status and a
        // body size inside the calibrated band): the target answers this way for absent paths too,
        // so it is not a real discovery.
        if probe_status == "found" {
            if let Some(s) = &self.soft404 {
                if response_status == s.status && body_length >= s.len_lo && body_length <= s.len_hi
                {
                    probe_status = "not_found".to_string();
                }
            }
        }

        // Create and return the ProbeResult
        Ok(ProbeResult {
            status: probe_status,
            response: Response {
                status: response_status,
                headers,
                headers_length,
                body,
                body_length,
                final_url,
            },
        })
    }
}
