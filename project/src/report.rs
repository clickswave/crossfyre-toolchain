//! A report, rendered from the project rather than from the window.
//!
//! Here and not in a user interface for one reason that decides it: the window is handed
//! bounded, lossy previews of bodies, because shipping whole responses into a webview is
//! how a capture tool becomes a memory problem. A report assembled from those would
//! quietly contain a truncated request as the proof of a finding, which is the class of
//! wrongness this product keeps finding in itself. The store has the bytes, so the
//! renderer lives next to the bytes.
//!
//! Markdown first because it is the format that is readable as a file, pastes into
//! everything, and converts to the two things a client actually asks for. Nothing here
//! styles anything: a renderer that tried to look like a document would be competing with
//! whatever the reader converts it with.

use crate::{Error, Finding, Project, Severity};

/// What a report says about itself.
///
/// Supplied by the caller rather than read from anywhere: this crate has no opinion about
/// what an engagement is called, and a date it invented from the system clock would be
/// the date the file was rendered rather than the date the work was done.
#[derive(Debug, Clone, Default)]
pub struct Meta {
    pub title: String,
    pub prepared_for: String,
    pub prepared_on: String,
    /// One paragraph the operator writes. Empty is fine and prints nothing.
    pub summary: String,
}

/// How much of a body goes into a report.
///
/// A report is read by a person. Whole responses belong in the project file, which is the
/// thing handed over alongside it when somebody wants to check the work.
const EVIDENCE_BODY_MAX: usize = 4 * 1024;

/// Render the whole project as one Markdown document.
pub async fn markdown(project: &Project, meta: &Meta) -> Result<String, Error> {
    let findings = project.findings().await?;
    let mut out = String::new();

    let title = if meta.title.trim().is_empty() {
        "Security assessment"
    } else {
        meta.title.trim()
    };
    out.push_str(&format!("# {}\n\n", escape(title)));

    if !meta.prepared_for.trim().is_empty() {
        out.push_str(&format!(
            "Prepared for {}\n\n",
            escape(meta.prepared_for.trim())
        ));
    }
    if !meta.prepared_on.trim().is_empty() {
        out.push_str(&format!("{}\n\n", escape(meta.prepared_on.trim())));
    }
    if !meta.summary.trim().is_empty() {
        out.push_str(meta.summary.trim());
        out.push_str("\n\n");
    }

    out.push_str(&counts_table(&findings));

    if findings.is_empty() {
        // Said rather than left as an empty document. "No findings" and "this report was
        // generated before anything was written up" look identical on a blank page, and
        // they are very different things to hand somebody.
        out.push_str(
            "\nNo findings have been recorded in this project. That is not the same as a \
             target with nothing wrong with it.\n",
        );
        return Ok(out);
    }

    out.push_str("\n---\n\n");
    for (i, f) in findings.iter().enumerate() {
        // Each section already ends with a blank line, so the separator does not add
        // another one: three blank lines in a row is the sort of thing a reader notices
        // without being able to say why the document looks unfinished.
        out.push_str(render_finding(project, f, i + 1).await?.trim_end());
        out.push('\n');
        if i + 1 < findings.len() {
            out.push_str("\n---\n\n");
        }
    }
    Ok(out)
}

fn counts_table(findings: &[Finding]) -> String {
    let mut out = String::from("| Severity | Count |\n|---|---|\n");
    for sev in [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Info,
    ] {
        let n = findings.iter().filter(|f| f.severity == sev).count();
        // Every row, including the zeroes. A table that listed only what was found reads
        // as a table of what was looked for.
        out.push_str(&format!("| {} | {n} |\n", title_case(sev.as_str())));
    }
    out
}

async fn render_finding(project: &Project, f: &Finding, n: usize) -> Result<String, Error> {
    let mut out = String::new();
    out.push_str(&format!(
        "## {n}. {} ({})\n\n",
        escape(&f.title),
        title_case(f.severity.as_str())
    ));

    if !f.affected.trim().is_empty() {
        out.push_str(&format!("**Affected:** {}\n\n", escape(f.affected.trim())));
    }
    if !f.description.trim().is_empty() {
        out.push_str(&format!("{}\n\n", f.description.trim()));
    }
    if !f.repro.trim().is_empty() {
        out.push_str(&format!("### Reproduction\n\n{}\n\n", f.repro.trim()));
    }

    if f.evidence.is_empty() {
        // The absence is printed. A finding with no evidence is a claim, and a reader
        // should be able to tell which ones are which without counting code blocks.
        out.push_str("### Evidence\n\nNone recorded against this finding.\n\n");
    } else {
        out.push_str("### Evidence\n\n");
        for id in &f.evidence {
            out.push_str(&render_evidence(project, *id).await?);
        }
    }

    if !f.remediation.trim().is_empty() {
        out.push_str(&format!("### Remediation\n\n{}\n\n", f.remediation.trim()));
    }
    Ok(out)
}

async fn render_evidence(project: &Project, id: i64) -> Result<String, Error> {
    let Some(stored) = project.get(id).await? else {
        // A citation that does not resolve is printed as one. Eviction cannot cause this
        // (a cited exchange is not evictable) but a hand-deleted exchange can, and a
        // silently missing block would read as a finding with less evidence than it has.
        return Ok(format!(
            "Exchange {id} is cited by this finding and is no longer in the project.\n\n"
        ));
    };
    let ex = &stored.exchange;
    let mut out = String::new();
    out.push_str(&format!(
        "**{} {}**{}\n\n",
        escape(&ex.method),
        escape(&ex.url),
        match ex.status {
            Some(s) => format!(" returned {s}"),
            None => String::new(),
        }
    ));

    let mut req = format!("{} {} HTTP/1.1\n", ex.method, path_of(&ex.url));
    for [k, v] in &ex.req_headers {
        req.push_str(&format!("{k}: {v}\n"));
    }
    req.push('\n');
    req.push_str(&body_text(&ex.req_body));
    out.push_str(&fenced("http", &req));

    let mut resp = match ex.status {
        Some(s) => format!("HTTP/1.1 {s}\n"),
        None => String::new(),
    };
    for [k, v] in &ex.resp_headers {
        resp.push_str(&format!("{k}: {v}\n"));
    }
    resp.push('\n');
    resp.push_str(&body_text(&ex.resp_body));
    out.push_str(&fenced("http", &resp));
    Ok(out)
}

/// A body as a report shows it: bounded, and honest when it was cut or is not text.
fn body_text(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return String::new();
    }
    if crate::searchable_text(bytes).is_empty() {
        // The same test the index uses for "is there text here", so a body the project
        // declined to index is not one the report pretends to quote.
        return format!("[{} bytes, not text]\n", bytes.len());
    }
    let head = &bytes[..bytes.len().min(EVIDENCE_BODY_MAX)];
    let mut s = match std::str::from_utf8(head) {
        Ok(s) => s.to_string(),
        Err(e) => String::from_utf8_lossy(&head[..e.valid_up_to()]).into_owned(),
    };
    if bytes.len() > head.len() {
        s.push_str(&format!(
            "\n[cut here: {} of {} bytes shown]",
            head.len(),
            bytes.len()
        ));
    }
    s.push('\n');
    s
}

/// A fenced block whose fence is longer than anything inside it.
///
/// A response containing three backticks would otherwise close the block early and the
/// rest of it would render as prose, which is a report that silently reformats evidence.
fn fenced(lang: &str, body: &str) -> String {
    let longest = body
        .split(|c| c != '`')
        .map(|run| run.len())
        .max()
        .unwrap_or(0);
    let fence = "`".repeat(longest.max(2) + 1);
    format!("{fence}{lang}\n{}\n{fence}\n\n", body.trim_end())
}

/// Markdown characters that would otherwise turn a title into formatting.
///
/// Only the ones that bite in a heading or a table cell. Escaping everything would make a
/// URL unreadable, and a URL is the thing most often in these fields.
fn escape(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('|', "\\|")
        .replace('*', "\\*")
        .replace('_', "\\_")
        .replace('`', "\\`")
        .replace('\n', " ")
}

fn title_case(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
        None => String::new(),
    }
}

fn path_of(url: &str) -> String {
    match url.find("://") {
        Some(i) => match url[i + 3..].find('/') {
            Some(j) => url[i + 3 + j..].to_string(),
            None => "/".to_string(),
        },
        None => url.to_string(),
    }
}
