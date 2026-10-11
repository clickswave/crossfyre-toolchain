# Plessor templates

Detection templates the plessor engine loads at run time, on top of the checks built
into the binary. The format is a practical subset of the nuclei schema, so many
existing nuclei templates work here unchanged.

Point plessor at this folder with `PLESSOR_TEMPLATES_DIR`. It reads the folder
recursively, so the subdirectories below are just categories.

## Categories

| Folder | What it holds |
|---|---|
| `technologies/` | Passive fingerprints for web tech, frameworks, servers, and CDNs (WordPress, Django, Laravel, Spring Boot, Jenkins, GitLab, Grafana, nginx, IIS, and so on). |
| `exposures/` | Sensitive files left web-readable (.git/HEAD, .npmrc, .htpasswd, Dockerfile, docker-compose, Spring actuator env and heapdump, backups). |
| `misconfigurations/` | Insecure defaults and exposed services (CORS reflection, open redirect, unauthenticated Elasticsearch, Docker registry, Kubernetes, Prometheus). |
| `panels/` | Reachable admin and login consoles (Tomcat Manager, Adminer, Swagger UI, Keycloak, Portainer). |
| `default-logins/` | Well-known default credentials being accepted (Tomcat Manager, Grafana admin/admin). |
| `vulnerabilities/` | Active probes for injection and logic flaws (SQLi, XXE, SSRF, command injection, reflected XSS, SSTI, CRLF, cloud-metadata SSRF, mass assignment, JWT alg:none). |
| `cves/` | Specific known CVEs, detected without running a destructive payload. |

## Adding a template

Drop a `.yaml` file into the category folder it fits, and give it a unique `id`.
plessor picks it up the next time it starts. A file that fails to parse, or uses a
feature plessor does not support, is skipped without breaking the rest.

## Writing good templates

A few rules keep templates useful instead of noisy:

- Confirm before you fire. plessor re-issues every response-based match once and needs
  the same result twice before it reports, so avoid matchers that depend on one-off
  state.
- Combine signals. Use `matchers-condition: and` with a content match plus a `status`
  (and a header where you can). A single loose `word` is the usual cause of false
  positives. Matching only "PHP Version", for example, flags a blog post about PHP.
- Match what the target actually sends: real header names and values, real body
  strings, real error text, not guesses that look plausible.
- Set severity by impact, not by how interesting it sounds. A fingerprint is `info`.
  A readable private key or heap dump is `critical`.
- Prove active findings with a unique marker. XSS, SSTI, and CRLF probes echo a
  distinctive token (`cxss7h9k`, `cxk1337`, `cxcrlf9k2`) so a hit cannot be chance.

## Supported subset

Templates may use:

- `http[].method`, `http[].path` (with `{{BaseURL}}`, `{{RootURL}}`, `{{Hostname}}`),
  `headers`, `body`, `payloads` with `attack`, and `matchers-condition`.
- matcher `type`: `status`, `word`, `regex`, `dsl`, `size`.
- matcher `part`: `body`, `header` or `all_headers`, `all` or `raw` or `response`.
- out-of-band via `{{interactsh-url}}`, when an OAST endpoint is set (see the
  [plessor README](../README.md)).
- `unsafe: true` on an http entry sends the request path exactly as written, so `.`
  and `%2e` sequences are not collapsed before the request goes out. Path-traversal
  checks need this, because the bypass depends on the target resolving the path, not
  the client.

Extractors, matcher types or parts not in the lists above, and multi-document files
are not loaded. `info.tags`, `info.metadata`, and `info.classification` are kept for
readability and ignored when running.
