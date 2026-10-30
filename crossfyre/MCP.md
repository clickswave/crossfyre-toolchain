# crossfyre mcp

`crossfyre mcp` serves `toolmark` and `plessor` to an MCP client over stdio. An agent can fingerprint a service, test endpoints for injection and replay single requests. It needs no account. With an MCP key it can also reach a Crossfyre Cloud workspace; see [Cloud](#cloud), which is not live yet. Tool calls are refused for any destination the scope file you write does not list; requests an engine makes on its own are covered under [Known limits](#known-limits).

It is in crossfyre 0.1.38 and later, and needs the `toolmark` and `plessor` released with it. An older engine daemon is refused before anything is sent, because it cannot be told to dial only the addresses the server checked or to leave redirects alone.

## Before you start

Install the engines and start the two daemons it uses:

```sh
crossfyre extension install toolmark
crossfyre extension install plessor
crossfyre extension start toolmark
crossfyre extension start plessor
```

No database is needed.

## The scope file

The server reads one file when it starts and never writes it. By default it is `<data-dir>/mcp/scope.toml`, which on Linux is `~/.config/crossfyre/mcp/scope.toml`. `crossfyre mcp` prints the path to stderr when it starts, and the `get_scope` tool shows it. `--scope-file` points somewhere else.

```toml
# Written by a person. crossfyre mcp reads this file when it starts and never writes it.
entries = ["app.example.com", "api.example.com:8443", "*.staging.example.com", "10.20.0.0/24"]
allow_writes = false                  # test_writes, and non-GET/HEAD/OPTIONS methods in send_http_request
allow_private = false                 # names that resolve to private, loopback or link-local addresses
max_concurrent_scans = 3              # 1..=10
max_scan_starts_per_hour = 20         # 1..=200
requests_per_second_per_host = 2      # 1..=20, for send_http_request and fingerprint
```

| Key | Meaning |
| --- | --- |
| `entries` | The destinations traffic may go to, in the same syntax as the [`scope`](../scope/) crate: a host, `host:port`, `*.domain` (subdomains only, not the domain itself), an address, or a range such as `10.0.0.0/24`. A wildcard covers every name under its base, so `*.co.uk` means every site under `.co.uk`. One whose base ends in a number, such as `*.0.0.1`, is refused, since it could only ever match addresses. |
| `allow_writes` | Lets `test_injection` use `test_writes` and `send_http_request` use methods other than GET, HEAD and OPTIONS. Each still needs a confirmation. |
| `allow_private` | Lets a name in `entries` reach a private, loopback or link-local address. An address you list yourself is always allowed. |
| `max_concurrent_scans`, `max_scan_starts_per_hour` | Caps on `test_injection`. |
| `requests_per_second_per_host` | Pace for `send_http_request` and `fingerprint`. |

The server refuses to start if an entry does not parse, a key is unknown, a number is out of range, or, on Linux and macOS, the file or its directory belongs to another user or can be written by its group or by everyone. A missing file, or one with no entries, starts the server with every traffic tool refusing until you write it. Changes take effect when the server restarts; `status` says when the file on disk no longer matches what was loaded.

Keep the file outside the project the agent works in, and deny the client edits to it. The scope guard covers only the traffic these tools send. It protects against a model's mistakes and against instructions planted in what it reads. It does not stop an agent that also has a shell or can write files: such an agent can edit the scope file, or leave this server out and run the engines, curl or anything else directly. Only the client's own permission settings limit that.

## Add it to your client

Claude Code:

```sh
claude mcp add crossfyre -- crossfyre mcp
claude mcp add crossfyre -- crossfyre mcp --scope-file /home/you/engagements/acme/scope.toml
```

or in `.mcp.json`:

```json
{ "mcpServers": { "crossfyre": { "command": "crossfyre", "args": ["mcp"] } } }
```

Cursor (`~/.cursor/mcp.json` or `.cursor/mcp.json`):

```json
{ "mcpServers": { "crossfyre": { "command": "crossfyre", "args": ["mcp"] } } }
```

VS Code (`.vscode/mcp.json`):

```json
{ "servers": { "crossfyre": { "type": "stdio", "command": "crossfyre", "args": ["mcp"] } } }
```

If the daemons require `CFX_DAEMON_TOKEN`, put it in the server's `env` in your user-level client config (for example `claude mcp add -e CFX_DAEMON_TOKEN=... crossfyre -- crossfyre mcp`, or `~/.cursor/mcp.json`), not in a project file you commit.

## Tools

| Tool | What it does | Sends traffic |
| --- | --- | --- |
| `status` | Version, the loaded scope and its hash, which daemons are listening, limits, recent refusals, and hints. | No |
| `get_scope` | The scope file's entries and settings, or how to write one. | No |
| `check_scope` | Whether URLs, hosts, `host:port` or ranges are in scope, and which entry admits them. | No |
| `fingerprint` | toolmark on one URL: technologies, CVE leads by version, title and server. | Yes |
| `test_injection` | plessor's injection pass on one URL or up to 100 endpoints on one origin. Returns a scan handle. | Yes |
| `send_http_request` | One request, with redirects followed only when asked. | Yes |
| `list_scans` | Scans, newest first. | No |
| `get_scan` | One scan's status, progress, counts and notes. | No |
| `list_findings` | Findings, oldest first, with a cursor that also follows a running scan. | No |
| `get_finding` | One finding with up to 32 KB of evidence. | No |
| `cancel_scan` | Stops a running scan. Says `stopped` when the engine confirmed it and `requested` when it could not. | No |

Scans are kept in `jobs/` next to the scope file. When the server starts, it removes all but the newest 200 finished ones. A scan still running when the server stops is marked `interrupted`.

## What it will not do

- Write or widen the scope. No tool takes a scope entry.
- Reach a private, loopback, link-local or cloud metadata address through a name, unless the file allows it. The engines are given the address the server checked for each name, so they do not look the name up again.
- Let an engine follow a redirect. `send_http_request` follows redirects only when asked, and then it checks every hop before sending to it.
- Run commands or take file paths.
- Return text from a target anywhere but under `target_data`, which is marked `"untrusted": true`. That text is stripped of terminal escapes, control characters and invisible or reordering characters, and capped.

Secrets in responses and evidence (authorization headers, bearer tokens, common key formats, and JSON members and multipart form parts whose names say they hold a password, token, key, secret or session) are masked in results. Cookie headers keep each cookie's name and lose its value, so `sid=[redacted]; theme=[redacted]` still shows that a session was there. `--no-redact` turns that off for results; the audit log is masked either way.

## Confirmations

The first time a tool would send traffic, the server asks you, through the client, to confirm that you are authorised to test everything in the scope file. It asks once per server process. If you say no, every later traffic call in that process is refused without asking again; restart the server to be asked again. If you dismiss the question, or leave it unanswered for two minutes, only that call is refused, and the next one asks again. A call cancelled while the question is open ends at once.

A write action needs `allow_writes` and a yes each time: every `test_injection` call with `test_writes`, and the first request with a write method to each host and port in `send_http_request`. A client that cannot show a confirmation gets the first-traffic check from the file alone, and is refused write actions.

`test_injection` tests POST endpoints without `test_writes`, as plessor always has, since POST is its main injection surface and what it creates is usually recoverable. Only PUT, PATCH and DELETE endpoints wait for `test_writes`. Leave POST endpoints out of the list if the target cannot take that.

## Audit log

Every tool call, refusals and malformed calls included, writes one line to `audit.jsonl` next to the scope file. A call still open when the server stops gets its line then, with `"decision":"interrupted"`. Each line carries the hash of the scope file the server loaded, so a line can be matched to the permission it was made under. Arguments are masked: URLs lose secret query and fragment values, header values are masked by name, and a request body is reduced to its length and hash.

```json
{"ts":"2026-10-30T09:12:44.512Z","event":"call","session":"m_5c1e0a9b2f","seq":7,"pid":4242,"client":"example-client 1.0","tool":"send_http_request","args":{"method":"GET","url":"https://evil.example/?token=%5Bredacted%5D"},"scope_sha256":"9f2c...","decision":"refused","reason":"out_of_scope","message":"Out of scope: evil.example:443. Nothing was sent. ...","refused":[{"host":"evil.example","port":443,"at":"tool_boundary"}],"confirmation":null,"scan_id":null,"result":null,"duration_ms":1}
```

The server also writes a `start` and a `stop` line, the `stop` line on Ctrl-C, SIGTERM and SIGHUP too. If a line cannot be written, traffic tools refuse until the server is restarted; the read-only tools keep working. Lines are plain JSON, so `tail` and `jq` read them.

## Cloud

**The Cloud side is not live yet.** The platform routes these tools call, the Agent access page that makes keys, and the approval page are not deployed, so there is nothing to log in to today. What follows describes the client, which is built and tested against a stand-in for the platform.

With an MCP key, the same `crossfyre mcp` also reaches one workspace on the platform: its scans, results, verdicts, assets and nodes, and, with a launch key, scans started on the workspace's nodes. Without a key nothing changes: the tool list, the results and the audit log are what they are above.

### Keys

As the platform is designed, a key is made in Settings, Agent access. It is `cfm_` and 32 hex characters, bound to one workspace, and expires after 7, 30 or 90 days. It is one of two kinds:

- read: scans, results, verdicts, assets, nodes and the scope;
- launch: also starts and stops scans on the workspace's nodes. Making one asks you to confirm that you are authorised to test every entry in the workspace's scope at that moment, and the key can launch only against those entries, as long as they stay in the scope. An entry added later needs confirming again.

A key is not your account's `cfk_` key, and neither works in place of the other. Changing your password revokes every MCP key you hold.

### Logging in

```sh
crossfyre mcp cloud login                 # asks for the key without echoing it
echo "$KEY" | crossfyre mcp cloud login   # or reads one line of stdin
crossfyre mcp cloud status                # what the platform says about the saved key
crossfyre mcp cloud logout --revoke       # revokes it, then removes the file
```

`login` asks the platform about the key first and saves it only if the platform accepts it. The key is never taken from the command line. It goes to `<data-dir>/mcp/cloud.toml` (or `--cloud-file`), next to the scope file, written with mode 0600. The origin is `--api-url`, else the one `crossfyre login` saved, else this build's. It must be `https`, except for `http://localhost`, `127.0.0.1` and `[::1]`.

`crossfyre mcp` reads the file when it starts. It starts without Cloud, and `status` says why, when the file belongs to another user, has any group or other permission bit, sits in a directory others can write, or names a plain `http` origin on another machine. `--no-cloud` serves without Cloud whatever is set up, and `--cloud-file PATH` reads another file.

When there is no file, `CROSSFYRE_MCP_CLOUD_KEY` is read instead, with `CROSSFYRE_MCP_CLOUD_URL` for the origin. Prefer the file: a key in an `env` block of a project's `.mcp.json` ends up in the repository sooner or later. The key goes nowhere but the `Authorization` header of requests to that origin. No redirect is followed. It is never in a tool's arguments or results, `status`, the audit log or stderr, which show at most `cfm_` and the next 8 characters.

### What the agent gets

With a read key, the shared tools take Cloud ids as well as local ones, and four tools are added: 15 in all. A launch key adds six more: 21. If the platform refuses the key, at start or later in the session, the Cloud tools are withdrawn, and a client that already has the list is told it changed.

| Tool | With a Cloud key |
| --- | --- |
| `status` | Gains a `cloud` object: state, API host, key prefix, permission, workspace, expiry, approval policy and whether a phone is registered. |
| `get_scope` | Gains the workspace's entries, the entries a launch may target, and whether the scope file narrows them. |
| `check_scope` | Adds the platform's answer for each target and `cloud_launch_allowed`, which also needs the scope file to admit it when the file has entries. `kind: zone` checks a recon domain. |
| `list_scans` | Both backends merged newest first, or one with `backend`. Each row says its backend. |
| `get_scan` | Also `cs_` (a Cloud scan, with progress) and `ap_` (a launch waiting for approval). |
| `list_findings` | Also a Cloud scan's results (`cs_`), or the workspace's verdicts with `backend: cloud`. |
| `get_finding` | Also `cf_` (a result) and `cv_` (a verdict). |
| `cancel_scan` | Also `cs_` (stops a scan the key's owner started; needs a launch key) and `ap_` (withdraws a launch still waiting for approval). |
| `whoami` | The key's prefix, permission and expiry, its workspace, plan limits, approval policy and scope counts. |
| `list_nodes`, `list_assets`, `get_asset` | The workspace's nodes (never their addresses), assets (`ca_`) and one asset in full. |
| `start_recon`, `start_port_scan`, `start_crawl`, `start_content_discovery`, `start_vuln_scan`, `start_authz_scan` | Launch key only. Targets, node ids (`cn_`) and a few options per type. Everything else is fixed by the platform. |

Local ids are `s_` and `f_` with 10 hex characters and never leave this machine. Cloud ids are a prefix and 32 hex characters: `cs_` scan, `cf_` result, `cv_` verdict, `ca_` asset, `cn_` node, `ap_` approval. A tool given an id of the wrong kind refuses it before anything is sent.

### Scope for Cloud launches

The platform admits a launch only against the workspace scope entries the key's owner confirmed that are still in the workspace's scope. That check is the one that counts.

When the scope file has entries, `crossfyre mcp` also holds every launch to them before it sends anything, and refuses with `out_of_local_scope`, naming each target, when one is not admitted. It can only narrow what the platform would allow, never widen it. Targets are judged as the platform judges them: a URL by its host and port; a port scan's host or address by an entry that covers every port on it (a `host:port` entry is not one), and its range by one entry that contains all of it; a recon domain by an entry for the domain, or for active recon by a `*.` entry over it. Names are not looked up here: the nodes resolve them. When the file is missing or has no entries, it does not narrow Cloud launches, and `get_scope` says so.

### Confirmation and approval

The first launch in a server process asks you to confirm that you are authorised to test everything the key may launch against, with the list shown. A no holds until the server restarts. A client that cannot show a form proceeds on the confirmation you gave when the key was made, and the audit log records `key_attestation`.

A workspace can hold launches for a person. Then the launch call waits, up to 100 seconds or the approval's 10 minute expiry, whichever is sooner:

- If you have a phone registered in the Crossfyre app, only the phone can approve. The call waits and reports which phone it is waiting on.
- If you have none and the workspace allows it, you are asked in the agent's client: sent to the approval page when the client can open a URL, or shown what would start in a form (type, targets, node count and every option, with the recon mode always named), whose answer is sent as your decision. The platform records that the decision came from the agent's client, since a client can be set to answer on its own.
- Otherwise the call returns an `ap_` handle and the approval page. `get_scan` on the handle says whether it is still waiting, was denied or expired, failed to start, or became a `cs_` scan.

The platform launches the request it stored, so nothing the agent sends after asking can change what is approved. When the workspace holds every launch, the approval replaces the confirmation question.

### Long scans

A `start_*` call returns at once with a `cs_` handle, or after `wait_seconds` (up to 50), reporting progress while it waits. `get_scan` says how long to wait before asking again, 10, 20, 40 and then 60 seconds. `list_findings` with a `cs_` scan and the last `next_cursor` returns only what the scan recorded since. Cancelling the call stops the waiting, not the scan; `cancel_scan` stops the scan. Once the platform has made a launch, a request in the same call that then fails does not hide it: the call returns the `cs_` or `ap_` handle as last seen, with `cloud_error` saying what failed. When `scans/start` itself gets no answer, the refusal says the launch may have been made and `list_scans` shows it.

### What comes back

The platform is ours, but most of what it holds was written by someone else. Ids, severities, statuses, kinds, timestamps, hosts and URLs reach the top of a result only when they pass a check a sentence cannot: a known word, a parsed time, a name that parses as a host. Anything a scanned system or an engine wrote goes under `target_data`, marked untrusted, stripped and capped like local findings, and masked unless `--no-redact`. Names written by people in the workspace (scan names, node names, scope notes) go under `workspace_text`.

### Audit

With a key set up, each line also carries `backend` (`local`, `cloud` or `both`), `key_prefix`, `workspace_id`, `cloud_call_id` (the platform's record of the request, for matching the two logs) and `approval_id`. `confirmation` can also be `key_attestation`, `approval:phone`, `approval:dashboard` or `approval:agent_client`.

## Known limits

- `fingerprint` and `test_injection` run the engines with redirects off and each name pinned to the address the server checked. An endpoint that answers with a redirect is tested on the redirect response itself.
- If the plessor daemon has an OAST endpoint configured (`PLESSOR_OAST_DOMAIN` and `PLESSOR_OAST_API_URL` in its environment), `test_injection` registers with and polls that endpoint, and blind payloads ask the target to call it. Neither host has to be in the scope file.
- A request to a name never goes through a proxy, since the proxy would look the name up again: `HTTP(S)_PROXY` and `CROSSFYRE_EGRESS_PROXY` are not used for it. A destination the scope file lists as an address can still be reached through one of them, from wherever that proxy runs. `status` reports `egress_proxy: true` when one is set.
- The scan caps are counted across every `crossfyre mcp` process that shares the scope file's directory, but each process checks them under its own lock, so two processes can both start a scan in the last free slot.
- A client can be set to answer confirmations on its own. The scope file is the real gate.
- Redaction matches names and known formats, not meaning. A secret with an ordinary name in an ordinary format is not masked.
- Cloud: the platform checks each launch's targets. Requests an engine makes on its own (recon's active pass, takeover probes, redirects, follow-ups to other entries in the workspace scope) are fenced only where that engine fences them. A Cloud crawl is pinned to its target's host.
- Cloud: an approval reaches a phone only while the app is open or polling. The approval page works whenever you are signed in.
