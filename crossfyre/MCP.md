# crossfyre mcp

`crossfyre mcp` serves `toolmark` and `plessor` to an MCP client over stdio. An agent can fingerprint a service, test endpoints for injection and replay single requests. It needs no account. Tool calls are refused for any destination the scope file you write does not list; requests an engine makes on its own are covered under [Known limits](#known-limits).

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

Secrets in responses and evidence (authorization and cookie headers, bearer tokens, common key formats) are masked in results. `--no-redact` turns that off for results; the audit log is masked either way.

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

## Known limits

- `fingerprint` and `test_injection` run the engines with redirects off and each name pinned to the address the server checked. An endpoint that answers with a redirect is tested on the redirect response itself.
- If the plessor daemon has an OAST endpoint configured (`PLESSOR_OAST_DOMAIN` and `PLESSOR_OAST_API_URL` in its environment), `test_injection` registers with and polls that endpoint, and blind payloads ask the target to call it. Neither host has to be in the scope file.
- A request to a name never goes through a proxy, since the proxy would look the name up again: `HTTP(S)_PROXY` and `CROSSFYRE_EGRESS_PROXY` are not used for it. A destination the scope file lists as an address can still be reached through one of them, from wherever that proxy runs. `status` reports `egress_proxy: true` when one is set.
- The scan caps are counted across every `crossfyre mcp` process that shares the scope file's directory, but each process checks them under its own lock, so two processes can both start a scan in the last free slot.
- A client can be set to answer confirmations on its own. The scope file is the real gate.
- Redaction matches names and known formats, not meaning. A secret with an ordinary name in an ordinary format is not masked.
