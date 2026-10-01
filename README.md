<div align="center">

<a href="https://crossfyre.io"><img src="https://crossfyre.io/og/default.png" alt="Crossfyre" width="100%"></a>

# Crossfyre Toolchain

### Five standalone reconnaissance and scanning engines for offensive security, written in Rust.

`voyage` enumerates subdomains, `pulse` scans hosts and ports, `mach` does content discovery, `scout` fingerprints services and `cortex` tests for vulnerabilities. Run them on their own from the terminal, or connect them to the [Crossfyre platform](https://crossfyre.io) when one machine isn't enough.

[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-1f6feb.svg)](LICENSE)
[![Made with Rust](https://img.shields.io/badge/made%20with-Rust-b7410e.svg)](https://www.rust-lang.org)
![Platforms](https://img.shields.io/badge/platforms-Linux%20%C2%B7%20macOS%20%C2%B7%20Windows-444.svg)
[![Discord](https://img.shields.io/badge/discord-join-5865F2.svg)](https://discord.gg/cPccst2Vr6)

</div>

---

The Crossfyre toolchain is a set of standalone reconnaissance and scanning engines plus a lightweight node agent. **Every tool here works on its own.** There is no account to sign up for, and nothing leaves your machine unless you connect it to the platform yourself. When you outgrow a single box, the same engines plug into the hosted platform for fleet-wide, scheduled, resumable scans.

## Highlights

- **Standalone first.** Use `mach`, `voyage`, and `pulse` like any other CLI. Nothing phones home unless you ask it to.
- **Stateful and resumable.** Findings are written as they're discovered, so a scan you stop picks up exactly where it left off.
- **Live in the terminal.** Every engine shares one terminal dashboard: progress, hits and throughput as they happen, the same keys and layout across all of them. The scan tools show it by default; the daemon tools take `--tui`.
- **One coherent CLI.** `crossfyre` installs the engines, runs scans, and manages nodes from a single command.
- **Scales when you do.** Enrol a host as a node and the same engines run distributed under the optional [platform](https://crossfyre.io).

## What's inside

| Tool | What it does |
| --- | --- |
| [**`mach`**](mach/) | HTTP fuzzing and content-discovery engine. Stateful and resumable. |
| [**`voyage`**](voyage/) | Subdomain enumeration engine: passive sources plus active wordlist brute-forcing. |
| [**`pulse`**](pulse/) | Host and port-scanning engine (connect and SYN techniques, service detection). |
| [**`scout`**](scout/) | Service enumeration and web fingerprinting engine: identifies technologies and versions, and flags version-based CVE leads. |
| [**`cortex`**](cortex/) | Vulnerability-scanning engine: a nuclei-compatible template and matcher pipeline with active fuzzing and out-of-band confirmation, so every finding is verified before it is reported. |
| [**`oast`**](oast/) | Out-of-band interaction server. Run your own so `cortex` can confirm blind bugs (SSRF, blind RCE) against your own domain instead of the hosted pool. |
| [**`node`**](node/) | The Crossfyre node agent. Runs the engines on your machine and, optionally, connects to the platform. |
| [**`crossfyre`**](crossfyre/) | The CLI that ties it together: install engines, run scans, manage nodes. |

Also in the workspace: **`adaptive`**, an open reference library the engines use to pace themselves and decide retries. It ships an untuned baseline; the tuned pacing is a platform feature (see [`adaptive/README.md`](adaptive/README.md)).

## Quick start

### Install

Linux and macOS:

```sh
curl -fsSL https://get.crossfyre.io/install.sh | sudo bash
```

Windows (PowerShell):

```powershell
irm https://get.crossfyre.io/install.ps1 | iex
```

Prebuilt binaries for each release are on the [Releases](../../releases) page, or [build from source](#building-from-source).

### Run something

```sh
# Content discovery: fuzz a path with a wordlist
mach scan --url https://example.com/::FUZZ:: --wordlist-path ./wordlist.txt

# Subdomain enumeration: passive sources + active brute-force
voyage scan --domain example.com --wordlist-path ./subdomains.txt

# Port scan a network range, with service detection
pulse scan --targets 10.0.0.0/24 --ports top-1000 --service-detection
```

Every engine is a daemon plus a client: start it with `--daemon` and the client subcommands talk to it over loopback. All five take `scan` for a run you drive and `exec` for a raw JSON op, and `mach`, `voyage` and `pulse` keep findings in a local store, so a run you interrupt can be resumed.

Output is newline-delimited JSON, one event per line, each carrying a `type`. A dashboard is drawn instead when stdout is a terminal: on by default for `mach`, `voyage` and `pulse`, where a run is long enough to want progress, and on `--tui` for `scout` and `cortex`. Either way, redirecting or piping gives you the JSON, and `--no-tui` forces it in a terminal. A run that ends in a `type: "error"` event exits non-zero, so a script can read `$?` without parsing the stream.

### The daemon boundary

The daemons speak unauthenticated newline-delimited JSON with no session or handshake, so **the bind address is the security boundary**. They listen on loopback only, which is all the node needs, and two environment variables move that:

| Variable | Effect |
|---|---|
| `CFX_DAEMON_BIND` | Binds the listener to this IP instead of loopback. A value that is not an IP falls back to loopback rather than widening the listener. |
| `CFX_DAEMON_TOKEN` | Requires a matching token on every request. Set it on the daemon and on anything that talks to it; the clients and the node read the same variable and stamp it automatically. |

Binding off loopback without a token is allowed, for operators who have put the port behind a firewall, but it is announced on every start. `mach`'s wordlist parameter is a filesystem path, so an exposed daemon is also a file-read primitive: if you move the listener, set the token.

## Standalone, or part of the platform

Run them on systems you are authorized to test, from any terminal.

When you need more than one machine can give you (a fleet of nodes, scheduled recurring scans, adaptive rate limiting that paces each scan to what the target can take, a shared findings dashboard), enrol the host as a node and the same engines run under the [Crossfyre platform](https://crossfyre.io):

```sh
crossfyre login
crossfyre node init
crossfyre node list
```

The platform is optional. The tools never require it, and nothing here reports back unless you connect it yourself.

## Building from source

You need a recent stable [Rust toolchain](https://rustup.rs).

```sh
git clone https://github.com/clickswave/crossfyre-toolchain.git
cd crossfyre-toolchain
cargo build --release
# binaries land in ./target/release/{crossfyre,node,mach,voyage,pulse,scout,cortex}
```

Install a single engine straight from the repo:

```sh
cargo install --git https://github.com/clickswave/crossfyre-toolchain.git mach
```

## Responsible use

These are offensive-security tools. **Only scan systems you own or have explicit, written permission to test.** Unauthorized scanning is illegal in most jurisdictions and can disrupt the systems you point it at. How you use them is on you.

## Contributing

Issues and pull requests are welcome. Open pull requests against the `dev` branch: that is where development happens, and `main` tracks the latest release. For a bug, include the tool, the exact command, and what you expected. For larger changes, open an issue first so we can agree on the approach before you invest the work. See [CONTRIBUTING.md](CONTRIBUTING.md).

Found a security issue? Please don't open a public issue. See [SECURITY.md](SECURITY.md) or email **team@clickswave.org**.

## License

Licensed under the [Apache License, Version 2.0](LICENSE). Use, modify, and distribute freely, including commercially, subject to the license terms.

---

<div align="center">
Built by <a href="https://clickswave.org">Clickswave</a> · The platform lives at <a href="https://crossfyre.io">crossfyre.io</a>
</div>
