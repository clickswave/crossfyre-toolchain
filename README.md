<div align="center">

<a href="https://crossfyre.io"><img src="https://crossfyre.io/og/default.png" alt="Crossfyre" width="100%"></a>

# Crossfyre Toolchain

### Five standalone recon and vulnerability scanning engines, written in Rust, for systems you are authorized to test.

`voyage` enumerates subdomains, `doorward` scans hosts and ports, `ambulo` does content discovery, `toolmark` fingerprints services and `plessor` tests for vulnerabilities. Run them on their own from the terminal, or connect them to the [Crossfyre platform](https://crossfyre.io) when one machine isn't enough.

[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-1f6feb.svg)](LICENSE)
[![Made with Rust](https://img.shields.io/badge/made%20with-Rust-b7410e.svg)](https://www.rust-lang.org)
![Platform](https://img.shields.io/badge/platform-Linux-444.svg)
[![Discord](https://img.shields.io/badge/discord-join-5865F2.svg)](https://discord.gg/cPccst2Vr6)

</div>

---

The Crossfyre toolchain is a set of standalone reconnaissance and scanning engines plus a lightweight node agent. **Every tool here works on its own.** There is no account to sign up for, and nothing leaves your machine unless you connect it to the platform yourself. When you outgrow a single box, the same engines plug into the hosted platform for fleet-wide, scheduled, resumable scans.

## Highlights

- **Standalone first.** Use `ambulo`, `voyage`, and `doorward` like any other CLI. Nothing phones home unless you ask it to.
- **Stateful and resumable.** Findings are written as they're discovered, so a scan you stop picks up exactly where it left off.
- **Live in the terminal.** Every engine shares one terminal dashboard: progress, hits and throughput as they happen, the same keys and layout across all of them. The scan tools show it by default; the daemon tools take `--tui`.
- **One coherent CLI.** `crossfyre` installs the engines, runs scans, and manages nodes from a single command.
- **Scales when you do.** Enrol a host as a node and the same engines run distributed under the optional [platform](https://crossfyre.io).

## What's inside

| Tool | What it does |
| --- | --- |
| [**`ambulo`**](ambulo/) | HTTP fuzzing and content-discovery engine. Stateful and resumable. |
| [**`voyage`**](voyage/) | Subdomain enumeration engine: passive sources plus active wordlist brute-forcing. |
| [**`doorward`**](doorward/) | Host and port-scanning engine (connect and SYN techniques, service detection). |
| [**`toolmark`**](toolmark/) | Service enumeration and web fingerprinting engine: identifies technologies and versions, and flags version-based CVE leads. |
| [**`plessor`**](plessor/) | Vulnerability-scanning engine: a nuclei-compatible template and matcher pipeline with active fuzzing and out-of-band confirmation, so every finding is verified before it is reported. |
| [**`oast`**](oast/) | Out-of-band interaction server. Run your own so `plessor` can confirm blind bugs (SSRF, blind RCE) against your own domain instead of the hosted pool. |
| [**`node`**](node/) | The Crossfyre node agent. Runs the engines on your machine and, optionally, connects to the platform. |
| [**`crossfyre`**](crossfyre/) | The CLI that ties it together: installs the engines, manages nodes, runs `.cfx` scripts, and runs the Web Tracer's local capture proxy (`crossfyre trace`). |
| [**`cfx-script`**](cfx-script/) | Runs one `.cfx` script in an embedded Python interpreter, for `node` and `crossfyre`. It is a binary of its own so that neither of them links libpython. |
| [**`mobile`**](mobile/) | An Android app that inspects the device's own HTTPS traffic through a `VpnService`, without root, and its native core in `mobile/rust`. |
| [**`relsign`**](relsign/) | Signs the release manifest. A tool for the machine that builds releases: it is not shipped and not listed in the manifest. |

The libraries they share:

| Crate | What it does |
| --- | --- |
| [**`core`**](core/) | Code `crossfyre` and `node` share: signing in, installing and updating the engines, checking the release manifest's signature, the node service, and the Web Tracer. |
| [**`capture`**](capture/) | The Web Tracer's capture core, used by the desktop proxy and the Android app: a session CA that issues a certificate per host, forwarding, and a redacted shape of each request. |
| [**`tui`**](tui/) | The terminal dashboard every engine draws. |
| [**`finding`**](finding/) | The one shape every engine reports a finding in. |
| [**`transport`**](transport/) | The outbound HTTP client the engines use, reqwest with rustls. The optional `impersonate` feature swaps in a client that presents a browser's TLS and HTTP/2 fingerprint. |
| [**`dguard`**](dguard/) | Listener policy for the engine daemons: loopback unless told otherwise, and an optional token (see [The daemon boundary](#the-daemon-boundary)). |
| [**`scope`**](scope/) | The destinations an operator has said they may test, and the guard that refuses everything else. |
| [**`spec`**](spec/) | Reads OpenAPI, Swagger, Postman, HAR and Insomnia files into a flat list of operations and their request shapes. |
| [**`surface`**](surface/) | Turns what a scan saw into a stable description of the attack surface: hosts, endpoint templates, content hashes and typed diffs. |

Also in the workspace: **`adaptive`**, an open reference library the engines use to pace themselves and decide retries. It ships an untuned baseline; the tuned pacing is a platform feature (see [`adaptive/README.md`](adaptive/README.md)).

## Renamed in 0.1.31

Four engines took new names in 0.1.31:

| Now | Before |
|---|---|
| `ambulo` | `mach` |
| `doorward` | `pulse` |
| `toolmark` | `scout` |
| `plessor` | `cortex` |

The first `crossfyre update` or `crossfyre node init` after upgrading moves an existing install over: it stops the old service, moves the binary and any systemd drop-in directory, and starts the service under the new name. 0.1.31 and 0.1.32 also left a link under each old name, so the old commands kept running the engines. 0.1.33 makes no link and removes the ones those releases left, so `mach`, `pulse`, `scout` and `cortex` are no longer commands. The old environment variables (`CORTEX_OAST_DOMAIN`, `MACH_BROWSER` and the rest) still work, with a notice naming the new one, and `crossfyre extension install cortex` keeps working for good.

The old names stay where a value is stored or sent between a node and the platform, because they are identifiers rather than names: the engine ids, a finding's `source` (`mach`, `scout`, `scout-cve`, `scout-services`), finding tool ids such as `cortex-inject`, template ids such as `cortex:waf-challenge`, and the local scan databases `mach` and `pulse`.

## Quick start

### Install

On Linux, x86_64 or aarch64:

```sh
curl -fsSL https://get.crossfyre.io/install.sh | sudo bash
```

On Debian, Ubuntu or Kali, you can install from the apt repository instead:

```sh
curl -fsSLO https://bins.crossfyre.io/apt/crossfyre-archive-keyring.gpg
echo "5dd16a4067070a7763afe58deb829c5129618af9ac3bc096637345b6f43cc020  crossfyre-archive-keyring.gpg" | sha256sum -c - && sudo tee /usr/share/keyrings/crossfyre-archive-keyring.gpg < crossfyre-archive-keyring.gpg > /dev/null
sudo tee /etc/apt/sources.list.d/crossfyre.sources > /dev/null <<'EOF'
Types: deb
URIs: https://bins.crossfyre.io/apt
Suites: stable
Components: main
Signed-By: /usr/share/keyrings/crossfyre-archive-keyring.gpg
EOF
sudo apt update
sudo apt install crossfyre crossfyre-archive-keyring
```

The keyring is installed only if its SHA-256 matches. It holds one key, fingerprint
`992F106C6CF032E43A3CA8BED5D92DAC3BA8CDBF`, which `gpg --show-keys` prints.

The archive key's fingerprint is `992F 106C 6CF0 32E4 3A3C A8BE D5D9 2DAC 3BA8 CDBF`. From then on, `sudo apt update && sudo apt upgrade` updates the CLI, and `crossfyre update all` updates the node and the engines. [crossfyre.io/docs/install](https://crossfyre.io/docs/install) also covers the standalone .deb, checking signatures, and removal.

No macOS or Windows build is published. On Windows, run `wsl --install` and then the installer inside WSL 2. On a Mac, install on a Linux host or a Linux virtual machine instead.

The installer and `bins.crossfyre.io` ship the first-party build. The [Releases](../../releases) page of this repository carries the open build for Linux x86_64 and aarch64, compiled by GitHub Actions from each tag. The open build has no authorization oracle, no per-node egress isolation, untuned pacing, and no `impersonate` feature (see [`transport`](transport/)). You can also [build from source](#building-from-source), which gives you the open build too.

### Run something

```sh
# Content discovery: fuzz a path with a wordlist
ambulo scan --url https://example.com/::FUZZ:: --wordlist-path ./wordlist.txt

# Subdomain enumeration: passive sources + active brute-force
voyage scan --domain example.com --wordlist-path ./subdomains.txt

# Port scan a network range, with service detection
doorward scan --targets 10.0.0.0/24 --ports top-1000 --service-detection
```

Every engine is a daemon plus a client: start it with `--daemon` and the client subcommands talk to it over loopback. All five take `scan` for a run you drive and `exec` for a raw JSON op, and `ambulo`, `voyage` and `doorward` keep findings in a local store, so a run you interrupt can be resumed.

Output is newline-delimited JSON, one event per line, each carrying a `type`. A dashboard is drawn instead when stdout is a terminal: on by default for `ambulo`, `voyage` and `doorward`, where a run is long enough to want progress, and on `--tui` for `toolmark` and `plessor`. Either way, redirecting or piping gives you the JSON, and `--no-tui` forces it in a terminal. A run that ends in a `type: "error"` event exits non-zero, so a script can read `$?` without parsing the stream.

### The daemon boundary

The daemons speak unauthenticated newline-delimited JSON with no session or handshake, so **the bind address is the security boundary**. They listen on loopback only, which is all the node needs, and two environment variables move that:

| Variable | Effect |
|---|---|
| `CFX_DAEMON_BIND` | Binds the listener to this IP instead of loopback. A value that is not an IP falls back to loopback rather than widening the listener. |
| `CFX_DAEMON_TOKEN` | Requires a matching token on every request. Set it on the daemon and on anything that talks to it; the clients and the node read the same variable and stamp it automatically. |

Binding off loopback without a token is allowed, for operators who have put the port behind a firewall, but it is announced on every start. `ambulo`'s wordlist parameter is a filesystem path, so an exposed daemon is also a file-read primitive: if you move the listener, set the token.

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
# binaries land in ./target/release/{crossfyre,node,ambulo,voyage,doorward,toolmark,plessor}
```

Install a single engine straight from the repo:

```sh
cargo install --git https://github.com/clickswave/crossfyre-toolchain.git ambulo
```

Both give you the open build, the one the [Releases](../../releases) page carries. The authorization oracle, the egress isolation and the tuned pacing are not in this repository, and the `impersonate` feature is off unless you build with it.

## Responsible use

These are security testing tools. **Only scan systems you own or have explicit, written permission to test.** Unauthorized scanning is illegal in most jurisdictions and can disrupt the systems you point it at. How you use them is on you.

## Contributing

Issues and pull requests are welcome. Open pull requests against the `dev` branch: that is where development happens, and `main` tracks the latest release. For a bug, include the tool, the exact command, and what you expected. For larger changes, open an issue first so we can agree on the approach before you invest the work. See [CONTRIBUTING.md](CONTRIBUTING.md).

Found a security issue? Please don't open a public issue. See [SECURITY.md](SECURITY.md) or email **team@clickswave.org**.

## License

Licensed under the [Apache License, Version 2.0](LICENSE). Use, modify, and distribute freely, including commercially, subject to the license terms.

---

<div align="center">
Built by <a href="https://clickswave.org">Clickswave</a> · The platform lives at <a href="https://crossfyre.io">crossfyre.io</a>
</div>
