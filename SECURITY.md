# Security Policy

## Reporting a vulnerability

If you find a security issue in any of the Crossfyre toolchain tools, please report it privately. Do **not** open a public GitHub issue, and do not disclose it publicly until we have had a chance to fix it.

Email **team@clickswave.org** with:

- The tool and version affected.
- A description of the issue and its impact.
- Steps to reproduce, or a proof of concept if you have one.

We will acknowledge your report, keep you updated on the fix, and credit you once a patch is released (unless you prefer to remain anonymous).

## Scope

This policy covers the code in this repository: the recon and scanning engines (`mach`, `voyage`, `pulse`, `scout`, `cortex`), the out-of-band server (`oast`), the node agent (`node`), and the `crossfyre` CLI. For issues in the hosted Crossfyre platform, use the same address and say so in your report.

One deployment note, so reports land on the right thing. Each engine daemon speaks unauthenticated JSON over TCP and binds loopback by default; `CFX_DAEMON_BIND` moves it and `CFX_DAEMON_TOKEN` requires a shared secret. A daemon deliberately bound to a public interface without a token is a configuration choice, announced on every start, and not a finding on its own. A way to reach a loopback-bound daemon from off-host, or to bypass the token when one is set, is.

## A note on responsible use

These are offensive-security tools. Running them against systems you do not own or have explicit written authorization to test may be illegal. Reports that amount to "this tool can scan things" are not vulnerabilities. We are interested in flaws in the tools themselves: memory safety, credential handling, unexpected outbound connections, and similar.
