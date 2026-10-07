# Contributing to the Crossfyre Toolchain

Thanks for taking the time to contribute. This repo holds the open-source recon and scanning engines (`mach`, `voyage`, `pulse`, `scout`, `cortex`), the out-of-band server (`oast`), the node agent (`node`), and the `crossfyre` CLI.

## Ground rules

- Be respectful. We follow the standard expectation of professional, harassment-free conduct.
- Only contribute code you have the right to contribute. By opening a pull request, you agree your contribution is licensed under the same [Apache-2.0](LICENSE) terms as the project, and you sign each commit off as described below.

## Signing off

Every commit in a pull request from outside Clickswave Labs needs a `Signed-off-by:` line with your real name and the email you commit with. `git commit -s` adds it. The line certifies the [Developer Certificate of Origin 1.1](https://developercertificate.org/): that you wrote the change, or otherwise have the right to submit it under this project's licence, and that you understand it and your sign-off are recorded publicly. A pull request with a commit that is not signed off is not merged until it is; `git rebase --signoff dev` fixes a branch in one step.

## Reporting bugs

Open an issue and include:

- The tool and version (`mach --version`).
- The exact command you ran.
- What you expected, and what happened instead.
- Your OS and architecture.

For anything security-sensitive, do **not** open a public issue. See [SECURITY.md](SECURITY.md).

## Proposing changes

- For small fixes (typos, obvious bugs), a pull request is fine.
- For anything larger (new flags, new behavior, new sources), open an issue first so we can agree on the approach before you invest the work. It saves everyone time.

## Branching

Development happens on `dev`; `main` tracks the latest release. Branch your work off `dev` and open the pull request against `dev`, not `main`. Maintainers promote `dev` to `main` when a release is cut.

## Development

You need [rustup](https://rustup.rs). `rust-toolchain.toml` pins Rust 1.88.0, the version CI uses, and rustup installs it on first use; rustfmt's output differs between versions, so formatting on another one produces diffs CI rejects.

```sh
cargo build            # build the whole workspace
cargo test             # run the tests
cargo fmt              # format before you commit
cargo clippy           # lint; please keep it warning-clean
```

Run `scripts/install-hooks.sh` once per clone to enable the local git hooks (`core.hooksPath -> .githooks`). They run fast, dependency-free checks on push; on a public checkout they no-op cleanly.

Keep pull requests focused: one logical change per PR, with a clear description of what and why. Match the style of the surrounding code.

## What belongs here

This repo is the open toolchain: scanning and recon engines, plus the agent that runs them. Platform and orchestration features (scheduling, fleet management, the hosted dashboard) live in the Crossfyre platform, not here. If you are unsure whether something fits, open an issue and ask.
