# crossfyre

The command-line front end for the whole toolchain. It installs and updates the
engines, logs you in, enrols and manages nodes, runs scripts, and sets up a
self-hosted OAST server. If you only ever run one binary from this repo, it is this
one.

Part of the [Crossfyre toolchain](../).

## Common commands

```sh
crossfyre login                 # sign in to your account (api key, password, or browser)
crossfyre node init             # register this host as a node
crossfyre node up / down        # bring the node online / offline

crossfyre extension list        # engines and their daemon health
crossfyre extension install plessor
crossfyre update                # update the CLI and installed engines from the release manifest

crossfyre status                # overview: daemons, engines, database
crossfyre doctor                # check the environment for common problems
```

## Running scripts

`crossfyre run` executes a `.cfx` script locally, no control plane involved. Targets
are passed as `type:value`:

```sh
crossfyre run recon.cfx domain:example.com
```

## Self-hosting OAST

`crossfyre oast` stands up your own out-of-band server (see [`oast`](../oast/)):

```sh
sudo crossfyre oast setup --domain oob.yourdomain.com --email you@yourdomain.com
crossfyre oast status
```

## Notes

Most management commands need an account (`crossfyre login`). The exceptions are the
things that make sense on their own: `run`, `oast`, `doctor`, and cleanup. Run
`crossfyre --help` or `crossfyre <command> --help` for the details.
