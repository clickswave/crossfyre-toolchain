# node

The node agent. This is the piece that turns a machine into a Crossfyre node: it
supervises the engine daemons, claims work, and talks to the platform. You do not run
this binary by hand. The OS service runs it, and you drive it through the
[`crossfyre`](../crossfyre/) CLI.

Part of the [Crossfyre toolchain](../).

## What it does

When you enrol a host, the node registers with the control plane, installs the engines
that host is meant to run, and keeps their daemons alive. From then on it pulls
operations (a crawl, a port scan, a vuln scan), hands each to the right engine, and
relays findings back. Everything is engine-local, so a node with the `ambulo` and
`doorward` daemons running can take that work whether or not it can reach anything else.

## Using it

Through the CLI:

```sh
crossfyre login
crossfyre node init      # register this host, install its engines, set up the service
crossfyre node up        # bring it online
crossfyre node status    # what is running locally
crossfyre node list      # your fleet, from the control plane
```

`node init` installs a systemd service (on Linux) whose job is to exec this binary's
`supervise` command. If you would rather run it in the foreground, `crossfyre node up`
falls back to a foreground supervisor when no service is installed.

## Notes

The node is only useful with an account and the platform. If you just want to run the
engines on one box, you do not need it: use `ambulo`, `voyage`, `doorward`, `toolmark` and
`plessor` directly.
