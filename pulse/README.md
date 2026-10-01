# pulse

Host and port scanning. Give it targets (IPs, ranges, CIDRs) and a set of ports, and
it tells you what is open. It can do a plain connect scan or a SYN scan, and it can go
a step further and try to detect the service and OS behind an open port.

Part of the [Crossfyre toolchain](../). Runs standalone.

## Usage

```sh
# scan a range for the top ports, with service detection
pulse scan --targets 10.0.0.0/24 --ports top-1000 --service-detection

# specific hosts and ports
pulse scan -t 10.0.0.5 10.0.0.6 -p 22,80,443,8080

# pick the technique explicitly
pulse scan -t 192.168.1.0/24 -p top-100 --technique syn
```

SYN scanning needs raw-socket privileges, so run it with sudo (or the right
capability) when you use `--technique syn`.

For scripted single probes, `exec` takes a JSON payload and runs it through the
daemon.

The dashboard is on by default when stdout is a terminal, and off when it is
not, so piping or redirecting a scan gives you the daemon's newline-delimited
JSON rather than escape sequences. `--no-tui` forces the JSON path even in a
terminal, and `--tui` is accepted for symmetry with the other engines.

## Handy flags

- `-t, --targets` one or more hosts, ranges or CIDRs
- `-p, --ports` a list (`22,80,443`), a range, or a preset like `top-1000`
- `--technique` connect or syn
- `--service-detection` fingerprint the service on open ports
- `--os-detection` guess the host OS
- `--tasks` concurrency, `--timeout` and `--delay` to pace it
- `--fresh-start` ignore saved state

`pulse scan --help` for everything.

## Daemon

Under the Crossfyre node, pulse runs as a daemon (`--daemon`, default port 4443) that
takes work over a local socket. You do not need that for standalone use; just run
`pulse scan`.

## Notes

Port scanning is noisy and, in some places, regulated. Only point it at networks you
run or have written permission to test.
