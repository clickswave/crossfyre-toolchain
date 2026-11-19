# doorward

Host and port scanning. Give it targets (IPs, ranges, CIDRs) and a set of ports, and
it tells you what is open, with a TCP connect scan, and it can go a step further and
try to detect the service and OS behind an open port.

Part of the [Crossfyre toolchain](../). Runs standalone.

## Usage

```sh
# scan a range for the top ports, with service detection
doorward scan 10.0.0.0/24 --ports top-1000 --service-detection

# specific hosts and ports
doorward scan 10.0.0.5 10.0.0.6 -p 22,80,443,8080
```

For scripted single probes, `exec` takes a JSON payload and runs it through the
daemon.

The dashboard is on by default when stdout is a terminal, and off when it is
not, so piping or redirecting a scan gives you the daemon's newline-delimited
JSON rather than escape sequences. `--no-tui` forces the JSON path even in a
terminal.

## Handy flags

- `-p, --ports` a list (`22,80,443`), a range, or a preset like `top-1000`
- `--service-detection` fingerprint the service on open ports
- `--tasks` concurrency, `--timeout` and `--delay` to pace it
- `--fresh-start` ignore saved state

`doorward scan --help` for everything.

## How it runs

The scans run in doorward's daemon, on 127.0.0.1:4443, and the commands here are its
clients. The first command starts the daemon when none is running, and a daemon
started that way exits after 30 minutes with no client and no scan. `doorward daemon`
runs one by hand, and `--no-autostart` turns the starting off. It keeps each scan's
state in PostgreSQL, and the first daemon makes the database, so install PostgreSQL's
programs before the first scan (`sudo apt install postgresql` on Debian, Ubuntu or
Kali), or point it at a database you run with `crossfyre db external`. The root
[README](../#how-the-engines-run) has the details.

## Notes

Port scanning is noisy and, in some places, regulated. Only point it at networks you
run or have written permission to test.
