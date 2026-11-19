# voyage

Subdomain enumeration. It pulls names from passive sources and, if you give it a
wordlist, brute-forces more on top of that, then probes what it finds to see what is
actually live. Like the other engines it has a live TUI and keeps state in a local
database, so a big run survives a stop and restart.

Part of the [Crossfyre toolchain](../). Standalone, no account.

## Usage

```sh
# passive sources only
voyage scan example.com

# add active brute-forcing with a wordlist
voyage scan example.com --wordlist-path ./subdomains.txt

# passive off, active only
voyage scan example.com -w ./subdomains.txt --disable-passive-enum
```

Resumes by default; pass `--fresh-start` to run clean.

`exec` checks a single subdomain and prints the result, for scripting. It takes
one JSON argument:

```sh
voyage exec '{"domain":"api.example.com","volatility":0}'
```

The dashboard is on by default when stdout is a terminal, and off when it is
not, so piping or redirecting a scan gives you the daemon's newline-delimited
JSON rather than escape sequences. `--no-tui` forces the JSON path even in a
terminal.

## How it runs

The enumeration runs in voyage's daemon, on 127.0.0.1:4442, and the commands here are
its clients. The first command starts the daemon when none is running, and a daemon
started that way exits after 30 minutes with no client and no scan. `voyage daemon`
runs one by hand, and `--no-autostart` turns the starting off. It keeps each scan's
state in PostgreSQL, and the first daemon makes the database, so install PostgreSQL's
programs before the first scan (`sudo apt install postgresql` on Debian, Ubuntu or
Kali), or point it at a database you run with `crossfyre db external`. The root
[README](../#how-the-engines-run) has the details.

## Handy flags

- `-w, --wordlist-path` list for active brute-forcing
- `--disable-passive-enum` turn the passive sources off; without `-w` there is no active half
- `--exclude-passive-source` skip a specific source
- `--exclude-active-technique` skip a specific active technique
- `-t, --tasks` concurrency, `-i, --interval` delay between requests (ms)
- `--http-probing-port` / `--https-probing-port` where to probe for a live host
- `--passive-random-user-agent` / `--active-random-user-agent`

`voyage scan --help` has the rest.

## Notes

Passive sources vary in quality and rate limits, so results differ run to run. Keep
your scope to domains you own or are authorized to test.
