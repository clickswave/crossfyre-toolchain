# voyage

Subdomain enumeration. It pulls names from passive sources and, if you give it a
wordlist, brute-forces more on top of that, then probes what it finds to see what is
actually live. Like the other engines it has a live TUI and keeps state in a local
database, so a big run survives a stop and restart.

Part of the [Crossfyre toolchain](../). Standalone, no account.

## Usage

```sh
# passive sources only
voyage scan --domain example.com

# add active brute-forcing with a wordlist
voyage scan --domain example.com --wordlist-path ./subdomains.txt

# passive off, active only
voyage scan -d example.com -w ./subdomains.txt --disable-passive-enum
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
terminal, and `--tui` is accepted for symmetry with the other engines.

## Handy flags

- `-w, --wordlist-path` list for active brute-forcing
- `--disable-passive-enum` / `--disable-active-enum` turn either half off
- `--exclude-passive-source` skip a specific source
- `--exclude-active-technique` skip a specific active technique
- `-t, --tasks` concurrency, `-i, --interval` delay between requests (ms)
- `--http-probing-port` / `--https-probing-port` where to probe for a live host
- `--passive-random-user-agent` / `--active-random-user-agent`

`voyage scan --help` has the rest.

## Notes

Passive sources vary in quality and rate limits, so results differ run to run. Keep
your scope to domains you own or are authorized to test.
