# mach

Content discovery and HTTP fuzzing. Point it at a URL with a `FUZZ` marker and a
wordlist, and it walks the list looking for paths that exist. There is a live TUI so
you can watch hits come in, and the run is written to a local database as it goes, so
if you kill it halfway you can pick up where you left off instead of starting over.

Part of the [Crossfyre toolchain](../). Works on its own; no account needed.

## Usage

```sh
# fuzz a path. ::FUZZ:: is where each wordlist entry gets substituted
mach scan --url https://example.com/::FUZZ:: --wordlist-path ./words.txt

# tune concurrency and pacing
mach scan -u https://example.com/::FUZZ:: -w ./words.txt --tasks 40 --interval 20

# only treat these as hits
mach scan -u https://example.com/::FUZZ:: -w ./words.txt --success-status-codes 200,204,301,403
```

A stopped scan resumes by default. Use `--fresh-start` if you want to ignore prior
state and run the whole list again.

For one-off checks in a script, `exec` probes a single URL and prints the result
without the TUI or a wordlist. It takes one JSON argument, and fills in the
operation itself:

```sh
mach exec '{"url":"https://example.com/robots.txt","success_codes":[200],"method":"get"}'
```

The dashboard is on by default when stdout is a terminal, and off when it is
not, so piping or redirecting a scan gives you the daemon's newline-delimited
JSON rather than escape sequences. `--no-tui` forces the JSON path even in a
terminal, and `--tui` is accepted for symmetry with the other engines.

## Handy flags

- `-w, --wordlist-path` the list to fuzz with
- `--fuzz-marker` change the marker if `::FUZZ::` clashes with your target
- `-t, --tasks` concurrent requests
- `-i, --interval` delay between requests, in milliseconds
- `--headers` / `--cookies` / `--basic-auth` send auth or custom headers
- `--follow-redirects` and `--follow-redirects-depth`
- `--random-user-agent-request` rotate the UA per request
- `--save-response-body` keep bodies for later inspection

Run `mach scan --help` for the full list. Stored runs live under `mach db`.

## Notes

Only scan things you are allowed to scan. See the root [README](../#responsible-use).
