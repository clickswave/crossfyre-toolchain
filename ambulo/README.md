# ambulo

Content discovery and HTTP fuzzing. Point it at a URL with a `FUZZ` marker and a
wordlist, and it walks the list looking for paths that exist. There is a live TUI so
you can watch hits come in, and the run is written to a local database as it goes, so
if you kill it halfway you can pick up where you left off instead of starting over.

Part of the [Crossfyre toolchain](../). Works on its own; no account needed.

## Usage

```sh
# fuzz a path. ::FUZZ:: is where each wordlist entry gets substituted
ambulo scan https://example.com/::FUZZ:: --wordlist-path ./words.txt

# tune concurrency and pacing
ambulo scan https://example.com/::FUZZ:: -w ./words.txt --tasks 40 --interval 20

# only treat these as hits
ambulo scan https://example.com/::FUZZ:: -w ./words.txt --success-status-codes 200,204,301,403
```

A stopped scan resumes by default. Use `--fresh-start` if you want to ignore prior
state and run the whole list again.

For one-off checks in a script, `exec` probes a single URL and prints the result
without the TUI or a wordlist. It takes one JSON argument, and fills in the
operation itself:

```sh
ambulo exec '{"url":"https://example.com/robots.txt","success_codes":[200],"method":"get"}'
```

The dashboard is on by default when stdout is a terminal, and off when it is
not, so piping or redirecting a scan gives you the daemon's newline-delimited
JSON rather than escape sequences. `--no-tui` forces the JSON path even in a
terminal.

## How it runs

The scans run in ambulo's daemon, on 127.0.0.1:4441, and the commands here are its
clients. The first command starts the daemon when none is running, and a daemon
started that way exits after 30 minutes with no client and no scan. `ambulo daemon`
runs one by hand, and `--no-autostart` turns the starting off. It keeps each scan's
state in PostgreSQL, and the first daemon makes the database, so install PostgreSQL's
programs before the first scan (`sudo apt install postgresql` on Debian, Ubuntu or
Kali), or point it at a database you run with `crossfyre db external`. The root
[README](../#how-the-engines-run) has the details.

## Handy flags

- `-w, --wordlist-path` the list to fuzz with
- `--fuzz-marker` change the marker if `::FUZZ::` clashes with your target
- `-t, --tasks` concurrent requests
- `-i, --interval` delay between requests, in milliseconds
- `--headers` / `--cookies` / `--basic-auth` send auth or custom headers
- `--follow-redirects` and `--follow-redirects-depth`
- `--random-user-agent-request` rotate the UA per request

Run `ambulo scan --help` for the full list. `ambulo scans` lists the scans it keeps, the latest first, and Enter on a stopped one takes it up again. A scan given credentials keeps none of them, so it is taken up by asking for it as it was first asked for, with `--resume ID`. `ambulo db reset` deletes every stored run, and `ambulo db purge --scan ID` one of them.

## Notes

Only scan things you are allowed to scan. See the root [README](../#responsible-use).
