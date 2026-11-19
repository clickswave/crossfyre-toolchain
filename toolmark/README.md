# toolmark

Service enumeration and web fingerprinting. Once you know a host has something
listening, toolmark works out what it is: the web server, frameworks, libraries, and
their versions where it can pin them down. When it can tie a version to a known CVE,
it flags that as a lead worth checking.

Part of the [Crossfyre toolchain](../).

## How it runs

The fingerprinting runs in toolmark's daemon, on 127.0.0.1:4444, and the commands
here are its clients. The first command starts the daemon when none is running, and a
daemon started that way exits after 30 minutes with no client and no scan. `toolmark
daemon` runs one by hand, and `--no-autostart` turns the starting off. It keeps what it
finds in PostgreSQL: each host it looked at, the landing page it saw there, the products
and services on it with their versions, and a row each time one appears or changes. A
scan given credentials saw the page as that user, so it keeps no body. The first daemon
makes the database, so install PostgreSQL's programs before the first scan (`sudo apt
install postgresql` on Debian, Ubuntu or Kali), or point it at a database you run with
`crossfyre db external`. `toolmark db purge --scan ID` deletes one scan, and `toolmark
db reset` everything it keeps. The root [README](../#how-the-engines-run) has the
details.

```sh
# scan a target
toolmark scan https://example.com

# same run, as JSON in the terminal
toolmark scan https://example.com --no-tui
```

In a terminal, `scan` and `services` bring up the shared toolchain dashboard:
findings sorted into technologies, services and CVE leads as they arrive.
`--no-tui` prints the events as JSON instead, which is what piped or redirected
output always gets, so scripts still get clean JSON.

`exec` sends a raw JSON op to the daemon and streams the events back, which is what
the node uses under the hood:

```sh
toolmark exec '{"operation":"fingerprint","target":"https://example.com"}'
```

## What you get

Detected technologies and versions for the target, plus any version-based CVE leads.
A lead is not a confirmed vulnerability; it is a "this version is known to have had X,
go look." For actually confirming a bug, hand the target to [`plessor`](../plessor/).

## Notes

Fingerprinting is mostly passive (it reads what the server volunteers) but it still
sends requests, so keep to targets you are allowed to touch.
