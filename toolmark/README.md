# toolmark

Service enumeration and web fingerprinting. Once you know a host has something
listening, toolmark works out what it is: the web server, frameworks, libraries, and
their versions where it can pin them down. When it can tie a version to a known CVE,
it flags that as a lead worth checking.

Part of the [Crossfyre toolchain](../).

## How it runs

toolmark is a daemon. Start it, then send it targets:

```sh
# start the daemon (default port 4444)
toolmark daemon

# scan a target through the running daemon
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
