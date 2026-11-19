# toolmark

Service enumeration and web fingerprinting. Once you know a host has something
listening, toolmark works out what it is: the web server, frameworks, libraries, and
their versions where it can pin them down. When it can tie a version to a known CVE,
it flags that as a lead worth checking.

Part of the [Crossfyre toolchain](../).

## How it runs

The fingerprinting runs in toolmark's daemon, on 127.0.0.1:4444, and the commands here
are its clients. The first command starts the daemon when none is running, and a daemon
started that way exits after 30 minutes with no client and no scan. `toolmark daemon`
runs one by hand, and `--no-autostart` turns the starting off. It keeps what it finds in
PostgreSQL: each host it looked at, the pages it saw there, the products and services on
it with their versions, and a row each time one appears or changes. A scan given
credentials saw the pages as that user, so it keeps no body. The first daemon makes the
database, so install PostgreSQL's programs before the first scan (`sudo apt install
postgresql` on Debian, Ubuntu or Kali), or point it at a database you run with
`crossfyre db external`. `toolmark inventory` shows what it knows runs where: each host
and port it scanned, and the products and versions it found there. `toolmark scans`
lists the scans it keeps, the latest first, `toolmark db purge --scan ID` deletes one,
and `toolmark db reset` everything it keeps. The root [README](../#how-the-engines-run)
has the details.

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

## Signatures

Each product toolmark knows is a file in [`signatures/`](signatures/), compiled into the
binary. A file says what shows the product, where its version can be read, and what
else it implies:

```yaml
id: wordpress
info:
  name: WordPress
  category: CMS
  metadata:
    vendor: wordpress
    product: wordpress
implies: [php, mysql]
detect:
  any:
    - meta: { name: generator, regex: '(?i)wordpress' }
    - html: { regex: '(?i)/wp-content/|/wp-includes/' }
    - cookie: { name: '(?i)^wordpress_|^wp-settings' }
version:
  - meta: { name: generator, regex: '(?i)WordPress ([0-9.]+)' }
  - html: { regex: '(?i)WordPress ([0-9.]+)' }
```

A leaf reads a response header (`header`), the name of each cookie set (`cookie`), a
meta tag (`meta`), the first 60,000 bytes of the body (`html`) or the `src` of each
script (`script_src`) on the landing page. Three more each read a request of their own:
the body the host answers for another path (`path`, which matches its `regex`, is the
exact file its `sha256` names, or with neither only has to be there), the content of a
script the landing page loads from the host's own origin (`script`, whose `src` picks
the script and whose `regex` or `sha256` reads it), and the page the host answers for a
path it does not have (`not_found`, an error page that often names the server and its
version). Every leaf answers present, absent or unknown, and `all`, `any` and `none`
combine the answers, nested as deep as needed. A product is reported when its `detect`
is present. Each leaf that holds it up adds to the confidence, 50, 45, 60, 25, 40, 50,
50 and 40 by kind unless the leaf sets its own `confidence`, up to 100. The first
`version` leaf that matches gives the version from its first group, and `vendor` and
`product` make the CPE. A version leaf may give `since` or `until` in place of a group:
when its evidence is present the version lies from `since` on and before `until`, the
ranges of all such leaves that are present hold together, and an exact version, when one
is read, wins.

A `path`, a `script` or a `not_found` is a request the landing page did not need, so it
is sent from the standard depth tier up, and only when its answer could still change
what is reported. A script from another host is never fetched, and leaves its leaf
unknown. An error page answered with a 401, 403, 429 or 5xx proves nothing either way.
Each path is asked once per host, and a host is asked for 20 at most. Before the first,
two random paths learn what the host answers for a page it does not have. A path is
absent only on a 404, a 410 or that same page. A 401, 403, 429, 5xx, redirect or timeout
proves nothing, and leaves it unknown.

`refines: other-id` makes a signature a more specific form of another. When both are
present only the refining one is reported. When the evidence that would tell them apart
is unknown, the other is reported with this one among its `candidates`.

A new file goes in `src/signatures/files.rs` too, and needs saved responses in
`tests/responses` on which each of its leaves is present: a landing page, and for a
`path` the page the host answers, in a folder named after the landing page's file
(`src/signatures/golden.rs` has the layout). `cargo test -p toolmark` fails when a file
does not load or a leaf is present on none of them, and checks that every saved response
still gives the detections in `tests/responses/expected.json`.

## Notes

Fingerprinting is mostly passive (it reads what the server volunteers) but it still
sends requests, so keep to targets you are allowed to touch.
