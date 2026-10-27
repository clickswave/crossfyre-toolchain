# plessor

Formerly `cortex`, renamed in 0.1.31.

The vulnerability engine. plessor runs template-based checks against a target,
confirms anything that looks like a hit before reporting it, and can confirm blind
bugs out of band. It reads nuclei-style templates (a supported subset) plus its own
built-ins, so a lot of existing template packs work as-is.

Part of the [Crossfyre toolchain](../).

## How it runs

Like toolmark, plessor is a daemon you feed targets:

```sh
# start the daemon (default port 4445)
plessor --daemon

# scan a target through it
plessor scan https://example.com

# same run, with the live dashboard
plessor --tui scan https://example.com
```

`--no-tui` is accepted for symmetry with the other engines; here JSON is
already the default.

`--tui` brings up the shared toolchain dashboard, with findings ordered by
severity so a critical sits at the top the moment it is confirmed. It is
ignored when output is piped, so the node and any scripts still get JSON.

Every finding streams back as a JSON event. plessor only emits a finding after it
re-issues the request and gets the same result twice, so what you get out is the set
of checks it could actually reproduce, not a pile of maybes.

## Templates

`plessor scan` runs the built-in checks and the starter pack in
[`templates/`](templates/), which is compiled into the binary, so an installed copy
needs no folder beside it. Add your own with `--templates`:

```sh
plessor scan https://example.com --templates ./my-templates
```

plessor reads the nuclei format (a supported subset: matchers, status/word/regex/dsl
conditions, and payload fuzzing), so a lot of existing packs work as-is. A template in
your folder replaces a pack template with the same `id`. The pack's
[README](templates/README.md) covers the layout and how to write your own.

## Injection

`plessor inject` tests the parameters of URLs you give it: SQL, command and template
injection, XSS, file inclusion and the rest of the injection engine. Every query
parameter is tried, and `-d` sends a form as a POST and tests its fields too. A
cookie or headers carry a login:

```sh
plessor inject 'https://example.com/item?id=1' --cookie 'session=...'
plessor inject https://example.com/search -d 'q=shoes&page=1' -H 'Authorization: Bearer ...'
```

With no URLs it reads them from stdin, one per line, so another engine's output can
be piped in. It only sends GET and POST: a DELETE, PUT or PATCH could change or
remove what it tests, and the engine needs a separate opt-in for those.

## Out-of-band confirmation

Blind bugs (SSRF, blind RCE, some XXE and OOB SQLi) do not show up in the response, so
plessor confirms them with a callback. Set an OAST endpoint and any template using
`{{interactsh-url}}` / `{{oast-url}}` gets a real callback host injected; if the target
calls back, the finding is confirmed.

```sh
export PLESSOR_OAST_DOMAIN=oob.yourdomain.com
export PLESSOR_OAST_API_URL=https://api.oob.yourdomain.com
```

You can run your own OAST server with [`oast`](../oast/) / `crossfyre oast setup`, or,
on the platform, pick a managed one per scan. Interactions are encrypted to a
per-scan key, so the OAST server only ever stores ciphertext.

## exec

`plessor exec '<json>'` sends a raw op to the daemon and prints the stream. This is the
low-level interface the node uses:

```sh
plessor exec '{"operation":"scan","target":"https://example.com","response":"stream"}'
```

## Notes

This one actively sends attack payloads, not just probes. Only run it against targets
you own or have explicit permission to test.
