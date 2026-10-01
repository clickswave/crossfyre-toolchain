# cortex

The vulnerability engine. cortex runs template-based checks against a target,
confirms anything that looks like a hit before reporting it, and can confirm blind
bugs out of band. It reads nuclei-style templates (a supported subset) plus its own
built-ins, so a lot of existing template packs work as-is.

Part of the [Crossfyre toolchain](../).

## How it runs

Like scout, cortex is a daemon you feed targets:

```sh
# start the daemon (default port 4445)
cortex --daemon

# scan a target through it
cortex scan https://example.com

# same run, with the live dashboard
cortex --tui scan https://example.com
```

`--no-tui` is accepted for symmetry with the other engines; here JSON is
already the default.

`--tui` brings up the shared toolchain dashboard, with findings ordered by
severity so a critical sits at the top the moment it is confirmed. It is
ignored when output is piped, so the node and any scripts still get JSON.

Every finding streams back as a JSON event. cortex only emits a finding after it
re-issues the request and gets the same result twice, so what you get out is the set
of checks it could actually reproduce, not a pile of maybes.

## Templates

Point cortex at a directory of templates with `CORTEX_TEMPLATES_DIR`. The built-in
checks always run; anything in that directory runs on top. cortex reads the nuclei
format (a supported subset: matchers, status/word/regex/dsl conditions, and payload
fuzzing), so a lot of existing packs work as-is.

This repo ships a starter pack, grouped by category, in [`templates/`](templates/).
Its [README](templates/README.md) covers the layout and how to write your own.

## Out-of-band confirmation

Blind bugs (SSRF, blind RCE, some XXE and OOB SQLi) do not show up in the response, so
cortex confirms them with a callback. Set an OAST endpoint and any template using
`{{interactsh-url}}` / `{{oast-url}}` gets a real callback host injected; if the target
calls back, the finding is confirmed.

```sh
export CORTEX_OAST_DOMAIN=oob.yourdomain.com
export CORTEX_OAST_API_URL=https://api.oob.yourdomain.com
```

You can run your own OAST server with [`oast`](../oast/) / `crossfyre oast setup`, or,
on the platform, pick a managed one per scan. Interactions are encrypted to a
per-scan key, so the OAST server only ever stores ciphertext.

## exec

`cortex exec '<json>'` sends a raw op to the daemon and prints the stream. This is the
low-level interface the node uses:

```sh
cortex exec '{"operation":"scan","target":"https://example.com","response":"stream"}'
```

## Notes

This one actively sends attack payloads, not just probes. Only run it against targets
you own or have explicit permission to test.
