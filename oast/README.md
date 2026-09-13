# oast

An out-of-band interaction server. It answers DNS and HTTP(S) for a domain you
control and records who called back, so [`cortex`](../cortex/) can confirm blind
vulnerabilities: cortex plants a unique hostname in a payload, the vulnerable target
resolves or fetches it, and that callback lands here.

Part of the [Crossfyre toolchain](../). This is the same server that backs the hosted
pool; run your own when you want callbacks on your own domain.

## Why run your own

cortex talks to the server with Crossfyre's own encrypted register/poll protocol, so
a generic interactsh instance will not work here. The interaction contents are sealed
to a per-scan key before they are stored, so even you, running the server, only ever
have ciphertext at rest. The point of self-hosting is control of the domain, not
seeing the data.

## The easy way

If you have the `crossfyre` CLI on a public box, one command sets everything up,
including wildcard TLS and the DNS records you need to add:

```sh
sudo crossfyre oast setup --domain oob.yourdomain.com --email you@yourdomain.com
```

See the [self-host guide](https://github.com/clickswave/crossfyre-toolchain) for the
full walk-through.

## Running the binary directly

The `oast` binary reads its config from the environment. This is handy for containers
or a systemd unit you manage yourself:

```sh
OAST_DOMAIN=oob.yourdomain.com \
OAST_PUBLIC_IP=203.0.113.9 \
OAST_TLS_CERT=/etc/oast/fullchain.pem \
OAST_TLS_KEY=/etc/oast/privkey.pem \
oast
```

It listens on:

- `:53` UDP/TCP, authoritative DNS for the domain (this is the reliable signal, since
  a DNS lookup escapes most egress filters)
- `:80` HTTP capture
- `:443` HTTPS capture plus the register/poll API, under the wildcard cert

`OAST_DOMAIN` can be a comma-separated list, and TLS can resolve a cert per name, so
one box can serve several delegated zones.

## Watching interactions

Set `OAST_TUI=1` and, if you are running it in a terminal, oast brings up a live
feed of callbacks as they land: protocol, source address, and a short correlation
prefix, with a running count and uptime. It shows only this envelope metadata and
never the interaction contents, which stay sealed to the scan's key exactly as they
are at rest. Under a service unit with piped output the flag is ignored and oast logs
as usual.

## Notes

You need a real public box, a domain you can delegate, and ports 53/80/443 open.
Wildcard TLS is via ACME DNS-01, which the server answers itself because it is
authoritative for the zone.
