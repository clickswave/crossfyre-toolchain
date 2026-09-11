#!/usr/bin/env python3
"""What every oracle must find, and what it must never report.

The `must_not` lists are the reason this file exists. An oracle that reports
everything satisfies every `must_find` in here; only the negatives tell it apart
from one that discriminates. Each was chosen because it is a real way the oracle
could be wrong, and several of them caught a real bug the day they were written.
"""
from urllib.parse import quote

# The intrusive classes never run in a default sweep, so the cases that exercise
# them have to name them. See the module docs in cortex for why each is opt-in.
INTRUSIVE = ["race", "tampering", "smuggling", "proto_pollution"]


def inject(target, endpoints, **extra):
    req = {"operation": "inject", "response": "stream", "target": target,
           "tasks": 1, "timeout_ms": 15000, "endpoints": endpoints}
    req.update(extra)
    return req


def crawl(seed, **extra):
    req = {"operation": "crawl", "response": "stream", "seed": seed,
           "max_pages": 60, "max_depth": 4, "parse_js": True}
    req.update(extra)
    return req


def _u(port, path):
    return f"http://127.0.0.1:{port}{path}"


CASES = {
    # ---------------------------------------------------------------- race ---
    "race": {
        "what": "a single-use limit that concurrency walks past",
        "fixtures": [{"name": "app", "script": "race.py"}],
        "request": lambda p: inject(
            _u(p["app"], "/"), classes=["race"],
            endpoints=[{"method": "POST", "url": _u(p["app"], "/coupon"),
                        "body": [{"name": "code", "value": "SAVE50"}], "body_type": "form"}],
        ),
        "must_find": [{"class": "race", "severity": "high"}],
    },
    "race-negatives": {
        "what": "a locked limit, an unlimited endpoint, a rate limiter, a noisy body",
        "fixtures": [{"name": "app", "script": "race.py"}],
        "request": lambda p: inject(
            _u(p["app"], "/"), classes=["race"],
            endpoints=[{"method": "POST", "url": _u(p["app"], path),
                        "body": [{"name": "code", "value": "SAVE50"}], "body_type": "form"}
                       for path in ("/coupon-safe", "/open", "/ratelimited", "/noisy")],
        ),
        # Each of these is a different way to invent a race that is not there.
        "must_not": [{"class": "race"}],
    },
    # ------------------------------------------------------------ tampering ---
    "tampering": {
        "what": "a computed total that follows an out-of-domain quantity",
        "fixtures": [{"name": "app", "script": "tampering.py"}],
        "request": lambda p: inject(
            _u(p["app"], "/"), classes=["tampering"],
            endpoints=[{"method": "GET", "url": _u(p["app"], "/order?quantity=2")}],
        ),
        "must_find": [{"class": "tampering", "param": "quantity"}],
    },
    "tampering-negatives": {
        "what": "rejecting, clamping, echoing, a counter, and a total that drifts",
        "fixtures": [{"name": "app", "script": "tampering.py"}],
        "request": lambda p: inject(
            _u(p["app"], "/"), classes=["tampering"],
            endpoints=[{"method": "GET", "url": _u(p["app"], f"{path}?quantity=2")}
                       for path in ("/order-safe", "/order-clamp", "/echo", "/noisy",
                                    # /drift establishes a perfect scaling
                                    # relationship and then gives a different
                                    # answer to the same question. Only the
                                    # determinism re-check rejects it.
                                    "/drift")],
        ),
        # Clamping is CORRECT behaviour and must stay silent; a hit counter moves
        # for reasons that have nothing to do with the input.
        "must_not": [{"class": "tampering"}],
    },
    # ------------------------------------------------------------ smuggling ---
    "smuggling": {
        "what": "a CL.TE desync between two hops",
        "fixtures": [{"name": "front", "script": "smuggling.py"}],
        "request": lambda p: inject(
            _u(p["front"], "/"), classes=["smuggling"],
            endpoints=[{"method": "GET", "url": _u(p["front"], "/")}],
        ),
        "must_find": [{"class": "smuggling", "severity": "critical"}],
    },
    "smuggling-negatives": {
        "what": "a rejecting front-end, a lone server, and one that is merely slow",
        "fixtures": [{"name": "safe", "script": "smuggling.py", "args": ["safe"]},
                     {"name": "lone", "script": "race.py"},
                     {"name": "slow", "script": "slow_on_odd_body.py"}],
        "request": lambda p: inject(
            _u(p["safe"], "/"), classes=["smuggling"],
            endpoints=[{"method": "GET", "url": _u(p["safe"], "/")},
                       {"method": "GET", "url": _u(p["lone"], "/")},
                       # One process, so it cannot desync with itself, but it is
                       # slow about the probe body and fast about the control.
                       # That is the signature of a desync, and only the
                       # single-framing control says otherwise.
                       {"method": "GET", "url": _u(p["slow"], "/")}],
        ),
        # The lone server is the case mirage caught: one process cannot desync
        # with itself, and an under-fed Content-Length probe made it look like it
        # could.
        "must_not": [{"class": "smuggling"}],
    },
    # ------------------------------------------------------ proto pollution ---
    "proto-pollution": {
        "what": "a key written onto the prototype comes back on a later request",
        "fixtures": [{"name": "app", "script": "proto_pollution.py"}],
        "request": lambda p: inject(
            _u(p["app"], "/"), classes=["proto_pollution"],
            endpoints=[{"method": "POST", "url": _u(p["app"], "/vuln"),
                        "body": [{"name": "name", "value": "x"}], "body_type": "json"}],
        ),
        "must_find": [{"class": "proto_pollution"}],
    },
    "proto-pollution-negative": {
        "what": "the same endpoint with the key guarded",
        "fixtures": [{"name": "app", "script": "proto_pollution.py"}],
        "request": lambda p: inject(
            _u(p["app"], "/"), classes=["proto_pollution"],
            endpoints=[{"method": "POST", "url": _u(p["app"], "/safe"),
                        "body": [{"name": "name", "value": "x"}], "body_type": "json"}],
        ),
        "must_not": [{"class": "proto_pollution"}],
    },
    # ----------------------------------------------- not pressing the button ---
    "crawl-does-not-press-the-settings": {
        "what": "a settings link is reported, never followed, and the crawl survives",
        "engine": "mach",
        "fixtures": [{"name": "app", "script": "settings_as_links.py"}],
        "request": lambda p: crawl(_u(p["app"], "/"), max_depth=5),
        # /step4 is four links deep and only reachable if the crawl never
        # requested a settings link: the fixture breaks itself when one is used,
        # and every later fetch dies in a TLS handshake against a plaintext port.
        # Reaching it is the whole assertion; no fixture state is inspected.
        "must_find": [
            {"url_contains": "/step4"},
            # Still reported, because knowing a destructive endpoint exists is
            # worth having. Only requesting it is not.
            {"url_contains": "/settings?do=toggle-enforce-ssl"},
        ],
    },
    # ------------------------------------------------- self-inflicted drift ---
    "sqli-negative-drifting-page": {
        "what": "a page that changes length on its own is not a SQL oracle",
        "fixtures": [{"name": "app", "script": "self_inflicted_drift.py"}],
        "request": lambda p: inject(
            _u(p["app"], "/"), classes=["sqli"],
            endpoints=[{"method": "GET", "url": _u(p["app"], "/page?q=1"),
                        "params": ["q"]}],
        ),
        # Nothing behind this parameter reads a database, so any SQL finding is
        # wrong by construction. It used to be reported anyway: nine times on
        # DVWA, marked confirmed, because the application varied its own length
        # between the true and false requests and the pair had no control.
        "must_not": [{"class": "sqli"}],
    },
    # -------------------------------------------------------------- opt-in ---
    "intrusive-classes-are-opt-in": {
        "what": "a default sweep runs none of the state-changing classes",
        "fixtures": [{"name": "shop", "script": "tampering.py"},
                     {"name": "proto", "script": "proto_pollution.py"},
                     {"name": "front", "script": "smuggling.py"}],
        "request": lambda p: inject(
            _u(p["shop"], "/"), scope=["127.0.0.1"],
            endpoints=[
                # Deliberately endpoints a default sweep CANNOT consume. The
                # first version of this case pointed at a single-use coupon, and
                # the ordinary payloads spent it before the race probe ran, so
                # "no race reported" was true whether the gate worked or not. A
                # mutation that removed the gate entirely still passed. These
                # three are idempotent, so silence here means the class did not
                # run rather than that it ran and found nothing.
                {"method": "GET", "url": _u(p["shop"], "/order?quantity=2")},
                {"method": "POST", "url": _u(p["proto"], "/vuln"),
                 "body": [{"name": "name", "value": "x"}], "body_type": "json"},
                {"method": "GET", "url": _u(p["front"], "/")},
            ],
        ),
        "must_not": [{"class": c} for c in ("race", "tampering", "smuggling", "proto_pollution")],
        # And the gate itself, not just its consequences: the race banner is
        # printed the moment the class is enabled, before any endpoint is picked.
        "must_not_say": ["race-condition checks are ON"],
    },
    "intrusive-classes-run-when-named": {
        "what": "the same endpoints, with the classes named, do fire",
        "fixtures": [{"name": "shop", "script": "tampering.py"},
                     {"name": "proto", "script": "proto_pollution.py"},
                     {"name": "front", "script": "smuggling.py"}],
        "request": lambda p: inject(
            _u(p["shop"], "/"), classes=INTRUSIVE, scope=["127.0.0.1"],
            endpoints=[
                {"method": "GET", "url": _u(p["shop"], "/order?quantity=2")},
                {"method": "POST", "url": _u(p["proto"], "/vuln"),
                 "body": [{"name": "name", "value": "x"}], "body_type": "json"},
                {"method": "GET", "url": _u(p["front"], "/")},
            ],
        ),
        # The other half of the pair. Without this, the opt-in test above is
        # satisfied by an engine where these classes are simply broken.
        "must_find": [{"class": "tampering"}, {"class": "proto_pollution"},
                      {"class": "smuggling"}],
        "must_say": ["race-condition checks are ON"],
    },
    # ---------------------------------------------------------------- ssrf ---
    "ssrf-reflected": {
        "what": "a fetch whose answer comes back through the parameter",
        "fixtures": [{"name": "internal", "script": "internal_service.py"},
                     {"name": "app", "script": "ssrf_app.py", "args": ["{internal}"]}],
        "request": lambda p: inject(
            _u(p["app"], "/"), classes=["ssrf"],
            endpoints=[{"method": "GET", "url": _u(p["app"], "/fetch?url=" + quote("http://127.0.0.1:9/", safe=""))}],
        ),
        "must_find": [{"class": "ssrf", "param": "url"}],
    },
    "chain-config-to-service": {
        "what": "a disclosed config names an internal service the app can reach",
        "fixtures": [{"name": "internal", "script": "internal_service.py"},
                     {"name": "app", "script": "ssrf_app.py", "args": ["{internal}"]}],
        "request": lambda p: inject(
            _u(p["app"], "/"), classes=["lfi", "ssrf"], scope=["127.0.0.1"],
            endpoints=[{"method": "GET", "url": _u(p["app"], "/read?file=welcome.txt")},
                       {"method": "GET", "url": _u(p["app"], "/fetch?url=" + quote("http://127.0.0.1:9/", safe=""))}],
        ),
        "must_find": [{"class": "lfi"}, {"class": "ssrf"}, {"class": "chain"}],
    },
    "chain-needs-authorised-scope": {
        "what": "a leaked address is not an authorised one",
        "fixtures": [{"name": "internal", "script": "internal_service.py"},
                     {"name": "app", "script": "ssrf_app.py", "args": ["{internal}"]}],
        "request": lambda p: inject(
            _u(p["app"], "/"), classes=["lfi", "ssrf"],   # no scope
            endpoints=[{"method": "GET", "url": _u(p["app"], "/read?file=welcome.txt")},
                       {"method": "GET", "url": _u(p["app"], "/fetch?url=" + quote("http://127.0.0.1:9/", safe=""))}],
        ),
        "must_not": [{"class": "chain"}],
        "must_say": ["not in the authorised scope"],
    },
    "chain-black-holed-host": {
        "what": "a host that swallows every port is not a reachable service",
        "fixtures": [{"name": "internal", "script": "blackhole_host.py"},
                     {"name": "app", "script": "ssrf_app.py", "args": ["{internal}"]}],
        "request": lambda p: inject(
            _u(p["app"], "/"), classes=["lfi", "ssrf"], scope=["127.0.0.1"],
            endpoints=[{"method": "GET", "url": _u(p["app"], "/read?file=welcome.txt")},
                       {"method": "GET", "url": _u(p["app"], "/fetch?url=" + quote("http://127.0.0.1:9/", safe=""))}],
        ),
        # The config names it and the fetch reaches it, but nothing answers on
        # any port. A refusal and a silence are different answers, so without
        # the same-host control this reports a service that is not there.
        "must_not": [{"class": "chain"}],
    },

    # ---------------------------------------------------------------- flow ---
    # Flow cases are driven by `flow_cases.py`, which records the flow against
    # the fixture first: a recording is the input, so it cannot be a literal.
    # ---------------------------------------------------------------- mach ---
    "spa-static": {
        "what": "source maps, lazy chunks and route tables, without a browser",
        "engine": "mach",
        "fixtures": [{"name": "app", "script": "spa.py"}],
        "request": lambda p: crawl(_u(p["app"], "/")),
        "must_find": [
            {"url_contains": "/static/js/main.js.map"},
            {"url_contains": "/static/js/admin.7f21.js"},
            {"url_contains": "/api/v2/users"},
            {"url_contains": "/api/v2/admin/impersonate"},
            {"url_contains": "/admin/users"},
        ],
    },
    "headless-runtime": {
        "what": "URLs assembled at runtime, which exist in no served file",
        "engine": "mach",
        "fixtures": [{"name": "app", "script": "runtime.py"}],
        "request": lambda p: crawl(_u(p["app"], "/"), browser=True),
        "must_find": [
            {"url_contains": "/t/acme-7741/users"},
            {"url_contains": "/t/acme-7741/invoices", "method": "POST"},
        ],
        "needs_browser": True,
    },
    "headless-absent-is-loud": {
        "what": "no browser means a named gap, not a silent pass",
        "engine": "mach",
        "env": {"MACH_BROWSER": "/nonexistent/chrome", "PATH": "/nonexistent"},
        "fixtures": [{"name": "app", "script": "runtime.py"}],
        "request": lambda p: crawl(_u(p["app"], "/"), browser=True),
        "must_say": ["no browser was found"],
    },
}
