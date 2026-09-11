#!/usr/bin/env python3
"""A page whose length changes on its own, with no SQL anywhere behind it.

  /page?q=...   echoes nothing, evaluates nothing, and every few requests
                prepends a notice of about eighty bytes

This is the shape that produced nine false positives on DVWA. A concurrent
worker kept submitting a password-change form, DVWA queued a success banner in
the session, and the banner surfaced on whichever page rendered next. The
injection oracle sent a tautology and a contradiction, the banner happened to
land on one of them, and the difference read as "consistently different result
sets" twice in a row, because the second round of confirmation is two more
requests and the banner was still cycling.

The true/false payloads are already the same length, so reflection cannot
produce this, and a jitter sample taken before the pair cannot see it either:
the variation is BETWEEN requests, not within one of them. Only a control
answers it, which is what this fixture exists to require.

`?q=` is a plain echo-free parameter. Nothing here touches a database, so any
injection finding against it is wrong by construction.
"""
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# Every Nth response carries the notice. Two makes the pattern land on one half
# of a true/false pair and not the other, reliably, which is the case that
# fooled the oracle; a random rate would make the test flaky for no benefit.
EVERY = 2
NOTICE = ("<div class=\"flash\">Your settings were saved. This notice appears "
          "once and then clears.</div>")

BODY = ("<html><body><h1>Reports</h1><p>Nothing here reads a database. "
        "The parameter is not used.</p></body></html>")


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    count = 0

    def do_GET(self):
        H.count += 1
        page = BODY
        if H.count % EVERY == 0:
            page = NOTICE + BODY
        out = page.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    do_POST = do_GET

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    port = int(sys.argv[1])
    ThreadingHTTPServer(("127.0.0.1", port), H).serve_forever()
