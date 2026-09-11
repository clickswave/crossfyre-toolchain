#!/usr/bin/env python3
"""A page that is permanently different after it has been probed.

  /page?q=   200 and small, until one request carries a quote, after which every
             response is 302 and empty, forever

The shape of the two expensive failures of 2026-09-11. Following a settings link
put Mutillidae's session into SSL-enforced mode and every later fetch died in a
TLS handshake; submitting a password-change form set DVWA's admin password to
the crawl's own sample value and every later run authenticated as nobody. Both
showed up as fewer findings, which reads as a clean result.

Guards now stop the cases that can be recognised from a URL or a field name.
This is for the ones that cannot: the pass re-requests the endpoint's own
baseline at the end and says so if the answer has changed shape. It cannot say
what changed. It can say that something did, which is the part that was missing.
"""
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

STATE = {"broken": False}
BODY = "<html><body><p>reports</p></body></html>"


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        if "'" in self.path or "%27" in self.path:
            STATE["broken"] = True
        if STATE["broken"]:
            self.send_response(302)
            self.send_header("Location", "/locked")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        out = BODY.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    do_POST = do_GET

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
