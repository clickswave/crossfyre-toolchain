#!/usr/bin/env python3
"""An application that draws its settings as links, and breaks when one is used.

  /                     links to the next page, and to three settings links
  /step2 .. /step4      a chain; /step4 is only linked from /step3
  /settings?do=toggle-*  flips a switch, after which EVERYTHING returns a
                        redirect to https on this same plaintext port

This is Mutillidae's shape, reduced to the part that matters.
`index.php?do=toggle-enforce-ssl` is a link like any other, and following it
puts the session into a mode where every later request dies in a TLS handshake
against a port that speaks no TLS. The crawler recorded those as fetched pages
with no content, so a crawl that had lost most of its coverage reported a page
count that looked complete.

The test is whether the crawl reaches /step4. It only can if it never pressed
the switch, so no fixture state needs inspecting: the finding list says it.
"""
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

STATE = {"broken": False}

PAGES = {
    "/": """<html><body>
        <a href="/step2">next</a>
        <a href="/settings?do=toggle-enforce-ssl">Enforce SSL</a>
        <a href="/settings?do=toggle-security">Security level</a>
        <a href="/settings?action=reset">Reset</a>
        </body></html>""",
    "/step2": '<html><body><a href="/step3">next</a></body></html>',
    "/step3": '<html><body><a href="/step4">next</a></body></html>',
    "/step4": '<html><body><p>the far side of the crawl</p></body></html>',
}


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/settings":
            STATE["broken"] = True
            self._redirect()
            return
        if STATE["broken"]:
            # Exactly what Mutillidae does: same URL, https scheme, a port that
            # speaks only plaintext. The client cannot complete a handshake.
            self._redirect()
            return
        body = PAGES.get(path)
        if body is None:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        out = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    def _redirect(self):
        host = self.headers.get("Host") or "127.0.0.1"
        self.send_response(302)
        self.send_header("Location", f"https://{host}{self.path}")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
