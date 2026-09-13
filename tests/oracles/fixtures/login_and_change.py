#!/usr/bin/env python3
"""A login form, which must stay testable, and a password-change form, which
must never be submitted.

  /login?username=&password=        username reaches a SQL string; a quote
                                    produces a database error, so this is
                                    error-based SQL injection and finding it is
                                    the point of the scanner
  /change?password_new=&password_conf=&Change=Change
                                    echoes password_new into the page, raw

The two halves of one rule. A login form's `password` is one of the best SQL
injection targets there is and skipping it would cost real findings; a form
carrying a password AND a confirmation of it is a change form, and submitting it
sets the credential instead of testing it. DVWA's is exactly this shape, and the
scanner submitted it and set that lab's admin password to its own sample value.

`/change` reflects its input unescaped on purpose. If anything ever submits it,
the reflection is reported as cross-site scripting, so the absence of an XSS
finding is a direct statement that the form was never submitted. Nothing about
the fixture's internal state has to be read.
"""
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        one = lambda k: (q.get(k) or [""])[0]
        if u.path == "/login":
            user = one("username")
            # Odd number of quotes only: an even number closes the string again,
            # which is exactly the control the oracle sends before it will report.
            # A fixture that errors on `''` as well as on `'` is not a SQL string,
            # and refusing it there is the oracle being right.
            if user.count("'") % 2 == 1:
                body = ("<html><body>SQL error: unterminated quoted string at or near "
                        f"\"'{user}'\" LINE 1: SELECT * FROM users WHERE name = '{user}'"
                        "</body></html>")
            else:
                body = "<html><body>Sign in</body></html>"
        elif u.path == "/change":
            # Raw on purpose: submitting this is visible as an XSS finding.
            body = f"<html><body>New password set to {one('password_new')}</body></html>"
        else:
            body = ('<html><body><a href="/login?username=x&password=y">sign in</a>'
                    '<a href="/change?password_new=x&password_conf=x&Change=Change">'
                    'change password</a></body></html>')
        out = body.encode()
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
