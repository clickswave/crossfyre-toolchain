#!/usr/bin/env python3
"""An application that fetches a URL and hands back the answer.

    ssrf_app.py <port> [internal_port]

  /            a page with distinctive text, which is what the reflected SSRF
               oracle looks for coming back through the parameter
  /fetch?url=  the bug
  /read?file=  a traversal that reaches /etc/passwd and the app's own .env

The .env names `127.0.0.1:<internal_port>`, so a file read discloses an address
and the fetch can be pointed at it. Both halves of a chain, in one target.

The failure messages distinguish a refusal from a timeout on purpose: a host that
drops packets and a host that refuses are different, and an oracle that cannot
tell them apart reports black holes as services.
"""
import socket
import sys
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CANARY = "canary-7c1e-records-console-page"
INTERNAL = {"port": 0}

PASSWD = ("root:x:0:0:root:/root:/bin/bash\n"
          "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n")


def env_file():
    return (
        "APP_ENV=production\n"
        "SECRET_KEY_BASE=8f2a91bc4d7e0a5b6c3d2e1f0a9b8c7d\n"
        f"DATABASE_URL=postgres://appuser:s3cr3t-pw@127.0.0.1:{INTERNAL['port']}/appdb\n"
        f"REDIS_URL=redis://127.0.0.1:{INTERNAL['port']}/0\n"
        "AWS_SECRET_ACCESS_KEY=not-a-real-key-000000000000000000\n"
    )


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def reply(self, code, body, ct="text/html"):
        out = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        q = urllib.parse.parse_qs(u.query)

        if u.path == "/read":
            f = (q.get("file") or ["welcome.txt"])[0]
            name = f.replace("\\", "/").split("/")[-1]
            if "passwd" in f:
                return self.reply(200, f"<pre>{PASSWD}</pre>")
            if name in (".env", "env"):
                return self.reply(200, f"<pre>{env_file()}</pre>")
            return self.reply(200, "<pre>welcome</pre>")

        if u.path == "/fetch":
            url = (q.get("url") or [""])[0]
            if not url:
                return self.reply(200, "<html><body>nothing requested</body></html>")
            try:
                p = urllib.parse.urlparse(url)
                s = socket.create_connection((p.hostname, p.port or 80), timeout=3)
                s.sendall(f"GET {p.path or '/'} HTTP/1.0\r\nHost: {p.hostname}\r\n\r\n".encode())
                data = b""
                s.settimeout(3)
                while True:
                    c = s.recv(65536)
                    if not c:
                        break
                    data += c
                s.close()
                return self.reply(200, b"<html><body>" + data + b"</body></html>")
            except socket.timeout:
                ms = int(time.time() * 1000) % 4000
                return self.reply(200, f"<html><body>fetch timed out after {ms}ms</body></html>")
            except Exception:
                ms = int(time.time() * 1000) % 4000
                return self.reply(200, f"<html><body>fetch failed after {ms}ms</body></html>")

        return self.reply(
            200,
            "<!doctype html><html><body><h1>Records</h1>"
            f"<p>{CANARY}</p><p>reference {CANARY}-two</p></body></html>",
        )

    def log_message(self, *a):
        pass


class S(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    INTERNAL["port"] = int(sys.argv[2]) if len(sys.argv) > 2 else 0
    S(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
