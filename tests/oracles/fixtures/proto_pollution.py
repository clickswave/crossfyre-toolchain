#!/usr/bin/env python3
"""Prototype pollution, and the same endpoint with the key guarded.

  /vuln  merges request JSON into a shared prototype without guarding __proto__
  /safe  refuses the key

Separate prototypes per path, deliberately: with one shared dict the safe
endpoint inherits the pollution from the vulnerable one and the negative half of
the test proves nothing at all.
"""
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PROTO = {"vuln": {}, "safe": {}}


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        try:
            body = json.loads(self.rfile.read(n) or b"{}")
        except ValueError:
            body = {}
        which = "safe" if self.path.startswith("/safe") else "vuln"
        proto = PROTO[which]
        obj = {}
        for k, v in body.items():
            if k in ("__proto__", "constructor"):
                if which == "safe":
                    continue                      # the fix
                inner = v.get("prototype", v) if k == "constructor" else v
                if isinstance(inner, dict):
                    proto.update(inner)           # the bug
                continue
            obj[k] = v
        out = json.dumps({"ok": True, **proto, **obj}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    def do_GET(self):
        self.do_POST()

    def log_message(self, *a):
        pass


class S(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    S(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
