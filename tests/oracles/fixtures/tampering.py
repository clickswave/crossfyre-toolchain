#!/usr/bin/env python3
"""A quantity multiplied into a total, bounded four ways and unbounded once.

  /order        total = unit * quantity, no bound       -> must FIRE
  /order-safe   rejects quantity < 1                    -> must be SILENT
  /order-clamp  clamps quantity to >= 1                 -> must be SILENT
  /echo         returns the quantity, computes nothing  -> must be SILENT
  /noisy        a counter that moves on every request   -> must be SILENT

`/order-clamp` and `/noisy` are what separate an oracle from a wordlist of
parameters called `qty`. Clamping is CORRECT behaviour, and a hit counter moves
for reasons that have nothing to do with the input.
"""
import json
import sys
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

UNIT = 25.0
HITS = {"n": 1000}


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def reply(self, code, obj):
        out = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        q = urllib.parse.parse_qs(u.query)
        raw = (q.get("quantity") or ["1"])[0]
        p = u.path.rstrip("/") or "/"
        try:
            qty = float(raw)
        except ValueError:
            return self.reply(400, {"error": "quantity must be a number"})

        if p == "/order":
            return self.reply(200, {"quantity": qty, "unit": UNIT, "total": round(UNIT * qty, 2)})
        if p == "/order-safe":
            if qty < 1:
                return self.reply(400, {"error": "quantity must be at least 1"})
            return self.reply(200, {"quantity": qty, "unit": UNIT, "total": round(UNIT * qty, 2)})
        if p == "/order-clamp":
            eff = max(qty, 1.0)
            return self.reply(200, {"quantity": qty, "unit": UNIT, "total": round(UNIT * eff, 2)})
        if p == "/echo":
            return self.reply(200, {"quantity": qty})
        if p == "/noisy":
            HITS["n"] += 1
            return self.reply(200, {"quantity": qty, "views": HITS["n"], "total": UNIT})
        return self.reply(404, {"error": "no such thing"})

    def log_message(self, *a):
        pass


class S(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    S(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
