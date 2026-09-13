#!/usr/bin/env python3
"""A single-use limit, implemented four ways and mis-implemented once.

  /coupon       check-then-write with a real window     -> a race, must FIRE
  /coupon-safe  the same limit, held under a lock       -> must be SILENT
  /open         no limit at all, always accepts         -> must be SILENT
  /ratelimited  accepts a burst, then answers 429       -> must NOT be a race
  /noisy        always 200, body carries a fresh id     -> must be SILENT

The last three are the point. `/open` has nothing to race, `/ratelimited` is a
different bug wearing the same shape, and `/noisy` returns a different body every
time, so an oracle comparing bodies naively sees eight distinct "successes" and a
distinct late one. All three are ways to report a race that is not there.
"""
import itertools
import json
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

state = {"coupon": False, "coupon-safe": False, "ratelimited": 0}
LOCK = threading.Lock()
IDS = itertools.count(1)


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def reply(self, code, obj, extra_headers=()):
        out = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        for k, v in extra_headers:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(out)

    def do_GET(self):
        self.reply(200, {"ok": True, "hint": "POST here"})

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n:
            self.rfile.read(n)
        p = self.path.split("?")[0].strip("/")

        if p == "coupon":
            # The bug: read, then a window, then write.
            if state["coupon"]:
                return self.reply(409, {"error": "already redeemed"})
            time.sleep(0.05)
            state["coupon"] = True
            return self.reply(200, {"ok": True, "credit": 50})

        if p == "coupon-safe":
            # The fix: the check and the write are one indivisible step.
            with LOCK:
                if state["coupon-safe"]:
                    return self.reply(409, {"error": "already redeemed"})
                time.sleep(0.05)
                state["coupon-safe"] = True
            return self.reply(200, {"ok": True, "credit": 50})

        if p == "open":
            return self.reply(200, {"ok": True, "note": "no limit here"})

        if p == "ratelimited":
            with LOCK:
                state["ratelimited"] += 1
                k = state["ratelimited"]
            if k > 8:
                return self.reply(429, {"error": "slow down"}, [("Retry-After", "60")])
            return self.reply(200, {"ok": True})

        if p == "noisy":
            return self.reply(200, {"ok": True, "id": next(IDS), "at": time.time()})

        return self.reply(404, {"error": "no such thing"})

    def log_message(self, *a):
        pass


class S(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    S(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
