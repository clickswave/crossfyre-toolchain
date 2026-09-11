#!/usr/bin/env python3
"""A service that only the application is supposed to be able to reach.

Stands in for the Redis or Postgres a config file names, or that a port scan
found on the estate. It answers with a recognisable banner so a chain finding can
quote evidence.
"""
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def do_GET(self):
        body = b"PostgreSQL 15.4 on x86_64-pc-linux-gnu, internal only"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


class S(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    S(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
