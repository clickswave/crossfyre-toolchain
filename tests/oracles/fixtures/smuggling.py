#!/usr/bin/env python3
"""A CL.TE desync pair, and the same pair with the ambiguity rejected.

    smuggling.py <port> [safe]

The front-end listens on <port> and frames requests by Content-Length. Its
back-end runs inside this process on an ephemeral port and frames by
Transfer-Encoding. The disagreement is the bug: given a request carrying both
headers, the front-end forwards only the bytes Content-Length covers, and the
back-end, reading them as chunked, waits for a chunk header that is never coming.

With `safe`, the front-end rejects any request carrying both headers, which is
the fix and the negative half of the test.
"""
import socket
import socketserver
import sys
import threading
import time

BACKEND = ("127.0.0.1", 0)  # replaced at startup with the port the OS gave us


def read_headers(f):
    head = b""
    while b"\r\n\r\n" not in head:
        b = f.readline()
        if not b:
            return None
        head += b
    return head


def content_length(text):
    n = 0
    for line in text.split("\r\n"):
        if line.lower().startswith("content-length:"):
            try:
                n = int(line.split(":", 1)[1].strip())
            except ValueError:
                n = 0
    return n


class FrontEnd(socketserver.StreamRequestHandler):
    """Frames by Content-Length. Forwards verbatim to the back-end."""
    safe = False

    def handle(self):
        head = read_headers(self.rfile)
        if not head:
            return
        text = head.decode("latin-1")
        lower = text.lower()
        if self.safe and "transfer-encoding:" in lower and "content-length:" in lower:
            self.wfile.write(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
            return
        n = content_length(text)
        body = self.rfile.read(n) if n else b""
        try:
            up = socket.create_connection(BACKEND, timeout=12)
        except OSError:
            self.wfile.write(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
            return
        up.sendall(head + body)
        up.settimeout(12)
        out = b""
        try:
            while True:
                c = up.recv(65536)
                if not c:
                    break
                out += c
        except OSError:
            pass
        up.close()
        self.wfile.write(out or b"HTTP/1.1 504 Gateway Timeout\r\nContent-Length: 0\r\n\r\n")


class SafeFrontEnd(FrontEnd):
    safe = True


class BackEnd(socketserver.StreamRequestHandler):
    """Frames by Transfer-Encoding: chunked when present."""

    def handle(self):
        head = read_headers(self.rfile)
        if not head:
            return
        lower = head.decode("latin-1").lower()
        if "transfer-encoding:" in lower and "chunked" in lower:
            deadline = time.time() + 10
            while time.time() < deadline:
                line = self.rfile.readline()
                if not line:
                    break
                try:
                    size = int(line.strip().split(b";")[0] or b"0", 16)
                except ValueError:
                    break
                if size == 0:
                    self.rfile.readline()
                    break
                self.rfile.read(size)
                self.rfile.readline()
        else:
            n = content_length(head.decode("latin-1"))
            if n:
                self.rfile.read(n)
        body = b"backend-ok"
        self.wfile.write(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: "
            + str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n" + body
        )


class S(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    port = int(sys.argv[1])
    safe = len(sys.argv) > 2 and sys.argv[2] == "safe"
    back = S(("127.0.0.1", 0), BackEnd)
    BACKEND = ("127.0.0.1", back.server_address[1])
    threading.Thread(target=back.serve_forever, daemon=True).start()
    S(("127.0.0.1", port), SafeFrontEnd if safe else FrontEnd).serve_forever()
