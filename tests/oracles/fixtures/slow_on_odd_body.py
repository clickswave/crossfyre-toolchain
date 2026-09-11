#!/usr/bin/env python3
"""One server that is slow about a body it does not like, however it is framed.

    slow_on_odd_body.py <port>

A single process, so a desync is impossible here by construction. It answers a
cleanly terminated chunked body at once, and takes eight seconds over anything
else - whether the request carries both framing headers or only one.

That is precisely the shape the timing oracle would misread. The ambiguous probe
is slow and its control is fast, which is the signature of a desync; the only
thing that says otherwise is asking again with ONE framing header and getting the
same delay. Without that control this server is reported as critical.
"""
import socketserver
import sys
import time

SLOW = 8.0


def read_headers(f):
    head = b""
    while b"\r\n\r\n" not in head:
        b = f.readline()
        if not b:
            return None
        head += b
    return head


class H(socketserver.StreamRequestHandler):
    def handle(self):
        head = read_headers(self.rfile)
        if head is None:
            return
        text = head.decode("latin-1")
        n = 0
        for line in text.split("\r\n"):
            if line.lower().startswith("content-length:"):
                try:
                    n = int(line.split(":", 1)[1].strip())
                except ValueError:
                    n = 0
        body = self.rfile.read(n) if n else b""
        # A clean terminating chunk is the only thing it is quick about. Note
        # this looks at the BODY, not at the headers: the delay has nothing to
        # do with any disagreement about framing, which is the whole point.
        if body.strip() not in (b"0", b"", b"0\r\n"):
            time.sleep(SLOW)
        out = b"ok"
        self.wfile.write(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: "
            + str(len(out)).encode() + b"\r\nConnection: close\r\n\r\n" + out
        )


class S(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    S(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
