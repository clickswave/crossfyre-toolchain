#!/usr/bin/env python3
"""A host that accepts connections on every port and answers on none.

    blackhole_host.py <port>

Binds the given port AND the control port the chain oracle probes (47113), and
black-holes both: the connection is accepted and then nothing is ever sent.

This is the case the same-host control exists for. An address that swallows
packets is not a service, but it LOOKS like one to anything comparing against a
closed port on loopback, because a refusal and a silence are different answers.
Only asking the same host about a port nothing should be on tells them apart.
"""
import socket
import sys
import threading
import time

CONTROL_PORT = 47113  # keep in step with cortex chain::CONTROL_PORT


def swallow(port: int) -> None:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port))
    s.listen(64)
    while True:
        try:
            c, _ = s.accept()
            threading.Thread(target=lambda x: (time.sleep(30), x.close()),
                             args=(c,), daemon=True).start()
        except OSError:
            pass


if __name__ == "__main__":
    port = int(sys.argv[1])
    try:
        threading.Thread(target=swallow, args=(CONTROL_PORT,), daemon=True).start()
    except OSError as e:
        print(f"could not bind the control port {CONTROL_PORT}: {e}", file=sys.stderr)
        raise
    swallow(port)
