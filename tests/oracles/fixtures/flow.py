#!/usr/bin/env python3
"""A four-step checkout, enforced properly under /strict and not under /loose.

    login -> cart -> pay -> place

Under /loose, `place` checks only that a cart exists, so `pay` can be skipped and
the order can be placed twice; and `cart` fetches whatever cart id it is handed
without checking who owns it. Under /strict all three are enforced.

The CSRF token rotates per session and the cart id is per user, so a replay that
does not re-correlate fails outright. That is deliberate: a flow test whose clean
replay does not reproduce must report itself untestable rather than guess, and
this fixture is how that is proved.
"""
import http.cookies
import json
import secrets
import sys
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SESSIONS = {}
CARTS = {}


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def sess(self, create=False):
        c = http.cookies.SimpleCookie(self.headers.get("Cookie", ""))
        sid = c["sid"].value if "sid" in c else None
        if sid in SESSIONS:
            return sid, SESSIONS[sid]
        if not create:
            return None, None
        sid = secrets.token_hex(8)
        SESSIONS[sid] = {"csrf": "tok-" + secrets.token_hex(6), "cart": False,
                         "paid": False, "placed": False, "user": "anon", "cart_id": ""}
        return sid, SESSIONS[sid]

    def reply(self, code, body, set_sid=None):
        out = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(out)))
        if set_sid:
            self.send_header("Set-Cookie", f"sid={set_sid}; Path=/")
        self.end_headers()
        self.wfile.write(out)

    def form(self):
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n).decode() if n else ""
        return {k: v[0] for k, v in urllib.parse.parse_qs(raw).items()}

    def do_POST(self):
        parts = self.path.split("?")[0].strip("/").split("/")
        mode, action = (parts[0], parts[1]) if len(parts) == 2 else ("loose", parts[-1])
        strict = mode == "strict"

        if action == "login":
            sid, s = self.sess(create=True)
            f = self.form()
            s["user"] = f.get("user", "anon")
            s["cart_id"] = "cart-" + secrets.token_hex(5)
            CARTS[s["cart_id"]] = {"owner": s["user"],
                                   "secret": f"{s['user']}-private-{secrets.token_hex(4)}"}
            return self.reply(
                200,
                f'<form><input type="hidden" name="csrf" value="{s["csrf"]}">'
                f'<input type="hidden" name="cart_id" value="{s["cart_id"]}">'
                f'<span>signed in as {s["user"]}</span></form>',
                set_sid=sid,
            )

        sid, s = self.sess()
        if not s:
            return self.reply(401, "no session")
        f = self.form()
        if f.get("csrf") != s["csrf"]:
            return self.reply(403, "bad csrf")

        if action == "cart":
            s["cart"] = True
            cid = f.get("cart_id", s["cart_id"])
            c = CARTS.get(cid)
            if not c:
                return self.reply(404, "no such cart")
            # The bug: the cart is fetched by the id in the request and never
            # checked against the session that owns it.
            if strict and c["owner"] != s["user"]:
                return self.reply(403, "not your cart")
            return self.reply(
                200,
                f'<input type="hidden" name="csrf" value="{s["csrf"]}">'
                f'<input type="hidden" name="cart_id" value="{cid}">'
                f'cart ok for {c["owner"]} ref {c["secret"]}',
            )

        if action == "pay":
            if not s["cart"]:
                return self.reply(400, "nothing in the cart")
            s["paid"] = True
            return self.reply(200, f'<input type="hidden" name="csrf" value="{s["csrf"]}">paid')

        if action == "place":
            if not s["cart"]:
                return self.reply(400, "nothing in the cart")
            if strict:
                if not s["paid"]:
                    return self.reply(402, "payment required")
                if s["placed"]:
                    return self.reply(409, "already placed")
            s["placed"] = True
            return self.reply(200, "order placed")

        return self.reply(404, "no")

    def log_message(self, *a):
        pass


class S(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    S(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
