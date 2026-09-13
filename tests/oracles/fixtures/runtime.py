# An application whose API surface does not exist until it is running.
#
# /            an empty shell. No links, no content: the DOM is built by script.
# /app.js      fetches /config, then builds every later URL from what it returns.
#              The strings "/t/acme-7741/users" and friends appear NOWHERE in
#              any file the server serves. They are assembled at runtime.
# /config      returns the tenant id the URLs are built from.
#
# A static crawl can read app.js all day and never produce those paths. This is
# the case the headless tier exists for, and the one `spa` cannot reach.
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import sys

SHELL = """<!doctype html><html><head><title>Console</title></head>
<body><div id="root"></div><script src="/app.js"></script></body></html>"""

APP_JS = """
(async () => {
  const cfg = await (await fetch('/config')).json();
  const base = cfg.api_base, tenant = cfg.tenant;
  // Every one of these is assembled from values that arrived over the network.
  await fetch(`${base}/${tenant}/users`);
  await fetch(`${base}/${tenant}/invoices`, {method: 'POST', body: '{}'});
  await fetch(cfg.report_path);
  // And the DOM this page has is created here, not served.
  const a = document.createElement('a');
  a.href = `/${tenant}/settings`;
  a.textContent = 'Settings';
  document.getElementById('root').appendChild(a);
})();
"""

CONFIG = json.dumps({
    "api_base": "/t",
    "tenant": "acme-7741",
    "report_path": "/t/acme-7741/reports/quarterly",
})

ROUTES = {
    "/": ("text/html", SHELL),
    "/app.js": ("application/javascript", APP_JS),
    "/config": ("application/json", CONFIG),
}


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def respond(self):
        p = self.path.split("?")[0]
        ct, body = ROUTES.get(p, ("application/json", '{"ok":true}'))
        out = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(out)

    do_GET = respond
    do_POST = respond

    def log_message(self, *a):
        pass


ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
