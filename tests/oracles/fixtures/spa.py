# A single-page application that hides its surface the way real ones do.
#
# index.html links to exactly ONE file: /static/js/main.js. Everything else has
# to be recovered from inside that bundle.
#
#   /static/js/main.js       minified. Its API paths are FOLDED into a constant,
#                            so the readable ones are not in it at all. Carries a
#                            chunk map and a sourceMappingURL.
#   /static/js/main.js.map   the original source, where /api/v2/... is readable
#   /static/js/admin.7f21.js a lazily-loaded chunk nothing links to, holding the
#                            admin API calls and the admin routes
#
# A crawl that only follows what a page references sees one JS file and stops.
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import sys

INDEX = """<!doctype html><html><head><title>Console</title></head>
<body><div id="root"></div><script src="/static/js/main.js"></script></body></html>"""

# Minified: the paths are built from a constant, so grepping for "/api/v2/users"
# in this file finds nothing.
MAIN_JS = """var B="/api/v2";function f(p,o){return fetch(B+p,o)}
var R=[{path:"/",c:1},{path:"/reports/:id",c:2}];
var C=({1:"admin.7f21",2:"reports.3b90"}[e]+".js");
f("/u");f("/o");
//# sourceMappingURL=main.js.map
"""

# The original source, where everything is readable and complete.
MAIN_SRC = """export const BASE = '/api/v2';
export function listUsers() { return axios.get('/api/v2/users'); }
export function createOrder(b) { return axios.post('/api/v2/orders', b); }
export const routes = [{ path: '/', c: Home }, { path: '/reports/:id', c: Report }];
"""

MAP = json.dumps({
    "version": 3,
    "sources": ["src/api.js"],
    "sourcesContent": [MAIN_SRC],
})

# A chunk nothing links to. This is the admin section.
ADMIN_JS = """const routes=[{path:"/admin/users",c:AU},{path:"/admin/settings",c:AS}];
axios.post("/api/v2/admin/impersonate",{});
axios.delete("/api/v2/admin/users/:id");
"""

REPORTS_JS = """axios.get("/api/v2/reports/export");"""

ROUTES = {
    "/": ("text/html", INDEX),
    "/index.html": ("text/html", INDEX),
    "/static/js/main.js": ("application/javascript", MAIN_JS),
    "/static/js/main.js.map": ("application/json", MAP),
    "/static/js/admin.7f21.js": ("application/javascript", ADMIN_JS),
    "/static/js/reports.3b90.js": ("application/javascript", REPORTS_JS),
}


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        p = self.path.split("?")[0]
        ct, body = ROUTES.get(p, (None, None))
        if body is None:
            # History fallback, like every SPA: unknown paths serve the shell.
            ct, body = "text/html", INDEX
            code = 200
        else:
            code = 200
        out = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    def log_message(self, *a):
        pass


ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
