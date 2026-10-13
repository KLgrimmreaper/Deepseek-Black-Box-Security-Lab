import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

ROOT_HTML = "<!doctype html><html><body><h1>fake lab app</h1></body></html>"
LOGIN_PATH = "/rest/user/login"
SEARCH_PATH = "/rest/products/search"

SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'self'",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
}

BAD_PAGE_HEADERS = {
    "Server": "FakeServer/1.0",
    "X-Powered-By": "FakeStack",
    # a session cookie with none of the protective attributes
    "Set-Cookie": "session=abc123; Path=/",
}


class FakeTarget:
    """a tiny http target with a deliberately sloppy and a deliberately hardened mode."""

    def __init__(self, hardened=False):
        self.hardened = hardened
        self.valid_logins = {("admin@example.com", "fakepass1")}
        self.login_attempts = 0
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), self._build_handler())
        self.origin = f"http://127.0.0.1:{self.server.server_address[1]}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def stop(self):
        self.server.shutdown()
        self.server.server_close()

    def _build_handler(self):
        target = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args):
                pass

            def send_response(self, code, message=None):
                # the stock handler always adds a Server header, which would hide the
                # server_info_disclosure check in both modes
                self.log_request(code)
                self.send_response_only(code, message)
                self.send_header("Date", self.date_time_string())

            def _send(self, status, body="", content_type="text/html; charset=utf-8", extra_headers=None):
                payload = body.encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(payload)))
                for name, value in (extra_headers or {}).items():
                    self.send_header(name, value)
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(payload)

            def _page_headers(self, cors=False):
                headers = dict(SECURITY_HEADERS) if target.hardened else dict(BAD_PAGE_HEADERS)
                if target.hardened:
                    headers["Set-Cookie"] = "session=fake; Path=/; Secure; HttpOnly; SameSite=Strict"
                elif cors:
                    origin = self.headers.get("Origin")
                    if origin:
                        headers["Access-Control-Allow-Origin"] = origin
                        headers["Access-Control-Allow-Credentials"] = "true"
                return headers

            def _read_body(self):
                length = int(self.headers.get("Content-Length") or 0)
                return self.rfile.read(length).decode("utf-8", "replace")

            def do_HEAD(self):
                self.do_GET()

            def do_GET(self):
                parts = urlsplit(self.path)
                route = parts.path
                query = parse_qs(parts.query)

                if route == "/":
                    if not target.hardened and "to" in query and "evil.example" in query["to"][0]:
                        return self._send(302, "", extra_headers={"Location": query["to"][0]})
                    return self._send(200, ROOT_HTML, extra_headers=self._page_headers(cors=True))

                if route in ("/robots.txt", "/sitemap.xml"):
                    if target.hardened:
                        return self._send(404, "not found", "text/plain")
                    if route == "/robots.txt":
                        return self._send(
                            200, "User-agent: *\nDisallow: /admin\nSitemap: /sitemap.xml\n", "text/plain"
                        )
                    return self._send(404, "not found", "text/plain")

                if route == "/.env":
                    if target.hardened:
                        return self._send(404, "not found", "text/plain")
                    return self._send(200, "DB_PASSWORD=fake\n", "text/plain")

                if route == "/metrics":
                    if target.hardened:
                        return self._send(404, "not found", "text/plain")
                    return self._send(200, "# metrics\nfake_requests_total 42\n", "text/plain")

                if route == "/admin":
                    # same body as the app root on purpose, this is the client side route
                    # that sensitive_paths has to ignore
                    return self._send(200, ROOT_HTML, extra_headers=self._page_headers())

                if route == SEARCH_PATH:
                    value = query.get("q", [""])[0]
                    if target.hardened:
                        value = value.replace("<", "&lt;").replace(">", "&gt;")
                    return self._send(200, f"<html><body>results for {value}</body></html>")

                if route.startswith("/rest/products/"):
                    if target.hardened:
                        return self._send(400, "bad request", "text/plain")
                    return self._send(
                        500,
                        'Traceback (most recent call last):\n  File "app.js", line 1\n'
                        "SequelizeDatabaseError: SQLITE_ERROR: syntax error",
                        "text/plain",
                    )

                return self._send(404, "not found", "text/plain")

            def do_OPTIONS(self):
                allow = "GET, HEAD" if target.hardened else "GET, POST, PUT, DELETE, TRACE"
                return self._send(200, "", extra_headers={"Allow": allow})

            def do_TRACE(self):
                if target.hardened:
                    return self._send(405, "method not allowed", "text/plain")
                return self._send(200, "TRACE / HTTP/1.1\r\nHost: fake\r\n", "text/plain")

            def do_POST(self):
                if urlsplit(self.path).path != LOGIN_PATH:
                    return self._send(404, "not found", "text/plain")
                body = self._read_body()
                try:
                    data = json.loads(body)
                except ValueError:
                    if target.hardened:
                        return self._send(400, "bad request", "text/plain")
                    return self._send(500, "SequelizeDatabaseError: unexpected token in JSON", "text/plain")

                email = str(data.get("email", ""))
                password = str(data.get("password", ""))
                target.login_attempts += 1

                if target.hardened:
                    if target.login_attempts > 3:
                        return self._send(429, "too many requests", "text/plain")
                    return self._send(401, json.dumps({"error": "invalid credentials"}), "application/json")

                if "' OR 1=1" in email or (email, password) in target.valid_logins:
                    return self._send(
                        200,
                        json.dumps({"authentication": {"token": "fake-token"}}),
                        "application/json",
                        extra_headers={"Set-Cookie": "session=fake; Path=/"},
                    )
                return self._send(401, json.dumps({"error": "invalid credentials"}), "application/json")

        return Handler
