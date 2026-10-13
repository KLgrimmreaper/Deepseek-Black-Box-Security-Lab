import time
from urllib.parse import urljoin, urlparse

import requests

BODY_LIMIT = 8000


class ScopeError(Exception):
    pass


class Scope:
    # a class because the request counter, the rate limit clock and the http session
    # have to be shared by every check in a run.
    def __init__(self, target, allowed_targets, max_requests=120, delay_ms=200, timeout=10):
        parsed = urlparse(target)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise ScopeError(f"target has to be a http(s) url with a host: {target}")
        self.origin = f"{parsed.scheme}://{parsed.netloc}"
        if self.origin not in allowed_targets:
            raise ScopeError(
                f"{self.origin} is not in ALLOWED_TARGETS, add it to .env if it is an authorised target"
            )
        self.max_requests = max_requests
        self.delay_ms = delay_ms
        self.timeout = timeout
        self.requests_sent = 0
        self.session = requests.Session()
        self.session.headers["User-Agent"] = "dsh-blackbox-lab/1.0 (authorised local test)"
        self._last_request_at = 0.0

    @property
    def is_https(self):
        return self.origin.startswith("https://")

    def request(self, method, path, **kwargs):
        if self.requests_sent >= self.max_requests:
            raise ScopeError(f"request budget of {self.max_requests} reached")
        url = urljoin(self.origin + "/", path.lstrip("/"))
        if urlparse(url).netloc != urlparse(self.origin).netloc:
            raise ScopeError(f"refusing to send a request off the target host: {url}")
        wait = self.delay_ms / 1000 - (time.monotonic() - self._last_request_at)
        if wait > 0:
            time.sleep(wait)
        # redirects are never followed, so a redirect cannot walk the runner off the allowed host
        kwargs.setdefault("allow_redirects", False)
        response = self.session.request(method, url, timeout=self.timeout, **kwargs)
        self.requests_sent += 1
        self._last_request_at = time.monotonic()
        return response

    def get(self, path, **kwargs):
        return self.request("GET", path, **kwargs)

    def post(self, path, **kwargs):
        return self.request("POST", path, **kwargs)


def body_snippet(response, limit=BODY_LIMIT):
    text = response.text
    if len(text) > limit:
        return text[:limit] + f"... [{len(text) - limit} more characters]"
    return text


def lower_headers(response):
    return {name.lower(): value for name, value in response.headers.items()}
