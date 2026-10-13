import time
from pathlib import Path
from urllib.parse import urljoin, urlparse

import requests

BODY_LIMIT = 8000


class ScopeError(Exception):
    pass


class Scope:
    # a class because the request counter, the rate limit clock and the http session
    # have to be shared by every check in a run.
    def __init__(self, target, allowed_targets, max_requests=120, delay_ms=200, timeout=10, ca_bundle=""):
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
        self.ca_bundle = ca_bundle
        self.requests_sent = 0
        # how long the last response took, not counting the delay between requests, so the
        # rate limit check measures the target and not our own pacing
        self.last_elapsed_ms = 0
        self.session = requests.Session()
        self.session.headers["User-Agent"] = "dsh-blackbox-lab/1.0 (authorised local test)"
        # no verify argument is passed, so requests keeps its default of checking certificates
        # against the system trust store. CA_BUNDLE only adds a local ca for a lab target that
        # uses a self signed certificate, it never turns verification off.
        if ca_bundle:
            bundle = Path(ca_bundle)
            if not bundle.is_file():
                raise ScopeError(f"CA_BUNDLE does not point at a readable file: {bundle}")
            self.session.verify = str(bundle)
        self._last_request_at = 0.0

    @property
    def is_https(self):
        return self.origin.startswith("https://")

    def request(self, method, path, **kwargs):
        # these two only refuse work that was never sent, so a refused request costs no budget
        if self.requests_sent >= self.max_requests:
            raise ScopeError(f"request budget of {self.max_requests} reached")
        url = urljoin(self.origin + "/", path.lstrip("/"))
        if urlparse(url).netloc != urlparse(self.origin).netloc:
            raise ScopeError(f"refusing to send a request off the target host: {url}")
        wait = self.delay_ms / 1000 - (time.monotonic() - self._last_request_at)
        if wait > 0:
            time.sleep(wait)
        # counted before the request goes out, so a timeout or a refused connection still costs
        # budget. otherwise a target that never answers could be hit for free
        self.requests_sent += 1
        self._last_request_at = time.monotonic()
        # redirects are never followed, so a redirect cannot walk the runner off the allowed host.
        # that also means there are no redirect hops to count or validate
        kwargs.setdefault("allow_redirects", False)
        started = time.monotonic()
        try:
            return self.session.request(method, url, timeout=self.timeout, **kwargs)
        finally:
            self.last_elapsed_ms = int((time.monotonic() - started) * 1000)

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
