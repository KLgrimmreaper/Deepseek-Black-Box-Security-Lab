"""observes a target and turns what it sees into plain facts.

everything the model is told about a target comes from here, and every value is derived in
python first. no raw html from the target is ever put in a prompt, so a page cannot smuggle
instructions to the model through its own content.
"""

import secrets
from hashlib import sha256
from html.parser import HTMLParser

from .checks import looks_authenticated, search_url
from .scope import ScopeError, body_snippet, lower_headers

# links that usually lead to an authentication page
LOGIN_HINTS = ("login", "log-in", "signin", "sign-in", "signon", "auth")

# a path that very likely does not exist, used to see how the app answers unknown routes
UNKNOWN_PATH_PREFIX = "dsh-not-a-real-path-"

TITLE_LIMIT = 120


class _PageScan(HTMLParser):
    """collects the forms, the field names and the links out of one page of html."""

    def __init__(self):
        super().__init__()
        self.forms = []
        self.links = []
        self.title = ""
        self._form = None
        self._in_title = False

    def handle_starttag(self, tag, attrs):
        values = {name: (value or "") for name, value in attrs}
        if tag == "form":
            self._form = {
                "action": values.get("action", ""),
                "method": (values.get("method") or "get").lower(),
                "fields": [],
            }
        elif tag == "input" and self._form is not None:
            if values.get("name"):
                self._form["fields"].append(values["name"])
        elif tag == "a" and values.get("href"):
            self.links.append(values["href"])
        elif tag == "title":
            self._in_title = True

    def handle_endtag(self, tag):
        if tag == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None
        elif tag == "title":
            self._in_title = False

    def handle_data(self, data):
        if self._in_title:
            self.title += data


def scan_page(html):
    scanner = _PageScan()
    try:
        scanner.feed(html)
    except Exception:
        # a broken page should never stop a run, the facts we have are still usable
        pass
    return scanner


def _clean(value, limit=TITLE_LIMIT):
    # header values and page titles come from the target, so they are flattened and cut short
    # before they are used anywhere
    text = " ".join(str(value).split())
    return text[:limit]


def _login_link(links):
    for href in links:
        lowered = href.lower()
        if any(hint in lowered for hint in LOGIN_HINTS):
            return href
    return ""


def _looks_like_json(response):
    return "json" in (response.headers.get("Content-Type") or "").lower()


def application_shape(root_is_json, has_form, unknown_path_returns_app_shell, login_shape):
    """a rough label for what kind of app this looks like, using observed facts only.

    it is deliberately coarse. the point is to give the planner something honest to reason
    about, not to work out what product is running.
    """
    if root_is_json and not has_form:
        return "json_api"
    if has_form:
        return "server_rendered_html"
    if unknown_path_returns_app_shell:
        return "javascript_driven"
    if login_shape == "json":
        # an html page that talks to a json login api is an app driven by javascript
        return "javascript_driven"
    return "unknown"


def collect_recon(scope, cfg):
    """observes the target and returns the facts the planner is allowed to see."""
    try:
        base = scope.get("/")
        options = scope.request("OPTIONS", "/")
        head = scope.request("HEAD", "/")
    except ScopeError as exc:
        raise ScopeError(str(exc)) from exc

    scan = scan_page(base.text)
    base_headers = lower_headers(base)

    # how does this app answer a path that does not exist? this tells a server rendered app
    # apart from one that hands every route to a javascript shell
    missing = scope.get(f"/{UNKNOWN_PATH_PREFIX}{secrets.token_hex(4)}")
    app_shell = sha256(missing.content[:2000]).hexdigest() == sha256(base.content[:2000]).hexdigest()

    # find a login form, on this page or on the first page that looks like a login page
    form = next((item for item in scan.forms if item["method"] == "post" and len(item["fields"]) >= 2), None)
    linked_login = ""
    if form is None:
        linked_login = _login_link(scan.links)
        if linked_login:
            try:
                page = scope.get(linked_login)
            except ScopeError:
                page = None
            if page is not None and page.status_code == 200:
                linked = scan_page(page.text)
                form = next(
                    (item for item in linked.forms if item["method"] == "post" and len(item["fields"]) >= 2), None
                )
                if form is None:
                    linked_login = ""

    if form is not None:
        login_path = form["action"] or linked_login or "/"
        login_source = "form"
    else:
        login_path = cfg["login_path"]
        login_source = "configured"

    # one failed login tells us the shape of the login response without needing credentials
    login_probe = None
    if login_path:
        try:
            response = scope.post(
                login_path,
                json={"email": f"nobody{secrets.token_hex(3)}@example.com", "password": "not-the-password"},
            )
        except ScopeError:
            raise
        login_probe = {
            "path": login_path,
            "source": login_source,
            "status": response.status_code,
            "content_type": _clean(response.headers.get("Content-Type")),
            "json_response": _looks_like_json(response),
            "accepted": looks_authenticated(response),
            "body_sample": body_snippet(response, 200),
        }

    # and one query tells us whether the configured search endpoint exists at all
    search_response = scope.get(search_url(cfg, "dshprobe"))
    search_status = search_response.status_code

    if login_probe is None or login_probe["status"] in (404, 405, 501):
        login_shape = "absent"
    elif form is not None:
        # a form on the page wins, because the login checks post json and a form will not read it
        login_shape = "html_form"
    elif login_probe["status"] in (401, 403) or login_probe["json_response"]:
        # 401 or 403 to a json login attempt means the endpoint accepted the request format and
        # then judged the credentials, which is what a json login api does. juice shop answers a
        # failed login with an html error body, so the status is the reliable signal, not the type
        login_shape = "json"
    else:
        login_shape = "unknown"

    app_shape = application_shape(_looks_like_json(base), form is not None, app_shell, login_shape)
    profile = {
        "root_status": base.status_code,
        "root_content_type": _clean(base.headers.get("Content-Type")),
        "unknown_path_status": missing.status_code,
        "unknown_path_returns_app_shell": app_shell,
        "allow_header": _clean(options.headers.get("Allow", "")),
        "head_status": head.status_code,
        "application_shape": app_shape,
        "login_shape": login_shape,
        "login_form": (
            {"action": _clean(form["action"]), "method": form["method"], "fields": [_clean(f) for f in form["fields"]]}
            if form
            else None
        ),
        "login_probe": login_probe,
        "search_endpoint": {"path": cfg["search_path"], "status": search_status, "present": search_status != 404},
        # these three are target authored text, kept short and clearly marked as untrusted
        "untrusted": {
            "title": _clean(scan.title),
            "server_header": _clean(base_headers.get("server", "")),
            "powered_by": _clean(base_headers.get("x-powered-by", "")),
        },
    }
    return {"target": scope.origin, "https": scope.is_https, "profile": profile}
