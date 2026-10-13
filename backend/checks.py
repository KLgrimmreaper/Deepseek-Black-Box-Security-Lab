import re
import secrets
from hashlib import sha256
from urllib.parse import quote

from .scope import ScopeError, body_snippet, lower_headers

# every check returns a dict with:
#   result: failed | needs_review | passed | not_applicable | error
#   detail: one line for the results table
#   evidence: what gets written to evidence/<run_id>/<check_id>.json
#
# the result is a claim about the evidence, so each value has an evidence requirement:
#
#   failed          the recorded response directly demonstrates the condition the check describes
#                   (a header really is absent, a payload really was accepted, a file really was served)
#   needs_review    the response is consistent with the condition but does not demonstrate it
#                   (a 403 instead of a 200, no 429 seen, a wildcard header, a non html reflection,
#                   a non session cookie, a method only advertised). a human decides if it counts
#   passed          the specific thing was checked and not found. it never means the target is clean
#   not_applicable  the check could not reach a conclusion at all (nothing reflected, no cookie set)
#   error           the check could not run (tls failure, timeout, budget reached, endpoint missing)
#
# failed and needs_review both produce a finding, with status confirmed and needs_review respectively.
# a check never decides its own severity and never writes a finding, the runner does that.

SENSITIVE_PATHS = [
    "/.env",
    "/.git/HEAD",
    "/ftp",
    "/metrics",
    "/api-docs",
    "/swagger.json",
    "/server-status",
    "/actuator/health",
    "/backup.zip",
    "/config.json",
    "/db.sqlite",
    "/package.json",
    "/.DS_Store",
    "/admin",
    "/.well-known/security.txt",
    "/rest/admin/application-configuration",
]

ERROR_MARKERS = [
    "traceback (most recent call last)",
    "sqlite_error",
    "sqlstate[",
    "you have an error in your sql syntax",
    "sequelize",
    "at object.<anonymous>",
    "ora-01756",
    "microsoft ole db provider for sql server",
]

MARKER = "dshxss7f3a"
XSS_PAYLOAD = f"{MARKER}<script>alert(1)</script>"
SQLI_EMAIL = "' OR 1=1--"
REDIRECT_TARGET = "https://evil.example/dsh-lab"
REDIRECT_PARAMS = ["/?to=", "/?next=", "/redirect?url="]

# a cookie whose name suggests a session is judged as one, other cookies are only observations
SESSION_COOKIE_HINTS = ("session", "sess", "sid", "token", "auth", "jwt", "remember", "login")

# paths and words that point at an authentication page
LOGIN_HINTS = ("login", "log-in", "signin", "sign-in", "signon", "auth")

# words a page shows after a successful form login, used only when the answer is a page
FORM_SUCCESS_HINTS = ("logout", "log out", "sign out", "dashboard")


def form_field_names(form):
    """picks the username and password fields out of the names that were actually observed.

    it recognises names, it never guesses one. a form whose fields do not look like a username
    and a password is refused, so credentials are never posted into the wrong field.
    """
    names = [str(name) for name in ((form or {}).get("fields") or [])]
    password = next((name for name in names if "pass" in name.lower()), "")
    username = next(
        (
            name
            for name in names
            if name != password and any(hint in name.lower() for hint in ("user", "email", "login", "name"))
        ),
        "",
    )
    if not username or not password:
        return None
    return username, password


def login_mode(cfg):
    """which request format the observed login endpoint speaks."""
    profile = cfg.get("profile") or {}
    return "form" if profile.get("login_shape") == "html_form" else "json"


def login_path(cfg):
    profile = cfg.get("profile") or {}
    if login_mode(cfg) == "form":
        return (profile.get("login_form") or {}).get("path") or cfg["login_path"]
    return cfg["login_path"]


def login_attempt(scope, cfg, username, password):
    """one login attempt, sent in the format that was observed on this target.

    the only things taken from the target are the request format and the field names, both of
    which came from recon. the username and the password are always ours.
    """
    if login_mode(cfg) == "form":
        mapping = form_field_names((cfg.get("profile") or {}).get("login_form"))
        if mapping is None:
            raise ScopeError("the observed login form fields could not be mapped to a username and a password")
        username_field, password_field = mapping
        return scope.post(login_path(cfg), data={username_field: username, password_field: password})
    return scope.post(login_path(cfg), json={"email": username, "password": password})


def http_evidence(response, limit=2000):
    return {
        "request": {"method": response.request.method, "url": response.request.url},
        "status": response.status_code,
        "headers": dict(response.headers),
        "body": body_snippet(response, limit),
    }


SECRET_FIELDS = ("token", "password", "access_token", "authorization")


def posted_fields(response):
    """the names of the form fields that were posted, with every value blanked out.

    a form mode finding has to show how the login was sent, and the field names are what makes
    it checkable. the values are never stored.
    """
    body = response.request.body
    if not isinstance(body, str) or not body:
        return ""
    if body.lstrip().startswith("{"):
        return "[json body, values not stored]"
    return "&".join(f"{part.partition('=')[0]}=[sent]" for part in body.split("&") if part)


def response_summary(response):
    # for the login checks: the body is kept so the evidence can be checked, but the value of
    # anything that looks like a token or a password is blanked out first
    return {
        "request": {"method": response.request.method, "url": response.request.url},
        "posted_fields": posted_fields(response),
        "status": response.status_code,
        "headers": dict(response.headers),
        "body": redacted_body(response),
        "body_note": "token and password values are replaced with [redacted], everything else is unchanged",
    }


def redacted_body(response, limit=1200):
    text = body_snippet(response, limit)
    for field in SECRET_FIELDS:
        text = re.sub(rf'("{field}"\s*:\s*)"[^"]*"', rf'\1"[redacted]"', text, flags=re.IGNORECASE)
    return text


def set_cookie_values(response):
    try:
        return response.raw.headers.getlist("Set-Cookie")
    except AttributeError:
        value = response.headers.get("Set-Cookie")
        return [value] if value else []


def looks_authenticated(response, form_mode=False):
    if form_mode:
        if response.status_code in (301, 302, 303, 307, 308):
            # a form login that worked usually redirects away from the login page
            location = (response.headers.get("Location") or "").lower()
            return not any(hint in location for hint in LOGIN_HINTS)
        if response.status_code == 200:
            body = response.text.lower()
            return any(hint in body for hint in FORM_SUCCESS_HINTS)
        return False
    if response.status_code != 200:
        return False
    body = response.text.lower()
    return any(key in body for key in ("token", "authenticated", "access_token", "sessionid"))


def looks_rejected(response):
    """did the login endpoint refuse these credentials in a way we can compare against?

    this is what stops a false clean. when a wrong password does not produce a refusal, an
    accepted login and a refused one cannot be told apart, and a check that compares them
    proves nothing.
    """
    if response.status_code in (401, 403):
        return True
    if response.status_code in (301, 302, 303, 307, 308):
        location = (response.headers.get("Location") or "").lower()
        return any(hint in location for hint in LOGIN_HINTS)
    return False


def no_refusal_reason(response):
    """why a login comparison cannot be trusted, for a response that did not refuse."""
    if response.status_code in (429, 503):
        return (
            f"the login endpoint answered {response.status_code}, which looks like throttling, so the "
            "credentials could not be tested"
        )
    return (
        f"the login endpoint answered {response.status_code} to a wrong password without refusing it, so an "
        "accepted and a refused login cannot be told apart"
    )


def search_url(cfg, value):
    path = cfg["search_path"]
    separator = "&q=" if "?" in path else "?q="
    return f"{path}{separator}{quote(value, safe='')}"


def check_security_headers(scope, cfg):
    response = scope.get("/")
    headers = lower_headers(response)
    wanted = [
        "content-security-policy",
        "x-frame-options",
        "x-content-type-options",
        "referrer-policy",
        "strict-transport-security",
    ]
    missing = [name for name in wanted if name not in headers]
    note = ""
    if not scope.is_https and "strict-transport-security" in missing:
        # hsts is ignored by browsers over plain http, so it is not a finding here
        missing.remove("strict-transport-security")
        note = " (strict-transport-security skipped, the target is http)"
    evidence = http_evidence(response)
    evidence["missing_headers"] = missing
    if not missing:
        return {"result": "passed", "detail": f"all checked headers are present{note}", "evidence": evidence}
    return {"result": "failed", "detail": "missing headers: " + ", ".join(missing) + note, "evidence": evidence}


def check_server_info_disclosure(scope, cfg):
    response = scope.get("/")
    headers = lower_headers(response)
    disclosing = {
        name: headers[name]
        for name in ("server", "x-powered-by", "x-aspnet-version", "x-generator")
        if name in headers
    }
    evidence = http_evidence(response)
    evidence["disclosing_headers"] = disclosing
    if not disclosing:
        return {"result": "passed", "detail": "no version or stack headers in the response", "evidence": evidence}
    detail = "headers that reveal the stack: " + ", ".join(f"{k}: {v}" for k, v in disclosing.items())
    return {"result": "failed", "detail": detail, "evidence": evidence}


def check_cookie_flags(scope, cfg):
    responses = [scope.get("/")]
    login_note = ""
    try:
        # the login response often sets the session cookie, but a cookie check does not need to
        # log in, so a login that cannot be sent is recorded as a note rather than a failure
        responses.append(login_attempt(scope, cfg, "nobody@example.com", "not-the-password"))
    except ScopeError as exc:
        login_note = str(exc)
    cookies = []
    for response in responses:
        for raw in set_cookie_values(response):
            cookies.append({"url": response.request.url, "cookie": raw})
    evidence = {"responses": [response_summary(r) for r in responses], "set_cookie": cookies}
    if login_note:
        evidence["login_response"] = f"not probed: {login_note}"
    if not cookies:
        return {
            "result": "not_applicable",
            "detail": "neither the main page nor the login endpoint set a cookie",
            "evidence": evidence,
        }
    problems = []
    observations = []
    for item in cookies:
        parts = [part.strip() for part in item["cookie"].split(";")]
        name = parts[0].split("=")[0].strip()
        attributes = {part.split("=")[0].strip().lower() for part in parts[1:]}
        issues = []
        if "secure" not in attributes:
            issues.append("no secure")
        if "httponly" not in attributes:
            issues.append("no httponly")
        if not any(attribute.startswith("samesite") for attribute in attributes):
            issues.append("no samesite")
        if not issues:
            continue
        lowered = name.lower()
        if any(hint in lowered for hint in SESSION_COOKIE_HINTS):
            problems.append(f"{name}: " + ", ".join(issues))
        else:
            # a preference or consent cookie missing httponly is not a session handling problem
            observations.append(f"{name}: " + ", ".join(issues))
    evidence["session_cookie_problems"] = problems
    evidence["other_cookie_observations"] = observations
    if problems:
        return {"result": "failed", "detail": "; ".join(problems), "evidence": evidence}
    if observations:
        return {
            "result": "needs_review",
            "detail": "no session cookie was set, but non session cookie(s) lack protective flags: "
                      + "; ".join(observations),
            "evidence": evidence,
        }
    return {"result": "passed", "detail": f"secure flags present on {len(cookies)} cookie(s)", "evidence": evidence}


def check_cors_policy(scope, cfg):
    response = scope.get("/", headers={"Origin": "https://evil.example"})
    headers = lower_headers(response)
    allow_origin = headers.get("access-control-allow-origin", "")
    allow_credentials = headers.get("access-control-allow-credentials", "")
    evidence = http_evidence(response)
    evidence["sent_origin"] = "https://evil.example"
    evidence["access_control_allow_origin"] = allow_origin
    evidence["access_control_allow_credentials"] = allow_credentials
    reflected = allow_origin == "https://evil.example"
    wildcard = allow_origin == "*"
    credentials = allow_credentials.lower() == "true"
    if reflected and credentials:
        # the header pair is what a browser acts on, so this is demonstrated rather than suspected
        return {
            "result": "failed",
            "detail": "the sent origin is reflected and allow-credentials is true, so a browser would let "
                      "https://evil.example read credentialed responses from this endpoint",
            "evidence": evidence,
        }
    if reflected:
        return {
            "result": "needs_review",
            "detail": "the sent origin https://evil.example is reflected, but allow-credentials is not true, so a "
                      "browser would only let it read responses that need no credentials",
            "evidence": evidence,
        }
    if wildcard:
        return {
            "result": "needs_review",
            "detail": "access-control-allow-origin is *, which lets any site read responses that need no "
                      "credentials. this run only asked for the main page, so whether anything sensitive is "
                      "readable was not established",
            "evidence": evidence,
        }
    if not allow_origin:
        return {"result": "passed", "detail": "no cors headers on the main page", "evidence": evidence}
    return {"result": "passed", "detail": f"allow-origin is limited to {allow_origin}", "evidence": evidence}


def check_http_methods(scope, cfg):
    options_response = scope.request("OPTIONS", "/")
    trace_response = scope.request("TRACE", "/")
    allow = lower_headers(options_response).get("allow", "")
    methods = {method.upper() for method in re.split(r"[,\s]+", allow) if method}
    risky = sorted(methods & {"TRACE", "PUT", "DELETE", "PATCH"})
    trace_allowed = trace_response.status_code == 200
    evidence = {
        "options": http_evidence(options_response),
        "trace": http_evidence(trace_response),
        "allow": allow,
        "risky_methods": risky,
    }
    detail = []
    if trace_allowed:
        # trace answering is demonstrated by the response, so this part is a finding
        detail.append("trace answered with 200, which echoes the request back")
        advertised = [method for method in risky if method != "TRACE"]
        if advertised:
            detail.append("options also advertises: " + ", ".join(advertised))
        return {"result": "failed", "detail": "; ".join(detail), "evidence": evidence}
    if risky:
        return {
            "result": "needs_review",
            "detail": "options advertises " + ", ".join(risky) + f" but the trace probe returned "
                      f"{trace_response.status_code}, so nothing was demonstrated to be enabled",
            "evidence": evidence,
        }
    if not allow:
        return {"result": "not_applicable", "detail": "no allow header in the options response", "evidence": evidence}
    return {"result": "passed", "detail": f"only {allow} allowed", "evidence": evidence}


def check_robots_disclosure(scope, cfg):
    responses = [(path, scope.get(path)) for path in ("/robots.txt", "/sitemap.xml")]
    hints = []
    for _, response in responses:
        if response.status_code == 200:
            hints += [
                line.strip()
                for line in response.text.splitlines()
                if line.strip().lower().startswith(("disallow:", "sitemap:"))
            ]
    evidence = {
        "responses": [http_evidence(response) for _, response in responses],
        "hints": hints,
    }
    if hints:
        return {
            "result": "failed",
            "detail": f"{len(hints)} path hint(s), for example {hints[0]}",
            "evidence": evidence,
        }
    if any(response.status_code == 200 for _, response in responses):
        return {"result": "passed", "detail": "robots.txt or sitemap.xml is served but lists nothing", "evidence": evidence}
    return {"result": "not_applicable", "detail": "no robots.txt or sitemap.xml", "evidence": evidence}


def check_sensitive_paths(scope, cfg):
    base = scope.get("/")
    base_hash = sha256(base.content[:2000]).hexdigest()
    probes = []
    served = []
    restricted = []
    for path in SENSITIVE_PATHS:
        response = scope.get(path)
        probe = {"path": path, "status": response.status_code, "bytes": len(response.content)}
        if response.status_code in (401, 403):
            # the path exists but the server refused it. that is the correct behaviour and
            # nothing was disclosed, so it is an observation and not an exposure
            probe["note"] = "access refused, nothing was disclosed"
            restricted.append(dict(probe))
        elif response.status_code == 200:
            if sha256(response.content[:2000]).hexdigest() == base_hash:
                # a single page app answers 200 with the app shell for unknown paths,
                # that is not an exposed file
                probe["note"] = "same body as the app root, treated as a client side route"
            else:
                probe["note"] = "served"
                probe["body"] = body_snippet(response, 300)
                served.append(dict(probe))
        probes.append(probe)
    evidence = {
        "base_status": base.status_code,
        "probes": probes,
        "served_without_authentication": served,
        "answered_but_refused": restricted,
    }
    if served:
        paths = ", ".join(f"{item['path']} ({item['status']})" for item in served)
        return {
            "result": "failed",
            "detail": f"content served to an unauthenticated request: {paths}",
            "evidence": evidence,
        }
    if restricted:
        paths = ", ".join(f"{item['path']} ({item['status']})" for item in restricted)
        return {
            "result": "needs_review",
            "detail": f"{len(restricted)} path(s) exist but refused access, so nothing leaked: {paths}",
            "evidence": evidence,
        }
    return {"result": "passed", "detail": "none of the 16 probed paths returned content", "evidence": evidence}


def check_error_disclosure(scope, cfg):
    probes = [
        ("malformed path parameter", scope.get("/rest/products/1%27")),
        (
            "malformed json body",
            scope.post(cfg["login_path"], data="{not valid json", headers={"Content-Type": "application/json"}),
        ),
    ]
    matches = []
    for label, response in probes:
        body = response.text.lower()
        for marker in ERROR_MARKERS:
            if marker in body:
                matches.append({"probe": label, "status": response.status_code, "marker": marker})
    evidence = {"responses": [http_evidence(r) for _, r in probes], "matches": matches}
    if matches:
        detail = "; ".join(f"{item['probe']} returned '{item['marker']}'" for item in matches)
        return {"result": "failed", "detail": detail, "evidence": evidence}
    return {"result": "passed", "detail": "no stack trace or database error in the responses", "evidence": evidence}


def check_sql_injection_login(scope, cfg):
    form = login_mode(cfg) == "form"
    baseline = login_attempt(scope, cfg, f"nobody{secrets.token_hex(3)}@example.com", "not-the-password")
    attempt = login_attempt(scope, cfg, SQLI_EMAIL, "not-the-password")
    baseline_ok = looks_authenticated(baseline, form)
    attempt_ok = looks_authenticated(attempt, form)
    baseline_rejected = looks_rejected(baseline)
    evidence = {
        "request_format": "form" if form else "json",
        "login_path": login_path(cfg),
        "baseline": response_summary(baseline),
        "payload": {"email": SQLI_EMAIL, "password": "not-the-password"},
        "payload_response": response_summary(attempt),
        "baseline_authenticated": baseline_ok,
        "baseline_rejected": baseline_rejected,
        "payload_authenticated": attempt_ok,
    }
    if baseline.status_code in (404, 405, 501):
        return {
            "result": "error",
            "detail": f"the login endpoint answered {baseline.status_code}, check LOGIN_PATH in .env",
            "evidence": evidence,
        }
    if baseline_ok:
        return {
            "result": "error",
            "detail": "the baseline login with a random email was accepted, so the payload result means nothing",
            "evidence": evidence,
        }
    if not baseline_rejected:
        # the endpoint answered a wrong password without refusing it, so there is nothing to
        # compare against and a "pass" here would be a false clean
        return {
            "result": "error",
            "detail": no_refusal_reason(baseline) + ", so comparing the payload would prove nothing",
            "evidence": evidence,
        }
    if attempt_ok:
        return {
            "result": "failed",
            "detail": f"'{SQLI_EMAIL}' was accepted where a normal bad login got {baseline.status_code}",
            "evidence": evidence,
        }
    return {
        "result": "passed",
        "detail": f"the payload was refused the same way a wrong password was ({attempt.status_code})",
        "evidence": evidence,
    }


def check_reflected_xss(scope, cfg):
    response = scope.get(search_url(cfg, XSS_PAYLOAD))
    body = response.text
    content_type = response.headers.get("Content-Type", "")
    is_html = "html" in content_type.lower()
    evidence = {
        "payload": XSS_PAYLOAD,
        "response": http_evidence(response),
        "content_type": content_type,
        "html_response": is_html,
        "raw_payload_in_body": XSS_PAYLOAD in body,
        "marker_in_body": MARKER in body,
    }
    if XSS_PAYLOAD in body and is_html:
        return {
            "result": "failed",
            "detail": "the script tag came back unencoded in an html response",
            "evidence": evidence,
        }
    if XSS_PAYLOAD in body:
        return {
            "result": "needs_review",
            "detail": f"the payload came back unencoded, but the response is {content_type or 'not html'}, which a "
                      "browser does not execute as html. this is an encoding problem, not proven xss",
            "evidence": evidence,
        }
    if MARKER in body or "&lt;script&gt;" in body:
        return {"result": "passed", "detail": "the input is reflected but encoded", "evidence": evidence}
    return {
        "result": "not_applicable",
        "detail": "the search parameter was not reflected in the response body",
        "evidence": evidence,
    }


def check_open_redirect(scope, cfg):
    quoted = quote(REDIRECT_TARGET, safe="")
    probes = []
    hits = []
    for param in REDIRECT_PARAMS:
        response = scope.get(param + quoted)
        location = response.headers.get("Location", "")
        probes.append({"param": param, "status": response.status_code, "location": location})
        if response.status_code in (301, 302, 303, 307, 308) and "evil.example" in location:
            hits.append({"param": param, "status": response.status_code, "location": location})
    evidence = {
        "target": REDIRECT_TARGET,
        "probes": probes,
        "hits": hits,
        "note": "only server side redirects on the to, next and url parameters are checked, "
                "client side redirects need a browser",
    }
    if hits:
        detail = "; ".join(f"{item['param']} redirected to {item['location']}" for item in hits)
        return {"result": "failed", "detail": detail, "evidence": evidence}
    return {"result": "passed", "detail": "no off site location header on the probed parameters", "evidence": evidence}


def check_weak_credentials(scope, cfg):
    form = login_mode(cfg) == "form"
    # one definitely wrong login first, because "none of the passwords worked" only means
    # something if the endpoint actually refuses a wrong password
    baseline = login_attempt(
        scope, cfg, f"nobody{secrets.token_hex(3)}@example.com", "definitely-not-the-password"
    )
    attempts = []
    accepted = None
    for entry in cfg["credentials"]:
        email, _, password = entry.partition(":")
        response = login_attempt(scope, cfg, email, password)
        ok = looks_authenticated(response, form)
        attempts.append({"email": email, "status": response.status_code, "accepted": ok})
        if ok:
            accepted = email
            break
    evidence = {
        "request_format": "form" if form else "json",
        "login_path": login_path(cfg),
        "baseline": response_summary(baseline),
        "baseline_rejected": looks_rejected(baseline),
        "attempts": attempts,
        "accepted": accepted,
    }
    if baseline.status_code in (404, 405, 501):
        return {
            "result": "error",
            "detail": f"the login endpoint answered {baseline.status_code}, check LOGIN_PATH in .env",
            "evidence": evidence,
        }
    if looks_authenticated(baseline, form):
        return {
            "result": "error",
            "detail": "a login with a random email and a random password was accepted, so this check means nothing",
            "evidence": evidence,
        }
    if not looks_rejected(baseline):
        return {
            "result": "error",
            "detail": no_refusal_reason(baseline) + ", so trying the demo passwords would prove nothing",
            "evidence": evidence,
        }
    if accepted:
        return {
            "result": "failed",
            "detail": f"the login accepted {accepted} with a public demo password",
            "evidence": evidence,
        }
    return {"result": "passed", "detail": f"none of the {len(attempts)} demo passwords worked", "evidence": evidence}


def _median(values):
    ordered = sorted(values)
    return ordered[len(ordered) // 2]


def check_rate_limit(scope, cfg):
    attempts = min(cfg["rate_limit_attempts"], 10)
    email = f"nobody{secrets.token_hex(3)}@example.com"
    attempt_log = []
    for _ in range(attempts):
        response = login_attempt(scope, cfg, email, "not-the-password")
        attempt_log.append({"status": response.status_code, "ms": scope.last_elapsed_ms})

    statuses = [item["status"] for item in attempt_log]
    evidence = {"attempts": attempts, "attempt_log": attempt_log, "request_format": login_mode(cfg)}

    throttled = [item for item in attempt_log if item["status"] in (429, 503)]
    if throttled:
        first = attempt_log.index(throttled[0]) + 1
        return {
            "result": "passed",
            "detail": f"throttling appeared on attempt {first} of {attempts} with status {throttled[0]['status']}",
            "evidence": evidence,
        }

    if len(set(statuses)) > 1 and statuses[0] in (200, 302, 401, 403):
        changed = next(item for item in attempt_log if item["status"] != statuses[0])
        return {
            "result": "needs_review",
            "detail": f"the login status changed from {statuses[0]} to {changed['status']} during the run, "
                      "which may be an account lockout rather than a throttle",
            "evidence": evidence,
        }

    window = max(1, attempts // 3)
    early = _median([item["ms"] for item in attempt_log[:window]])
    late = _median([item["ms"] for item in attempt_log[-window:]])
    if late > max(3 * early, 250):
        return {
            "result": "needs_review",
            "detail": f"responses slowed from about {early}ms to about {late}ms over {attempts} attempts, "
                      "which may be delay based throttling",
            "evidence": evidence,
        }

    # 302 and 303 are in here because a form login answers a wrong password with a redirect
    if any(status in (200, 301, 302, 303, 401, 403) for status in statuses):
        return {
            "result": "needs_review",
            "detail": f"{attempts} quick login attempts all got {statuses[0]}, with no 429, no slowdown and no "
                      "lockout. this does not show that throttling is absent, only that it did not trigger here",
            "evidence": evidence,
        }
    return {
        "result": "error",
        "detail": f"unexpected statuses from the login endpoint: {sorted(set(statuses))}",
        "evidence": evidence,
    }


CHECKS = {
    "security_headers": check_security_headers,
    "server_info_disclosure": check_server_info_disclosure,
    "cookie_flags": check_cookie_flags,
    "cors_policy": check_cors_policy,
    "http_methods": check_http_methods,
    "robots_disclosure": check_robots_disclosure,
    "sensitive_paths": check_sensitive_paths,
    "error_disclosure": check_error_disclosure,
    "sql_injection_login": check_sql_injection_login,
    "reflected_xss": check_reflected_xss,
    "open_redirect": check_open_redirect,
    "weak_credentials": check_weak_credentials,
    "rate_limit": check_rate_limit,
}
