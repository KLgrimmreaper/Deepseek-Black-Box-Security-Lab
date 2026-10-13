import re
import secrets
from hashlib import sha256
from urllib.parse import quote

from .scope import body_snippet, lower_headers

# every check returns a dict with:
#   result: passed | failed | error | not_applicable
#   detail: one line for the results table
#   evidence: what gets written to evidence/<run_id>/<check_id>.json
# a check never decides its own severity or whether it becomes a finding, the runner does that.

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


def http_evidence(response, limit=2000):
    return {
        "request": {"method": response.request.method, "url": response.request.url},
        "status": response.status_code,
        "headers": dict(response.headers),
        "body": body_snippet(response, limit),
    }


SECRET_FIELDS = ("token", "password", "access_token", "authorization")


def response_summary(response):
    # for the login checks: the body is kept so the evidence can be checked, but the value of
    # anything that looks like a token or a password is blanked out first
    return {
        "request": {"method": response.request.method, "url": response.request.url},
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


def looks_authenticated(response):
    if response.status_code != 200:
        return False
    body = response.text.lower()
    return any(key in body for key in ("token", "authenticated", "access_token", "sessionid"))


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
    responses = [
        scope.get("/"),
        scope.post(cfg["login_path"], json={"email": "nobody@example.com", "password": "not-the-password"}),
    ]
    cookies = []
    for response in responses:
        for raw in set_cookie_values(response):
            cookies.append({"url": response.request.url, "cookie": raw})
    evidence = {"responses": [response_summary(r) for r in responses], "set_cookie": cookies}
    if not cookies:
        return {
            "result": "not_applicable",
            "detail": "neither the main page nor the login endpoint set a cookie",
            "evidence": evidence,
        }
    problems = []
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
        if issues:
            problems.append(f"{name}: " + ", ".join(issues))
    evidence["problems"] = problems
    if not problems:
        return {"result": "passed", "detail": f"secure flags present on {len(cookies)} cookie(s)", "evidence": evidence}
    return {"result": "failed", "detail": "; ".join(problems), "evidence": evidence}


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
    if reflected and allow_credentials.lower() == "true":
        detail = "the sent origin is reflected and allow-credentials is true, any site can read authenticated responses"
        return {"result": "failed", "detail": detail, "evidence": evidence}
    if reflected:
        return {
            "result": "failed",
            "detail": "the sent origin https://evil.example is reflected in access-control-allow-origin",
            "evidence": evidence,
        }
    if wildcard:
        return {
            "result": "failed",
            "detail": "access-control-allow-origin is *, any site can read the response",
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
        detail.append("trace answered with 200")
    if risky:
        detail.append("options allows: " + ", ".join(risky))
    if detail:
        return {"result": "failed", "detail": "; ".join(detail), "evidence": evidence}
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
    reachable = []
    for path in SENSITIVE_PATHS:
        response = scope.get(path)
        probe = {"path": path, "status": response.status_code, "bytes": len(response.content)}
        if response.status_code in (401, 403):
            probe["note"] = "answers, but restricted"
            reachable.append(dict(probe))
        elif response.status_code == 200:
            if sha256(response.content[:2000]).hexdigest() == base_hash:
                # a single page app answers 200 with the app shell for unknown paths,
                # that is not an exposed file
                probe["note"] = "same body as the app root, treated as a client side route"
            else:
                probe["note"] = "served"
                probe["body"] = body_snippet(response, 300)
                reachable.append(dict(probe))
        probes.append(probe)
    evidence = {"base_status": base.status_code, "probes": probes, "reachable": reachable}
    if not reachable:
        return {"result": "passed", "detail": "none of the 16 probed paths was reachable", "evidence": evidence}
    paths = ", ".join(f"{item['path']} ({item['status']})" for item in reachable)
    return {"result": "failed", "detail": f"reachable: {paths}", "evidence": evidence}


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
    baseline = scope.post(
        cfg["login_path"],
        json={"email": f"nobody{secrets.token_hex(3)}@example.com", "password": "not-the-password"},
    )
    attempt = scope.post(cfg["login_path"], json={"email": SQLI_EMAIL, "password": "not-the-password"})
    baseline_ok = looks_authenticated(baseline)
    attempt_ok = looks_authenticated(attempt)
    evidence = {
        "baseline": response_summary(baseline),
        "payload": {"email": SQLI_EMAIL, "password": "not-the-password"},
        "payload_response": response_summary(attempt),
        "baseline_authenticated": baseline_ok,
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
    if attempt_ok:
        return {
            "result": "failed",
            "detail": f"'{SQLI_EMAIL}' was accepted where a normal bad login got {baseline.status_code}",
            "evidence": evidence,
        }
    return {
        "result": "passed",
        "detail": f"the payload got {attempt.status_code}, the same as a normal bad login",
        "evidence": evidence,
    }


def check_reflected_xss(scope, cfg):
    path = cfg["search_path"]
    separator = "&q=" if "?" in path else "?q="
    response = scope.get(f"{path}{separator}{quote(XSS_PAYLOAD, safe='')}")
    body = response.text
    evidence = {
        "payload": XSS_PAYLOAD,
        "response": http_evidence(response),
        "raw_payload_in_body": XSS_PAYLOAD in body,
        "marker_in_body": MARKER in body,
    }
    if XSS_PAYLOAD in body:
        return {
            "result": "failed",
            "detail": "the script tag came back unencoded in the response body",
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
    attempts = []
    accepted = None
    for entry in cfg["credentials"]:
        email, _, password = entry.partition(":")
        response = scope.post(cfg["login_path"], json={"email": email, "password": password})
        ok = looks_authenticated(response)
        attempts.append({"email": email, "status": response.status_code, "accepted": ok})
        if ok:
            accepted = email
            break
    evidence = {"attempts": attempts, "accepted": accepted}
    if accepted:
        return {
            "result": "failed",
            "detail": f"the login accepted {accepted} with a public demo password",
            "evidence": evidence,
        }
    if all(item["status"] in (404, 405, 501) for item in attempts):
        return {
            "result": "error",
            "detail": f"the login endpoint answered {attempts[0]['status']}, check LOGIN_PATH in .env",
            "evidence": evidence,
        }
    return {"result": "passed", "detail": f"none of the {len(attempts)} demo passwords worked", "evidence": evidence}


def check_rate_limit(scope, cfg):
    attempts = min(cfg["rate_limit_attempts"], 10)
    email = f"nobody{secrets.token_hex(3)}@example.com"
    statuses = []
    for _ in range(attempts):
        response = scope.post(cfg["login_path"], json={"email": email, "password": "not-the-password"})
        statuses.append(response.status_code)
    evidence = {"attempts": attempts, "statuses": statuses}
    if any(status in (429, 503) for status in statuses):
        first_throttled = next(index for index, status in enumerate(statuses) if status in (429, 503)) + 1
        return {
            "result": "passed",
            "detail": f"throttling appeared on attempt {first_throttled} of {attempts}",
            "evidence": evidence,
        }
    if any(status in (401, 403, 200) for status in statuses):
        return {
            "result": "failed",
            "detail": f"{attempts} quick login attempts, none of them answered 429 or 503",
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
