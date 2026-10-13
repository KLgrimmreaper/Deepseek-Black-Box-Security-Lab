# the explicit list of checks the agent is allowed to request.
# the model picks ids from here, it can never add a check that does not exist,
# and the pass or fail decision is made in checks.py, not by the model.
#
# severity is a fixed property of the check, so the model cannot talk a finding up or down.
# fix is the fallback text used when the model does not write a remediation.
#
# a check returns failed when the response directly demonstrates the condition it describes,
# and needs_review when the response is only consistent with it. the descriptions below say
# which of the two each check can produce, so the difference is visible before a run starts.
#
# "requires" names a fact that has to be observed on the target before the check can run.
# the gate for that lives in unmet_requirement below, and the facts come from recon.py, so a
# check is never run against a request format it does not support. saying nothing means the
# check works on any target.

CATALOGUE = [
    {
        "id": "security_headers",
        "name": "missing security headers",
        "category": "misconfiguration",
        "severity": "low",
        "description": "reads the main page and looks for a missing content-security-policy, x-frame-options, "
                       "x-content-type-options, referrer-policy or strict-transport-security header",
        "fix": "set the missing response headers, usually at the reverse proxy or in the framework defaults",
    },
    {
        "id": "server_info_disclosure",
        "name": "server software disclosed in headers",
        "category": "information leak",
        "severity": "info",
        "description": "reports server, x-powered-by and similar headers that tell an attacker which stack is running",
        "fix": "turn off or rewrite the version banners in the server configuration",
    },
    {
        "id": "cookie_flags",
        "name": "session cookie without secure flags",
        "category": "session handling",
        "severity": "medium",
        "description": "checks the main page and the login endpoint for set-cookie headers missing secure, httponly or "
                       "samesite. a cookie whose name does not look session like is only an observation",
        "fix": "set secure, httponly and samesite on every session cookie",
    },
    {
        "id": "cors_policy",
        "name": "permissive cors policy",
        "category": "misconfiguration",
        "severity": "medium",
        "description": "sends origin: https://evil.example and checks whether the origin is reflected back. a reflected "
                       "origin together with allow-credentials is a finding, a wildcard or a reflection without "
                       "credentials is an observation because nothing sensitive was shown to be readable",
        "fix": "return access-control-allow-origin only for origins you actually trust, never reflect the request origin "
               "while also sending allow-credentials",
    },
    {
        "id": "http_methods",
        "name": "risky http methods enabled",
        "category": "misconfiguration",
        "severity": "low",
        "description": "sends options and trace to the main page. trace answering with 200 is a finding, a risky method "
                       "that is only listed in the allow header is an observation",
        "fix": "disable trace at the server and restrict put, delete and patch to the routes that need them",
    },
    {
        "id": "robots_disclosure",
        "name": "robots.txt or sitemap.xml lists paths",
        "category": "information leak",
        "severity": "info",
        "description": "reads robots.txt and sitemap.xml and reports disallow and sitemap lines, which make a handy "
                       "target list for an attacker",
        "fix": "keep internal paths out of robots.txt, use authentication instead of obscurity",
    },
    {
        "id": "sensitive_paths",
        "name": "sensitive path reachable",
        "category": "exposure",
        "severity": "medium",
        "description": "requests a fixed 16 line list of paths such as /.env, /.git/HEAD, /ftp, /metrics and /server-status. "
                       "only content served to an unauthenticated request is a finding, a 401 or 403 means the server "
                       "refused it and is recorded without being called an exposure",
        "fix": "remove the file or route from the deployment, or block it at the proxy",
    },
    {
        "id": "error_disclosure",
        "name": "error details leaked to the client",
        "category": "information leak",
        "severity": "low",
        "description": "sends malformed input and looks for stack traces or database error strings in the response body",
        "fix": "return a generic error to the client and log the details on the server",
    },
    {
        "id": "sql_injection_login",
        "name": "sql injection in the login endpoint",
        "category": "injection",
        "severity": "high",
        "requires": "login_json",
        "description": "sends a normal failed login as a baseline and then the email payload ' OR 1=1-- and compares "
                       "the two responses",
        "fix": "use parameterised queries for the login lookup instead of building sql from the submitted values",
    },
    {
        "id": "reflected_xss",
        "name": "reflected input in the search parameter",
        "category": "injection",
        "severity": "high",
        "requires": "search_endpoint",
        "description": "sends a harmless marker plus a script tag to the search parameter and checks whether the tags "
                       "come back unencoded in an html response. reflection in a json response is recorded as an "
                       "encoding problem, because a browser does not run it",
        "fix": "encode output, or render the parameter as text instead of html",
    },
    {
        "id": "open_redirect",
        "name": "open redirect on a redirect parameter",
        "category": "misconfiguration",
        "severity": "medium",
        "description": "tries the common to, url and next parameters with an off site address and checks whether the "
                       "location header points there",
        "fix": "validate redirect targets against an allowlist of internal paths",
    },
    {
        "id": "weak_credentials",
        "name": "public demo credentials accepted",
        "category": "authentication",
        "severity": "high",
        "requires": "login_json",
        "description": "tries a short list of well known demo account passwords against the login endpoint",
        "fix": "change the default accounts and remove the demo users from anything that is not a training lab",
    },
    {
        "id": "rate_limit",
        "name": "no throttling on login attempts",
        "category": "authentication",
        "severity": "low",
        "requires": "login_json",
        "description": "sends 10 quick failed logins and reports throttling when it shows up as a 429, a lockout or "
                       "clearly slower answers. ten requests cannot show that throttling is absent, so a quiet run "
                       "is only an observation",
        "fix": "add rate limiting and account lockout on the login endpoint",
    },
]

CATALOGUE_BY_ID = {entry["id"]: entry for entry in CATALOGUE}

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}


def get_entry(check_id):
    return CATALOGUE_BY_ID.get(check_id)


def unmet_requirement(entry, profile):
    """why this check cannot run against the observed target, or None when it can.

    this is the deterministic gate. the model may ask for any catalogue id, but a check whose
    request format does not match what was observed is refused here rather than run and
    reported as a pass.
    """
    need = entry.get("requires")
    if not need:
        return None

    if need == "login_json":
        shape = profile.get("login_shape")
        if shape == "json":
            return None
        if shape == "html_form":
            return ("the login page is an html form and the login checks only speak the json login "
                    "api, so this was not run")
        return f"no json login endpoint was observed (login shape: {shape})"

    if need == "search_endpoint":
        search = profile.get("search_endpoint") or {}
        if search.get("present"):
            return None
        return f"no search endpoint answered at {search.get('path')} (status {search.get('status')})"

    return f"unknown requirement '{need}', so the check was not run"


def catalogue_ids():
    return [entry["id"] for entry in CATALOGUE]


def model_summary():
    # the compact view that gets sent to the model, one line per check
    return [
        {
            "id": entry["id"],
            "name": entry["name"],
            "category": entry["category"],
            "severity": entry["severity"],
            "description": entry["description"],
        }
        for entry in CATALOGUE
    ]
