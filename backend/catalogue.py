# the explicit list of checks the agent is allowed to request.
# the model picks ids from here, it can never add a check that does not exist,
# and the pass or fail decision is made in checks.py, not by the model.
#
# severity is a fixed property of the check, so the model cannot talk a finding up or down.
# fix is the fallback text used when the model does not write a remediation.

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
        "description": "checks the main page and the login endpoint for set-cookie headers missing secure, httponly or samesite",
        "fix": "set secure, httponly and samesite on every session cookie",
    },
    {
        "id": "cors_policy",
        "name": "permissive cors policy",
        "category": "misconfiguration",
        "severity": "medium",
        "description": "sends origin: https://evil.example and checks whether the origin is reflected back, "
                       "especially together with allow-credentials",
        "fix": "return access-control-allow-origin only for origins you actually trust, never reflect the request origin "
               "while also sending allow-credentials",
    },
    {
        "id": "http_methods",
        "name": "risky http methods enabled",
        "category": "misconfiguration",
        "severity": "low",
        "description": "sends options and trace to the main page and reports trace, put, delete or patch when they are allowed",
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
        "description": "requests a fixed 16 line list of paths such as /.env, /.git/HEAD, /ftp, /metrics and /server-status "
                       "and reports the ones that answer with 200, 401 or 403",
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
        "description": "sends a normal failed login as a baseline and then the email payload ' OR 1=1-- and compares "
                       "the two responses",
        "fix": "use parameterised queries for the login lookup instead of building sql from the submitted values",
    },
    {
        "id": "reflected_xss",
        "name": "reflected input in the search parameter",
        "category": "injection",
        "severity": "high",
        "description": "sends a harmless marker plus a script tag to the search parameter and checks whether the tags "
                       "come back unencoded in the response body",
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
        "description": "tries a short list of well known demo account passwords against the login endpoint",
        "fix": "change the default accounts and remove the demo users from anything that is not a training lab",
    },
    {
        "id": "rate_limit",
        "name": "no throttling on login attempts",
        "category": "authentication",
        "severity": "low",
        "description": "sends 10 quick failed logins and reports whether any request was answered with 429 or 503",
        "fix": "add rate limiting and account lockout on the login endpoint",
    },
]

CATALOGUE_BY_ID = {entry["id"]: entry for entry in CATALOGUE}

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}


def get_entry(check_id):
    return CATALOGUE_BY_ID.get(check_id)


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
