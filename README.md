# deepseek black-box security lab

a small local lab that tests a running web app from the outside. a deepseek model picks which
checks to run and writes up the findings. ordinary python code sends the requests, records the
responses, and decides whether each check passed or failed.

the default target is OWASP Juice Shop in docker on localhost:3000.

## the idea

the interesting part of this project is where the model is and is not allowed to decide.

the model does two things:

1. it looks at a short recon summary and picks which checks to run from a fixed catalogue, with a reason for each
2. it writes the impact and remediation text for findings that the code already confirmed

the model does not do these things:

- it cannot add a check that is not in the catalogue, unknown ids are dropped
- it cannot decide a result, the pass or fail comes from the recorded status code and response body
- it cannot set a severity, severities live in the catalogue in code
- it cannot create a finding, a finding is only written when a check failed and its evidence file is on disk
- it cannot mark anything as verified

so the results table is evidence and the summary paragraph is commentary. the report and the
dashboard both label which is which.

## how a run works

```
POST /api/runs or cli run
  scope check        the target has to match ALLOWED_TARGETS exactly (scheme, host and port)
  recon              GET /, OPTIONS /, HEAD /, counted against the request budget
  planning           deepseek returns a json list of check ids and reasons (or the fallback plan)
  execution          each check sends its requests, one at a time, with a delay between them
  evidence           evidence/<run_id>/<check_id>.json gets the request, status, headers and body
  findings           written in code, only for failed checks that have an evidence file
  write up           deepseek writes impact and remediation for each finding
  report             reports/run_<id>.md
```

if a check fails but its evidence file cannot be written, the check is recorded as `error` and no
finding is created. a failed check with no evidence is not a finding.

## the checks

13 checks, all black-box, none of them destructive. every one of them can be confirmed from a
recorded response, and there is no fuzzing or exploitation beyond a login probe on a lab that is
built to be probed.

| id | category | severity | what it does |
|---|---|---|---|
| `security_headers` | misconfiguration | low | looks for missing csp, x-frame-options, x-content-type-options, referrer-policy (hsts is skipped on http targets) |
| `server_info_disclosure` | information leak | info | reports `server`, `x-powered-by` and similar headers |
| `cookie_flags` | session handling | medium | checks set-cookie on the main page and the login endpoint for secure, httponly, samesite |
| `cors_policy` | misconfiguration | medium | sends `origin: https://evil.example` and checks if it is reflected, especially with allow-credentials |
| `http_methods` | misconfiguration | low | sends options and trace, flags trace, put, delete or patch |
| `robots_disclosure` | information leak | info | reads robots.txt and sitemap.xml for path hints |
| `sensitive_paths` | exposure | medium | 16 fixed paths (`/.env`, `/.git/HEAD`, `/ftp`, `/metrics`, ...), reports the ones that answer 200, 401 or 403 |
| `error_disclosure` | information leak | low | sends malformed input, looks for stack traces and database errors in the body |
| `sql_injection_login` | injection | high | baseline bad login, then `' OR 1=1--`, compares the two responses |
| `reflected_xss` | injection | high | puts a marker plus a script tag in the search parameter, checks if the tags come back unencoded |
| `open_redirect` | misconfiguration | medium | tries the `to`, `next` and `url` parameters with an off site address |
| `weak_credentials` | authentication | high | tries 5 well known demo passwords against the login endpoint |
| `rate_limit` | authentication | low | 10 quick failed logins, reports whether anything answered 429 or 503 |

a check returns `passed`, `failed`, `error` or `not_applicable`. `not_applicable` means the check
could not reach a conclusion, for example a reflected xss check where the parameter is not
reflected at all, or a password check where the login endpoint does not exist.

findings from the softer checks (`server_info_disclosure`, `robots_disclosure`, `rate_limit`,
`http_methods`) are marked `needs_review` instead of `confirmed`, because a human should decide
whether they count.

`sensitive_paths` compares each 200 response against the app root. single page apps answer 200
with the app shell for unknown paths, and reporting that as an exposed file would be a false
positive, so identical bodies are ignored.

## safety limits

these are all in ordinary code, outside the model:

- the target has to match an entry in `ALLOWED_TARGETS` exactly, so `http://localhost:3001` is refused when only `http://localhost:3000` is listed
- redirects are never followed, so a redirect cannot walk the runner off the allowed host
- `MAX_REQUESTS_PER_RUN` (default 120) is counted in the scope object and the run stops with an error when it is reached
- `REQUEST_DELAY_MS` (default 200) between requests
- response bodies are truncated to 8kb when read and to 2kb in the evidence files
- login evidence stores the status and headers but not the response body, because a successful login response contains a session token
- the evidence endpoint only serves files for check ids that exist in the catalogue, so the path cannot be talked out of the evidence folder
- the api key is only read from the environment, `.env` is gitignored

keep this pointed at your own lab. the scope check is there to make an accident harder, not to
make hostile use acceptable.

## setup

python 3.12 or newer, node 20 or newer for the dashboard, docker for the lab target.

```powershell
# 1. the lab target (start docker desktop first)
docker compose -f lab/docker-compose.yml up -d
# juice shop is then on http://localhost:3000

# 2. python environment
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r backend\requirements.txt

# 3. settings
copy .env.example .env
# then put your key in .env: DEEPSEEK_API_KEY=sk-...
```

`.env` keys:

| key | default | meaning |
|---|---|---|
| `ALLOWED_TARGETS` | `http://localhost:3000` | comma separated list of targets a run may touch |
| `DEEPSEEK_API_KEY` | empty | required unless `MOCK_AGENT=1` or the run uses `--only` |
| `DEEPSEEK_MODEL` | `deepseek-chat` | model name sent to the api |
| `MAX_REQUESTS_PER_RUN` | `120` | hard cap for one run |
| `REQUEST_DELAY_MS` | `200` | pause between requests |
| `REQUEST_TIMEOUT` | `10` | seconds per request |
| `MOCK_AGENT` | `0` | 1 skips the api and uses the fallback plan |
| `LOGIN_PATH` | `/rest/user/login` | the login endpoint the auth checks use |
| `SEARCH_PATH` | `/rest/products/search` | the search endpoint the xss check uses |
| `LAB_CREDENTIALS` | 5 demo logins | `email:password` pairs for the weak credentials check |

## running it

from the terminal:

```powershell
# see what the agent is allowed to ask for
.\.venv\Scripts\python.exe -m backend.cli checks

# a full run, the model plans the checks
.\.venv\Scripts\python.exe -m backend.cli run --target http://localhost:3000 --notes "first run"

# no api calls, useful for testing the pipeline without a key
.\.venv\Scripts\python.exe -m backend.cli run --mock --only security_headers,sensitive_paths

# what has been run so far
.\.venv\Scripts\python.exe -m backend.cli runs
```

the dashboard:

```powershell
# backend on http://127.0.0.1:8000
.\.venv\Scripts\python.exe -m uvicorn backend.app:app --host 127.0.0.1 --port 8000

# in another terminal, the dev server on http://localhost:5173, it proxies /api to the backend
cd frontend
npm.cmd install
npm.cmd run dev
```

or build the dashboard once and let the backend serve it, so everything is on port 8000:

```powershell
cd frontend
npm.cmd run build
```

the dashboard shows the allowed targets, whether a key is loaded, the run list with live progress,
the plan with the model's reasons, a results table, the findings with their evidence, and the
markdown report for the run.

tests:

```powershell
.\.venv\Scripts\python.exe -m pytest backend/tests
```

the checks are tested against an in-process fake target (a small `http.server` in
`backend/tests/fake_target.py`) with a deliberately sloppy mode and a hardened mode. that means
the checks are tested for both false negatives and false positives without needing docker.

## what works and what i have verified

verified:

- 18 pytest tests pass (`18 passed in 5.00s`), covering the checks in both fake target modes, the scope rules, the request budget, the evidence-before-finding rule, and report generation
- a full run against a live local http server, from the cli and again through the http api: 13 checks, 52 requests, 3 findings, evidence files and `reports/run_2.md` written, the evidence and report endpoints both answering
- the dashboard typechecks (`tsc --noEmit`) and builds, and the built version is served by the backend on port 8000

not verified yet, because the docker daemon was not running and no key was configured while i
built this:

- a real run against OWASP Juice Shop. the request flow is identical to the http server run above, but i have not watched it against juice shop, so i am not claiming the check results for it
- a real deepseek api call. `--mock` and `--only` were used for every run so far, so the model planning and the explanations have not run against the real api yet

to close both gaps, start docker desktop and run:

```powershell
docker compose -f lab/docker-compose.yml up -d
.\.venv\Scripts\python.exe -m backend.cli run --target http://localhost:3000 --notes "juice shop, real model"
```

## known limitations

- one target at a time, and only targets on the allowlist
- no session or login handling, so anything behind a login is out of reach
- the injection checks are shallow: one login payload and one reflected marker. they can show a problem exists, they cannot show a target is clean
- http only, no browser, so most client side issues are out of reach. the open redirect check only sees server side redirects
- checks run one at a time on purpose, so the request budget stays honest and the target is not hammered
- the run executes in a thread inside the api process, so stopping the api kills a run in progress
- starting two runs at the same time works (each has its own budget) but both hit the same target
- the model summary can be vague or wrong. that is exactly why the result column never comes from the model
- `LAB_CREDENTIALS` defaults to public juice shop demo logins, so `weak_credentials` is not meaningful against a different target unless you change that list

## not built yet

- screenshots as evidence (would need playwright)
- a zap baseline scan as one more check id
- jwt checks (alg none, weak secret)
- pdf export of the report

## layout

```
backend/
  app.py         fastapi endpoints
  cli.py         run a test from the terminal
  config.py      .env loading and defaults
  scope.py       the only place that builds a request url, plus the budget and delay
  catalogue.py   the explicit check list with severities and fallback fixes
  checks.py      the http checks and the pass or fail decisions
  runner.py      recon, planning, execution, findings, report
  agent.py       the three deepseek calls
  db.py          sqlite schema and queries
  report.py      markdown report
  tests/         pytest, with the fake target
frontend/        react + typescript + vite dashboard
lab/             docker compose for juice shop
data/            sqlite file (gitignored)
evidence/        raw requests and responses per run (gitignored)
reports/         markdown report per run (gitignored)
```

## what i learned

- keeping a model inside a narrow role is more about what the code refuses to take from it than about the prompt. the model returns check ids, and the code validates them against a list and ignores everything else
- a "scanner" is really a pile of small explicit http checks with a written down decision rule for each one. most of the work is deciding what counts as a result
- evidence has to be written before a finding exists, otherwise the report makes claims the run cannot back up
- a false positive is usually a wrong assumption about the framework, not a bug. the single page app fallback answering 200 for `/admin` is the example that bit me here
- testing a security tool without a vulnerable target needs a fake target with a bad mode and a good mode, otherwise you only ever test the failing branch
- sqlite needed WAL because a worker thread writes results while the dashboard polls the same file

## notes for anyone reading the code

- `checks.py` has no severity or title logic, and `catalogue.py` has no http logic. the runner joins them, which is why the two lists are checked against each other in the tests
- `Scope.request` is the only place a request is sent. everything else goes through it, which is what makes the allowlist check and the budget actually hold
- the model prompts are three short constants in `agent.py`, not a prompt framework
