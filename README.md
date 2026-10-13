# deepseek black-box security lab

a small local lab that tests a running web app from the outside. a deepseek model picks which
checks to run and writes up the findings. ordinary python code sends the requests, records the
responses, and decides the result of each check.

**read this first: `failed` means the problem is present in the target, not that the tool failed.**
a check "fails" when it finds the thing it was looking for. so on a vulnerable app most rows read
`failed`, and that is the scanner working correctly. the five result words are explained in
[the checks](#the-checks) section, and every one of them is tied to a recorded response.

what it is: 13 black-box http checks, chosen by a model from facts observed about the target, with
a markdown report and a dashboard.

what it is not: a ctf solver, and not a replacement for burp or zap. juice shop alone has more than
a hundred challenges and most of them (jwt tricks, business logic, anything that needs a browser)
are outside an http-only runner. it is 13 checks that say what they can and cannot prove.

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

## the dashboard

![the overview page](docs/dashboard-overview.png)

five pages, each one showing something the backend actually stored:

| page | what is on it |
|---|---|
| overview | run, check, finding and request totals, findings by severity, findings per run, the checks that failed most, and the spread of results |
| runs | start a run, the run list with live progress, and the detail for one run: the facts the runner observed, then tabs for results, plan, findings and the markdown report |
| check catalogue | all 13 checks with their severity, what they send, and the fallback fix text |
| findings | every finding from every run, filterable by severity, with the impact, remediation and raw evidence |
| settings | the values the backend loaded, and where data, evidence and reports are written |

the overview and the finding cards are built from real runs only, nothing is seeded. the screenshot
above is two smoke runs against a throwaway local http server on purpose, so the numbers are small.

each page has a url, so it can be linked to directly: `#overview`, `#runs`, `#catalogue`,
`#findings`, `#settings`. a single run is linkable too, for example `#runs/24`, which is what makes
one run easy to share or screenshot.

![the findings page](docs/dashboard-findings.png)


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

## how a run adapts to the target

the checklist above is the same for every target, but which parts of it make sense is not. so a run
goes round a loop instead of walking one fixed list:

```
observe    recon.py collects facts in python: content types, whether unknown paths return the app
           page, the allow header, any html login form and its field names, what the login endpoint
           answers to a failed json login, and whether the search endpoint exists
plan       deepseek is shown those facts plus the checks that have not run yet, and picks the next
           few with a reason each
validate   python decides which of the picks may actually run (see below)
test       the approved checks run, one at a time, through the existing runner
evaluate   the results so far go back to the model, which can ask for another round or stop
stop       when the checks are done, the budget is out, the iteration cap is reached, nothing left
           can run, or the model says further testing is unlikely to add evidence
```

the model cannot widen any of this. `MAX_ITERATIONS` (default 3) and `MAX_REQUESTS_PER_RUN` are
enforced in python, and neither is something the model can see or change.

### what is observed, and what is only inferred

| fact | how it is established |
|---|---|
| application shape | derived from content types plus whether a form or an app shell was seen |
| login shape | a form on the page, or the status of one failed json login attempt |
| login form fields | read out of the html with `html.parser` |
| search endpoint | one request, present unless it answers 404 |
| unknown path behaviour | one request to a path that does not exist, compared with the app root |

these are **observations, not conclusions**. "unknown paths return the app page" is a fact about
responses, and it is used to avoid calling a javascript route an exposed file. it is not a claim
about what the app is.

### which request format each login check uses

the three login checks send their attempts in the format that was actually observed, and the field
names come from the observed form, never from a guess:

| what was observed | what the login checks do |
|---|---|
| a json login api | post `{"email": ..., "password": ...}` to it |
| an html form with a recognisable username and password field | post those two fields to the form's own action, on the same host only |
| an html form whose fields cannot be mapped | `not_applicable`, naming the observed fields. nothing is filled in |
| a form whose action points at another host | the action is recorded as an observation, but the check is `not_applicable` because it is off scope |
| an authentication flow that answers 400 or wants a challenge | `error`, because a refusal and an acceptance cannot be told apart |
| no login endpoint at the configured path | `not_applicable`, with the observed status |

### a login check never reports a clean result it cannot support

this is the case that used to be a false clean, and it is the one worth remembering. if a wrong
password does not produce a refusal, there is no way to tell an accepted login from a refused one,
so a check that compares them proves nothing. the login checks therefore require a refusal first
(`401`, `403`, or a redirect back to a login page) and otherwise report `error` with the reason:

```
error   sql_injection_login   the login endpoint answered 200 to a wrong password without
                              refusing it, so an accepted and a refused login cannot be told
                              apart, so comparing the payload would prove nothing
```

a throttled endpoint is called out separately, because "we could not test the passwords" is a
different statement from "the passwords were refused":

```
error   weak_credentials      the login endpoint answered 429, which looks like throttling, so
                              the credentials could not be tested
```

## demo: the same loop against two mock applications

the mock applications used by the tests can be started on their own, which is the quickest way to
watch the adaptation happen. one command starts a target, another runs against it:

```powershell
# terminal 1: pick one of the mock apps
.\.venv\Scripts\python.exe -m backend.tests.fake_target --profile form-odd-fields --port 4010

# terminal 2: allow it, then run (the shell value overrides .env for this window)
$env:ALLOWED_TARGETS = "http://127.0.0.1:4010"
.\.venv\Scripts\python.exe -m backend.cli run --target http://127.0.0.1:4010 --mock
```

profiles: `json-vulnerable`, `json-hardened`, `form-vulnerable`, `form-hardened`,
`form-ambiguous-200`, `form-off-host`, `form-odd-fields`, `unsupported-auth`, `prompt-injection`.

**a json login api, where every check applies.** output trimmed to the planning lines and the
login checks:

```
run 11 against http://127.0.0.1:4010 (agent: mock agent (no api calls))
  checking the target
  target looks like javascript_driven with a json login
  planning round 1
  round 1: 13 check(s) from mock
  running sql_injection_login (9 of 13)
  ...
  failed         sql_injection_login          '' OR 1=1--' was accepted where a normal bad login got 401
  passed         weak_credentials             none of the 5 demo passwords worked
  needs_review   rate_limit                   10 quick login attempts all got 401, with no 429, no
                                              slowdown and no lockout. this does not show that throttling
                                              is absent, only that it did not trigger here
```

**an html form whose fields cannot be mapped, where three checks are skipped with a reason.** same
runner, same catalogue, different target:

```
run 13 against http://127.0.0.1:4012 (agent: mock agent (no api calls))
  checking the target
  target looks like server_rendered_html with a html_form login
  planning round 1
  skipping sql_injection_login: prerequisites not met
  skipping weak_credentials: prerequisites not met
  skipping rate_limit: prerequisites not met
  round 1: 10 check(s) from mock
  ...
  not_applicable sql_injection_login          the observed login form fields ['user_id', 'secret'] could not
                                              be mapped to a username and a password, so it was not filled in
  not_applicable weak_credentials             the observed login form fields ['user_id', 'secret'] could not
                                              be mapped to a username and a password, so it was not filled in
  not_applicable rate_limit                   the observed login form fields ['user_id', 'secret'] could not
                                              be mapped to a username and a password, so it was not filled in
  failed         cookie_flags                 session: no secure, no httponly, no samesite
```

the point of the second one is that the three checks are missing from the findings **with a reason
attached**, rather than being run against fields that do not mean what the check assumes. the other
ten checks still ran, and the report lists the skipped ones under "not tested or inconclusive".

with the real model the same run also plans in rounds and picks a subset. run 8 in the database
above is a real example against an external practice target: the model asked for six checks, saw
the results, then asked for four more.

### keeping the target out of the prompt

recon reduces the target to the facts above. **no page html and no response body text is sent to
the model**, so a page cannot smuggle instructions in through its own content. the few values that
are target authored (page title, server header) are truncated and passed under an `untrusted` key
with an explicit instruction that they are data. the model's reply is then validated: only
catalogue ids are read, only `id` and `reason` are kept, and anything else is dropped. a hostile
page can still influence which check ids the model picks, which is why the ids are checked and the
prerequisites are enforced in python rather than trusted.

### what is still coarse

- the application labels are hints, not conclusions. "javascript_driven" means an html root with no
  form that talks to a json api
- a login form whose field names do not look like a username and a password is skipped rather than
  guessed at, so an app that names its fields unusually gets no login coverage
- a json login api with different field names is only supported through `LOGIN_PATH`, not by
  observing the field names, because there is no form to read them from

## the checks

13 checks, all black-box, none of them destructive. every one of them can be confirmed from a
recorded response, and there is no fuzzing or exploitation beyond a login probe on a lab that is
built to be probed.

| id | category | severity | what it does |
|---|---|---|---|
| `security_headers` | misconfiguration | low | looks for missing csp, x-frame-options, x-content-type-options, referrer-policy (hsts is skipped on http targets and required on https) |
| `server_info_disclosure` | information leak | info | reports `server`, `x-powered-by` and similar headers |
| `cookie_flags` | session handling | medium | checks set-cookie on the main page and the login endpoint for secure, httponly, samesite |
| `cors_policy` | misconfiguration | medium | sends `origin: https://evil.example` and checks if it is reflected, especially with allow-credentials |
| `http_methods` | misconfiguration | low | sends options and trace, flags trace answering 200, and notes risky methods that are only advertised |
| `robots_disclosure` | information leak | info | reads robots.txt and sitemap.xml for path hints |
| `sensitive_paths` | exposure | medium | 16 fixed paths (`/.env`, `/.git/HEAD`, `/ftp`, `/metrics`, ...). only content served without authentication is a finding |
| `error_disclosure` | information leak | low | sends malformed input, looks for stack traces and database errors in the body |
| `sql_injection_login` | injection | high | baseline bad login, then `' OR 1=1--`, compares the two responses |
| `reflected_xss` | injection | high | puts a marker plus a script tag in the search parameter, checks if the tags come back unencoded in an html response |
| `open_redirect` | misconfiguration | medium | tries the `to`, `next` and `url` parameters with an off site address |
| `weak_credentials` | authentication | high | tries 5 well known demo passwords against the login endpoint |
| `rate_limit` | authentication | low | 10 quick failed logins, reports throttling when it appears as a 429, a lockout, or clearly slower answers |

a check returns one of five results, and each one has an evidence requirement. this is the part
that keeps the report honest, so it is worth reading before the check list:

| result | in plain english | what the evidence has to show | becomes a finding |
|---|---|---|---|
| `failed` | **the issue was found** | the recorded response directly demonstrates the condition the check describes (a header really is absent, a payload really was accepted, a file really was served) | yes, `confirmed` |
| `needs_review` | possibly an issue, a human decides | the response is consistent with the condition but does not demonstrate it (a 403 instead of a 200, no 429 seen after 10 tries, a wildcard cors header, a script tag reflected as json, a consent cookie, a method only advertised in `Allow`) | yes, `needs_review` |
| `passed` | that issue was not observed | the specific thing was checked and not found. it never means the target is clean | no |
| `not_applicable` | could not be tested | the check could not reach a conclusion at all (nothing reflected, no cookie set, no `Allow` header, or a prerequisite that this target does not meet) | no |
| `error` | could not run | the check could not complete (tls failure, timeout, budget reached, endpoint missing, or a login that gives no refusal to compare against) | no |

so on a real vulnerable target the rows you want to see are the `failed` ones. worked example from
a run against juice shop:

| check | result | what that actually means |
|---|---|---|
| `sql_injection_login` | `failed` | the sql injection is there. `' OR 1=1--` was accepted where a bad login got 401 |
| `weak_credentials` | `failed` | the default `admin@juice-sh.op` password works |
| `cors_policy` | `needs_review` | the header is `*`, but nothing sensitive was shown to be readable |
| `reflected_xss` | `not_applicable` | the search api returns json and never echoes the query, so there was nothing to judge. juice shop's reflected xss is in the client side route and needs a browser |

so a 403 on `/.env` is an observation that the path exists and is refused (which is correct
behaviour), not an exposure. ten login attempts that are all answered normally are an observation,
because ten requests cannot show that throttling is absent. and a `*` cors header is an
observation, because nothing sensitive was shown to be readable.

the same rule made two checks stricter in the other direction: `TRACE` answering with 200 is
directly demonstrated, so `http_methods` reports `failed` for that and `needs_review` for a method
that is merely listed in `Allow`.

findings from `needs_review` results are marked `needs_review` instead of `confirmed`, and the
report and dashboard both show which is which.

`sensitive_paths` compares each 200 response against the app root. single page apps answer 200
with the app shell for unknown paths, and reporting that as an exposed file would be a false
positive, so identical bodies are ignored.

## safety limits

these are all in ordinary code, outside the model:

- the target has to match an entry in `ALLOWED_TARGETS` exactly, so `http://localhost:3001` is refused when only `http://localhost:3000` is listed
- redirects are never followed. every request is sent with `allow_redirects=False`, so there are no redirect hops to validate and no way for a redirect to walk the runner off the allowed host. `open_redirect` records the `Location` header without visiting it
- `MAX_REQUESTS_PER_RUN` (default 120) is counted **before** each request goes out, so a timeout, a refused connection or an error still costs budget. a refused request (off host, or over budget) costs nothing, because nothing was sent
- `REQUEST_DELAY_MS` (default 200) between requests
- response bodies are truncated to 8kb when read and to 2kb in the evidence files
- login evidence keeps the response body so a finding can be checked, but the value of any `token` or `password` field is replaced with `[redacted]`
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
| `MAX_ITERATIONS` | `3` | how many observe, plan, test, evaluate rounds one run may take |
| `CA_BUNDLE` | empty | path to a ca certificate file, only for a lab target with a self signed certificate. adds a ca, never turns checking off |
| `MOCK_AGENT` | `0` | 1 skips the api and uses the fallback plan |
| `LOGIN_PATH` | `/rest/user/login` | the login endpoint the auth checks use |
| `SEARCH_PATH` | `/rest/products/search` | the search endpoint the xss check uses |
| `LAB_CREDENTIALS` | 5 demo logins | `email:password` pairs for the weak credentials check |

## http and https targets

both schemes are accepted, and the scheme is part of the allowlist match, so `https://localhost:3000`
and `http://localhost:3000` are two different targets and each has to be listed:

```ini
ALLOWED_TARGETS=https://localhost:3000
```

- certificate checking stays on. nothing in the code passes `verify=False`, and there is no option
  to turn it off. a failure is reported as `error`, never as a finding
- if the lab target uses a self signed certificate, point `CA_BUNDLE` at the ca file and the checks
  run normally:
  ```ini
  CA_BUNDLE=C:/certs/lab-ca.pem
  ```
  a relative path is resolved from the project folder. if the file is missing the run stops with a
  clear message instead of failing on every request
- over https, `security_headers` requires `strict-transport-security`. over http it skips it,
  because browsers ignore hsts on plain http
- redirects are never followed, over either scheme. a `302` to another host is recorded in the
  evidence as the response, and no request is made to the destination

what a connection problem looks like, rather than a vulnerability:

| what happened | recorded as |
|---|---|
| untrusted or self signed certificate | run `failed`, or the check `error`, with `tls certificate verification failed` and no finding |
| host refuses the connection | `could not connect to <target>` |
| host accepts but never answers | `did not answer within 10s` (or whatever `REQUEST_TIMEOUT` is) |
| budget reached mid check | that check `error` with `request budget of 120 reached`, the run still finishes |

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

the api the dashboard talks to:

| endpoint | what it returns |
|---|---|
| `GET /api/health` | the settings the backend loaded, whether a key is present, and the allowlist |
| `GET /api/checks` | the check catalogue |
| `GET /api/stats` | the totals and series the overview page draws |
| `GET /api/findings` | every finding across all runs, newest first |
| `POST /api/runs` | start a run (the body is the target and notes) |
| `GET /api/runs` | the run list with finding counts |
| `GET /api/runs/{id}` | one run with its plan, results and findings |
| `GET /api/runs/{id}/report` | the markdown report |
| `GET /api/runs/{id}/evidence/{check_id}` | the raw evidence json, only for catalogue check ids |

tests:

```powershell
.\.venv\Scripts\python.exe -m pytest backend/tests
```

the checks are tested against an in-process fake target (a small `http.server` in
`backend/tests/fake_target.py`) with a deliberately sloppy mode and a hardened mode, plus single
behaviour switches so one check can be pinned down at a time. the https tests use a throwaway
certificate authority in `backend/tests/certs/` so they need no network and no extra package.

## the behaviour matrix

`backend/tests/test_behaviour_matrix.py` holds 37 labelled cases. each one states what the target
does and what result the check has to return, written by hand next to the behaviour rather than
taken from the check. if a check starts claiming more than its evidence supports, the row fails.

```
37 cases covering all 13 checks
12 expect failed          12 expect passed
 9 expect needs_review     4 expect not_applicable
plus 1 run level row where the host is dead and the run has to fail without a finding
```

each row also asserts the finding status, so the vocabulary is tested end to end: `failed` has to
produce a `confirmed` finding, `needs_review` has to produce a `needs_review` finding, and the
other three results must produce no finding at all.

this is not a precision and recall benchmark, and i am not going to dress it up as one. the target
and the labels come from the same person, so recall here is true by construction. what it does
prove is that each check returns the documented result for a known behaviour, and that the cases
which used to be over-claimed now land in `needs_review`. real precision and recall would need a
hardened application with labels nobody derived from this code.

## what works and what i have verified

verified:

- 122 pytest tests pass (`122 passed in 59.57s`), covering the checks in both fake target modes, the 37 case behaviour matrix, a login check matrix across nine kinds of login (json, form, ambiguous 200, unmappable fields, off host action, unsupported flow, missing endpoint), the observe and plan loop with a scripted model, the scope rules over both schemes, the request budget including failed attempts, the evidence-before-finding rule, the stats queries, the interrupted run cleanup and report generation
- the false clean cases are tested explicitly: a form login that answers 200 to everything, and an auth flow that answers 400, must both come back as `error` and never as `passed`
- a form login is tested end to end against a local mock: the checks post the observed field names, the request format is recorded in the evidence with the values blanked, and a form whose action points off host is recorded but never requested
- the adaptive loop is tested with the deepseek api replaced by a scripted agent that asserts on the prompts: the model is offered only the checks that have not run, its second prompt contains the first round's results, a check that already ran is refused, the iteration cap stops a model that always wants more, and a model that keeps returning rubbish fails the run instead of leaving it looking clean
- the loop ran for real against juice shop with the real model and stopped itself: 3 rounds, 12 of the 13 checks planned, 51 requests, 8 findings. round 3's own note was *"the only other available check, server_info_disclosure, is already answered by the observed empty server and x-powered-by headers, so no further useful evidence is expected"*. nothing in the code tells it to skip a check whose answer is already visible in the facts, and it saved a request by predicting `passed` correctly (a later mock run of the same target confirmed `passed: no version or stack headers`)
- a hostile page is tested directly: a target whose page and header both say "IGNORE ALL PREVIOUS INSTRUCTIONS" cannot get that text into the prompt as an instruction, and a hostile plan is still refused
- the mock path is tested to make sure `MOCK_AGENT=1` never reaches the api at all
- a full run against OWASP Juice Shop in docker: with the fallback plan (48 requests) and with the real model (12 checks planned by deepseek, 47 requests, 8 findings, `reports/run_3.md`)
- the real deepseek call works end to end: the model planned 12 of the 13 checks with a reason each, wrote the impact and remediation for all 8 findings, and wrote the summary. every one of those texts is labelled as model written in the report and the dashboard
- the headline finding was checked by hand, not just trusted: a normal bad login returned `401` with 26 bytes of html, and `' OR 1=1--` returned `200` with 799 bytes of json reading `{"authentication":{"token":"[redacted]","bid":1,"umail":"admin@juice-sh.op"}}`, so the injection logs in as the first admin user
- the false positive fixes were re-run against Juice Shop and moved claims in both directions: its `Access-Control-Allow-Origin: *` now reports `needs_review` with "whether anything sensitive is readable was not established" instead of a confirmed finding, `rate_limit` now reports an observation instead of "no throttling", while `http_methods` (TRACE really answered 200) and `robots_disclosure` (the file really lists paths) moved from `needs_review` to `confirmed`, because those are demonstrated
- a run against a second, external target (`https://pentest-ground.com:81`, listed by OWASP as intentionally vulnerable) ran end to end over tls: 52 requests, 3 confirmed findings, 1 observation, and 3 checks correctly reported `error` because that app has no `/rest/user/login`, rather than inventing findings
- the interrupted run cleanup was checked against the real database: a run left in progress by a killed process now shows `failed` with "the process that started it is gone", instead of staying `running` forever
- tls behaviour is verified against a real tls socket: a trusted local ca is tested normally, an untrusted certificate fails the run with a clear message and zero findings, and a per check tls failure becomes `error`
- the dashboard typechecks, builds, and its five pages were each loaded in a browser against real data from those runs, which is where the screenshots in this readme come from

not verified:

- a hardened real target. the only clean target the checks have run against is the fake one in the tests, so the pass branches are tested, but not against a real hardened application
- nothing browser based is tested at all, because there is no browser in the pipeline

## two ways the settings can surprise you

both of these are environment variable behaviour, not bugs, and both cost me time:

1. **`.env` is read once, when the process starts.** changing it does nothing to a backend that is
   already running. the cli is fine, because every run is a new process.
2. **a shell variable beats `.env`.** `python-dotenv` does not overwrite a variable that is already
   set, so `$env:MOCK_AGENT = "1"` in the window you started uvicorn in will keep every run in mock
   mode even though the file says `0`, and `$env:ALLOWED_TARGETS = "http://x"` will make the whole
   allowlist just that one target.

the fastest way to see what a running backend actually loaded is the target field's placeholder in
the dashboard (it shows the first allowed target) and the **Settings** page, which lists them all.
if either disagrees with `.env`, restart the backend in a **fresh** window.

## known limitations

- one target at a time, and only targets on the allowlist
- reconnaissance now costs 6 requests per run instead of 3, because it probes the login endpoint, the search endpoint and one unknown path. that is the price of planning from observations rather than assumptions
- the application labels are coarse on purpose. "javascript_driven" means an html root with no form that talks to a json api, and it is a hint for the planner, not a statement about the app
- the login checks support two request formats: a json login api taking `email` and `password`, and an html form whose field names look like a username and a password. anything else is skipped rather than guessed at, which is honest but is still missing coverage
- a login endpoint that answers 200 to both a bad and a good login is now reported as `error` instead of `passed`, so it is no longer a false clean, but it also means such an app gets no login coverage at all
- the model still decides which checks to ask for, so a hostile page could nudge that choice. what it cannot do is add a check, change a path, widen the scope, exceed a budget or have its reasoning decide a result
- the result words describe the check, not the target in general. `failed` is a finding, `passed` only means the one specific thing was not observed, and neither is a verdict on the whole app
- no session or login handling, so anything behind a login is out of reach. on a login-gated app like dvwa, webgoat or mutillidae that means most of the app, and a csrf token field would stop the form checks filling a real login in
- the injection checks are shallow: one login payload and one reflected marker. they can show a problem exists, they cannot show a target is clean
- no browser, so most client side issues are out of reach. `reflected_xss` can only judge reflection, not whether a page actually executes it, and `open_redirect` only sees server side redirects
- redirects are never followed at all, which is deliberate. a target that only exposes a problem behind a redirect, such as a login page at a new path, is not tested
- `needs_review` is a judgement call made by the check, not by a person at run time. it means "the evidence does not demonstrate this", which is not the same as "this is probably fine"
- `cors_policy` only asks the main page, so it cannot tell whether a credentialed api endpoint is readable. it says so in the result
- checks run one at a time on purpose, so the request budget stays honest and the target is not hammered
- the run executes in a thread inside the api process, so stopping the api kills a run in progress. that run is then marked `failed` as interrupted the next time the backend starts, because a run only lives inside the process that started it and the row records that process id. this is not a job queue and there is no resume
- the pid check that closes interrupted runs is windows specific in its implementation (it asks the process handle instead of using `os.kill`, which is not a usable probe there). on other platforms it falls back to `os.kill(pid, 0)`, which i have not tested
- starting two runs at the same time works (each has its own budget) but both hit the same target
- the model summary can be vague or wrong. that is exactly why the result column never comes from the model
- the reasons in the plan table are model commentary, not evidence. against juice shop the model wrote things like "juice shop is famous for accepting well-known demo credentials", which is prior knowledge of a well known target rather than something the recon showed. treat the plan as the agent explaining itself, not as a finding
- `LAB_CREDENTIALS` defaults to public juice shop demo logins, so `weak_credentials` is not meaningful against a different target unless you change that list
- the test certificates expire in 10 years. after that the https tests fail with a verification error and `backend/tests/certs/README.md` explains how to regenerate them

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
  scope.py       the only place that builds a request url, plus the budget, the delay, the tls ca and the error types
  recon.py       observes the target and reduces it to facts, so no page text reaches a prompt
  catalogue.py   the explicit check list with severities, prerequisites and fallback fixes
  checks.py      the http checks, the result vocabulary and the pass or fail decisions
  runner.py      the observe, plan, test, evaluate loop and the deterministic gate
  agent.py       the deepseek calls: planning, write ups and the summary
  db.py          sqlite schema and queries
  report.py      markdown report
  tests/         pytest, with the fake target, the scripted model, the behaviour matrix and the test certificates
frontend/        react + typescript + vite dashboard
  src/api.ts     the fetch calls the pages use
  src/theme.ts   severity and result colours and ordering
  src/components/ Sidebar, Dashboard, RunsView, RunDetail, Catalogue, FindingsView, SettingsView, charts
  src/components/charts.tsx  the stat card, donut, area chart and bar list, plain svg, no chart library
lab/             docker compose for juice shop
docs/            the dashboard screenshots used in this readme
data/            sqlite file (gitignored)
evidence/        raw requests and responses per run (gitignored)
reports/         markdown report per run (gitignored)
```

## what i learned

- keeping a model inside a narrow role is more about what the code refuses to take from it than about the prompt. the model returns check ids, and the code validates them against a list and ignores everything else
- a "scanner" is really a pile of small explicit http checks with a written down decision rule for each one. most of the work is deciding what counts as a result
- evidence has to be written before a finding exists, otherwise the report makes claims the run cannot back up
- a false positive is usually a wrong assumption about the framework, not a bug. the single page app fallback answering 200 for `/admin` is the example that bit me here
- a check that cannot tell success from failure has to say so. the login comparison was the most dangerous bug here: it reported a pass on the strength of a comparison that could not distinguish an accepted login from a refused one, and a "passed" line in a report is believed
- a check's result is a claim, and the claim has to match the evidence. splitting "the response shows this" from "the response is consistent with this" removed more over-claiming than any amount of threshold tuning, and it made three checks report more, not less, because trace answering 200 and robots.txt listing a path really are demonstrated
- a request budget that is only incremented after a response is not a budget. timeouts and refused connections were free, which is the opposite of what you want when the target is misbehaving
- one ordering detail cost me a confusing failure: `requests.exceptions.ConnectTimeout` inherits from both `ConnectionError` and `Timeout`, so whichever you catch first decides whether a refused host is described as unreachable or slow
- testing a security tool without a vulnerable target needs a fake target with a bad mode and a good mode, and single switches per behaviour, otherwise you only ever test the failing branch
- sqlite needed WAL because a worker thread writes results while the dashboard polls the same file

## notes for anyone reading the code

- `checks.py` has no severity or title logic, and `catalogue.py` has no http logic. the runner joins them, which is why the two lists are checked against each other in the tests
- `Scope.request` is the only place a request is sent. everything else goes through it, which is what makes the allowlist check and the budget actually hold
- the model prompts are three short constants in `agent.py`, not a prompt framework
