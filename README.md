# Financial Intelligence Platform (Local Prototype)

A demonstration system for **Track 3 (Finance)**: data-driven anomaly
detection, cash-flow forecasting, accounts-payable intelligence, an
expense/approval agent running on a durable local workflow engine, and a
Qwen-backed decision assistant — all behind an analyst console. This repository
is a **prototype**, not an EnterPro SDK and not a production deployment.
Everything runs in **mock mode by default** on synthetic or user-supplied data:
an anomaly score measures unusualness against an account's own history, it is
**not** a probability of fraud, forecasts are estimates of cash movement (never
guarantees), and no LLM output is ever an instruction to move money.

Design highlights:

* **Two processes, two credentials.** A scoring API ingests, scores, and serves
  the platform; an analyst dashboard BFF proxies to it. The scoring-service
  credential (`DEMO_API_TOKEN`) never reaches a browser — the dashboard uses a
  derived, HttpOnly session cookie.
* **Data-driven, not hardcoded.** Detection features are computed relative to
  *per-account baselines learned from the account's own ingested history*
  (cold-start accounts fall back to a labeled global reference). Currency,
  amounts, and direction come from the data; a settings store carries FX rates
  and workflow policy instead of constants in code.
* **Fail-closed configuration.** Both services refuse to serve traffic while a
  required token is empty or still a `<placeholder>`; the forecast endpoint
  returns `insufficient_data` instead of inventing numbers from thin history.
* **Alert-first, human-review-only.** A flagged transaction is persisted before
  any LLM call, and every flag routes to human review regardless of what the
  model recommends. Models may only suggest `monitor`, `review`, or
  `step_up_verification`.
* **Prompt-injection hardened.** Identifier fields are restricted to
  `[A-Za-z0-9_-]`, invoice/expense descriptions allow a narrow character set,
  unknown fields are rejected (`extra="forbid"`), payloads sent to models are
  minimized, and model output is re-validated against strict schemas.
* **Real workflow engine locally.** Expense approvals execute as durable steps
  (retry with backoff, notify-once, resumable after restart) through
  `app/enterpro_local.py`. `app/enterpro_workflow_pseudocode.py` remains a
  deliberately inert design sketch for the hosted platform (`NotImplementedError`
  everywhere, enforced by CI).

```
┌──────────────┐  CSV / XLSX upload   ┌─────────────────────────────┐
│   Browser    │ ───────────────────▶ │  Scoring API   fraud_demo   │
│  (console)   │  POST /transactions  │  :8000                      │
│              │ ───────────────────▶ │  • per-account baselines    │
│  Overview /  │                      │  • Isolation Forest + rules │
│  Alerts /    │                      │  • ingest (CSV/XLSX)        │
│  Ingest /    │                      │  • cash-flow forecast       │
│  Forecast /  │                      │  • invoices (AP risk)       │
│  Invoices /  │                      │  • expenses + workflow      │
│  Expenses /  │                      │  • Qwen assistant           │
│  Assistant   │                      │  (SQLite, migrations, FX)   │
└──────┬───────┘                      └─────────────▲───────────────┘
       │ session cookie                             │ X-API-Key
┌──────▼─────────────────────┐                      │
│  Dashboard BFF  dashboard  │──────────────────────┘
│  :8001 (cookie + CSRF,     │  only literal upstream paths,
│  strict CSP, whitelists)   │  never a generic proxy
└────────────────────────────┘
```

---

## Prerequisites

* **Option A (native):** Python 3.11+ (this prototype is pinned/tested on
  CPython 3.12.x) and `python3-venv`.
* **Option B (Docker):** Docker with Compose v2 (`docker compose version`).
  The provided `deploy/docker-compose.yml` targets Compose v2 syntax. The older
  standalone `docker-compose` v1 binary mostly works but has known quirks (see
  [Troubleshooting](#port-conflicts-and-compose-v1-quirks)).
* Optional: Node.js (`node --check`) for the front-end syntax gate that CI runs.

---

## 1. Verify the offline test suite first

Install dependencies into a virtualenv (uses the pinned transitive closure,
tested against this codebase):

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r deploy/requirements.lock.txt
```

Run all 105 offline tests (no network, no provider calls; mock mode):

```bash
cd app
QWEN_MODE=mock DEMO_API_TOKEN=ci-only-not-a-secret DASHBOARD_TOKEN=ci-only-not-a-secret \
  python -m unittest discover -s . -p "test_*.py" -v
```

If the suite is green, the build is sane. (Want just the direct dependencies?
`deploy/requirements.txt` lists them; prefer the lock file for reproducible runs.)

---

## 2. Run natively (fastest for a demo)

The provided launcher starts both services on loopback, generates strong
ephemeral tokens if you don't supply them, and writes logs under `run/`:

```bash
source .venv/bin/activate
./scripts/run_local.sh
```

* Dashboard (analyst console): **http://127.0.0.1:8001** — sign in with the
  printed `DASHBOARD_TOKEN`.
* Scoring API: **http://127.0.0.1:8000** (interactive docs at `:8000/docs`).
* Streaming / submitting traffic uses the printed `DEMO_API_TOKEN`.
* `Ctrl+C` stops both; the SQLite database stays in `run/`.

Override host ports if needed, and/or supply your own tokens:

```bash
API_PORT=8010 DASH_PORT=8011 DEMO_API_TOKEN=... DASHBOARD_TOKEN=... ./scripts/run_local.sh
```

### Manual start (no script)

```bash
cd app
export DEMO_API_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
export DASHBOARD_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
export QWEN_MODE=mock
python -m uvicorn fraud_demo:app --host 127.0.0.1 --port 8000 --workers 1
# in a second terminal:
cd app
export FRAUD_API_BASE_URL=http://127.0.0.1:8000 FRAUD_API_ALLOW_PRIVATE_HTTP=0 DASHBOARD_SECURE_COOKIES=0
python -m uvicorn dashboard:app --host 127.0.0.1 --port 8001 --workers 1
```

> `--workers 1` is required: the prototype keeps cross-request state in one
> SQLite file guarded by an in-process lock, and the workflow engine assumes a
> single writer. Scale by sharding tenants, or move to PostgreSQL plus a
> durable workflow engine before adding workers.

---

## 3. Run with Docker

### Build

Build the runtime image from the **repository root** (the Dockerfile expects the
repo root as build context):

```bash
docker build -f deploy/Dockerfile -t fraud-platform:local .
```

Optional: run the offline test suite *inside* the image as a build gate:

```bash
docker build -f deploy/Dockerfile --target test -t fraud-platform:test .
```

### Configure secrets

```bash
cp deploy/.env.example deploy/.env
chmod 600 deploy/.env
# edit deploy/.env and set DEMO_API_TOKEN and DASHBOARD_TOKEN to
# distinct random values, e.g.:
#   python -c 'import secrets; print(secrets.token_urlsafe(32))'
```

Both services **fail closed** (503/401) while a value is empty or still a
`<placeholder>`, so a mis-deploy cannot silently run unauthenticated.
`deploy/.env` is gitignored — never commit it.

### Start the stack

```bash
docker compose -f deploy/docker-compose.yml --env-file deploy/.env up -d --build
```

* Dashboard: **http://127.0.0.1:8001** — sign in with `DASHBOARD_TOKEN`.
* Scoring API: **http://127.0.0.1:8000**.
* The compose file hardens both containers: read-only root FS, `cap_drop: ALL`,
  `no-new-privileges`, loopback-published ports only, non-root user.

### Stop / tear down

```bash
docker compose -f deploy/docker-compose.yml --env-file deploy/.env down
# add -v to also delete the SQLite data volume
```

---

## 4. Deploy to Railway

[Railway](https://railway.com) runs this stack as **two services from one
image**: the scoring API and the dashboard BFF. The repo already contains the
Railway wiring; no local behavior changes:

* `railway.json` (repo root) — tells Railway to build `deploy/Dockerfile`,
  gives it a start command that listens on Railway's injected `PORT`, and
  enables `/health`-based checks with restart-on-failure. Both services stay
  at `numReplicas: 1` on purpose (SQLite single-writer design).
* `deploy/Dockerfile` — the image CMD now listens on `${PORT:-8000}` and picks
  the service via `${APP_MODULE:-fraud_demo:app}`, so the same image serves as
  either the API or the dashboard without a rebuild.
* `deploy/railway.env.example` — the per-service variables, documented.

### 1. Push to GitHub and create the project

Push this repository to GitHub, then in Railway: **New Project → Deploy from
GitHub repo** and select it. Railway reads `railway.json` and builds
`deploy/Dockerfile`. (If you deploy only a subdirectory, or Railway skips the
config file, set the service variable `RAILWAY_DOCKERFILE_PATH=deploy/Dockerfile`.)

### 2. Create the two services

The first service this repo deploys is the scoring API — **name it `api`**.
Add a second service from the **same repo** (`+ New → GitHub Repo` again) and
**name it `dashboard`**. The names matter: over Railway private networking the
dashboard reaches the API at `api.railway.internal`.

For the `dashboard` service only, set a custom start command (Settings →
Deploy):

```bash
python -m uvicorn dashboard:app --host 0.0.0.0 --port ${PORT:-8001} --workers 1
```

(or, if it inherits the shared `railway.json` command, just set the variable
`APP_MODULE=dashboard:app` instead — both produce the same process).

For the `api` service:

* Attach a **Volume** mounted at `/srv/data` (the image's `DEMO_DB_PATH`
  default) so the SQLite file survives restarts. Railway mounts volumes as
  root while this image runs as a non-root user, so also set the variable
  `RAILWAY_RUN_UID=0` on the api service. Skipping the volume also works for a
  demo — data then resets on every redeploy.
* Keep scaling at **1 replica** for both services (Settings → Scale): the
  prototype keeps cross-request state in one SQLite file guarded by an
  in-process lock, and the workflow engine assumes a single writer.

### 3. Set the variables

Set these per service (generate the two tokens as distinct random values:
`python -c "import secrets; print(secrets.token_urlsafe(32))"`; full
explanations in `deploy/railway.env.example`):

| Service | Variables |
| --- | --- |
| `api` | `PORT=8000`, `DEMO_API_TOKEN=<random>`, `QWEN_MODE=mock` |
| `dashboard` | `PORT=8001`, `APP_MODULE=dashboard:app` (if no custom start command), `DEMO_API_TOKEN=<same value>`, `DASHBOARD_TOKEN=<different random>`, `FRAUD_API_BASE_URL=http://api.railway.internal:8000`, `FRAUD_API_ALLOW_PRIVATE_HTTP=1`, `DASHBOARD_SECURE_COOKIES=1` |

`QWEN_MODE=mock` is demo-safe and provider-cost-free; for live Qwen calls also
set `DASHSCOPE_API_KEY`, `QWEN_BASE_URL`, and `QWEN_MODEL` (region rules in
`deploy/.env.example`). Railway redeploys on every variable change — wait for
both services to show a healthy deployment before continuing.

### 4. Expose the dashboard

On the **dashboard** service: Settings → Networking → Public Networking →
**Generate Domain** (target port 8001). Open the `.railway.app` URL and sign
in with `DASHBOARD_TOKEN` — the session cookie is already marked Secure.

Leave the **api** service without a public domain; the dashboard reaches it
privately (`http://api.railway.internal:8000`, Wireguard-encrypted, so plain
`http://` is correct there — `FRAUD_API_ALLOW_PRIVATE_HTTP=1` is the required
opt-in for a private non-loopback backend, by design). Generate a domain for
the api service only if you want to stream/ingest with `curl` or
`scripts/smoke.py` from your machine; every scoring endpoint requires
`X-API-Key: $DEMO_API_TOKEN` regardless.

---

## 5. Load data and smoke-test

### Upload your own transactions (CSV / Excel)

The console's **Ingest** tab uploads a CSV or `.xlsx` file; the API also accepts
direct calls. Required columns: `transaction_id`, `account_id`, `event_time`
(ISO-8601 **with timezone**), `amount_minor` (integer, minor units), `currency`,
`country`, `device_id`; optional: `direction` (`inflow`/`outflow`).

```bash
TOKEN='<service token>'
curl -s http://127.0.0.1:8000/ingest/csv \
  -H "X-API-Key: $TOKEN" \
  -F "file=@transactions.csv"
# spreadsheets with different headers: map them explicitly
curl -s http://127.0.0.1:8000/ingest/csv \
  -H "X-API-Key: $TOKEN" \
  -F "file=@export.xlsx" \
  -F 'column_map_json={"Amount":"amount_minor","Date":"event_time"}'
```

* Limits: 5 MiB, 5,000 rows per upload. Rows are validated individually — the
  response reports `accepted` and `errors` **per row number**, so one bad row
  never poisons the batch.
* Idempotency: a byte-identical replay of the same rows is accepted again; the
  same `transaction_id` with different amounts is a per-row `conflict`.
* `GET /ingest/schema` (or the console's schema panel) states the contract.

### Built-in synthetic batch (no server needed)

```bash
cd app
python fraud_demo.py --simulate
```

### Stream transactions into a running API

```bash
cd app
DEMO_API_TOKEN='<service token>' \
  python fraud_demo.py --stream --base-url http://127.0.0.1:8000 \
    --rate 2 --count 40 --anomaly-rate 0.25 --assess
```

* `--count 0` streams until `Ctrl+C`.
* `--assess` also requests an explanation for each flag (in mock mode this is a
  labeled synthetic fixture at zero provider cost).
* `--start-time` plus `--seed` gives deterministic, replayable runs; retries
  reuse identical payloads, so replays stay idempotent.

### End-to-end smoke harness

Proves the HTTP contract, idempotency, the Track-3 platform endpoints
(ingest, forecast, invoices, expenses, assistant), dashboard auth/CSRF/CSP,
absence of credential leakage, and the stream simulator:

```bash
DEMO_API_TOKEN='<service token>' DASHBOARD_TOKEN='<dashboard token>' \
  python scripts/smoke.py --base-url http://127.0.0.1:8000 --dashboard-url http://127.0.0.1:8001
```

(`--skip-dashboard` / `--skip-stream` to trim it.)

---

## 6. Using the console

At **http://127.0.0.1:8001**, after signing in with the dashboard token
(browser session is a derived cookie, HttpOnly + SameSite=Strict, 8-hour
expiry), the console offers:

1. **Overview** — live platform snapshot: alert queue status, per-account
   baseline health (sample size, source, median amount), and the state of each
   Track-3 capability.
2. **Alert queue** — flagged records, sortable; click a row for the detail
   drawer with the measured evidence, then **request explanation** (Qwen or
   mock). The result is decision support only; the alert stays at human review
   regardless.
3. **Ingest** — upload CSV/XLSX transactions with column mapping; per-row
   accept/error results are shown inline.
4. **Forecast** — daily net cash-flow projection with an 80% interval; the
   endpoint honestly reports `insufficient_data` until ≥ 14 days of history
   exist, and the card links the method and its disclaimer.
5. **Invoices (AP)** — register vendor invoices; each gets automatic risk
   checks (duplicate invoice number/amount for the same vendor, math
   inconsistency, unregistered vendor, anomalous amount vs. history, due date
   inside a projected cash dip).
6. **Expenses** — submit employee expenses; the approval agent auto-approves
   small items under the configured threshold, gates larger ones into a
   durable finance-review workflow step, and requires receipts above a
   configurable amount. Workflow steps and notification state are visible per
   expense.
7. **Assistant** — ask questions like *"which invoices look risky this week?"*
   In mock mode answers are computed from your actual data and labeled
   `mock_computed`; in live mode Qwen answers from a minimized context pack.

### Direct API calls

```bash
TOKEN='<service token>'

# Score one event (amounts in minor units; direction defaults to "outflow")
curl -s http://127.0.0.1:8000/transactions \
  -H "X-API-Key: $TOKEN" -H 'Content-Type: application/json' \
  -d '{"transaction_id":"txn_001","account_id":"acct_001",
       "event_time":"2026-03-01T14:00:00Z","amount_minor":499900,
       "currency":"USD","country":"GB","device_id":"dev_new"}'

# Assess a flagged transaction
curl -s -X POST http://127.0.0.1:8000/transactions/txn_001/assess \
  -H "X-API-Key: $TOKEN"

# List the alert queue
curl -s http://127.0.0.1:8000/alerts -H "X-API-Key: $TOKEN"

# 30-day cash-flow forecast
curl -s "http://127.0.0.1:8000/forecast/cashflow?horizon=30" -H "X-API-Key: $TOKEN"

# Register an invoice and read its risks
curl -s http://127.0.0.1:8000/invoices \
  -H "X-API-Key: $TOKEN" -H 'Content-Type: application/json' \
  -d '{"invoice_id":"inv_001","vendor_id":"vend_001","invoice_number":"INV-001",
       "issue_date":"2026-09-01","due_date":"2026-09-15",
       "amount_minor":150000,"currency":"USD","description":"Consulting"}'

# Submit an expense (durable workflow decides the route)
curl -s "http://127.0.0.1:8000/expenses?receipt_attached=true" \
  -H "X-API-Key: $TOKEN" -H 'Content-Type: application/json' \
  -d '{"expense_id":"exp_001","employee_id":"emp_001","category":"travel",
       "amount_minor":40000,"currency":"USD","description":"Client visit"}'

# Ask the assistant
curl -s http://127.0.0.1:8000/assistant/ask \
  -H "X-API-Key: $TOKEN" -H 'Content-Type: application/json' \
  -d '{"question":"Which invoices look risky this week?"}'
```

### Endpoint map

| Method | Path | Purpose |
| --- | --- | --- |
| POST | `/transactions` | Ingest + score one event (idempotent; 409 on conflicting replay) |
| POST | `/transactions/{id}/assess` | Qwen/mock explanation for a flagged record |
| GET | `/alerts` | Alert queue (whitelisted fields) |
| POST | `/ingest/csv`, `/ingest/xlsx` | Bulk upload with per-row results and optional column map |
| GET | `/ingest/schema` | Upload contract (columns, currencies, limits) |
| GET | `/forecast/cashflow?horizon=1..90` | Daily net-cash forecast + 80% interval |
| POST | `/invoices`, `/invoices/csv` | Register invoices (risk-assessed at write) |
| GET | `/invoices`, `/invoices/{id}` | List / detail with risks |
| POST | `/expenses?receipt_attached=` | Submit expense through the approval agent |
| GET | `/expenses`, `/expenses/{id}` | List / detail with workflow steps |
| POST | `/assistant/ask` | Qwen/mock decision support from a context pack |
| GET | `/overview` | Aggregate snapshot for the console |
| GET | `/health` | Liveness, no credential required |

Input contract (see `Transaction` in `app/fraud_demo.py`): IDs are
`[A-Za-z0-9_-]{1,64}`; currency is one of `AUD CAD EUR GBP INR JPY USD`
(normalized to USD through the settings-store FX table); `amount_minor` is a
strict positive integer ≤ 10<sup>12</sup>; `country` is `[A-Z]{2}`;
`event_time` must be timezone-aware; `direction` is `inflow` or `outflow`;
**no other fields are accepted** (`extra="forbid"`).

---

## 7. Configuration reference

All variables live in `deploy/.env.example`. Required values are the two tokens.

| Variable | Purpose | Required? |
| --- | --- | --- |
| `DEMO_API_TOKEN` | Service credential sent as `X-API-Key` to the scoring API; held by the workflow and the dashboard BFF only | **Yes** |
| `DASHBOARD_TOKEN` | Browser sign-in credential for the analyst console (distinct from `DEMO_API_TOKEN`) | **Yes** |
| `QWEN_MODE` | `mock` (default, labeled synthetic fixtures, zero cost) or `live` (real paid Qwen calls) | No |
| `DASHSCOPE_API_KEY` / `QWEN_BASE_URL` / `QWEN_MODEL` | Provider settings, only used when `QWEN_MODE=live` | No |
| `FRAUD_API_BASE_URL` | Scoring-API location as seen by the dashboard BFF (`http://127.0.0.1:8000` locally, `http://api:8000` in compose, `https://…` in production) | No |
| `FRAUD_API_ALLOW_PRIVATE_HTTP` | Opt in to plaintext HTTP for a private non-loopback backend hostname (required inside compose). Production: keep `0` and use TLS/mTLS | No |
| `DASHBOARD_SECURE_COOKIES` | `1` when the dashboard is served over HTTPS (marks the session cookie Secure) | No |
| `DEMO_DB_PATH` | SQLite file location (the API service). Must be a writable volume in containers | No |

Runtime policy lives in the **settings store** (the `settings` table), not in
code: the FX rate table and the expense policy (`auto_approve_minor`,
`receipt_required_minor`) are editable per deployment via
`settings_store.SettingsStore.set(...)`.

Fail-closed rule: empty or `<placeholder>` values for required credentials make
the affected service return 503/401 until fixed.

---

## 8. Troubleshooting

**"Submission failed: conflict" in the console / HTTP 409.**
The `transaction_id` already exists with a **different payload**. Same ID +
identical payload is an idempotent 200 (returns the stored record); same ID +
changed payload is a 409. Use a new `transaction_id`, or resubmit byte-identical
details. The form auto-generates a fresh ID after a successful submit.

**HTTP 422 on `/transactions` or a row error on ingest.**
The payload violated the strict schema — e.g. non-integer `amount_minor`,
naive `event_time` (missing timezone), an unsupported currency, a free-text
prose field, or an ID outside `[A-Za-z0-9_-]{1,64}`. For uploads, the response
names the offending **row numbers**.

**Forecast says `insufficient_data`.**
Fewer than 14 calendar days of net-cash history exist. Ingest more history
(spanning multiple weeks) and retry; the endpoint refuses to extrapolate from
thin data by design.

**An expense is stuck at `pending_approval`.**
That is the durable workflow working: large amounts (over `auto_approve_minor`)
or missing receipts route to a finance-review step. Approvals are a demo
workflow — no notification leaves the machine and no funds move.

**Assistant answer says `mock_computed`.**
`QWEN_MODE=mock` computes answers locally from your ingested data and labels
them. Live mode requires `DASHSCOPE_API_KEY`, `QWEN_BASE_URL`, and `QWEN_MODEL`
(costs apply; see `deploy/.env.example` for region notes).

**Port 8000 (or 8001) already in use.**
Something else is listening. The native launcher honors `API_PORT`/`DASH_PORT`.
For Docker, publish alternate host ports, e.g.
`127.0.0.1:8090:8000` / `127.0.0.1:8091:8001` (and point `FRAUD_API_BASE_URL`
at the new API port).

**Only the banner shows after a refresh (no login, no console).**
Your browser may be showing a cached `app.js`. Hard-refresh (Ctrl+Shift+R). A
valid session shows the console directly; an expired session shows the sign-in
form.

**Session expired.**
The dashboard session cookie lasts 8 hours. Sign in again.

**Port conflicts and Compose v1 quirks.**
The standalone `docker-compose` binary (v1) **appends** `ports` lists when
merging `-f` override files (it does not replace them), and its
`--force-recreate` can crash with `KeyError: 'ContainerConfig'` on newer daemons.
Use Compose v2 (`docker compose`) where possible. If you must use v1, provide a
single self-contained compose file with a correct absolute `build.context`, and
recreate by removing containers first (`docker-compose rm -sf …` then
`up -d …`).

**Banner about assumptions.**
Baselines for brand-new accounts come from a labeled global reference
(`baseline_source: cold_start`) until enough real history accumulates, and
mock-mode "explanations" are labeled synthetic fixtures. See `QWEN_MODE=live`
for real provider calls, and read `app/enterpro_workflow_pseudocode.py` before
attempting any hosted-orchestration wiring.

---

## 9. Testing and CI

* Offline suite: `python -m unittest discover -s app -p "test_*.py"` — 105
  tests across the core API, the platform modules, the BFF (real uvicorn over
  HTTP), and executable security boundaries.
* `.github/workflows/ci.yml` runs on Python 3.11 and 3.12 and also gates on:
  `node --check app/static/app.js`, the EnterPro pseudocode module remaining
  inert (still raising `NotImplementedError`), the expense agent driving the
  **real** local workflow engine, compose hardening assertions, and a scan for
  committed secrets.
* `app/test_platform.py` covers baselines, CSV/XLSX ingest, the forecast
  engine, AP risk rules, and the durable expense workflow end to end.
* `app/test_dashboard.py` runs a real uvicorn instance of the scoring API on an
  ephemeral loopback port and exercises the BFF over actual HTTP (mock mode),
  including every Track-3 console route.
* `app/test_security.py` makes the security boundaries executable: no
  free-text fields, minimized Qwen payload, no consequential actions, and
  alerts that survive a missing explanation.

## 10. Scope and limitations

* SQLite, single worker, in-process lock: the workflow engine is durable within
  this one process (steps persist and resume on restart) but is not a
  distributed engine — no outbox, per-case leases across machines, or multi-node
  recovery.
* Detection is statistical, not adversarial: baselines are learned from
  ingested history, so a patient attacker who shapes history shapes the
  baseline. Production needs entity-level features, drift monitoring, and
  labeled-feedback loops.
* The forecast is a seasonal-naive + trend model with empirical intervals:
  honest and explainable, not a replacement for a trained demand/cash model.
* The dashboard is a demo BFF: real identity/RBAC, session rotation, login rate
  limiting, audit logging, and TLS termination (see `deploy/nginx-tls.conf` as
  an example) are **not** implemented here.
* Everything is synthetic or locally supplied and for demonstration: scores are
  unusualness, not fraud probability; forecasts are estimates, not guarantees;
  LLM output is decision support only. No funds are ever moved, nothing is
  blocked or frozen, and no customer is contacted.
