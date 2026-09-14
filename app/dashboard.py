"""Analyst dashboard backend-for-frontend (BFF) for the fraud prototype.

This is a SECOND process. It exists so the scoring service credential
(DEMO_API_TOKEN) never reaches a browser, and so the only state-changing
action an analyst can trigger is an explicit explanation request.

Run (separate terminal from the scoring API):
    DASHBOARD_TOKEN=... DEMO_API_TOKEN=... \
      uvicorn dashboard:app --host 127.0.0.1 --port 8001 --workers 1

Then open http://127.0.0.1:8001 and sign in with DASHBOARD_TOKEN.

Security decisions encoded here:
  * Two distinct credentials. DASHBOARD_TOKEN authenticates the human/browser;
    DEMO_API_TOKEN authenticates this BFF to the scoring API. Only the latter
    is a service secret, and it is held server-side.
  * The browser receives an HMAC-derived session value, never the shared
    token itself, in an HttpOnly SameSite=Strict cookie.
  * No generic proxy. Every reachable upstream path is a literal built into a
    named route (alerts, assess, overview, forecast, invoices, expenses,
    assistant, ingest, schema), so a hostile dashboard parameter cannot be
    used to reach another internal URL (SSRF) or to traverse paths.
  * Strict Content-Security-Policy with no 'unsafe-inline': JS and CSS live in
    their own files. Model-generated prose is rendered by the browser with
    textContent/createElement only, never as HTML.
  * follow_redirects=False upstream, so a compromised or misconfigured backend
    cannot bounce this service to an unintended host.

Not implemented here (production requirements): real identity/RBAC, session
expiry and rotation, login rate limiting, audit logging of analyst actions,
TLS termination, and multi-tenant authorization.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import re
from typing import Any
from urllib.parse import urlparse

import httpx
from fastapi import FastAPI, Header, Query, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field

from pydantic import ValidationError

# Reused deliberately: one implementation of the "HTTPS, or HTTP only on
# loopback, no credentials/query/fragment in a base URL" rule.
from fraud_demo import simulation_base_url
# The exact upstream payload models, so the BFF validates before proxying with
# the same rules the scoring API will apply (no schema drift between processes).
import invoices as api_invoices
import expenses as api_expenses

STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
TX_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,64}$")

# Whitelist of record keys forwarded to the browser. Unknown upstream fields
# are dropped rather than silently surfaced into the analyst UI.
RECORD_FIELDS = frozenset({
    "transaction_id", "transaction", "detection", "flagged", "status",
    "policy_action", "created_at", "updated_at", "explanation",
    "assessment_attempts", "explanation_error",
})
SESSION_COOKIE = "dash_session"
SESSION_CONTEXT = b"fraud-dashboard-session-v1"
CSRF_HEADER_VALUE = "dashboard"

# --- per-shape whitelists for the Track-3 payloads ---------------------------
# The BFF is the only door between the API and the browser: every payload shape
# is whitelisted recursively, so an upstream regression cannot leak fields.

PACK_SECTIONS = {
    "transactions": frozenset({"count", "flagged", "flag_rate",
                               "recent_7d_count", "recent_7d_flagged"}),
    "alerts": frozenset({"count", "top_by_score"}),
    "forecast": frozenset({"status", "coverage_days", "horizon_days",
                           "projected_net_usd_cents"}),
    "accounts_payable": frozenset({"open_invoices", "open_with_high_risk",
                                   "due_within_7_days"}),
    "expenses": frozenset({"pending_approval", "auto_approved", "missing_receipt"}),
}
OVERVIEW_FIELDS = frozenset({"overview", "baselines", "deployment"})
TOP_ALERT_FIELDS = frozenset({"transaction_id", "anomaly_score", "baseline_source"})
BASELINE_FIELDS = frozenset({"sample_size", "baseline_source", "median_amount_minor"})
FORECAST_FIELDS = frozenset({
    "status", "horizon_days", "coverage_days", "history_start", "history_end",
    "trend_per_day_usd_cents", "trend_coefficient", "seasonality_strength",
    "historical_inflow_usd_cents", "historical_outflow_usd_cents",
    "projected_net_usd_cents", "projected_low_usd_cents", "projected_high_usd_cents",
    "points", "method", "disclaimer"})
FORECAST_POINT_FIELDS = frozenset({"date", "net_usd_cents", "low_usd_cents", "high_usd_cents"})
INVOICE_FIELDS = frozenset({
    "invoice_id", "vendor_id", "invoice_number", "issue_date", "due_date",
    "amount_minor", "currency", "amount_usd_minor", "description", "status",
    "risks", "created_at", "updated_at"})
RISK_FIELDS = frozenset({"code", "severity", "detail"})
EXPENSE_FIELDS = frozenset({
    "expense_id", "employee_id", "category", "amount_minor", "currency",
    "amount_usd_minor", "description", "receipt_attached", "status",
    "decision_reason", "created_at", "updated_at", "workflow_steps",
    "notification", "replayed"})
STEP_FIELDS = frozenset({"step", "status", "attempts", "result"})
NOTIFICATION_FIELDS = frozenset({"delivered", "already_sent", "channel"})
ASSISTANT_FIELDS = frozenset({"source", "prompt_version", "pack", "answer",
                              "provider_model", "request_id"})
ANSWER_FIELDS = frozenset({"answer", "references", "recommendations", "caveats"})
RECOMMENDATION_FIELDS = frozenset({"action", "rationale"})

SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self'; style-src 'self'; "
        "img-src 'self' data:; connect-src 'self'; form-action 'none'; "
        "frame-ancestors 'none'; base-uri 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}


class SessionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    token: str = Field(min_length=8, max_length=256)


# Upstream client-error statuses that belong to the analyst's own action and
# are therefore passed through (with detail) instead of masked as 502. Note 404
# is handled separately: it is normalized to {"error": "not_found"} so the
# upstream URL structure never leaks into the browser.
CLIENT_ERROR_STATUSES = frozenset({409, 413, 415, 422})


class AuthError(Exception):
    pass


def _configured(name: str) -> str:
    """Read a required setting; fail closed on unset or placeholder values."""
    value = os.getenv(name, "")
    if not value or value.startswith("<"):
        raise AuthError(f"{name} is not configured")
    return value


def _backend_url() -> str:
    """Resolve and validate the scoring API base URL.

    Default rule (reused from fraud_demo): HTTPS required, except plain HTTP on
    loopback; never credentials, query, or fragment in a base URL.

    Container-to-container calls use a private hostname such as
    `http://api:8000`, which the default rule correctly rejects. Rather than
    weaken the rule globally, an operator must set
    `FRAUD_API_ALLOW_PRIVATE_HTTP=1` to opt in to plaintext on a trusted private
    network. That is a demo/compose convenience: production must use TLS or a
    mesh with mTLS, and this flag must stay unset there.
    """
    raw = os.getenv("FRAUD_API_BASE_URL", "http://127.0.0.1:8000")
    try:
        if os.getenv("FRAUD_API_ALLOW_PRIVATE_HTTP", "0") == "1":
            return _private_base_url(raw)
        return simulation_base_url(raw)
    except ValueError as exc:
        raise AuthError(f"FRAUD_API_BASE_URL is invalid: {exc}") from None


def _private_base_url(value: str) -> str:
    parsed = urlparse(value)
    if (parsed.scheme not in {"http", "https"} or not parsed.hostname
            or parsed.username or parsed.password or parsed.query or parsed.fragment):
        raise ValueError("expected http(s)://host[:port] with no credentials, query, or fragment")
    return value.rstrip("/")


def _session_value(dashboard_token: str) -> str:
    """Derive the cookie value so the shared secret is never stored client-side."""
    return hmac.new(SESSION_CONTEXT, dashboard_token.encode(), hashlib.sha256).hexdigest()


def _authorize(request: Request, requested_with: str, state_changing: bool) -> None:
    """Cookie proves the session; the custom header blocks simple CSRF on writes."""
    presented = request.cookies.get(SESSION_COOKIE, "")
    expected = _session_value(_configured("DASHBOARD_TOKEN"))
    if not hmac.compare_digest(presented.encode(), expected.encode()):
        raise AuthError("dashboard session is missing or invalid")
    if state_changing and requested_with != CSRF_HEADER_VALUE:
        raise AuthError("missing X-Requested-With header")


def _sanitize(payload: Any) -> Any:
    if not isinstance(payload, dict):
        raise ValueError("backend returned a non-object")
    if isinstance(payload.get("items"), list):
        return {"items": [_record(item) for item in payload["items"]]}
    if "transaction_id" in payload:
        return _record(payload)
    return {key: value for key, value in payload.items() if key in {"status", "deployment"}}


def _record(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        return {}
    return {key: value for key, value in payload.items() if key in RECORD_FIELDS}


def _pick(payload: Any, allowed: frozenset) -> dict[str, Any]:
    if not isinstance(payload, dict):
        return {}
    return {key: payload[key] for key in payload if key in allowed}


def _clean_pack(pack: Any) -> dict[str, Any]:
    if not isinstance(pack, dict):
        return {}
    out = {}
    for section, allowed in PACK_SECTIONS.items():
        value = pack.get(section)
        if not isinstance(value, dict):
            continue
        cleaned = {key: value[key] for key in value if key in allowed}
        if section == "alerts" and isinstance(cleaned.get("top_by_score"), list):
            cleaned["top_by_score"] = [_pick(item, TOP_ALERT_FIELDS)
                                       for item in cleaned["top_by_score"]
                                       if isinstance(item, dict)]
        out[section] = cleaned
    return out


def _clean_forecast(payload: Any) -> dict[str, Any]:
    cleaned = _pick(payload, FORECAST_FIELDS)
    if isinstance(cleaned.get("points"), list):
        cleaned["points"] = [_pick(point, FORECAST_POINT_FIELDS)
                             for point in cleaned["points"] if isinstance(point, dict)]
    return cleaned


def _clean_invoice(payload: Any) -> dict[str, Any]:
    cleaned = _pick(payload, INVOICE_FIELDS)
    if isinstance(cleaned.get("risks"), list):
        cleaned["risks"] = [_pick(risk, RISK_FIELDS)
                            for risk in cleaned["risks"] if isinstance(risk, dict)]
    return cleaned


def _clean_expense(payload: Any) -> dict[str, Any]:
    cleaned = _pick(payload, EXPENSE_FIELDS)
    if isinstance(cleaned.get("workflow_steps"), list):
        cleaned["workflow_steps"] = [_pick(step, STEP_FIELDS)
                                     for step in cleaned["workflow_steps"]
                                     if isinstance(step, dict)]
    notification = cleaned.get("notification")
    if notification is not None:
        cleaned["notification"] = _pick(notification, NOTIFICATION_FIELDS)
    return cleaned


def _clean_overview(payload: Any) -> dict[str, Any]:
    cleaned = _pick(payload, OVERVIEW_FIELDS)
    pack = cleaned.get("overview")
    if pack is not None:
        cleaned["overview"] = _clean_pack(pack)
    baselines = cleaned.get("baselines")
    if isinstance(baselines, dict):
        cleaned["baselines"] = {account: _pick(value, BASELINE_FIELDS)
                                for account, value in baselines.items()
                                if isinstance(value, dict)}
    return cleaned


def _clean_assistant(payload: Any) -> dict[str, Any]:
    cleaned = _pick(payload, ASSISTANT_FIELDS)
    pack = cleaned.get("pack")
    if pack is not None:
        cleaned["pack"] = _clean_pack(pack)
    answer = cleaned.get("answer")
    if isinstance(answer, dict):
        cleaned_answer = _pick(answer, ANSWER_FIELDS)
        if isinstance(cleaned_answer.get("recommendations"), list):
            cleaned_answer["recommendations"] = [
                _pick(rec, RECOMMENDATION_FIELDS)
                for rec in cleaned_answer["recommendations"] if isinstance(rec, dict)]
        cleaned["answer"] = cleaned_answer
    return cleaned


def create_dashboard_app() -> FastAPI:
    application = FastAPI(title="Fraud Analyst Dashboard BFF", docs_url=None, redoc_url=None)
    # Separate JS/CSS files (rather than inline) so the CSP needs no 'unsafe-inline'.
    application.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    @application.middleware("http")
    async def apply_security_headers(request: Request, call_next):
        response = await call_next(request)
        for key, value in SECURITY_HEADERS.items():
            response.headers[key] = value
        return response

    def proxy(method: str, path: str, tx_id: str | None = None,
              json_body: dict | None = None,
              sanitize=None) -> JSONResponse:
        """The only route to the scoring API. `path` is built from literals."""
        if tx_id is not None and not TX_ID_PATTERN.match(tx_id):
            return JSONResponse({"error": "invalid_transaction_id"}, status_code=400)
        try:
            url = _backend_url() + path
            headers = {"X-API-Key": _configured("DEMO_API_TOKEN")}
        except AuthError as exc:
            return JSONResponse({"error": "misconfigured", "detail": str(exc)}, status_code=503)
        try:
            with httpx.Client(timeout=httpx.Timeout(30, connect=5),
                              follow_redirects=False) as client:
                upstream = client.request(method, url, headers=headers, json=json_body)
        except httpx.TransportError:
            return JSONResponse({"error": "backend_unavailable"}, status_code=502)
        if upstream.status_code == 200:
            try:
                payload = upstream.json()
            except ValueError:
                return JSONResponse({"error": "invalid_backend_response"}, status_code=502)
            try:
                return JSONResponse(sanitize(payload) if sanitize else _sanitize(payload))
            except ValueError:
                return JSONResponse({"error": "invalid_backend_response"}, status_code=502)
        if upstream.status_code in (401, 403):
            # Our own service credential was rejected; never echo upstream detail.
            return JSONResponse({"error": "upstream_rejected_credentials"}, status_code=502)
        if upstream.status_code in CLIENT_ERROR_STATUSES:
            # Legitimate client errors (409 duplicate, 413 too large, 415 encoding,
            # 422 validation) belong to the analyst's action, so pass the body
            # through for the console to render; upstream 500+ detail never flows.
            try:
                payload = upstream.json()
            except ValueError:
                payload = {"error": f"upstream_error_{upstream.status_code}"}
            if not isinstance(payload, dict):
                return JSONResponse({"error": f"upstream_error_{upstream.status_code}"},
                                    status_code=upstream.status_code)
            return JSONResponse(payload, status_code=upstream.status_code)
        if upstream.status_code == 404:
            return JSONResponse({"error": "not_found"}, status_code=404)
        return JSONResponse({"error": f"upstream_error_{upstream.status_code}"}, status_code=502)

    @application.get("/health")
    def health() -> dict[str, Any]:
        # Liveness only. Reports configuration state, never credential values.
        state = {}
        for name in ("DASHBOARD_TOKEN", "DEMO_API_TOKEN"):
            raw = os.getenv(name, "")
            state[name.lower() + "_configured"] = bool(raw) and not raw.startswith("<")
        try:
            _backend_url()
            state["backend_url_valid"] = True
        except AuthError:
            state["backend_url_valid"] = False
        return {"status": "ok", "role": "dashboard_bff", **state}

    @application.post("/session")
    def sign_in(body: SessionRequest) -> JSONResponse:
        try:
            expected = _configured("DASHBOARD_TOKEN")
        except AuthError as exc:
            return JSONResponse({"error": "misconfigured", "detail": str(exc)}, status_code=503)
        if not hmac.compare_digest(body.token.encode(), expected.encode()):
            return JSONResponse({"error": "invalid_token"}, status_code=401)
        out = JSONResponse({"status": "authenticated"})
        out.set_cookie(SESSION_COOKIE, _session_value(expected), httponly=True,
                       samesite="strict", path="/", max_age=8 * 3600,
                       secure=os.getenv("DASHBOARD_SECURE_COOKIES", "0") == "1")
        return out

    @application.post("/session/logout")
    def sign_out() -> JSONResponse:
        out = JSONResponse({"status": "signed_out"})
        out.delete_cookie(SESSION_COOKIE, path="/")
        return out

    @application.get("/")
    def index() -> FileResponse:
        return FileResponse(os.path.join(STATIC_DIR, "index.html"))

    @application.get("/api/alerts")
    def alerts(request: Request, limit: int = Query(50, ge=1, le=100),
               offset: int = Query(0, ge=0),
               x_requested_with: str = Header(default="")) -> JSONResponse:
        try:
            _authorize(request, x_requested_with, state_changing=False)
        except AuthError as exc:
            return JSONResponse({"error": str(exc)}, status_code=401)
        return proxy("GET", f"/alerts?limit={limit}&offset={offset}")

    @application.post("/api/alerts/{tx_id}/assess")
    def assess(tx_id: str, request: Request,
               x_requested_with: str = Header(default="")) -> JSONResponse:
        try:
            _authorize(request, x_requested_with, state_changing=True)
        except AuthError as exc:
            return JSONResponse({"error": str(exc)}, status_code=401)
        if not TX_ID_PATTERN.match(tx_id):
            return JSONResponse({"error": "invalid_transaction_id"}, status_code=400)
        return proxy("POST", f"/transactions/{tx_id}/assess", tx_id)

    # ---- Track-3 platform routes (same auth model, per-shape whitelists) ----

    async def _read_ask_body(request: Request) -> dict | None:
        try:
            body = await request.json()
        except ValueError:
            return None
        if not isinstance(body, dict):
            return None
        question = body.get("question")
        if not isinstance(question, str) or not (8 <= len(question) <= 500):
            return None
        return {"question": question}

    @application.get("/api/overview")
    def overview(request: Request,
                 x_requested_with: str = Header(default="")) -> JSONResponse:
        try:
            _authorize(request, x_requested_with, state_changing=False)
        except AuthError as exc:
            return JSONResponse({"error": str(exc)}, status_code=401)
        return proxy("GET", "/overview", sanitize=_clean_overview)

    @application.get("/api/forecast")
    def forecast(request: Request, horizon: int = Query(30, ge=1, le=90),
                 x_requested_with: str = Header(default="")) -> JSONResponse:
        try:
            _authorize(request, x_requested_with, state_changing=False)
        except AuthError as exc:
            return JSONResponse({"error": str(exc)}, status_code=401)
        return proxy("GET", f"/forecast/cashflow?horizon={horizon}",
                     sanitize=_clean_forecast)

    @application.get("/api/invoices")
    def invoices(request: Request, status: str | None = Query(None),
                 limit: int = Query(50, ge=1, le=100), offset: int = Query(0, ge=0),
                 x_requested_with: str = Header(default="")) -> JSONResponse:
        try:
            _authorize(request, x_requested_with, state_changing=False)
        except AuthError as exc:
            return JSONResponse({"error": str(exc)}, status_code=401)
        query = f"/invoices?limit={limit}&offset={offset}"
        if status:
            query += f"&status={status}"
        return proxy("GET", query,
                     sanitize=lambda payload: {"items": [
                         _clean_invoice(item) for item in payload.get("items", [])
                         if isinstance(item, dict)]}
                     if isinstance(payload, dict) else (_ for _ in ()).throw(ValueError))

    @application.get("/api/expenses")
    def expenses(request: Request, status: str | None = Query(None),
                 limit: int = Query(50, ge=1, le=100), offset: int = Query(0, ge=0),
                 x_requested_with: str = Header(default="")) -> JSONResponse:
        try:
            _authorize(request, x_requested_with, state_changing=False)
        except AuthError as exc:
            return JSONResponse({"error": str(exc)}, status_code=401)
        query = f"/expenses?limit={limit}&offset={offset}"
        if status:
            query += f"&status={status}"
        return proxy("GET", query,
                     sanitize=lambda payload: {"items": [
                         _clean_expense(item) for item in payload.get("items", [])
                         if isinstance(item, dict)]}
                     if isinstance(payload, dict) else (_ for _ in ()).throw(ValueError))

    @application.post("/api/assistant/ask")
    async def assistant_ask(request: Request,
                            x_requested_with: str = Header(default="")) -> JSONResponse:
        try:
            _authorize(request, x_requested_with, state_changing=True)
        except AuthError as exc:
            return JSONResponse({"error": str(exc)}, status_code=401)
        body = await _read_ask_body(request)
        if body is None:
            return JSONResponse({"error": "invalid_question"}, status_code=400)
        return proxy("POST", "/assistant/ask", json_body=body,
                     sanitize=_clean_assistant)

    # Same pydantic models as the scoring API (one image, one import), so the
    # browser-side validation story and the upstream schema cannot drift apart.
    async def _read_upstream_model(model_cls, request: Request):
        try:
            body = await request.json()
        except ValueError:
            return None
        try:
            return model_cls.model_validate(body)
        except ValidationError:
            return None

    @application.post("/api/invoices")
    async def create_invoice(request: Request,
                             x_requested_with: str = Header(default="")) -> JSONResponse:
        try:
            _authorize(request, x_requested_with, state_changing=True)
        except AuthError as exc:
            return JSONResponse({"error": str(exc)}, status_code=401)
        invoice = await _read_upstream_model(api_invoices.Invoice, request)
        if invoice is None:
            return JSONResponse({"error": "invalid_invoice"}, status_code=400)
        return proxy("POST", "/invoices", json_body=invoice.model_dump(mode="json"),
                     sanitize=_clean_invoice)

    @application.post("/api/expenses")
    async def submit_expense(request: Request,
                             x_requested_with: str = Header(default="")) -> JSONResponse:
        try:
            _authorize(request, x_requested_with, state_changing=True)
        except AuthError as exc:
            return JSONResponse({"error": str(exc)}, status_code=401)
        expense = await _read_upstream_model(api_expenses.Expense, request)
        if expense is None:
            return JSONResponse({"error": "invalid_expense"}, status_code=400)
        return proxy("POST", "/expenses", json_body=expense.model_dump(mode="json"),
                     sanitize=_clean_expense)

    @application.get("/api/schema")
    def ingest_schema(request: Request,
                      x_requested_with: str = Header(default="")) -> JSONResponse:
        """Column contract for the upload form, fetched from the scoring API."""
        try:
            _authorize(request, x_requested_with, state_changing=False)
        except AuthError as exc:
            return JSONResponse({"error": str(exc)}, status_code=401)
        return proxy("GET", "/ingest/schema")

    @application.post("/api/ingest")
    async def ingest_upload(request: Request,
                            x_requested_with: str = Header(default="")) -> JSONResponse:
        """Multipart passthrough to /ingest/csv or /ingest/xlsx.

        The browser never learns the service credential: this endpoint holds it.
        Uploads are size-capped at the API layer; only the mapped fields survive.
        """
        try:
            _authorize(request, x_requested_with, state_changing=True)
        except AuthError as exc:
            return JSONResponse({"error": str(exc)}, status_code=401)
        try:
            form = await request.form()
        except Exception:
            return JSONResponse({"error": "invalid_form"}, status_code=400)
        upload = form.get("file")
        if upload is None or not hasattr(upload, "read"):
            return JSONResponse({"error": "missing_file"}, status_code=400)
        filename = (getattr(upload, "filename", "") or "").lower()
        target = "/ingest/xlsx" if filename.endswith(".xlsx") else "/ingest/csv"
        column_map = form.get("column_map_json")
        data = await upload.read()
        if len(data) > 5 * 1024 * 1024:
            return JSONResponse({"error": "file_too_large"}, status_code=413)
        try:
            url = _backend_url() + target
            headers = {"X-API-Key": _configured("DEMO_API_TOKEN")}
        except AuthError as exc:
            return JSONResponse({"error": "misconfigured", "detail": str(exc)}, status_code=503)
        files = {"file": (filename or "upload.csv", data,
                          getattr(upload, "content_type", "") or "application/octet-stream")}
        form_fields = {}
        if column_map:
            form_fields["column_map_json"] = str(column_map)
        try:
            with httpx.Client(timeout=httpx.Timeout(60, connect=5),
                              follow_redirects=False) as client:
                upstream = client.post(url, headers=headers, files=files, data=form_fields)
        except httpx.TransportError:
            return JSONResponse({"error": "backend_unavailable"}, status_code=502)
        if upstream.status_code == 200:
            try:
                payload = upstream.json()
            except ValueError:
                return JSONResponse({"error": "invalid_backend_response"}, status_code=502)
            return JSONResponse({
                "accepted": [_pick(item, {"row", "transaction_id", "flagged"})
                             for item in payload.get("accepted", []) if isinstance(item, dict)],
                "errors": [_pick(item, {"row", "field", "reason"})
                           for item in payload.get("errors", []) if isinstance(item, dict)],
                "accepted_count": payload.get("accepted_count", 0),
                "error_count": payload.get("error_count", 0),
                "source": payload.get("source", "csv")})
        if upstream.status_code in (401, 403):
            return JSONResponse({"error": "upstream_rejected_credentials"}, status_code=502)
        if upstream.status_code == 422:
            return JSONResponse({"error": "invalid_upload"}, status_code=422)
        if upstream.status_code == 413:
            return JSONResponse({"error": "file_too_large"}, status_code=413)
        if upstream.status_code == 415:
            # The UTF-8/JSON decode detail comes from our own parser, not from
            # infrastructure, so it is safe to show the analyst what was wrong.
            try:
                payload = upstream.json()
            except ValueError:
                payload = {"error": "unsupported_media_type"}
            if not isinstance(payload, dict):
                payload = {"error": "unsupported_media_type"}
            return JSONResponse(payload, status_code=415)
        return JSONResponse({"error": f"upstream_error_{upstream.status_code}"}, status_code=502)

    return application


app = create_dashboard_app()
