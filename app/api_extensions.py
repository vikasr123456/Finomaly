"""Endpoint wiring for the financial platform modules.

Keeps `fraud_demo.create_app` unchanged in shape (existing tests keep passing)
while mounting the Track-3 endpoints: ingest upload, forecasting, invoices,
expenses, the assistant, and the overview aggregate. All endpoints are keyed by
the same X-API-Key tenant dependency as the core API.

Security properties preserved:
  * every module writes through the same single-writer SQLite connection guarded
    by the Store lock;
  * no free-text reaches any model; descriptions are bounded and
    charset-restricted at the schema layer;
  * uploads are size- and row-capped; errors are row-level, never silent.
"""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import Depends, HTTPException, Query, UploadFile
from pydantic import BaseModel, ConfigDict, Field

import assistant as assistant_module
import csv_ingest
import enterpro_local
import expenses as expenses_module
import forecast as forecast_module
import invoices as invoices_module
from fraud_demo import Transaction


def _error(status: int, code: str, detail: str):
    return HTTPException(status_code=status, detail={"error": code, "detail": detail})


class AskIn(BaseModel):
    """Module level on purpose: FastAPI evaluates endpoint annotations against
    module globals, so a body model defined inside register_endpoints would be
    invisible to it and silently degrade into a query parameter."""
    model_config = ConfigDict(extra="forbid")
    question: str = Field(min_length=8, max_length=500)


def register_endpoints(application) -> None:
    """Mount the Track-3 endpoints onto a running FastAPI application.

    `application.state.store` is created by the fraud_demo lifespan hook, so
    every endpoint resolves the store lazily at request time.
    """
    tenant = application.state.tenant_dependency

    # ---- ingest -------------------------------------------------------------

    @application.post("/ingest/csv")
    def ingest_csv(file: UploadFile, column_map_json: str | None = None,
                   tenant_id=Depends(tenant)):
        content = csv_ingest.read_upload_sync(file.file)
        mapping = csv_ingest.apply_column_map_json(column_map_json)
        parsed = csv_ingest.parse_csv(content, mapping)
        return _apply_ingest(application.state.store, parsed, source="csv")

    @application.post("/ingest/xlsx")
    def ingest_xlsx(file: UploadFile, column_map_json: str | None = None,
                    tenant_id=Depends(tenant)):
        content = csv_ingest.read_upload_sync(file.file)
        mapping = csv_ingest.apply_column_map_json(column_map_json)
        parsed = csv_ingest.parse_xlsx(content, mapping)
        return _apply_ingest(application.state.store, parsed, source="xlsx")

    @application.get("/ingest/schema")
    def ingest_schema(tenant_id=Depends(tenant)):
        import fraud_demo
        return {"required_columns": sorted(csv_ingest.REQUIRED_COLUMNS),
                "optional_columns": ["direction"],
                "accepted_currencies": sorted(fraud_demo.ACCEPTED_CURRENCIES),
                "max_rows": csv_ingest.MAX_ROWS,
                "max_bytes": csv_ingest.MAX_UPLOAD_BYTES,
                "event_time_format": "ISO-8601 with timezone, e.g. 2026-03-01T14:00:00Z",
                "column_map": "pass column_map_json as JSON like {\"Amount\": \"amount_minor\"}"}

    # ---- forecast -----------------------------------------------------------

    @application.get("/forecast/cashflow")
    def cashflow(horizon: int = Query(30, ge=1, le=90), tenant_id=Depends(tenant)):
        store = application.state.store
        with store.lock:
            return forecast_module.forecast_cashflow(store.db, horizon_days=horizon)

    # ---- invoices -----------------------------------------------------------

    @application.post("/invoices")
    def create_invoice(invoice: invoices_module.Invoice, tenant_id=Depends(tenant)):
        store = application.state.store
        with store.lock:
            risks = invoices_module.invoice_risks(
                store.db, invoice, store.settings,
                forecast_lookup=_shortfall_lookup(store))
            record = invoices_module.invoice_record(
                store.db, invoice, tenant_id, store.settings, risks)
            stored = invoices_module.get_invoice(store.db, tenant_id, invoice.invoice_id)
            stored["amount_usd_minor"] = record["amount_usd_minor"]
            stored["risks"] = risks
        return stored

    @application.post("/invoices/csv")
    def create_invoices_csv(file: UploadFile, column_map_json: str | None = None,
                            tenant_id=Depends(tenant)):
        content = csv_ingest.read_upload_sync(file.file)
        mapping = csv_ingest.apply_column_map_json(column_map_json)
        parsed = csv_ingest.parse_invoice_csv(content, mapping)
        store = application.state.store
        accepted, errors = [], list(parsed["errors"])
        with store.lock:
            for item in parsed["rows"]:
                invoice, row_number = item["invoice"], item["row"]
                try:
                    risks = invoices_module.invoice_risks(
                        store.db, invoice, store.settings,
                        forecast_lookup=_shortfall_lookup(store))
                    record = invoices_module.invoice_record(
                        store.db, invoice, tenant_id, store.settings, risks)
                    accepted.append({"row": row_number, "invoice_id": invoice.invoice_id,
                                     "risks": risks})
                except Exception as exc:  # row-level failure never kills the batch
                    errors.append({"row": row_number, "field": "-",
                                   "reason": type(exc).__name__})
        return {"accepted": accepted, "errors": errors,
                "accepted_count": len(accepted), "error_count": len(errors),
                "source": "invoice_csv"}

    @application.get("/invoices")
    def list_invoices(status: str | None = Query(None),
                      limit: int = Query(50, ge=1, le=100), offset: int = Query(0, ge=0),
                      tenant_id=Depends(tenant)):
        store = application.state.store
        with store.lock:
            return {"items": invoices_module.list_invoices(
                store.db, tenant_id, limit, offset, status)}

    @application.get("/invoices/{invoice_id}")
    def invoice_detail(invoice_id: str, tenant_id=Depends(tenant)):
        store = application.state.store
        with store.lock:
            record = invoices_module.get_invoice(store.db, tenant_id, invoice_id)
        if not record:
            raise _error(404, "not_found", "invoice does not exist")
        return record

    # ---- expenses -----------------------------------------------------------

    @application.post("/expenses")
    def submit(expense: expenses_module.Expense, receipt_attached: bool = Query(False),
               tenant_id=Depends(tenant)):
        store = application.state.store
        engine = enterpro_local.WorkflowEngine(store.db, lock=store.lock)
        with store.lock:
            return expenses_module.submit_expense(
                store.db, store.settings, engine, tenant_id, expense,
                receipt_attached=receipt_attached,
                risk_lookup=_expense_risk_lookup(store, tenant_id))

    @application.get("/expenses")
    def list_expenses(status: str | None = Query(None),
                      limit: int = Query(50, ge=1, le=100), offset: int = Query(0, ge=0),
                      tenant_id=Depends(tenant)):
        store = application.state.store
        with store.lock:
            return {"items": expenses_module.list_expenses(
                store.db, tenant_id, limit, offset, status)}

    @application.get("/expenses/{expense_id}")
    def expense_detail(expense_id: str, tenant_id=Depends(tenant)):
        store = application.state.store
        with store.lock:
            record = expenses_module.get_expense(store.db, tenant_id, expense_id)
        if not record:
            raise _error(404, "not_found", "expense does not exist")
        return record

    # ---- assistant ----------------------------------------------------------

    @application.post("/assistant/ask")
    def assistant_ask(body: AskIn, tenant_id=Depends(tenant)):
        store = application.state.store
        with store.lock:
            try:
                return assistant_module.ask(store.db, body.question)
            except assistant_module.AssistantUnavailable as exc:
                raise _error(503, "assistant_unavailable", str(exc)) from None

    # ---- overview -----------------------------------------------------------

    @application.get("/overview")
    def overview(tenant_id=Depends(tenant)):
        store = application.state.store
        with store.lock:
            pack = assistant_module.build_context_pack(store.db)
            baselines = {
                account: {"sample_size": baseline.sample_size,
                          "baseline_source": baseline.baseline_source,
                          "median_amount_minor": baseline.median_amount_minor}
                for account, baseline in (
                    (account, store.baselines.get(account, tenant=tenant_id))
                    for account in store.baselines.all_account_ids(tenant_id))}
        return {"overview": pack, "baselines": baselines,
                "deployment": "local_prototype"}


def _apply_ingest(store, parsed, source: str) -> dict:
    accepted, errors = [], list(parsed["errors"])
    for item in parsed["rows"]:
        tx, row_number = item["tx"], item["row"]
        try:
            record = store.ingest("demo-tenant", tx)
            accepted.append({"row": row_number, "transaction_id": record["transaction_id"],
                             "flagged": record["flagged"]})
        except HTTPException as exc:
            code = exc.detail.get("error") if isinstance(exc.detail, dict) else "conflict"
            errors.append({"row": row_number, "field": "transaction_id",
                           "reason": code})
    return {"accepted": accepted, "errors": errors,
            "accepted_count": len(accepted), "error_count": len(errors),
            "source": source}


def _shortfall_lookup(store):
    """Forecast-based payment-risk check: due date inside a projected dip."""
    try:
        forecast = forecast_module.forecast_cashflow(store.db, horizon_days=30)
    except Exception:
        return None
    if forecast.get("status") != "ok":
        return None
    low_days = {point["date"] for point in forecast.get("points", [])
                if point.get("net_usd_cents", 0) < 0}

    def lookup(due_date: str):
        return due_date in low_days
    return lookup


def _expense_risk_lookup(store, tenant: str):
    """Risk gate for the expense policy.

    An expense is gated by the employee account's detector score when that
    account has enough history for a trusted baseline; otherwise the policy
    handles the expense on amount alone. The lookup never fabricates a risk
    score for thin data.
    """
    def lookup(expense):
        baseline = store.baselines.get(expense.employee_id, allow_reference=False,
                                       tenant=tenant)
        if baseline is None or baseline.baseline_source != "account":
            return None
        probe = Transaction(
            transaction_id=f"expense_{expense.expense_id}",
            account_id=expense.employee_id,
            event_time=datetime.now(timezone.utc),
            amount_minor=expense.amount_minor,
            currency=expense.currency,
            country="US",
            device_id="dev_expense_probe")
        detection = store.detector.score(probe, baseline)
        return round(min(1.0, detection["anomaly_score"] / detection["threshold"]), 4)
    return lookup
