"""AccountsPayable invoice intelligence (Track 3: Finance).

Checks performed at ingest (all decision support; nothing is paid or blocked):
  * duplicate invoice — same vendor + invoice_number already stored, or same
    vendor + amount inside the configurable duplicate window (settings key
    `ap_duplicate_window_days`);
  * arithmetic inconsistency — provided subtotal + tax != total;
  * unusual vendor activity — first-seen vendor with a large amount, or a
    vendor submitting many invoices in a short window;
  * payment risk — due date falls inside a forecasted cash shortfall window.

Free text surface: `description` is the ONLY free-text field, bounded to 200
characters of a restricted charset, and is never forwarded to any model.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Literal

from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict, Field, field_validator

from fraud_demo import to_usd_minor

DESCRIPTION_MAX = 200
_DESCRIPTION_ALLOWED = set(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 "
    ".,;:!?()[]/-&'@#%+=")

INVOICE_ID_PATTERN = r"^[A-Za-z0-9_-]{1,64}$"


class Invoice(BaseModel):
    model_config = ConfigDict(extra="forbid")
    invoice_id: str = Field(pattern=INVOICE_ID_PATTERN)
    vendor_id: str = Field(pattern=INVOICE_ID_PATTERN)
    invoice_number: str = Field(pattern=r"^[A-Za-z0-9._/-]{1,64}$")
    issue_date: str = Field(pattern=r"^\d{4}-\d{2}-\d{2}$")
    due_date: str = Field(pattern=r"^\d{4}-\d{2}-\d{2}$")
    amount_minor: int = Field(strict=True, gt=0, le=10**12)
    currency: str = Field(pattern=r"^[A-Z]{3}$")
    subtotal_minor: int | None = Field(default=None, strict=True, ge=0, le=10**12)
    tax_minor: int | None = Field(default=None, strict=True, ge=0, le=10**12)
    description: str = Field(default="", max_length=DESCRIPTION_MAX)

    @field_validator("currency")
    @classmethod
    def currency_supported(cls, value):
        from fraud_demo import ACCEPTED_CURRENCIES
        if value not in ACCEPTED_CURRENCIES:
            raise ValueError(f"currency must be one of {', '.join(ACCEPTED_CURRENCIES)}")
        return value

    @field_validator("description")
    @classmethod
    def description_charset(cls, value):
        bad = set(value) - _DESCRIPTION_ALLOWED
        if bad:
            raise ValueError("description contains characters outside the allowed set")
        return value

    @field_validator("due_date")
    @classmethod
    def due_not_before_issue(cls, value, info):
        issue = (info.data or {}).get("issue_date")
        if issue and value < issue:
            raise ValueError("due_date must not precede issue_date")
        return value


def invoice_risks(db, invoice: Invoice, settings, forecast_lookup=None) -> list[dict]:
    """Compute the risk list for a NEW invoice (call before it is stored)."""
    risks: list[dict] = []
    now = datetime.now(timezone.utc)

    window_days = int(settings.get_str("ap_duplicate_window_days", "14") or 14)
    exact = db.execute(
        "SELECT 1 FROM invoices WHERE vendor_id=? AND invoice_number=? LIMIT 1",
        (invoice.vendor_id, invoice.invoice_number)).fetchone()
    if exact:
        risks.append({"code": "duplicate_invoice_number", "severity": "high",
                      "detail": "same vendor + invoice_number already stored"})
    # Compare on when WE stored the prior invoice (created_at), not on the
    # claimed issue date: re-submitting an old invoice is exactly the
    # duplicate pattern this check exists to catch.
    window_start = (now - timedelta(days=window_days)).isoformat()
    similar = db.execute(
        """SELECT COUNT(*) FROM invoices WHERE vendor_id=? AND amount_minor=?
           AND created_at >= ?""",
        (invoice.vendor_id, invoice.amount_minor, window_start)).fetchone()
    if similar and similar[0]:
        risks.append({"code": "possible_duplicate_amount", "severity": "medium",
                      "detail": f"same vendor+amount invoice stored within {window_days} days"})

    if invoice.subtotal_minor is not None and invoice.tax_minor is not None:
        if invoice.subtotal_minor + invoice.tax_minor != invoice.amount_minor:
            risks.append({"code": "arithmetic_mismatch", "severity": "medium",
                          "detail": "subtotal + tax does not equal total"})

    vendor_count = db.execute(
        "SELECT COUNT(*) FROM invoices WHERE vendor_id=?", (invoice.vendor_id,)).fetchone()
    first_seen = not vendor_count or not vendor_count[0]
    vendor_recent = db.execute(
        """SELECT COUNT(*) FROM invoices WHERE vendor_id=? AND created_at >= ?""",
        (invoice.vendor_id, (now - timedelta(days=7)).isoformat())).fetchone()
    if first_seen and invoice.amount_minor >= 500000:
        risks.append({"code": "new_vendor_large_amount", "severity": "medium",
                      "detail": "first invoice from this vendor is unusually large"})
    if vendor_recent and vendor_recent[0] >= 10:
        risks.append({"code": "vendor_velocity", "severity": "low",
                      "detail": "vendor submitted 10+ invoices within 7 days"})

    if forecast_lookup is not None:
        shortfall = forecast_lookup(invoice.due_date)
        if shortfall:
            risks.append({"code": "due_inside_cash_shortfall", "severity": "medium",
                          "detail": "due date falls inside a forecasted net-cash dip"})

    return risks


def invoice_record(db, invoice: Invoice, tenant: str, settings, risks: list[dict]) -> dict:
    canonical = json.dumps(invoice.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(canonical.encode()).hexdigest()
    now = datetime.now(timezone.utc).isoformat()
    record = {
        "invoice_id": invoice.invoice_id,
        "vendor_id": invoice.vendor_id,
        "invoice_number": invoice.invoice_number,
        "issue_date": invoice.issue_date,
        "due_date": invoice.due_date,
        "amount_minor": invoice.amount_minor,
        "currency": invoice.currency,
        "amount_usd_minor": to_usd_minor(invoice.amount_minor, invoice.currency, settings),
        "description": invoice.description,
        "status": "open",
        "risks": risks,
        "created_at": now,
        "updated_at": now,
    }
    with db:
        db.execute(
            """INSERT INTO invoices
               (invoice_id, tenant, vendor_id, invoice_number, issue_date, due_date,
                amount_minor, currency, description, status, payload_hash, risks,
                created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (invoice.invoice_id, tenant, invoice.vendor_id, invoice.invoice_number,
             invoice.issue_date, invoice.due_date, invoice.amount_minor,
             invoice.currency, invoice.description, record["status"], digest,
             json.dumps(risks), now, now))
    return record


def get_invoice(db, tenant: str, invoice_id: str) -> dict | None:
    row = db.execute("SELECT risks, status, payload_hash, created_at, updated_at "
                     "FROM invoices WHERE tenant=? AND invoice_id=?",
                     (tenant, invoice_id)).fetchone()
    if not row:
        return None
    import json as _json
    risks, status, payload_hash, created_at, updated_at = row
    # Reconstruct from the row (not JSON blob) so updates to status stay live.
    base = db.execute(
        """SELECT vendor_id, invoice_number, issue_date, due_date, amount_minor,
                  currency, description FROM invoices
           WHERE tenant=? AND invoice_id=?""", (tenant, invoice_id)).fetchone()
    vendor_id, invoice_number, issue_date, due_date, amount_minor, currency, description = base
    return {
        "invoice_id": invoice_id, "vendor_id": vendor_id, "invoice_number": invoice_number,
        "issue_date": issue_date, "due_date": due_date, "amount_minor": amount_minor,
        "currency": currency, "description": description, "status": status,
        "amount_usd_minor": None, "risks": _json.loads(risks),
        "created_at": created_at, "updated_at": updated_at,
    }


def list_invoices(db, tenant: str, limit: int = 50, offset: int = 0,
                  status: str | None = None) -> list[dict]:
    query = ("SELECT invoice_id, vendor_id, invoice_number, issue_date, due_date, "
             "amount_minor, currency, description, status, risks, created_at "
             "FROM invoices WHERE tenant=?")
    params: list = [tenant]
    if status:
        query += " AND status=?"
        params.append(status)
    query += " ORDER BY rowid DESC LIMIT ? OFFSET ?"
    params += [limit, offset]
    rows = db.execute(query, params).fetchall()
    import json as _json
    out = []
    for row in rows:
        out.append({
            "invoice_id": row[0], "vendor_id": row[1], "invoice_number": row[2],
            "issue_date": row[3], "due_date": row[4], "amount_minor": row[5],
            "currency": row[6], "description": row[7], "status": row[8],
            "risks": _json.loads(row[9]), "created_at": row[10],
        })
    return out
