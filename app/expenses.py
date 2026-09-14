"""Expense/approval agent (Track 3: Finance).

Policy is data, not code: thresholds come from the `expense_policy` settings
key (auto-approve cap, finance-review floor, receipt requirement, risk gate).
The pipeline is orchestrated by the local EnterPro engine (enterpro_local.py):
validate -> risk_check -> decide -> deliver, each stage durable and idempotent.

The agent approves nothing consequential by itself: "approved" means the
review queue is told the policy permits reimbursement — a human completes
payment in the real world. The model (Qwen) may only ADVISE inside the
documented policy; it never approves or denies.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timezone

from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict, Field, field_validator

from enterpro_local import WorkflowEngine, expense_approval_workflow
from fraud_demo import to_usd_minor

_DESCRIPTION_ALLOWED = set(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 "
    ".,;:!?()[]/-&'@#%+=")

DEFAULT_POLICY = {
    "auto_approve_minor": 50000,       # below: policy auto-approves (USD minor)
    "finance_review_minor": 200000,    # at/above: finance review + receipt
    "receipt_required_minor": 100000,  # at/above: receipt must be attached
    "risk_score_gate": 0.85,           # normalized anomaly score gate
}


class Expense(BaseModel):
    model_config = ConfigDict(extra="forbid")
    expense_id: str = Field(pattern=r"^[A-Za-z0-9_-]{1,64}$")
    employee_id: str = Field(pattern=r"^[A-Za-z0-9_-]{1,64}$")
    category: str = Field(pattern=r"^[a-z_]{1,32}$")
    amount_minor: int = Field(strict=True, gt=0, le=10**12)
    currency: str = Field(pattern=r"^[A-Z]{3}$")
    description: str = Field(default="", max_length=200)

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


def get_policy(settings) -> dict:
    policy = settings.get_json("expense_policy", DEFAULT_POLICY)
    if not isinstance(policy, dict):
        return dict(DEFAULT_POLICY)
    merged = dict(DEFAULT_POLICY)
    for key, value in policy.items():
        if key in merged:
            merged[key] = value
    return merged


def decide(policy: dict, amount_usd_minor: int, risk_score: float | None,
           receipt_attached: bool) -> tuple[str, str]:
    """Pure policy function: (status, reason). Deterministic, no side effects."""
    if amount_usd_minor >= policy["finance_review_minor"]:
        if not receipt_attached:
            return ("pending_approval", "finance_review: receipt required at/above "
                    f"{policy['finance_review_minor']} USD minor")
        return ("pending_approval", "finance_review: amount at/above "
                f"{policy['finance_review_minor']} USD minor")
    if amount_usd_minor >= policy["receipt_required_minor"] and not receipt_attached:
        return ("missing_receipt",
                f"receipt required at/above {policy['receipt_required_minor']} USD minor")
    if risk_score is not None and risk_score >= policy["risk_score_gate"]:
        return ("pending_approval",
                f"risk gate: detector score {risk_score:.3f} >= {policy['risk_score_gate']}")
    if amount_usd_minor <= policy["auto_approve_minor"]:
        return ("auto_approved", f"within auto-approve cap "
                f"{policy['auto_approve_minor']} USD minor")
    return ("pending_approval", "between caps: manager review")


def submit_expense(db, settings, engine: WorkflowEngine, tenant: str, expense: Expense,
                   receipt_attached: bool, risk_lookup=None) -> dict:
    """Validate, persist, and run the approval workflow for one expense."""
    canonical = json.dumps(expense.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(canonical.encode()).hexdigest()
    existing = db.execute("SELECT status, decision_reason, payload_hash, created_at, updated_at "
                          "FROM expense_requests WHERE tenant=? AND expense_id=?",
                          (tenant, expense.expense_id)).fetchone()
    if existing:
        if existing[2] != digest:
            raise HTTPException(409, "Expense ID already has a different payload")
        row = db.execute(
            """SELECT employee_id, category, amount_minor, currency, description,
                      receipt_attached, status, decision_reason, created_at, updated_at
               FROM expense_requests WHERE tenant=? AND expense_id=?""",
            (tenant, expense.expense_id)).fetchone()
        return {"expense_id": expense.expense_id, "employee_id": row[0],
                "category": row[1], "amount_minor": row[2], "currency": row[3],
                "description": row[4], "receipt_attached": bool(row[5]),
                "status": row[6], "decision_reason": row[7],
                "created_at": row[8], "updated_at": row[9], "replayed": True}

    amount_usd = to_usd_minor(expense.amount_minor, expense.currency, settings)
    risk_score = None
    if risk_lookup is not None:
        risk_score = risk_lookup(expense)
    status, reason = decide(get_policy(settings), amount_usd, risk_score, receipt_attached)

    now = datetime.now(timezone.utc).isoformat()
    with db:
        db.execute(
            """INSERT INTO expense_requests
               (expense_id, tenant, employee_id, category, amount_minor, currency,
                description, receipt_attached, status, decision_reason, payload_hash,
                created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (expense.expense_id, tenant, expense.employee_id, expense.category,
             expense.amount_minor, expense.currency, expense.description,
             int(receipt_attached), status, reason, digest, now, now))

    workflow = expense_approval_workflow(
        engine, tenant, expense.expense_id,
        risk_check=lambda: {"risk_score": risk_score},
        decide=lambda: {"status": status, "reason": reason},
        deliver=lambda: engine.notify_once(
            (tenant, expense.expense_id, "approval_requested"),
            channel="dashboard",
            message=f"Expense {expense.expense_id} reached state '{status}'; review required"
                    if status == "pending_approval" else
                    f"Expense {expense.expense_id} auto-approved by policy"))

    record = {"expense_id": expense.expense_id, "employee_id": expense.employee_id,
              "category": expense.category, "amount_minor": expense.amount_minor,
              "currency": expense.currency, "description": expense.description,
              "receipt_attached": receipt_attached, "status": status,
              "decision_reason": reason, "created_at": now, "updated_at": now,
              "amount_usd_minor": amount_usd,
              "notification": workflow["notification"], "replayed": False}
    return record


def get_expense(db, tenant: str, expense_id: str) -> dict | None:
    row = db.execute(
        """SELECT employee_id, category, amount_minor, currency, description,
                  receipt_attached, status, decision_reason, created_at, updated_at
           FROM expense_requests WHERE tenant=? AND expense_id=?""",
        (tenant, expense_id)).fetchone()
    if not row:
        return None
    steps = db.execute(
        "SELECT step_name, status, attempts, result FROM workflow_steps WHERE step_key=?",
        (f"{tenant}:{expense_id}",)).fetchall()
    return {"expense_id": expense_id, "employee_id": row[0], "category": row[1],
            "amount_minor": row[2], "currency": row[3], "description": row[4],
            "receipt_attached": bool(row[5]), "status": row[6],
            "decision_reason": row[7], "created_at": row[8], "updated_at": row[9],
            "workflow_steps": [{"step": s[0], "status": s[1], "attempts": s[2],
                                "result": s[3]} for s in steps]}


def list_expenses(db, tenant: str, limit: int = 50, offset: int = 0,
                  status: str | None = None) -> list[dict]:
    query = ("SELECT expense_id, employee_id, category, amount_minor, currency, "
             "description, receipt_attached, status, decision_reason, created_at "
             "FROM expense_requests WHERE tenant=?")
    params: list = [tenant]
    if status:
        query += " AND status=?"
        params.append(status)
    query += " ORDER BY rowid DESC LIMIT ? OFFSET ?"
    params += [limit, offset]
    rows = db.execute(query, params).fetchall()
    return [{"expense_id": row[0], "employee_id": row[1], "category": row[2],
             "amount_minor": row[3], "currency": row[4], "description": row[5],
             "receipt_attached": bool(row[6]), "status": row[7],
             "decision_reason": row[8], "created_at": row[9]} for row in rows]
