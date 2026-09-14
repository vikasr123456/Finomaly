"""Local EnterPro-compatible workflow engine.

Implements the primitive semantics the design pseudocode describes — for real,
locally, on top of SQLite:

  * `durable_step` — a step runs at most once per (key, step_name); its result
    is persisted BEFORE being returned, so a crash or restart resumes with the
    stored result instead of re-executing side effects. Failed steps record the
    error class and can be retried up to a bounded attempt budget.
  * `notify_once` — exactly-once notification ledger keyed by a unique string;
    a repeated key is a no-op that reports `already_sent`.
  * `http_action` — bounded, non-redirecting HTTP request usable as a step body.

This is NOT the EnterPro platform. It is the local engine the expense workflow
runs on, with the same durable semantics so moving to the real orchestrator is
a mechanical substitution of primitives, not a redesign.

Keys: pass a tuple (tenant, entity_id, ...) or a prejoined string; tuples are
normalized to colon-joined strings so the workflow_steps primary key stays a
single column. Results are stored as JSON — never store credentials here.
"""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone

import httpx

MAX_STEP_ATTEMPTS = 3


class WorkflowStepError(RuntimeError):
    """A durable step exhausted its attempt budget or failed terminally."""


def _key(value) -> str:
    if isinstance(value, tuple):
        return ":".join(str(part) for part in value)
    return str(value)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class WorkflowEngine:
    """Durable step + notification primitives bound to one SQLite connection."""

    def __init__(self, db: sqlite3.Connection, lock=None):
        self.db = db
        # Share the store's lock when embedded in the request path so step
        # writes serialize with the rest of storage.
        self.lock = lock

    # -- durable steps -------------------------------------------------------

    def _load(self, key: str, name: str):
        return self.db.execute(
            "SELECT status, result, attempts FROM workflow_steps WHERE step_key=? AND step_name=?",
            (key, name)).fetchone()

    def durable_step(self, key, name: str, operation, max_attempts: int = MAX_STEP_ATTEMPTS):
        """Run `operation` at most once per (key, name); resume from storage.

        A completed step returns its stored result without re-running. A failed
        step records the failure and re-raises; once failures reach
        `max_attempts` the step is stuck and raises WorkflowStepError without
        executing again (a stuck step is surfaced, never silently retried).
        """
        key = _key(key)

        def execute():
            row = self._load(key, name)
            if row:
                status, result, attempts = row
                if status == "done":
                    return json.loads(result), False
                if status == "failed" and attempts >= max_attempts:
                    raise WorkflowStepError(
                        f"step {name} for {key} stuck after {attempts} failure(s): {result}")
            try:
                value = operation()
            except Exception as exc:
                message = type(exc).__name__ + (f": {exc}" if str(exc) else "")
                self._record(key, name, "failed", message)
                raise
            return self._record(key, name, "done", value), True

        if self.lock is not None:
            with self.lock:
                stored, executed = execute()
        else:
            stored, executed = execute()
        return stored, executed

    def _record(self, key: str, name: str, status: str, value):
        payload = json.dumps(value)
        self.db.execute(
            """INSERT INTO workflow_steps (step_key, step_name, status, result, attempts, updated_at)
               VALUES (?, ?, ?, ?, 1, ?)
               ON CONFLICT(step_key, step_name) DO UPDATE SET
                 status=excluded.status,
                 result=excluded.result,
                 attempts=workflow_steps.attempts + 1,
                 updated_at=excluded.updated_at""",
            (key, name, status, payload, _now()))
        self.db.commit()
        return value

    def step_state(self, key, name: str) -> dict | None:
        row = self._load(_key(key), name)
        if not row:
            return None
        return {"status": row[0], "result": row[1], "attempts": row[2]}

    # -- exactly-once notifications ------------------------------------------

    def notify_once(self, key, channel: str, message: str) -> dict:
        """Record-and-send semantics: the ledger row IS the send.

        Returns {"delivered": bool, "already_sent": bool}. In production this
        writes an outbox row that a real channel drains; the idempotency
        contract is identical.
        """
        notify_key = _key(key)
        with self.db:
            cursor = self.db.execute(
                "INSERT OR IGNORE INTO notifications (notify_key, channel, message, sent_at) "
                "VALUES (?, ?, ?, ?)",
                (notify_key, channel, message, _now()))
        return {"delivered": cursor.rowcount == 1, "already_sent": cursor.rowcount != 1,
                "channel": channel}

    # -- HTTP action ----------------------------------------------------------

    def http_action(self, method: str, url: str, json_body: dict | None = None,
                    headers: dict | None = None, timeout: float = 10.0) -> dict:
        """Bounded HTTP request usable inside a step body.

        No redirects (a compromised target cannot bounce this service), strict
        timeout, JSON in/JSON out. The caller supplies credentials explicitly;
        nothing here reads or stores secrets.
        """
        with httpx.Client(timeout=httpx.Timeout(timeout, connect=5),
                          follow_redirects=False) as client:
            response = client.request(method, url, json=json_body, headers=headers or {})
        if response.status_code >= 400:
            raise WorkflowStepError(f"http_{response.status_code}")
        try:
            return response.json()
        except ValueError as exc:
            raise WorkflowStepError("non_json_response") from exc


def expense_approval_workflow(engine: WorkflowEngine, tenant: str, expense_id: str,
                              risk_check, decide, deliver) -> dict:
    """Reference workflow: validate -> risk-check -> decide -> deliver.

    Each stage is a durable step keyed by (tenant, expense_id), so a replayed
    submission resumes instead of re-deciding. `risk_check`, `decide` and
    `deliver` are zero-arg callables supplied by the caller; `deliver` performs
    the notification side effects through notify_once.
    """
    key = (tenant, expense_id)
    _, risk_ran = engine.durable_step(key, "risk_check", risk_check)
    decision, _ = engine.durable_step(key, "decide", decide)
    notified, _ = engine.durable_step(key, "deliver", deliver)
    return {"risk_check_executed": risk_ran, "decision": decision,
            "notification": notified}
