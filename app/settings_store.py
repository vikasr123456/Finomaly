"""Operator-editable settings persisted in SQLite (the `settings` table).

Deliberately NOT hardcoded detector constants: approval thresholds, FX rates and
calibration knobs live in versioned rows, read through this store with explicit
defaults. Values are plain JSON so operators can inspect them with sqlite3.
"""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone

DEFAULT_FX_USD_PER_UNIT: dict[str, float] = {
    "USD": 1.0,
    "EUR": 1.08,
    "GBP": 1.27,
    "INR": 0.012,
    "CAD": 0.73,
    "AUD": 0.66,
    "JPY": 0.0067,
}

DEFAULT_SETTINGS: dict[str, str] = {
    "fx_rates": json.dumps(DEFAULT_FX_USD_PER_UNIT),
    "expense_policy": json.dumps({
        "auto_approve_minor": 50000,
        "finance_review_minor": 200000,
        "receipt_required_minor": 100000,
        "risk_score_gate": 0.85,
    }),
    "ap_duplicate_window_days": "14",
}


class SettingsStore:
    """JSON-backed settings with typed defaults; writes are operator actions."""

    def __init__(self, db: sqlite3.Connection):
        self.db = db

    def get_json(self, key: str, default):
        row = self.db.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
        if not row:
            return default
        try:
            return json.loads(row[0])
        except ValueError:
            return default

    def get_str(self, key: str, default: str) -> str:
        row = self.db.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
        if not row:
            return default
        return row[0]

    def set(self, key: str, value: str) -> None:
        self.db.execute(
            """INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)
               ON CONFLICT(key) DO UPDATE SET value=excluded.value,
                                              updated_at=excluded.updated_at""",
            (key, value, datetime.now(timezone.utc).isoformat()))
        self.db.commit()

    def fx_rate(self, currency: str) -> float:
        """USD per one unit of `currency`; falls back to documented defaults."""
        rates = self.get_json("fx_rates", DEFAULT_FX_USD_PER_UNIT)
        if not isinstance(rates, dict):
            return DEFAULT_FX_USD_PER_UNIT.get(currency, 1.0)
        rate = rates.get(currency)
        if not isinstance(rate, (int, float)) or rate <= 0:
            rate = DEFAULT_FX_USD_PER_UNIT.get(currency, 1.0)
        return float(rate)
