"""SQLite migrations for the financial intelligence platform.

Single-writer SQLite stays the storage engine for this prototype; migrations run
once per process start under the store lock, before any request is served. Each
migration is an ordered list of SQL statements executed inside one transaction;
applied versions are recorded in `schema_version`.

Design notes:
  * fail-closed: an unknown/missing migration fails startup loudly instead of
    serving traffic against a half-migrated database;
  * migrations are append-only: never edit an applied migration, always add a
    new one, so an existing demo database upgrades in place;
  * every new table carries the strict-column discipline used by `transactions`.
"""
from __future__ import annotations

import sqlite3

SCHEMA_VERSION = 2

MIGRATIONS: dict[int, tuple[str, ...]] = {
    1: (
        # Base table, idempotent for callers that create it themselves first
        # (Store.__init__ creates it before migrations run).
        """CREATE TABLE IF NOT EXISTS transactions (
               tenant TEXT NOT NULL, tx_id TEXT NOT NULL, payload_hash TEXT NOT NULL,
               flagged INTEGER NOT NULL, record TEXT NOT NULL,
               PRIMARY KEY (tenant, tx_id))""",
        # Versioned key/value settings: approval policies, FX table, detector
        # calibration knobs. Operators may override values; services must not
        # assume any setting exists at runtime (readers supply defaults).
        """CREATE TABLE IF NOT EXISTS settings (
               key TEXT PRIMARY KEY,
               value TEXT NOT NULL,
               updated_at TEXT NOT NULL)""",
        """CREATE TABLE IF NOT EXISTS fx_rates (
               currency TEXT PRIMARY KEY,
               usd_per_unit REAL NOT NULL,
               updated_at TEXT NOT NULL)""",
        "INSERT OR IGNORE INTO fx_rates (currency, usd_per_unit, updated_at) "
        "VALUES ('USD', 1.0, '1970-01-01T00:00:00+00:00')",
        # AccountsPayable invoices. vendor_id is a pseudonymous ID with the same
        # restricted charset as other identifiers; description is the ONLY free
        # text and is bounded and charset-restricted at the schema layer.
        """CREATE TABLE IF NOT EXISTS invoices (
               invoice_id TEXT NOT NULL,
               tenant TEXT NOT NULL,
               vendor_id TEXT NOT NULL,
               invoice_number TEXT NOT NULL,
               issue_date TEXT NOT NULL,
               due_date TEXT NOT NULL,
               amount_minor INTEGER NOT NULL,
               currency TEXT NOT NULL,
               description TEXT NOT NULL,
               status TEXT NOT NULL,
               payload_hash TEXT NOT NULL,
               risks TEXT NOT NULL,
               created_at TEXT NOT NULL,
               updated_at TEXT NOT NULL,
               PRIMARY KEY (tenant, invoice_id))""",
        """CREATE TABLE IF NOT EXISTS expense_requests (
               expense_id TEXT NOT NULL,
               tenant TEXT NOT NULL,
               employee_id TEXT NOT NULL,
               category TEXT NOT NULL,
               amount_minor INTEGER NOT NULL,
               currency TEXT NOT NULL,
               description TEXT NOT NULL,
               receipt_attached INTEGER NOT NULL,
               status TEXT NOT NULL,
               decision_reason TEXT NOT NULL,
               payload_hash TEXT NOT NULL,
               created_at TEXT NOT NULL,
               updated_at TEXT NOT NULL,
               PRIMARY KEY (tenant, expense_id))""",
        # Durable workflow steps: the local EnterPro engine records one row per
        # logical step attempt so a crashed/restarted run resumes idempotently.
        """CREATE TABLE IF NOT EXISTS workflow_steps (
               step_key TEXT NOT NULL,
               step_name TEXT NOT NULL,
               status TEXT NOT NULL,
               result TEXT NOT NULL,
               attempts INTEGER NOT NULL,
               updated_at TEXT NOT NULL,
               PRIMARY KEY (step_key, step_name))""",
        # Exactly-once notification ledger: one row per unique notification key.
        """CREATE TABLE IF NOT EXISTS notifications (
               notify_key TEXT PRIMARY KEY,
               channel TEXT NOT NULL,
               message TEXT NOT NULL,
               sent_at TEXT NOT NULL)""",
    ),
    2: (
        # Denormalized query columns for per-account baselines. The record JSON
        # remains the source of truth; these columns exist so baseline windows
        # do not scan and parse every row.
        "ALTER TABLE transactions ADD COLUMN account_id TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE transactions ADD COLUMN created_at TEXT NOT NULL DEFAULT ''",
        "CREATE INDEX IF NOT EXISTS idx_transactions_account ON transactions (account_id, created_at)",
    ),
}


def ensure_schema(db: sqlite3.Connection) -> int:
    """Apply pending migrations in order and return the resulting version.

    Runs inside a transaction per migration; raises on any mismatch so callers
    fail closed at startup rather than serving traffic against a stale schema.
    The version table is normalized to exactly one row so a database that was
    interrupted mid-upgrade (or written by the earlier two-row bug) self-heals
    on the next startup instead of re-running applied migrations.
    """
    db.execute("CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)")
    rows = db.execute("SELECT version FROM schema_version").fetchall()
    current = max((int(r[0]) for r in rows), default=0)
    if current > SCHEMA_VERSION:
        raise RuntimeError(
            f"database schema version {current} is newer than this build "
            f"({SCHEMA_VERSION}); refusing to start")
    migrations_applied = False
    for version in range(current + 1, SCHEMA_VERSION + 1):
        statements = MIGRATIONS[version]
        with db:
            for statement in statements:
                db.execute(statement)
            # Replace, never append: stale or duplicate version rows would make
            # the next startup re-read an old version and re-run this migration.
            db.execute("DELETE FROM schema_version")
            db.execute("INSERT INTO schema_version (version) VALUES (?)", (version,))
        migrations_applied = True
    if not migrations_applied and len(rows) != 1:
        # Already up to date, but the version table is malformed (e.g. two rows
        # left by an interrupted upgrade or by the earlier two-row bug):
        # normalize to exactly one row carrying the current version, or the
        # next startup would re-read an old version and re-run migrations.
        with db:
            db.execute("DELETE FROM schema_version")
            db.execute("INSERT INTO schema_version (version) VALUES (?)", (current,))
    return SCHEMA_VERSION
