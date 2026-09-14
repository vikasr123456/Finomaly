"""Per-account behavioral baselines computed from ingested history.

Replaces the hardcoded `acct_demo` / `dev_known` / US / 5000-minor-unit profile:
every feature the detector uses is now relative to statistics derived from the
account's OWN transaction history (rolling window over everything ingested).

Honesty rules preserved from the prototype's design:
  * cold start: an account with fewer than MIN_ACCOUNT_EVENTS events has no
    trusted baseline and falls back to the global synthetic reference (the
    original seed-42 Isolation Forest population). Detection still runs, but
    evidence is labeled `baseline_source: "cold_start"` so no analyst mistakes
    a thin-data score for a calibrated one;
  * statistics are robust (median/MAD and frequency sets), never raw means that
    one large transaction can drag around;
  * nothing here is a probability of fraud — baseline statistics describe the
    account's observed history only.
"""
from __future__ import annotations

import math
import sqlite3
from datetime import datetime, timedelta, timezone

import numpy as np

MIN_ACCOUNT_EVENTS = 30
WINDOW_DAYS = 90
# The global reference population was generated with this divisor as its median
# spend scale; it is a property of the synthetic reference, not a business rule.
REFERENCE_MEDIAN_MINOR = 5000
REFERENCE_HOUR_MEAN = 14.0
REFERENCE_HOUR_STD = 3.0


def _median_mad(values: list[float]) -> tuple[float, float]:
    array = np.asarray(values, dtype=float)
    median = float(np.median(array))
    mad = float(np.median(np.abs(array - median)))
    if mad <= 0:
        mad = float(np.std(array)) or 1.0
    return median, mad


class AccountBaseline:
    """Statistics for one account over the rolling window."""

    __slots__ = ("account_id", "sample_size", "median_amount_minor", "mad_log_amount",
                 "known_devices", "known_countries", "hour_weights",
                 "baseline_source", "computed_at")

    def __init__(self, account_id: str, sample_size: int, median_amount_minor: float,
                 mad_log_amount: float, known_devices: set[str], known_countries: set[str],
                 hour_weights: list[float], baseline_source: str, computed_at: str):
        self.account_id = account_id
        self.sample_size = sample_size
        self.median_amount_minor = median_amount_minor
        self.mad_log_amount = mad_log_amount
        self.known_devices = known_devices
        self.known_countries = known_countries
        # 24 bins of historical activity by UTC hour, each in [0, 1].
        self.hour_weights = hour_weights
        self.baseline_source = baseline_source
        self.computed_at = computed_at

    def hour_deviation(self, hour: float) -> float:
        """1 - activity weight at this hour: 0 = typical hour, 1 = never seen."""
        if not self.hour_weights or max(self.hour_weights) <= 0:
            # No usable hour signal: fall back to the synthetic profile's shape.
            weight = math.exp(-0.5 * ((hour - REFERENCE_HOUR_MEAN) / REFERENCE_HOUR_STD) ** 2)
            return 1.0 - weight
        index = int(math.floor(hour)) % 24
        return 1.0 - self.hour_weights[index]


class BaselineStore:
    """Computes and caches per-account baselines from the transactions table."""

    def __init__(self, db: sqlite3.Connection, refresh_every: int = 25):
        self.db = db
        self.refresh_every = max(1, int(refresh_every))
        self._cache: dict[tuple[str, str], AccountBaseline] = {}
        self._since_refresh = 0

    def invalidate(self, account_id: str | None = None) -> None:
        if account_id is None:
            self._cache.clear()
        else:
            for key in [k for k in self._cache if k[1] == account_id]:
                del self._cache[key]

    def note_ingest(self, tenant: str | None = None, account_id: str | None = None) -> None:
        """Called after each accepted ingest.

        The account's cached baseline is dropped immediately so the next score
        uses fresh statistics; a periodic full sweep also expires entries whose
        rolling window has moved on.
        """
        if account_id is not None:
            self._cache.pop((tenant or "demo-tenant", account_id), None)
        self._since_refresh += 1
        if self._since_refresh >= self.refresh_every:
            self._since_refresh = 0
            self.invalidate()

    def all_account_ids(self, tenant: str = "demo-tenant") -> list[str]:
        rows = self.db.execute("SELECT DISTINCT account_id FROM transactions WHERE tenant=?",
                               (tenant,)).fetchall()
        return [row[0] for row in rows]

    def compute(self, account_id: str, tenant: str = "demo-tenant") -> AccountBaseline | None:
        """Compute a baseline from stored history, or None with no history at all."""
        cutoff = (datetime.now(timezone.utc) - timedelta(days=WINDOW_DAYS)).isoformat()
        rows = self.db.execute(
            """SELECT record FROM transactions
               WHERE tenant=? AND account_id=? AND created_at >= ?
               ORDER BY created_at DESC LIMIT 5000""",
            (tenant, account_id, cutoff)).fetchall()
        if not rows:
            return None
        import json as _json
        events = []
        for row in rows:
            record = _json.loads(row[0])
            # Records nest the transaction; tolerate both shapes defensively.
            events.append(record["transaction"] if isinstance(record.get("transaction"), dict)
                          else record)
        amounts = [float(event["amount_minor"]) for event in events]
        devices = [event["device_id"] for event in events]
        countries = [event["country"] for event in events]
        hours = [int(event["event_time"][11:13]) for event in events]

        # _median_mad works in log1p space (robust for heavy-tailed amounts);
        # the stored median must be converted BACK to real minor units, or every
        # amount-to-baseline ratio is inflated by roughly the log of the amount.
        median_log, mad_log = _median_mad([math.log1p(a) for a in amounts])
        median_amount = math.expm1(median_log)
        hour_weights = [0.0] * 24
        for hour in hours:
            hour_weights[hour % 24] += 1.0
        total = float(sum(hour_weights)) or 1.0
        hour_weights = [weight / total for weight in hour_weights]

        source = "account" if len(events) >= MIN_ACCOUNT_EVENTS else "cold_start"
        return AccountBaseline(
            account_id=account_id,
            sample_size=len(events),
            median_amount_minor=median_amount,
            mad_log_amount=mad_log,
            known_devices=set(devices),
            known_countries=set(countries),
            hour_weights=hour_weights,
            baseline_source=source,
            computed_at=datetime.now(timezone.utc).isoformat(),
        )

    def get(self, account_id: str, allow_reference: bool = True,
            tenant: str = "demo-tenant") -> AccountBaseline | None:
        """Return the cached-or-computed baseline for a (tenant, account).

        Baselines are tenant-scoped: one tenant's history never shapes another
        tenant's statistics. With no stored history and `allow_reference`, a
        synthetic reference baseline is returned (cold start) so detection
        remains functional for brand-new accounts; it is always labeled
        `cold_start` with sample_size 0.
        """
        cache_key = (tenant, account_id)
        if cache_key in self._cache:
            return self._cache[cache_key]
        baseline = self.compute(account_id, tenant)
        if baseline is not None:
            self._cache[cache_key] = baseline
            return baseline
        if allow_reference:
            # Synthetic cold-start reference; deliberately NOT cached so a
            # caller that refuses the fallback (allow_reference=False) always
            # sees the truth: no trusted baseline exists yet.
            return AccountBaseline(
                account_id=account_id,
                sample_size=0,
                median_amount_minor=float(REFERENCE_MEDIAN_MINOR),
                mad_log_amount=0.4,
                known_devices=set(),
                known_countries={"US"},
                hour_weights=[],
                baseline_source="cold_start",
                computed_at=datetime.now(timezone.utc).isoformat(),
            )
        return None
