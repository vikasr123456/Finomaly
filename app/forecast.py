"""Cash-flow forecasting from ingested transactions (Track 3: Finance).

Method (deliberately simple and explainable, no black boxes):
  * build a daily NET-cash series: outflows subtract, inflows add, amounts
    normalized to USD via the FX settings;
  * weekly seasonal-naive component (same weekday median over the window) plus
    a robust linear trend on log1p of positive days;
  * 80% interval from empirical residual quantiles — not a Gaussian fiction.

Fail-closed honesty: with fewer than MIN_HISTORY_DAYS of coverage the endpoint
returns `insufficient_data` with the coverage details instead of a made-up
forecast. A forecast here is an estimate of business cash movement, not a
guarantee, and never an instruction to move money.
"""
from __future__ import annotations

import math
from datetime import datetime, timedelta, timezone

MIN_HISTORY_DAYS = 14
FORECAST_HORIZON_MAX = 90


def _parse_day(value: str) -> str:
    return str(value)[:10]


def build_daily_series(db) -> dict[str, float]:
    """Aggregate ingested transactions into a day -> net-USD-cents mapping."""
    series: dict[str, float] = {}
    rows = db.execute(
        """SELECT record FROM transactions WHERE flagged IN (0, 1) ORDER BY created_at ASC"""
    ).fetchall()
    import json as _json
    for (record_text,) in rows:
        record = _json.loads(record_text)
        tx = record.get("transaction") or {}
        day = _parse_day(tx.get("event_time", ""))
        if not day:
            continue
        amount = record.get("amount_usd_minor")
        if amount is None:
            continue
        direction = 1.0 if tx.get("direction") == "inflow" else -1.0
        series[day] = series.get(day, 0.0) + direction * float(amount)
    return series


def _weekday_profile(days: list[str], values: dict[str, float]) -> list[float]:
    """Median NET cash per weekday; values are signed (inflow positive)."""
    buckets: dict[int, list[float]] = {i: [] for i in range(7)}
    for day in days:
        date = datetime.strptime(day, "%Y-%m-%d")
        buckets[date.weekday()].append(values.get(day, 0.0))
    profile = []
    for bucket in (buckets[i] for i in range(7)):
        if bucket:
            ordered = sorted(bucket)
            middle = len(ordered) // 2
            profile.append(ordered[middle] if len(ordered) % 2
                           else (ordered[middle - 1] + ordered[middle]) / 2.0)
        else:
            profile.append(0.0)
    return profile


def _trend(series_days: list[str], values: dict[str, float],
           weekday: list[float]) -> tuple[float, float]:
    """OLS slope/intercept on weekday-detrended residuals (signed values OK)."""
    xs, ys = [], []
    for index, day in enumerate(series_days):
        base = weekday[datetime.strptime(day, "%Y-%m-%d").weekday()]
        xs.append(float(index))
        ys.append(values.get(day, 0.0) - base)
    if len(xs) < 3:
        return 0.0, 0.0
    n = float(len(xs))
    mean_x = sum(xs) / n
    mean_y = sum(ys) / n
    cov = sum((x - mean_x) * (y - mean_y) for x, y in zip(xs, ys))
    var = sum((x - mean_x) ** 2 for x in xs)
    slope = cov / var if var else 0.0
    return slope, mean_y - slope * mean_x


def forecast_cashflow(db, horizon_days: int = 30) -> dict:
    horizon_days = max(1, min(int(horizon_days), FORECAST_HORIZON_MAX))
    series = build_daily_series(db)
    if not series:
        return {"status": "insufficient_data", "horizon_days": horizon_days,
                "coverage_days": 0, "reason": "no ingested transactions"}
    days = sorted(series)
    start = datetime.strptime(days[0], "%Y-%m-%d")
    end = datetime.strptime(days[-1], "%Y-%m-%d")
    coverage_days = (end - start).days + 1
    if coverage_days < MIN_HISTORY_DAYS:
        return {"status": "insufficient_data", "horizon_days": horizon_days,
                "coverage_days": coverage_days,
                "reason": f"need at least {MIN_HISTORY_DAYS} days of history"}

    weekday = _weekday_profile(days, series)
    slope, intercept = _trend(days, series, weekday)

    inflow_total = sum(v for v in series.values() if v > 0)
    outflow_total = sum(v for v in series.values() if v < 0)  # negative: cash leaving

    points = []
    residuals = []
    for index, day in enumerate(days):
        base = weekday[datetime.strptime(day, "%Y-%m-%d").weekday()]
        fitted = base + slope * index + intercept
        residuals.append(series.get(day, 0.0) - fitted)
    residuals.sort()
    if residuals:
        low_q = residuals[max(0, int(0.10 * len(residuals)))]
        high_q = residuals[min(len(residuals) - 1, int(0.90 * len(residuals)))]
    else:
        low_q = high_q = 0.0

    for step in range(1, horizon_days + 1):
        date = end + timedelta(days=step)
        base = weekday[date.weekday()]
        fitted = base + slope * (len(days) - 1 + step) + intercept
        points.append({
            "date": date.strftime("%Y-%m-%d"),
            "net_usd_cents": round(fitted),
            "low_usd_cents": round(fitted + low_q),
            "high_usd_cents": round(fitted + high_q),
        })

    total_net = sum(point["net_usd_cents"] for point in points)
    seasonality_strength = (max(weekday) - min(weekday)) / (max(abs(v) for v in weekday) or 1.0)
    return {
        "status": "ok",
        "horizon_days": horizon_days,
        "coverage_days": coverage_days,
        "history_start": days[0],
        "history_end": days[-1],
        "trend_per_day_usd_cents": round(slope, 0),
        "trend_coefficient": round(slope, 6),
        "seasonality_strength": round(min(1.0, max(0.0, seasonality_strength)), 3),
        "historical_inflow_usd_cents": round(inflow_total),
        "historical_outflow_usd_cents": round(outflow_total),
        "projected_net_usd_cents": round(total_net),
        "projected_low_usd_cents": round(sum(point["low_usd_cents"] for point in points)),
        "projected_high_usd_cents": round(sum(point["high_usd_cents"] for point in points)),
        "points": points,
        "method": "weekly seasonal (median net per weekday) + linear trend on residuals; empirical 80% interval",
        "disclaimer": ("Estimate of business cash movement from ingested history. "
                       "Not financial advice and not an instruction to move money."),
    }
