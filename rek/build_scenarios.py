"""Generate run/scenarios.json — realistic request payloads for one customer
across different risk scenarios for POST /api/v1/risk/evaluate.

Run:  ../.venv/bin/python run/build_scenarios.py     (from repo root)
Output: run/scenarios.json
"""
from __future__ import annotations

import json
from pathlib import Path

# --- Locations --------------------------------------------------------------
BENGALURU = {"latitude": 12.9716, "longitude": 77.5946}
DELHI = {"latitude": 28.6139, "longitude": 77.2090}

# --- Customer ---------------------------------------------------------------
CUSTOMER = {"id": "USER-1001", "accountAgeDays": 1240}

# --- Reusable baseline history ----------------------------------------------
# 16 'business as usual' transactions, Sep 1-13, INR 400-4500, daytime IST.

_MERCHANT_POOL = [
    ("Grocery Bazaar", "BEN-KIRANA"),
    ("Metro Electronics", "BEN-ELECTRO"),
    ("Pharmacy 24x7", "BEN-PHARMA"),
    ("Fuel Station", "BEN-FUEL"),
    ("City Rent", "BEN-RENT"),
]


def _baseline(n=16) -> list[dict]:
    """Daytime UPI history in Bengaluru on DEV-HOME-ANDROID."""
    txns = []
    for i in range(n):
        day = 1 + i % 13
        hour = 9 + (i * 4) % 10          # 09:00-18:00 IST
        minute = (i * 17) % 60
        amount = float(400 + (i * 231) % 4100)
        merchant, ben = _MERCHANT_POOL[i % len(_MERCHANT_POOL)]
        txns.append({
            "id": f"BASE-{i+1:02d}",
            "amount": amount,
            "currency": "INR",
            "timestamp": f"2026-09-{day:02d}T{hour:02d}:{minute:02d}:00+05:30",
            "merchant": merchant,
            "beneficiaryId": ben,
            "deviceId": "DEV-HOME-ANDROID",
            "location": BENGALURU,
            "channel": "UPI",
            "status": "SUCCESS",
        })
    return txns


def _tx(tid, amount, iso, merchant, ben, device="DEV-HOME-ANDROID",
        channel="UPI", status="SUCCESS", location=BENGALURU) -> dict:
    return {
        "id": tid, "amount": float(amount), "currency": "INR",
        "timestamp": iso, "merchant": merchant, "beneficiaryId": ben,
        "deviceId": device, "location": location, "channel": channel,
        "status": status,
    }


def _scenario(name, description, current, history, expected) -> dict:
    return {
        "name": name,
        "description": description,
        "expectedDecisionHint": expected,
        "customer": CUSTOMER,
        "currentTransaction": current,
        "history": history,
    }


S = []  # scenarios

# 1. Normal daily purchase ------------------------------------------------
S.append(_scenario(
    "normal_grocery_purchase",
    "Routine small grocery payment exactly matching history behaviour.",
    _tx("SCN-01", 1150, "2026-09-14T10:30:00+05:30",
        "Grocery Bazaar", "BEN-KIRANA"),
    _baseline(),
    "ALLOW / MONITOR",
))

# 2. Unusually large transfer ---------------------------------------------
S.append(_scenario(
    "unusual_amount_transfer",
    "Lump-sum IMPS transfer ~140x the customer's normal average to a brand-new beneficiary.",
    _tx("SCN-02", 300000, "2026-09-14T13:45:00+05:30",
        "IMPS Transfer", "BEN-THERAPY-NEW"),
    _baseline(),
    "REVIEW / FRAUD",
))

# 3. Round-number structuring ---------------------------------------------
_structuring_history = _baseline(13)
_structuring_history += [
    _tx("SCN-03A", 50000, "2026-09-12T16:05:00+05:30", "City Rent", "BEN-RENT2"),
    _tx("SCN-03B", 50000, "2026-09-13T16:08:00+05:30", "City Rent", "BEN-RENT2"),
]
S.append(_scenario(
    "round_number_structuring",
    "Three exact ₹50,000 transfers below reportable thresholds (structuring) to the same beneficiary.",
    _tx("SCN-03", 50000, "2026-09-14T16:10:00+05:30", "City Rent", "BEN-RENT2"),
    _structuring_history,
    "MONITOR / REVIEW",
))

# 4. Rapid money movement -------------------------------------------------
_rapid_history = [
    _tx("SCN-04A", 900000, "2026-09-14T17:52:00+05:30",
        "Property Refund", "BEN-REFUND-SRC", channel="NET_BANKING"),
    _tx("SCN-04B", 600, "2026-09-14T09:12:00+05:30", "Grocery Bazaar", "BEN-KIRANA"),
    *_baseline(4),
]
S.append(_scenario(
    "rapid_money_movement",
    "₹9,00,000 credit lands; ₹7,50,000 moves out to a fresh beneficiary ~8 minutes later.",
    _tx("SCN-04", 750000, "2026-09-14T18:00:00+05:30",
        "PayFriend", "BEN-LAYERING-NEW", channel="NET_BANKING"),
    _rapid_history,
    "REVIEW / FRAUD",
))

# 5. Velocity burst --------------------------------------------------------
_velocity_history = _baseline(4)
_burst_base = "2026-09-14T18:30:00+05:30"
for i in range(16):
    minute = i * 2                                     # 16 txs across 30 min
    _velocity_history.append(
        _tx(f"SCN-05{i:02d}", float(300 + (i % 5) * 100),
            f"2026-09-14T18:{minute:02d}:00+05:30",
            "Metro Electronics", "BEN-ELECTRO",))
S.append(_scenario(
    "velocity_burst",
    "16 purchases in 30 minutes (12 within 5 minutes) — far above the customer's cadence.",
    _tx("SCN-05", 4200, "2026-09-14T18:32:00+05:30",
        "Metro Electronics", "BEN-ELECTRO"),
    _velocity_history,
    "MONITOR / REVIEW",
))

# 6. New device + night-login transfer ------------------------------------
_night_history = [
    _tx(f"SCN-06B{i}", 300 + i * 250,
        f"2026-09-{10+i:02d}T19:30:00+05:30", "Grocery Bazaar", "BEN-KIRANA")
    for i in range(5)
]
S.append(_scenario(
    "new_device_night_transfer",
    "Large transfer at 02:30 UTC (~08:00 IST) from a brand-new device, new device + new beneficiary + amount anomaly.",
    _tx("SCN-06", 150000, "2026-09-15T02:30:00+00:00",
        "IMPS Transfer", "BEN-NIGHT-NEW", device="DEV-EMU-2026"),
    _night_history,
    "REVIEW / FRAUD",
))

# 7. Geographic jump -------------------------------------------------------
S.append(_scenario(
    "location_anomaly",
    "Same device/beneficiary but 1,740 km away in Delhi the same day.",
    _tx("SCN-07", 4200, "2026-09-14T14:00:00+05:30",
        "Grocery Bazaar", "BEN-KIRANA", location=DELHI),
    _baseline(),
    "MONITOR / REVIEW",
))

# 8. Escalating amounts ----------------------------------------------------
_progression_history = _baseline(4)
for i, amt in enumerate([1000, 2000, 4000, 8000]):
    _progression_history.append(
        _tx(f"SCN-08A{i}", amt, f"2026-09-{10+i:02d}T12:00:00+05:30",
            "Metro Electronics", "BEN-ELECTRO"))
S.append(_scenario(
    "amount_progression",
    "History shows 1k→2k→4k→8k creep, then a sudden ₹5,00,000 jump (fraud escalation pattern).",
    _tx("SCN-08", 500000, "2026-09-14T12:05:00+05:30",
        "Metro Electronics", "BEN-ELECTRO"),
    _progression_history,
    "REVIEW / FRAUD",
))

# 9. Beneficiary concentration ---------------------------------------------
_concentration_history = []
for i in range(12):
    _concentration_history.append(_tx(
        f"SCN-09A{i:02d}", 1000 + (i % 4) * 500,
        f"2026-09-{1+i%13:02d}T11:00:00+05:30", "Property Mgmt", "BEN-LANDLORD"))
_concentration_history += _baseline(4)
S.append(_scenario(
    "beneficiary_concentration",
    "75% of funds flow to one landlord beneficiary; money now routed somewhere new.",
    _tx("SCN-09", 6000, "2026-09-14T11:20:00+05:30",
        "Transfer", "BEN-NEW-REDIRECT"),
    _concentration_history,
    "MONITOR / REVIEW",
))

# 10. Failed attempts -> success -------------------------------------------
_failed_history = _baseline(6)
for i in range(3):
    _failed_history.append(_tx(
        f"SCN-10F{i}", 59999, f"2026-09-14T09:{10 + i * 3:02d}:00+05:30",
        "Electronics", "BEN-VENDOR", status="DECLINED"))
S.append(_scenario(
    "failed_pattern",
    "Three declined ₹59,999 attempts immediately followed by a successful one — card testing.",
    _tx("SCN-10", 59999, "2026-09-14T09:22:00+05:30",
        "Electronics", "BEN-VENDOR"),
    _failed_history,
    "MONITOR / REVIEW",
))

# 11. Brand-new customer, no history ---------------------------------------
S.append(_scenario(
    "new_customer_first_transaction",
    "Customer with zero history makes a small first payment — only mild identity rules can fire.",
    _tx("SCN-11", 1500, "2026-09-14T10:15:00+05:30",
        "Grocery Bazaar", "BEN-KIRANA"),
    [],
    "ALLOW",
))

# 12. Behavioural change (composite) ---------------------------------------
S.append(_scenario(
    "behavioral_change",
    "Everything differs at once: new device, new merchant, new beneficiary, big amount, different hour.",
    _tx("SCN-12", 95000, "2026-09-15T03:10:00+00:00",
        "Gold Trading Co", "BEN-GOLD-NEW", device="DEV-GALAXY-88"),
    _baseline(),
    "REVIEW / FRAUD",
))

out = Path(__file__).resolve().parent / "scenarios.json"
out.write_text(json.dumps(S, indent=2))
print(f"Wrote {len(S)} scenarios -> {out}")