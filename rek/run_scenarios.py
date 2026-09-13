"""POST every scenario in run/scenarios.json to /api/v1/risk/evaluate and
print a comparison table.

Usage:
    ../.venv/bin/python run/run_scenarios.py
Env overrides:
    RISK_API_URL  (default http://127.0.0.1:8000)
    DEMO_API_TOKEN (defaults to the local demo token)
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import httpx

BASE_URL = os.environ.get("RISK_API_URL", "http://127.0.0.1:8000")
TOKEN = os.environ.get(
    "DEMO_API_TOKEN",
    "2GfoVnRNCn8BrkxSlPMfg80AFA_xLOGRcTUzBaouChk",
)

HEADERS = {"X-API-Key": TOKEN, "Content-Type": "application/json"}


def main() -> int:
    scenarios_file = Path(__file__).resolve().parent / "scenarios.json"
    scenarios = json.loads(scenarios_file.read_text())

    print(f"POST -> {BASE_URL}/api/v1/risk/evaluate\n")
    print(f"{'SCENARIO':<34}{'EXPECTED':<18}{'DECISION':<10}{'SCORE':>7}  TRIGGERED RULES")
    print("-" * 118)

    failures = 0
    with httpx.Client(base_url=BASE_URL, headers=HEADERS, timeout=30) as client:
        for sc in scenarios:
            name = sc["name"]
            try:
                resp = client.post("/api/v1/risk/evaluate",
                                   json={"customer": sc["customer"],
                                         "currentTransaction": sc["currentTransaction"],
                                         "history": sc["history"]})
                if resp.status_code != 200:
                    print(f"{name:<34}{sc['expectedDecisionHint']:<18} HTTP {resp.status_code}")
                    failures += 1
                    continue
                body = resp.json()
                rules = ", ".join(f"{r['ruleId']}({r['score']:.0f})"
                                  for r in body["triggeredRules"]) or "-"
                print(f"{name:<34}{sc['expectedDecisionHint']:<18}"
                      f"{body['decision']:<10}{body['riskScore']:>7.1f}  {rules}")
            except httpx.HTTPError as exc:
                print(f"{name:<34}{sc['expectedDecisionHint']:<18} ERROR {exc}")
                failures += 1

    print("-" * 118)
    if failures:
        print(f"\n{failures} scenario(s) failed to reach the API.")
        return 1
    print("\nAll scenarios evaluated.")
    return 0


if __name__ == "__main__":
    sys.exit(main())