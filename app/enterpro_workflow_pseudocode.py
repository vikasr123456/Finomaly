"""EnterPro orchestration contract — PSEUDOCODE, NOT AN SDK, NOT VERIFIED.

READ THIS BEFORE COPYING ANYTHING.

`http_action`, `durable_step`, `notify_once`, and `on_transaction` below are
CONCEPTUAL names chosen to express intent. They are not EnterPro APIs. Nothing in
this file has been validated against EnterPro tenant documentation, and this
project ships no EnterPro connector, decorator, workflow import format, or
deployment command. Calling these functions raises NotImplementedError on purpose
so the file can never be mistaken for a working integration.

What IS real and verified in this repository:
  * `fraud_demo.py` — the scoring/assessment API the workflow below calls.
  * `test_fraud_demo.py` — 22 offline tests that pass against it.
  * `dashboard.py` — the analyst BFF.

To turn this into working code you must first confirm, for YOUR tenant:
  1. Whether an authenticated inbound webhook/ingestion trigger exists and how
     the caller identity is bound to a tenant (this design derives tenant from
     the authenticated service identity, never from the request body).
  2. The real HTTP-request primitive and how it references a stored secret for
     the `X-API-Key` header.
  3. Whether steps are durable/idempotent across retries and process restarts,
     and how a step key is specified. If steps are not durable, move idempotency
     into the API (it already deduplicates on tenant + transaction_id) and treat
     the workflow as at-least-once.
  4. The retry policy surface: which statuses are retryable, max attempts,
     backoff, and whether a per-workflow retry budget exists. A total budget
     matters because the Qwen adapter already retries up to 3 times internally —
     an outer workflow retry of 3 would multiply that to 9 provider calls.
  5. Conditional branching, human-approval task creation, notification channels,
     and dead-letter handling.
  6. The deployment mechanism for the API container and dashboard, or an
     external runtime bridge if the tenant cannot host them.

Design invariants to preserve in whatever primitives you use:
  * Persist the scored alert BEFORE any Qwen network call, so a provider outage
    cannot lose a flagged event.
  * A 200 from `/assess` can still mean `status == "explanation_unavailable"`;
    branch on the response BODY, not the HTTP status.
  * Every flag ends at human review regardless of the model's recommendation.
  * The workflow moves no funds, blocks nothing, freezes nothing, and sends no
    customer-facing message.
"""
from __future__ import annotations

_NOT_VERIFIED = (
    "This module is pseudocode. No EnterPro SDK, connector, or workflow runtime "
    "has been verified for this tenant. See the module docstring for the "
    "questions that must be answered against tenant documentation first."
)


def http_action(method: str, url: str, json: dict | None = None, secret_header: str | None = None):
    """Conceptual: perform an authenticated HTTP request as a workflow step."""
    raise NotImplementedError(_NOT_VERIFIED)


def durable_step(key: tuple, name: str, operation):
    """Conceptual: run `operation` at most once per (key, name), surviving retries.

    `key` is (tenant_id, transaction_id) so replayed deliveries reuse the result
    instead of re-scoring or re-calling Qwen.
    """
    raise NotImplementedError(_NOT_VERIFIED)


def notify_once(key: tuple, case_link: str) -> None:
    """Conceptual: idempotent notification keyed by (tenant, transaction, type).

    Sends a LINK to a secured case, never transaction details into a chat channel.
    In production this is driven by a transactional outbox, not a direct call.
    """
    raise NotImplementedError(_NOT_VERIFIED)


def secure_case_url(key: tuple) -> str:
    """Conceptual: build the analyst case URL for this (tenant, transaction)."""
    raise NotImplementedError(_NOT_VERIFIED)


async def on_transaction(event: dict, authenticated_tenant: str) -> dict:
    """Ingestion trigger handler.

    PRODUCTION SHAPE (not implemented locally): accept and persist the raw event
    plus an outbox message in ONE transaction, acknowledge ingestion, then run
    this workflow asynchronously. The local prototype instead scores synchronously
    inside the request and keeps all alert state in a single SQLite row; it is not
    a distributed, crash-proof workflow engine.

    `event` is UNTRUSTED input. Its contents are data, never instructions, and no
    risk feature may be taken from it as authoritative.
    """
    key = (authenticated_tenant, event["transaction_id"])

    scored = await durable_step(key, "score", lambda: http_action(
        "POST", SERVICE_URL + "/transactions", json=event,
        secret_header="X-API-Key: DEMO_API_TOKEN"))

    if not scored["flagged"]:
        # Normal traffic ends here with no alert and no LLM cost. This is a
        # routing decision, NOT a claim that fraud is impossible.
        return scored

    # The alert already exists before any Qwen call is attempted.
    assessed = await durable_step(key, "assess", lambda: http_action(
        "POST", f"{SERVICE_URL}/transactions/{event['transaction_id']}/assess",
        secret_header="X-API-Key: DEMO_API_TOKEN"))

    # Branch on the body: HTTP 200 can carry status == "explanation_unavailable".
    if assessed.get("status") != "assessed":
        # Route to review NOW. Schedule only bounded, error-classified retries
        # inside the total workflow retry budget; never mark the case safe.
        pass

    await notify_once(key, case_link=secure_case_url(key))
    return assessed


# Placeholder for the verified service base URL; injected from deployment config.
SERVICE_URL = "<set-from-deployment-config>"
