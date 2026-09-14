"""Offline tests. Provider traffic is simulated with HTTPX MockTransport."""
import json
import math
import os
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import httpx
from fastapi.testclient import TestClient
from pydantic import ValidationError

from fraud_demo import (
    AssessmentUnavailable, Detector, Qwen, Store, Transaction, create_app, simulate,
    StreamConfig, StreamEngine, simulation_base_url, stream_events,
)


class FraudTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.detector = Detector()
        cls.normal = next(simulate())
        cls.suspicious = list(simulate())[4]

    def setUp(self):
        self.store = Store(":memory:", self.detector, Qwen(mode="mock"))
        self.addCleanup(self.store.close)

    def record(self):
        return self.store.ingest("tenant-a", Transaction(**self.suspicious))

    def test_normal_bypasses_qwen(self):
        tx = Transaction(**self.normal)
        record = self.store.ingest("tenant-a", tx)
        self.assertFalse(record["flagged"])
        with patch.object(self.store.qwen, "assess", side_effect=AssertionError("No call expected")):
            self.assertIsNone(self.store.assess("tenant-a", tx.transaction_id)["explanation"])

    def test_anomaly_evidence(self):
        record = self.record()
        self.assertTrue(record["flagged"])
        self.assertTrue(record["detection"]["rule_flag"])
        self.assertTrue(record["detection"]["ml_flag"])
        self.assertTrue(math.isfinite(record["detection"]["anomaly_score"]))
        self.assertEqual(record["detection"]["evidence"][0]["observed"], 99.98)

    def test_idempotency_and_tenant_isolation(self):
        self.record()
        self.record()
        self.assertEqual(len(self.store.alerts("tenant-a")), 1)
        self.assertEqual(self.store.alerts("tenant-b"), [])
        self.store.ingest("tenant-b", Transaction(**self.suspicious))
        self.assertEqual(len(self.store.alerts("tenant-b")), 1)

    def test_validation(self):
        for field, bad in [("amount_minor", -1), ("amount_minor", 12.5),
                           ("amount_minor", True), ("currency", "AAA"),
                           ("currency", "eur"), ("direction", "sideways"),
                           ("event_time", "2026-03-01T14:00:00")]:
            with self.subTest(field=field, bad=bad), self.assertRaises(ValidationError):
                Transaction(**{**self.normal, field: bad})
        with self.assertRaises(ValidationError):
            Transaction(**self.normal, client_anomaly_score=0)

    def test_multi_currency_is_normalized_via_fx_settings(self):
        import sqlite3
        from migrations import ensure_schema
        from settings_store import SettingsStore
        conn = sqlite3.connect(":memory:")
        ensure_schema(conn)
        settings = SettingsStore(conn)
        from fraud_demo import to_usd_minor
        self.assertEqual(to_usd_minor(10000, "USD", settings), 10000)
        eur = to_usd_minor(10000, "EUR", settings)
        self.assertTrue(10000 < eur < 20000, eur)  # 1.08x default rate
        # Operator-editable: changing the FX row changes normalization.
        import json as _json
        rates = settings.get_json("fx_rates", {})
        rates["EUR"] = 2.0
        settings.set("fx_rates", _json.dumps(rates))
        self.assertEqual(to_usd_minor(10000, "EUR", settings), 20000)

    def test_mock_is_labeled_and_assessment_is_reused(self):
        record = self.record()
        assessed = self.store.assess("tenant-a", record["transaction_id"])
        self.assertEqual(assessed["explanation"]["source"], "mock_fixture")
        with patch.object(self.store.qwen, "assess", side_effect=AssertionError("Already assessed")):
            self.assertEqual(self.store.assess("tenant-a", record["transaction_id"]), assessed)

    def test_failure_preserves_alert_and_can_retry(self):
        record = self.record()
        with patch.object(self.store.qwen, "assess", side_effect=AssessmentUnavailable("invalid_output")):
            assessed = self.store.assess("tenant-a", record["transaction_id"])
        self.assertEqual(assessed["status"], "explanation_unavailable")
        self.assertEqual(assessed["policy_action"], "human_review")
        self.assertTrue(self.store.alerts("tenant-a")[0]["flagged"])
        retried = self.store.assess("tenant-a", record["transaction_id"])
        self.assertEqual(retried["status"], "assessed")
        self.assertEqual(retried["assessment_attempts"], 2)

    def provider_reply(self, record):
        assessment = Qwen(mode="mock").assess(record)["assessment"]
        return {"id": "mock-provider-request", "model": "qwen-test",
                "choices": [{"finish_reason": "stop", "message": {
                    "content": json.dumps(assessment)}}]}

    def adapter(self, handler):
        return Qwen(mode="live", transport=httpx.MockTransport(handler), sleeper=lambda _: None)

    def live_env(self):
        return patch.dict(os.environ, {"QWEN_BASE_URL": "https://provider.example/compatible-mode/v1",
                                       "QWEN_MODEL": "qwen-test", "DASHSCOPE_API_KEY": "fake-test-only"})

    def test_live_adapter_contract_and_minimization(self):
        record = self.record()

        def handler(request):
            self.assertEqual(str(request.url), "https://provider.example/compatible-mode/v1/chat/completions")
            self.assertEqual(request.headers["Authorization"], "Bearer fake-test-only")
            payload = json.loads(request.content)
            self.assertEqual(payload["model"], "qwen-test")
            self.assertNotIn("account_id", payload["messages"][1]["content"])
            self.assertNotIn("device_id", payload["messages"][1]["content"])
            self.assertIn("schema", json.loads(payload["messages"][1]["content"]))
            return httpx.Response(200, json=self.provider_reply(record))

        with self.live_env():
            result = self.adapter(handler).assess(record)
        self.assertEqual(result["source"], "qwen")
        self.assertEqual(result["request_id"], "mock-provider-request")

    def test_invalid_provider_output(self):
        record = self.record()
        good = self.provider_reply(record)
        assessment = json.loads(good["choices"][0]["message"]["content"])
        bad_assessments = ["not JSON", json.dumps({**assessment, "transaction_id": "wrong"}),
                           json.dumps({**assessment, "evidence_ids": ["E999"]}),
                           json.dumps({**assessment, "recommended_action": "freeze_account"}),
                           json.dumps({**assessment, "extra": "not allowed"})]
        for content in bad_assessments:
            reply = {"choices": [{"finish_reason": "stop", "message": {"content": content}}]}
            with self.subTest(content=content), self.live_env(), self.assertRaises(AssessmentUnavailable):
                self.adapter(lambda _: httpx.Response(200, json=reply)).assess(record)
        with self.live_env(), self.assertRaises(AssessmentUnavailable):
            self.adapter(lambda _: httpx.Response(200, json={"choices": [
                {"finish_reason": "length", "message": {"content": "{}"}}]})).assess(record)

    def test_retry_budget_and_no_auth_retry(self):
        for code, expected in [(429, 3), (503, 3), (401, 1), (400, 1)]:
            calls = []

            def handler(request):
                calls.append(request)
                return httpx.Response(code, json={"error": "test"})

            with self.subTest(code=code), self.live_env(), self.assertRaises(AssessmentUnavailable):
                self.adapter(handler).assess(self.record())
            self.assertEqual(len(calls), expected)

    def test_transport_retry_then_success(self):
        calls = []
        record = self.record()

        def handler(request):
            calls.append(request)
            if len(calls) == 1:
                raise httpx.ConnectError("simulated", request=request)
            return httpx.Response(200, json=self.provider_reply(record))

        with self.live_env():
            result = self.adapter(handler).assess(record)
        self.assertEqual(len(calls), 2)
        self.assertEqual(result["source"], "qwen")

    def test_api_auth_workflow_conflict_and_missing_account(self):
        with patch.dict(os.environ, {"DEMO_API_TOKEN": "test-token-only"}):
            with TestClient(create_app(self.store)) as client:
                self.assertEqual(client.get("/alerts").status_code, 401)
                headers = {"X-API-Key": "test-token-only"}
                scored = client.post("/transactions", json=self.suspicious, headers=headers)
                self.assertEqual(scored.status_code, 200)
                self.assertEqual(scored.json()["status"], "pending_explanation")
                conflict = client.post("/transactions", json={**self.suspicious, "amount_minor": 1}, headers=headers)
                self.assertEqual(conflict.status_code, 409)
                cold_start = client.post("/transactions", json={**self.suspicious, "account_id": "acct_unknown", "transaction_id": "txn_cold"}, headers=headers)
                self.assertEqual(cold_start.status_code, 200)
                self.assertEqual(cold_start.json()["detection"]["baseline_source"], "cold_start")
                assessed = client.post(f"/transactions/{self.suspicious['transaction_id']}/assess", headers=headers)
                self.assertEqual(assessed.json()["policy_action"], "human_review")
                # The suspicious alert plus the cold-start one (flagged, labeled).
                self.assertEqual(len(client.get("/alerts", headers=headers).json()["items"]), 2)
                self.assertEqual(client.post("/transactions/missing/assess", headers=headers).status_code, 404)


class SimulationTests(unittest.TestCase):
    start = datetime(2026, 3, 1, 14, tzinfo=timezone.utc)

    def setUp(self):
        self.elapsed = 0.0
        self.waits = []
        self.output = []

    def wait(self, seconds):
        self.waits.append(seconds)
        self.elapsed += seconds

    def engine(self, config, client, wait=None):
        return StreamEngine(config, client, "test-token-only", emit=self.output.append,
                            clock=lambda: self.elapsed, wait=wait or self.wait,
                            now=lambda: self.start + timedelta(seconds=self.elapsed))

    def record_response(self, request):
        tx = json.loads(request.content)
        return httpx.Response(200, json={"transaction_id": tx["transaction_id"],
                                        "flagged": False, "status": "not_flagged"})

    def test_reproducibility_unique_ids_and_no_label_leak(self):
        config = StreamConfig(count=20, seed=7, start_time=self.start, run_id="replay")
        events = list(stream_events(config))
        self.assertEqual(events, list(stream_events(config)))
        self.assertEqual(len({tx["transaction_id"] for tx, _ in events}), 20)
        self.assertTrue(any(injected for _, injected in events))
        self.assertTrue(any(not injected for _, injected in events))
        for tx, _ in events:
            Transaction(**tx)
            self.assertNotIn("injected_anomaly", tx)
        self.assertNotEqual(StreamConfig().run_id, StreamConfig().run_id)

    def test_config_validation_and_url_security(self):
        for values in [{"rate": 0}, {"rate": -1}, {"rate": float("nan")},
                       {"rate": float("inf")}, {"rate": 1001}, {"count": -1},
                       {"anomaly_rate": 1.1}, {"anomaly_rate": -0.1},
                       {"start_time": "2026-03-01T14:00:00"}, {"run_id": "../unsafe"}]:
            with self.subTest(values=values), self.assertRaises(ValidationError):
                StreamConfig(**values)
        for url in ["http://external.example", "https://user:secret@example.com",
                    "https://example.com?token=secret", "file:///private"]:
            with self.subTest(url=url), self.assertRaises(ValueError):
                simulation_base_url(url)
        self.assertEqual(simulation_base_url("http://127.0.0.1:8000/"), "http://127.0.0.1:8000")

    def test_pacing_and_wall_clock_timestamps(self):
        sent = []

        def handler(request):
            sent.append((self.elapsed, json.loads(request.content)))
            return self.record_response(request)

        with httpx.Client(transport=httpx.MockTransport(handler)) as client:
            result = self.engine(StreamConfig(count=3, rate=2), client).run()
        self.assertEqual([t for t, _ in sent], [0, 0.5, 1])
        self.assertEqual([tx["event_time"] for _, tx in sent],
                         [(self.start + timedelta(seconds=s)).isoformat() for s in [0, 0.5, 1]])
        self.assertEqual(result["accepted"], 3)
        self.assertEqual(result["status"], "completed")
        self.assertEqual(self.output[-1]["type"], "simulation_summary")

    def test_slow_server_applies_backpressure(self):
        sent = []

        def handler(request):
            sent.append(self.elapsed)
            self.elapsed += 0.75
            return self.record_response(request)

        with httpx.Client(transport=httpx.MockTransport(handler)) as client:
            self.engine(StreamConfig(count=3, rate=2), client).run()
        self.assertEqual(sent, [0, 0.75, 1.5])
        self.assertEqual(self.waits, [])

    def test_retries_reuse_identical_payload(self):
        payloads = []

        def handler(request):
            payloads.append(json.loads(request.content))
            return (httpx.Response(503) if len(payloads) < 3
                    else self.record_response(request))

        with httpx.Client(transport=httpx.MockTransport(handler)) as client:
            result = self.engine(StreamConfig(count=1), client).run()
        self.assertEqual(payloads[0], payloads[1])
        self.assertEqual(payloads[1], payloads[2])
        self.assertEqual(result["retries"], 2)
        self.assertEqual(result["accepted"], 1)
        self.assertEqual(self.waits, [1, 2])

    def test_retry_limits_auth_failure_and_conflict(self):
        for code, expected in [(429, 3), (503, 3), (401, 1), (409, 1)]:
            calls = []

            def handler(request):
                calls.append(request)
                return httpx.Response(code)

            with self.subTest(code=code), httpx.Client(transport=httpx.MockTransport(handler)) as client:
                result = self.engine(StreamConfig(count=2), client).run()
            self.assertEqual(len(calls), expected)
            self.assertEqual(result["status"], "failed")
            self.assertEqual(result["accepted"], 0)
            self.assertIn("last_transaction_id", result)

    def test_transport_failure_retries_and_malformed_response_stops(self):
        calls = []

        def handler(request):
            calls.append(request)
            raise httpx.ConnectError("simulated", request=request)

        with httpx.Client(transport=httpx.MockTransport(handler)) as client:
            result = self.engine(StreamConfig(count=1), client).run()
        self.assertEqual(len(calls), 3)
        self.assertEqual(result["error"], "transport_failure")
        with httpx.Client(transport=httpx.MockTransport(lambda _: httpx.Response(200, json=[]))) as client:
            result = self.engine(StreamConfig(count=1), client).run()
        self.assertEqual(result["error"], "invalid_api_response")

    def test_continuous_mode_stops_on_interrupt(self):
        def stop(_):
            raise KeyboardInterrupt

        with httpx.Client(transport=httpx.MockTransport(self.record_response)) as client:
            result = self.engine(StreamConfig(count=0), client, wait=stop).run()
        self.assertEqual(result["status"], "stopped")
        self.assertEqual(result["accepted"], 1)
        self.assertEqual(self.output[-1]["status"], "stopped")

    def test_end_to_end_scoring_assessment_and_replay(self):
        store = Store(":memory:", qwen=Qwen(mode="mock"))
        self.addCleanup(store.close)
        config = StreamConfig(count=3, rate=10, anomaly_rate=1, assess=True,
                              start_time=self.start, run_id="integration")
        with patch.dict(os.environ, {"DEMO_API_TOKEN": "test-token-only"}):
            with TestClient(create_app(store)) as client:
                result = self.engine(config, client).run()
                replay = self.engine(config, client).run()
        self.assertEqual(result["accepted"], 3)
        # Baselines are adaptive: with one shared account, the first flagged
        # event becomes history, so later identical events may score below
        # threshold (the account learned the pattern). The alert count is
        # therefore >= 1, not exactly 3; every alert is still assessed.
        self.assertGreaterEqual(result["flagged"], 1)
        self.assertEqual(result["assessed"], result["flagged"])
        self.assertEqual(replay["accepted"], 3)
        alerts = store.alerts("demo-tenant")
        self.assertEqual(len(alerts), result["flagged"])
        self.assertTrue(all(item["explanation"]["source"] == "mock_fixture" for item in alerts))
        self.assertTrue(all(item["assessment_attempts"] == 1 for item in alerts))

    def test_assessment_is_opt_in(self):
        paths = []

        def handler(request):
            paths.append(request.url.path)
            tx = json.loads(request.content)
            return httpx.Response(200, json={"transaction_id": tx["transaction_id"],
                                            "flagged": True, "status": "pending_explanation"})

        with httpx.Client(transport=httpx.MockTransport(handler)) as client:
            result = self.engine(StreamConfig(count=2), client).run()
        self.assertEqual(paths, ["/transactions", "/transactions"])
        self.assertEqual(result["flagged"], 2)
        self.assertEqual(result["assessed"], 0)

    def test_assessment_failure_does_not_lose_scored_events(self):
        for http_failure in [True, False]:
            def handler(request):
                if request.url.path.endswith("/assess"):
                    if http_failure:
                        return httpx.Response(503)
                    return httpx.Response(200, json={
                        "transaction_id": request.url.path.split("/")[-2],
                        "flagged": True, "status": "explanation_unavailable"})
                tx = json.loads(request.content)
                return httpx.Response(200, json={"transaction_id": tx["transaction_id"],
                                                "flagged": True, "status": "pending_explanation"})

            with self.subTest(http_failure=http_failure), httpx.Client(transport=httpx.MockTransport(handler)) as client:
                result = self.engine(StreamConfig(count=2, assess=True), client).run()
            self.assertEqual(result["status"], "completed")
            self.assertEqual(result["accepted"], 2)
            self.assertEqual(result["assessment_unavailable"], 2)
            self.assertEqual(result["retries"], 0)


if __name__ == "__main__":
    unittest.main()
