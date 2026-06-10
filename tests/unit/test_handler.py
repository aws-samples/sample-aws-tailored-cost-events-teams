"""
Unit tests for handler.py — record extraction, dispatch, and error handling.

CODE-1 (the headline handler defect): per-record exceptions are currently
caught, logged, and returned as {"ok": False} — so the Lambda returns success,
SNS never retries, and the SQS DLQ never engages. The corrected contract is
that a per-record processing failure must PROPAGATE (re-raise) so SNS retry /
DLQ kicks in. The propagation tests FAIL today (red) and must pass after Phase 2.

The happy-path Cost Anomaly test should PASS today (the one live source).
"""

from __future__ import annotations

import json

import pytest

import handler


# ===========================================================================
# _extract — SNS / EventBridge unwrapping
# ===========================================================================
class TestExtract:
    def test_extract_json_sns_message(self, cad_sns_records):
        rec = cad_sns_records["Records"][0]
        extracted = handler._extract(rec)
        assert extracted is not None
        assert extracted["source"] == "aws.ce"
        assert extracted["detail"]["accountId"] == "123456789012"

    def test_extract_bare_eventbridge_record(self, ta_eventbridge_event):
        # handler accepts a raw EventBridge event (source + detail present).
        extracted = handler._extract(ta_eventbridge_event)
        assert extracted is not None
        assert extracted["source"] == "aws.trustedadvisor"

    @pytest.mark.aws1
    def test_plaintext_sns_message_not_dropped(self, budgets_sns_records):
        """
        AWS-1: a plain-text (non-JSON) SNS Message is a real Budgets alert and
        must NOT be silently dropped. Today _extract's json.loads() throws and
        returns None ("non-json SNS message"). After Phase 2, the plain-text
        body must be recognized and routed to the Budgets parser.

        We assert the corrected contract: _extract returns a usable payload
        (not None) for a plain-text Budgets message. FAILS today.
        """
        rec = budgets_sns_records["Records"][0]
        extracted = handler._extract(rec)
        assert extracted is not None, (
            "AWS-1: plain-text Budgets SNS message must not be dropped"
        )


# ===========================================================================
# handler — happy path for the one live source (Cost Anomaly).
# ===========================================================================
class TestHandlerHappyPath:
    def test_cost_anomaly_processes_and_posts(
        self, aws_mocks, fake_teams, cad_sns_records, monkeypatch
    ):
        import routing

        # Account has no Organizations tag → default routing row.
        monkeypatch.setattr(routing, "_account_tag", lambda _acct: None)

        result = handler.handler(cad_sns_records, None)
        assert result["processed"] == 1
        record_result = result["results"][0]
        assert record_result["ok"] is True
        assert record_result["event_type"] == "cost_anomaly"
        assert record_result["teams_posted"] is True
        # An S3 object was written and a Teams POST was captured.
        assert fake_teams.call_count == 1

    def test_posted_envelope_is_workflows_message(
        self, aws_mocks, fake_teams, cad_sns_records, monkeypatch
    ):
        import routing

        monkeypatch.setattr(routing, "_account_tag", lambda _acct: None)
        handler.handler(cad_sns_records, None)
        body = fake_teams.last_body_json
        assert body["type"] == "message"
        assert (
            body["attachments"][0]["contentType"]
            == "application/vnd.microsoft.card.adaptive"
        )


# ===========================================================================
# CODE-1 — per-record failures must PROPAGATE (re-raise), not be swallowed.
# These tests FAIL today (handler catches and returns {"ok": False}).
# ===========================================================================
@pytest.mark.code1
class TestErrorPropagation:
    def test_s3_failure_propagates(
        self, aws_mocks, fake_teams, cad_sns_records, monkeypatch
    ):
        import routing

        monkeypatch.setattr(routing, "_account_tag", lambda _acct: None)

        # Force a downstream failure inside _process (S3 write).
        def boom(*_a, **_k):
            raise RuntimeError("simulated S3 outage")

        monkeypatch.setattr(handler, "write_to_s3", boom)

        with pytest.raises(Exception):
            handler.handler(cad_sns_records, None)

    def test_no_silent_ok_false_on_failure(
        self, aws_mocks, fake_teams, cad_sns_records, monkeypatch
    ):
        """
        The anti-pattern: returning {"ok": False} (HTTP 200 to SNS) on failure.
        The corrected contract is to raise so SNS retries / DLQ engages — the
        handler must NOT return a normal result that hides the failure.
        """
        import routing

        monkeypatch.setattr(routing, "_account_tag", lambda _acct: None)

        def boom(*_a, **_k):
            raise RuntimeError("simulated S3 outage")

        monkeypatch.setattr(handler, "write_to_s3", boom)

        try:
            result = handler.handler(cad_sns_records, None)
        except Exception:
            # Raising is the corrected, acceptable behavior.
            return
        # If it did NOT raise, it must not have masked the failure as success.
        results = result.get("results", [])
        assert not any(r.get("ok") is False for r in results), (
            "CODE-1: per-record failure was swallowed and returned as a normal "
            "{'ok': False} result; SNS sees success and the DLQ never engages"
        )


# ===========================================================================
# handler — unhandled source returns a non-crashing marker.
# ===========================================================================
def test_unhandled_source_does_not_crash(aws_mocks, fake_teams):
    event = {
        "Records": [
            {
                "Sns": {
                    "Message": json.dumps(
                        {"source": "aws.unknown", "detail-type": "x", "detail": {}}
                    )
                }
            }
        ]
    }
    result = handler.handler(event, None)
    assert result["processed"] == 1
    assert result["results"][0]["ok"] is False
    assert result["results"][0]["reason"] == "unhandled_source"
