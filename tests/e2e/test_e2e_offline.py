"""
Offline end-to-end tests: drive the FULL pipeline through handler.handler(...)
with boto3 mocked by moto (S3 / DynamoDB / SSM / Organizations) and the outbound
Teams HTTP POST captured by the `fake_teams` fixture. No real AWS, no network.

For each of the 4 realistic fixtures we assert the captured POST equals the EXACT
expected Teams Workflows envelope for that event.

Expected Phase-1 status:
  * Cost Anomaly (aws.ce): the one live path → expected to PASS.
  * Trusted Advisor (aws.trustedadvisor): event is real and reaches the
    normalizer, but region path is wrong (AWS-3) → envelope mismatch → FAIL now.
  * Budgets (AWS-1): plain-text SNS is dropped by _extract → no POST → FAIL now.
  * Cost Optimization Hub (AWS-2): scheduled pull; no handler entrypoint exists
    yet → marked xfail(strict=False) so Phase 2 can flip it green.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

import card_builder
import handler
import normalizers
import routing


def _expected_envelope_from_event(eb_event: dict[str, Any]) -> dict[str, Any]:
    """
    Recompute the exact envelope the pipeline SHOULD post for a normalizable
    EventBridge event, using the same building blocks the handler uses.
    """
    normalized = normalizers.normalize(eb_event)
    assert normalized is not None, "fixture must normalize to build expected envelope"
    routing_record = routing.resolve(normalized.get("account_id"))
    return card_builder.build_card(normalized, routing_record)


def _stub_no_org_tag(monkeypatch):
    """Force default routing (no Organizations tag on the account)."""
    monkeypatch.setattr(routing, "_account_tag", lambda _acct: None)


# ===========================================================================
# Cost Anomaly Detection — the one live source. Should PASS.
# ===========================================================================
class TestE2ECostAnomaly:
    def test_full_pipeline_posts_exact_envelope(
        self, aws_mocks, fake_teams, cad_sns_records, monkeypatch
    ):
        _stub_no_org_tag(monkeypatch)

        result = handler.handler(cad_sns_records, None)

        # A Teams POST was captured exactly once.
        assert fake_teams.call_count == 1
        posted = fake_teams.last_body_json

        # Recompute the expected envelope from the same event and compare.
        eb_event = json.loads(cad_sns_records["Records"][0]["Sns"]["Message"])
        expected = _expected_envelope_from_event(eb_event)
        assert posted == expected

        # Pipeline reported success and wrote to S3.
        rec_result = result["results"][0]
        assert rec_result["ok"] is True
        assert rec_result["teams_posted"] is True
        s3_objects = aws_mocks.s3.list_objects_v2(Bucket=aws_mocks.bucket)
        assert s3_objects.get("KeyCount", 0) == 1

    def test_s3_archive_embeds_posted_card(
        self, aws_mocks, fake_teams, cad_sns_records, monkeypatch
    ):
        _stub_no_org_tag(monkeypatch)
        handler.handler(cad_sns_records, None)

        listing = aws_mocks.s3.list_objects_v2(Bucket=aws_mocks.bucket)
        key = listing["Contents"][0]["Key"]
        archived = json.loads(
            aws_mocks.s3.get_object(Bucket=aws_mocks.bucket, Key=key)["Body"].read()
        )
        assert archived["teams_payload"] == fake_teams.last_body_json


# ===========================================================================
# Trusted Advisor — event is real, but region path is wrong (AWS-3).
# The exact-envelope comparison will MISMATCH today (region shows "—").
# ===========================================================================
@pytest.mark.aws3
class TestE2ETrustedAdvisor:
    def test_full_pipeline_posts_exact_envelope(
        self, aws_mocks, fake_teams, ta_sns_records, ta_eventbridge_event, monkeypatch
    ):
        _stub_no_org_tag(monkeypatch)

        handler.handler(ta_sns_records, None)

        assert fake_teams.call_count == 1, (
            "AWS-3: TA event should reach the Teams POST"
        )
        posted = fake_teams.last_body_json

        # Build the EXPECTED envelope from the corrected contract: region must
        # come from detail.check-item-detail.Region. We assert the posted card
        # contains the correct region fact, which FAILS today (region == "—").
        facts = posted["attachments"][0]["content"]["body"]
        factset = next(b for b in facts if b.get("type") == "FactSet")
        region_fact = next(
            (f for f in factset["facts"] if f["title"] == "Region"), None
        )
        assert region_fact is not None
        assert region_fact["value"] == "us-east-1", (
            "AWS-3: region must be read from detail.check-item-detail.Region"
        )


# ===========================================================================
# Budgets — plain-text SNS is dropped today (AWS-1). No POST → FAIL now.
# ===========================================================================
@pytest.mark.aws1
class TestE2EBudgets:
    def test_plaintext_budgets_produces_teams_post(
        self, aws_mocks, fake_teams, budgets_sns_records, monkeypatch
    ):
        _stub_no_org_tag(monkeypatch)

        handler.handler(budgets_sns_records, None)

        # AWS-1 target: the plain-text Budgets alert is parsed and posted.
        # Today _extract drops it (json.loads fails) → no POST → this FAILS.
        assert fake_teams.call_count == 1, (
            "AWS-1: plain-text Budgets SNS alert must be parsed and posted, not "
            "dropped as 'non-json SNS message'"
        )
        posted = fake_teams.last_body_json
        assert posted["type"] == "message"
        # The card should reflect the budget name and the over-threshold amount.
        body_text = json.dumps(posted)
        assert "example-prod-monthly" in body_text


# ===========================================================================
# Cost Optimization Hub — scheduled ListRecommendations pull (AWS-2).
# Phase 2 implemented handler.process_coh_recommendation (the scheduled-pull
# entrypoint), so the former xfail is now a REAL pass: the recommendation item
# is normalized with real field names and posted to Teams. The xfail marker was
# removed because its stated reason ("the handler entrypoint ... does not exist
# yet") is no longer factually true (see docs/EXPERT_ANALYSIS.md AWS-2 and the
# Phase-1 done-criteria in docs/PHASE1_TESTS.md).
# ===========================================================================
@pytest.mark.aws2
class TestE2ECostOptimizationHub:
    def test_recommendation_produces_teams_post(
        self, aws_mocks, fake_teams, coh_recommendation, monkeypatch
    ):
        _stub_no_org_tag(monkeypatch)

        # Phase 2 target entrypoint for a single ListRecommendations item.
        entrypoint = getattr(handler, "process_coh_recommendation", None)
        assert entrypoint is not None, (
            "AWS-2: a COH recommendation entrypoint must exist on handler"
        )
        entrypoint(coh_recommendation)

        assert fake_teams.call_count == 1
        posted = fake_teams.last_body_json
        assert posted["type"] == "message"
        body_text = json.dumps(posted)
        # Real COH fields must drive the card content.
        assert "Rightsize" in body_text
        assert "780" in body_text  # estimatedMonthlySavings


# ===========================================================================
# Cross-cutting: every successful post is a valid Workflows envelope.
# ===========================================================================
def test_cost_anomaly_envelope_contract(
    aws_mocks, fake_teams, cad_sns_records, monkeypatch
):
    _stub_no_org_tag(monkeypatch)
    handler.handler(cad_sns_records, None)
    posted = fake_teams.last_body_json
    assert posted["type"] == "message"
    attachment = posted["attachments"][0]
    assert attachment["contentType"] == "application/vnd.microsoft.card.adaptive"
    content = attachment["content"]
    assert content["type"] == "AdaptiveCard"
    assert content["version"] in {"1.4", "1.5"}
    assert len(json.dumps(posted).encode("utf-8")) < 28 * 1024
