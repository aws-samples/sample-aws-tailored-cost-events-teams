"""
Unit tests for normalizers.py — one section per AWS source, fed the REALISTIC
fixtures (tests/fixtures/). These assert the CORRECTED internal model defined by
EXPERT_ANALYSIS.md (AWS-1..AWS-4).

Several assertions encode behavior Phase 2 must implement, so they FAIL today:
  * Budgets plain-text parsing (AWS-1) — parser does not exist yet.
  * COH real-field mapping via a recommendation-item entrypoint (AWS-2).
  * Trusted Advisor region from detail.check-item-detail.Region (AWS-3).
Cost Anomaly (AWS-4 aside) is expected to PASS today — it is the one live path.
"""

from __future__ import annotations

from typing import Any

import pytest

import normalizers


def _fields(model: dict[str, Any]) -> dict[str, str]:
    """Flatten summary_fields [(label, value), ...] into a dict for lookups."""
    return {label: value for label, value in model.get("summary_fields", [])}


# ===========================================================================
# Cost Anomaly Detection (aws.ce) — the one source that works end-to-end.
# ===========================================================================
class TestCostAnomalyNormalizer:
    def test_dispatch_and_core_fields(self, cad_eventbridge_event):
        model = normalizers.normalize(cad_eventbridge_event)
        assert model is not None
        assert model["event_type"] == "cost_anomaly"
        # Linked/affected account comes from detail.accountId (AWS event matrix).
        assert model["account_id"] == "123456789012"
        assert model["account_name"] == "Production"

    def test_dollar_impact_from_total_impact(self, cad_eventbridge_event):
        # dollar_impact must equal detail.impact.totalImpact.
        model = normalizers.normalize(cad_eventbridge_event)
        assert model["dollar_impact"] == pytest.approx(1001.0)

    def test_severity_threshold(self, cad_eventbridge_event):
        # 500 <= 1001 < 5000  => "warning"
        model = normalizers.normalize(cad_eventbridge_event)
        assert model["severity"] == "warning"

    def test_summary_fields_read_correct_paths(self, cad_eventbridge_event):
        model = normalizers.normalize(cad_eventbridge_event)
        fields = _fields(model)
        # Service / region / usage type come from rootCauses[0].
        assert fields["Service"] == "Amazon Relational Database Service"
        assert fields["Region"] == "us-east-1"
        assert fields["Usage type"] == "USE1-RDS:GP3-Storage"
        assert "1,001.00" in fields["Impact"]

    def test_raw_detail_preserved(self, cad_eventbridge_event):
        model = normalizers.normalize(cad_eventbridge_event)
        # links.py reads raw.rootCauses / raw.anomalyStartDate, so raw must be
        # the event detail.
        assert model["raw"]["anomalyStartDate"] == "2026-05-01T00:00:00Z"
        assert model["raw"]["rootCauses"][0]["service"] == (
            "Amazon Relational Database Service"
        )


# ===========================================================================
# AWS Budgets (AWS-1) — real alert is PLAIN-TEXT SNS, not a JSON event.
# Phase 2 must add a plain-text parser. These tests pin that contract.
# ===========================================================================
@pytest.mark.aws1
class TestBudgetsPlainTextNormalizer:
    def _parser(self):
        # Phase 2 target: a plain-text Budgets parser (name per EXPERT_ANALYSIS
        # "Budgets plain-text parser sketch": _parse_budgets_sns_text).
        return getattr(normalizers, "_parse_budgets_sns_text", None)

    def test_parser_exists(self, budgets_plaintext):
        parser = self._parser()
        assert parser is not None, (
            "AWS-1: normalizers must expose a plain-text Budgets parser "
            "(_parse_budgets_sns_text); real Budgets alerts arrive as plain "
            "text via SNS, not as JSON EventBridge events."
        )

    def test_parser_extracts_budget_name(self, budgets_plaintext):
        parser = self._parser()
        assert parser is not None, "AWS-1: parser missing"
        parsed = parser(budgets_plaintext)
        assert parsed is not None
        assert parsed.get("budget_name") == "example-prod-monthly"

    def test_parser_extracts_amounts_and_account(self, budgets_plaintext):
        parser = self._parser()
        assert parser is not None, "AWS-1: parser missing"
        parsed = parser(budgets_plaintext)
        assert parsed is not None
        # Account number parsed out of the "AWS Account 1234..." line.
        assert parsed.get("account_id") == "123456789012"
        # Actual spend that breached the threshold.
        assert float(parsed.get("actual_amount")) == pytest.approx(42500.00)
        # Budgeted amount / threshold.
        assert float(parsed.get("budgeted_amount")) == pytest.approx(40000.00)

    def test_normalized_model_from_plaintext(self, budgets_plaintext):
        """
        End-to-end normalizer entrypoint for a plain-text Budgets message.
        Phase 2 may expose this as normalizers.normalize_budgets_text(body).
        """
        fn = getattr(normalizers, "normalize_budgets_text", None)
        assert fn is not None, (
            "AWS-1: a normalize_budgets_text(body) entrypoint should turn the "
            "parsed plain-text into the common model."
        )
        model = fn(budgets_plaintext)
        assert model["event_type"] == "budget_threshold"
        assert model["account_id"] == "123456789012"
        assert model["dollar_impact"] == pytest.approx(42500.00)
        # Actual ($42.5k) > budgeted ($40k) => over budget => critical.
        assert model["severity"] == "critical"


# ===========================================================================
# Cost Optimization Hub (AWS-2) — real ListRecommendations item, real fields.
# COH is a scheduled pull, so the normalizer entrypoint takes a recommendation
# OBJECT (not an EventBridge event).
# ===========================================================================
@pytest.mark.aws2
class TestCostOptimizationHubNormalizer:
    def _normalizer(self):
        # Phase 2 target entrypoint for a single ListRecommendations item.
        return getattr(normalizers, "normalize_coh_recommendation", None)

    def test_entrypoint_exists(self, coh_recommendation):
        fn = self._normalizer()
        assert fn is not None, (
            "AWS-2: normalizers must expose normalize_coh_recommendation(item) "
            "since COH is a scheduled ListRecommendations pull, not an event."
        )

    def test_maps_real_field_names(self, coh_recommendation):
        fn = self._normalizer()
        assert fn is not None, "AWS-2: entrypoint missing"
        model = fn(coh_recommendation)
        assert model["event_type"] == "cost_optimization_recommendation"
        # Real fields: actionType, currentResourceType, recommendationId.
        fields = _fields(model)
        assert "Rightsize" in fields.get("Recommendation", "")
        assert "Ec2Instance" in fields.get("Resource", "")
        # estimatedMonthlySavings drives dollar_impact.
        assert model["dollar_impact"] == pytest.approx(780.00)
        assert model["account_id"] == "123456789012"

    def test_recommendation_id_preserved_for_deep_link(self, coh_recommendation):
        fn = self._normalizer()
        assert fn is not None, "AWS-2: entrypoint missing"
        model = fn(coh_recommendation)
        # links.py builds the COH deep link from raw.recommendationId.
        assert model["raw"].get("recommendationId") == (
            "a1b2c3d4-1111-2222-3333-444455556666"
        )

    def test_does_not_use_legacy_field_names(self, coh_recommendation):
        """The corrected normalizer must NOT depend on recommendationType /
        resourceType (the fabricated names from the old fixture)."""
        fn = self._normalizer()
        assert fn is not None, "AWS-2: entrypoint missing"
        # The realistic item has NO recommendationType/resourceType keys.
        assert "recommendationType" not in coh_recommendation
        assert "resourceType" not in coh_recommendation
        model = fn(coh_recommendation)
        fields = _fields(model)
        # Recommendation label must not be the "—" fallback that the old code
        # produces when recommendationType is absent.
        assert fields.get("Recommendation", "—") != "—"


# ===========================================================================
# Trusted Advisor (AWS-3) — real EventBridge event; region is nested.
# ===========================================================================
@pytest.mark.aws3
class TestTrustedAdvisorNormalizer:
    def test_dispatch_and_check_name(self, ta_eventbridge_event):
        model = normalizers.normalize(ta_eventbridge_event)
        assert model is not None
        assert model["event_type"] == "trusted_advisor_cost_check"
        fields = _fields(model)
        assert fields["Check"] == "Low Utilization Amazon EC2 Instances"

    def test_status_and_severity(self, ta_eventbridge_event):
        model = normalizers.normalize(ta_eventbridge_event)
        fields = _fields(model)
        assert fields["Status"] == "WARN"
        assert model["severity"] == "warning"

    def test_region_from_check_item_detail(self, ta_eventbridge_event):
        # AWS-3: region must be read from detail.check-item-detail.Region,
        # NOT the non-existent top-level resource_region/region.
        model = normalizers.normalize(ta_eventbridge_event)
        fields = _fields(model)
        assert fields["Region"] == "us-east-1", (
            "AWS-3: region must come from detail.check-item-detail.Region"
        )

    def test_resource_id_top_level(self, ta_eventbridge_event):
        model = normalizers.normalize(ta_eventbridge_event)
        fields = _fields(model)
        assert fields["Resource"] == "i-0abcdef1234567890"


# ===========================================================================
# Dispatch behavior — unknown source returns None.
# ===========================================================================
def test_unknown_source_returns_none():
    assert normalizers.normalize({"source": "aws.unknown", "detail": {}}) is None
