"""
Unit tests for card_builder.py — the Teams Workflows envelope (the highest-value
Teams assertion per EXPERT_ANALYSIS.md).

Asserts the EXACT outer envelope and Adaptive Card contract, and that NO
unsupported `style:"positive"` survives on any action (TEAMS-1). The TEAMS-1
assertion FAILS today (links.py still sets style:positive when an SSO URL is
built) and must pass after Phase 2.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

import card_builder
import links
import routing


def _normalized(severity: str = "warning") -> dict[str, Any]:
    """A minimal-but-realistic normalized model (Cost Anomaly shaped)."""
    return {
        "event_type": "cost_anomaly",
        "account_id": "123456789012",
        "account_name": "Production",
        "title": "Cost Anomaly Detected — $1,001 impact",
        "severity": severity,
        "summary_fields": [
            ("Account", "123456789012 (Production)"),
            ("Service", "Amazon Relational Database Service"),
            ("Region", "us-east-1"),
            ("Impact", "$1,001.00 (333.7% increase)"),
        ],
        "dollar_impact": 1001.0,
        "investigation": "Workload owner steps: (1) sign in ...",
        "raw": {
            "rootCauses": [
                {
                    "linkedAccount": "123456789012",
                    "service": "Amazon Relational Database Service",
                    "region": "us-east-1",
                    "usageType": "USE1-RDS:GP3-Storage",
                }
            ],
            "anomalyStartDate": "2026-05-01T00:00:00Z",
            "anomalyEndDate": "2026-05-03T00:00:00Z",
        },
    }


def _card(routing_record, severity="warning") -> dict[str, Any]:
    return card_builder.build_card(_normalized(severity), routing_record)


# ===========================================================================
# Outer Workflows envelope
# ===========================================================================
class TestWorkflowsEnvelope:
    def test_top_level_type_is_message(self, routing_record):
        card = _card(routing_record)
        assert card["type"] == "message"

    def test_has_single_attachment_with_adaptive_content_type(self, routing_record):
        card = _card(routing_record)
        attachments = card["attachments"]
        assert isinstance(attachments, list) and len(attachments) == 1
        assert (
            attachments[0]["contentType"]
            == "application/vnd.microsoft.card.adaptive"
        )

    def test_attachment_has_content(self, routing_record):
        card = _card(routing_record)
        assert "content" in card["attachments"][0]


# ===========================================================================
# Inner Adaptive Card contract
# ===========================================================================
class TestAdaptiveCardContent:
    def _content(self, routing_record) -> dict[str, Any]:
        return _card(routing_record)["attachments"][0]["content"]

    def test_schema_present(self, routing_record):
        content = self._content(routing_record)
        assert content["$schema"] == "http://adaptivecards.io/schemas/adaptive-card.json"

    def test_type_is_adaptive_card(self, routing_record):
        assert self._content(routing_record)["type"] == "AdaptiveCard"

    def test_version_is_teams_supported(self, routing_record):
        # Teams supports "v1.5 or earlier". Accept 1.4 or 1.5 (TEAMS-3 allows
        # either; the contract is "a Teams-supported version").
        assert self._content(routing_record)["version"] in {"1.4", "1.5"}

    def test_msteams_full_width(self, routing_record):
        content = self._content(routing_record)
        assert content["msteams"]["width"].lower() == "full"

    def test_body_has_title_textblock_and_factset(self, routing_record):
        content = self._content(routing_record)
        body = content["body"]
        types = [b.get("type") for b in body]
        assert "TextBlock" in types
        assert "FactSet" in types
        # First block is the bold title.
        assert body[0]["type"] == "TextBlock"
        assert body[0].get("weight") == "Bolder"

    def test_only_supported_element_types(self, routing_record):
        content = self._content(routing_record)
        allowed = {"TextBlock", "FactSet", "ColumnSet", "Container", "Image"}
        for block in content["body"]:
            assert block.get("type") in allowed, (
                f"unsupported card element: {block.get('type')}"
            )


# ===========================================================================
# Actions: all Action.OpenUrl, https only, and NO style:positive (TEAMS-1)
# ===========================================================================
class TestActions:
    def test_actions_are_open_url_with_https(self, routing_record):
        content = _card(routing_record)["attachments"][0]["content"]
        for action in content.get("actions", []):
            assert action["type"] == "Action.OpenUrl"
            assert action["url"].startswith("https://")

    def test_no_action_submit_or_inputs(self, routing_record):
        content = _card(routing_record)["attachments"][0]["content"]
        for action in content.get("actions", []):
            assert action["type"] != "Action.Submit"
        for block in content["body"]:
            assert not str(block.get("type", "")).startswith("Input.")

    @pytest.mark.teams1
    def test_no_positive_style_on_actions_sso_enabled(
        self, routing_record, monkeypatch
    ):
        """
        TEAMS-1: with an SSO portal configured, links.build_actions currently
        emits an Action.OpenUrl carrying style:"positive", which Teams does not
        support. After Phase 2 removes it, NO action should carry that style.

        This test FAILS today (red) and must pass after Phase 2.
        """
        # Force the SSO branch so the (currently positive-styled) action is
        # built. Talos a1e659fa: the portal hostname now comes from SSM via
        # routing.get_sso_portal() (no links.SSO_PORTAL constant), so stub that
        # accessor to drive the SSO branch deterministically/offline.
        monkeypatch.setattr(routing, "get_sso_portal", lambda: "example-portal.awsapps.com")
        content = _card(routing_record)["attachments"][0]["content"]
        actions = content.get("actions", [])
        # Sanity: the SSO branch produced at least one action.
        assert actions, "expected SSO + direct actions to be generated"
        for action in actions:
            assert action.get("style") != "positive", (
                "TEAMS-1: Action style 'positive' is unsupported by Teams and "
                "must be removed"
            )


# ===========================================================================
# Serialization / size sanity
# ===========================================================================
class TestSerialization:
    def test_card_is_json_serializable(self, routing_record):
        card = _card(routing_record)
        # Must serialize cleanly (no non-JSON types).
        json.dumps(card)

    def test_card_under_28kb_webhook_limit(self, routing_record):
        # Incoming-webhook payload limit is 28 KB (DOC-2).
        card = _card(routing_record)
        size = len(json.dumps(card).encode("utf-8"))
        assert size < 28 * 1024
