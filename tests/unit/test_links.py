"""
Unit tests for links.py — console deep-link construction per event type.

Covers:
  * AWS-4: anomaly ISO-8601 timestamps must be trimmed to YYYY-MM-DD before
    they reach the Cost Explorer date range. FAILS today (raw ISO is passed
    straight through) and must pass after Phase 2.
  * AWS-5: the Cost Explorer base64(JSON) deep-link format is undocumented and
    unverified. The "renders a working pre-filtered CE view" assertion is
    marked xfail (cannot be verified offline).
  * TEAMS-1: when the SSO branch builds an action, it must NOT carry
    style:"positive". FAILS today.
  * Per-type direct URLs are well-formed https for each event type.
"""

from __future__ import annotations

import base64
import json
from typing import Any

import pytest

import links
import routing


def _force_sso_portal(monkeypatch, hostname: str) -> None:
    """
    Force links into (or out of) the SSO branch by stubbing the SSM-backed
    accessor links consumes (Talos a1e659fa).

    The SSO portal hostname now lives in SSM and is read at runtime via
    ``routing.get_sso_portal()``; ``links._sso_wrap`` calls that accessor (there
    is no longer a ``links.SSO_PORTAL`` module constant to patch). Stub it with a
    plain lambda so these unit tests stay offline and deterministic; pass "" to
    simulate the param being unset/missing (graceful degrade to direct links).
    """
    monkeypatch.setattr(routing, "get_sso_portal", lambda: hostname)


# ---------------------------------------------------------------------------
# Normalized-model factories per event type
# ---------------------------------------------------------------------------
def _cad_normalized() -> dict[str, Any]:
    return {
        "event_type": "cost_anomaly",
        "account_id": "123456789012",
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


def _budget_normalized() -> dict[str, Any]:
    return {
        "event_type": "budget_threshold",
        "account_id": "123456789012",
        "raw": {"budgetName": "example-prod-monthly"},
    }


def _coh_normalized() -> dict[str, Any]:
    return {
        "event_type": "cost_optimization_recommendation",
        "account_id": "123456789012",
        "raw": {"recommendationId": "a1b2c3d4-1111-2222-3333-444455556666"},
    }


def _ta_normalized() -> dict[str, Any]:
    return {
        "event_type": "trusted_advisor_cost_check",
        "account_id": "123456789012",
        "raw": {"check-name": "Low Utilization Amazon EC2 Instances"},
    }


def _first_url(normalized: dict[str, Any]) -> str:
    actions = links.build_actions(normalized)
    assert actions, "expected at least one action"
    return actions[0]["url"]


def _decode_ce_filter(url: str) -> dict[str, Any]:
    """Pull the base64(JSON) blob out of the CE deep link and decode it."""
    assert "filter=" in url
    blob = url.split("filter=", 1)[1]
    # restore base64 padding stripped by the encoder
    blob += "=" * (-len(blob) % 4)
    return json.loads(base64.urlsafe_b64decode(blob).decode())


# ===========================================================================
# Per-type URL well-formedness
# ===========================================================================
class TestPerTypeUrls:
    def test_cost_anomaly_links_to_cost_explorer(self):
        url = _first_url(_cad_normalized())
        assert url.startswith("https://")
        assert "cost-explorer" in url

    def test_budget_links_to_budget_details(self):
        url = _first_url(_budget_normalized())
        assert url.startswith("https://")
        assert "budgets/details" in url
        assert "example-prod-monthly" in url

    def test_coh_links_to_recommendation(self):
        url = _first_url(_coh_normalized())
        assert url.startswith("https://")
        assert "cost-optimization-hub" in url
        assert "a1b2c3d4-1111-2222-3333-444455556666" in url

    def test_trusted_advisor_links_to_ta_console(self):
        url = _first_url(_ta_normalized())
        assert url.startswith("https://")
        assert "trustedadvisor" in url

    def test_all_actions_are_open_url_https(self):
        for factory in (_cad_normalized, _budget_normalized, _coh_normalized, _ta_normalized):
            for action in links.build_actions(factory()):
                assert action["type"] == "Action.OpenUrl"
                assert action["url"].startswith("https://")


# ===========================================================================
# AWS-4 — anomaly dates trimmed to YYYY-MM-DD for the CE date range.
# FAILS today (raw ISO timestamps passed straight through).
# ===========================================================================
@pytest.mark.aws4
class TestCostExplorerDateFormat:
    def test_ce_dates_are_yyyy_mm_dd(self):
        url = _first_url(_cad_normalized())
        payload = _decode_ce_filter(url)
        # CE startDate/endDate must be date-only (YYYY-MM-DD), not ISO-8601.
        assert payload.get("startDate") == "2026-05-01", (
            "AWS-4: CE startDate must be trimmed to YYYY-MM-DD "
            f"(got {payload.get('startDate')!r})"
        )
        assert payload.get("endDate") == "2026-05-03", (
            "AWS-4: CE endDate must be trimmed to YYYY-MM-DD "
            f"(got {payload.get('endDate')!r})"
        )

    def test_ce_dates_contain_no_time_component(self):
        url = _first_url(_cad_normalized())
        payload = _decode_ce_filter(url)
        assert "T" not in str(payload.get("startDate", ""))
        assert "T" not in str(payload.get("endDate", ""))


# ===========================================================================
# AWS-5 — CE deep-link format unverified. Marked xfail: cannot be validated
# offline; Phase 2 must capture a real pre-filtered CE URL or fall back to
# the event's anomalyDetailsLink.
# ===========================================================================
@pytest.mark.aws5
@pytest.mark.xfail(
    reason="AWS-5: Cost Explorer deep-link format is undocumented/unverified; "
    "cannot confirm it renders a working pre-filtered view offline. Phase 2 "
    "should verify a real CE URL or fall back to anomalyDetailsLink.",
    strict=False,
)
def test_ce_deep_link_format_verified():
    # There is no documented, stable contract to assert against. Until a real
    # CE URL is captured, treat as expected-fail.
    url = _first_url(_cad_normalized())
    payload = _decode_ce_filter(url)
    # Placeholder for the (currently unknown) correct CE filter contract.
    assert payload.get("verified_ce_contract") is True


# ===========================================================================
# AWS-5 follow-up — anomalyDetailsLink is available as a reliable fallback.
# ===========================================================================
@pytest.mark.aws5
def test_anomaly_details_link_available_as_fallback(cad_eventbridge_event):
    # The real CAD event provides a documented anomalyDetailsLink that Phase 2
    # can use as a reliable action if the CE deep link can't be made to work.
    detail = cad_eventbridge_event["detail"]
    assert detail.get("anomalyDetailsLink", "").startswith("https://")


# ===========================================================================
# TEAMS-1 — SSO action must not carry style:"positive". FAILS today.
# ===========================================================================
@pytest.mark.teams1
def test_sso_action_has_no_positive_style(monkeypatch):
    # Force the SSO branch so the (currently positive-styled) action is built.
    _force_sso_portal(monkeypatch, "example-portal.awsapps.com")
    actions = links.build_actions(_cad_normalized())
    assert actions, "expected SSO + direct actions"
    for action in actions:
        assert action.get("style") != "positive", (
            "TEAMS-1: Action.OpenUrl style 'positive' is unsupported by Teams"
        )


# ===========================================================================
# SSO wrapping behavior (Talos a1e659fa: hostname now sourced from SSM at
# runtime via routing.get_sso_portal(), not a Lambda env var).
# ===========================================================================
class TestSsoWrapping:
    def test_no_sso_when_portal_unset(self, monkeypatch):
        # Param unset/missing in SSM → accessor returns "" → direct link only.
        _force_sso_portal(monkeypatch, "")
        actions = links.build_actions(_cad_normalized())
        # Only the direct action, no SSO wrapper.
        assert len(actions) == 1
        assert "(via SSO)" not in actions[0]["title"]

    def test_sso_and_direct_when_portal_set(self, monkeypatch):
        # Param present in SSM → accessor returns the hostname → SSO + direct.
        _force_sso_portal(monkeypatch, "example-portal.awsapps.com")
        actions = links.build_actions(_cad_normalized())
        assert len(actions) == 2
        titles = [a["title"] for a in actions]
        assert any("(via SSO)" in t for t in titles)
        assert any("(direct)" in t for t in titles)
