"""
Unit tests for routing.py — account-tag → DynamoDB routing resolution.

Uses moto DynamoDB + Organizations (via the `aws_mocks` fixture). The fixture
seeds a __default__ row; individual tests add a tag-specific row and stub the
Organizations tag lookup as needed.
"""

from __future__ import annotations

import routing


class TestResolveDefaultFallback:
    def test_no_account_falls_back_to_default(self, aws_mocks):
        rec = routing.resolve(None)
        assert rec["team_name"] == "default-channel"
        assert rec["webhook_ssm_param"] == aws_mocks.default_webhook_param
        assert rec["tag_value"] == "(none)"

    def test_unknown_account_uses_default(self, aws_mocks, monkeypatch):
        # Organizations returns no matching tag → default row.
        monkeypatch.setattr(routing, "_account_tag", lambda _acct: None)
        rec = routing.resolve("999999999999")
        assert rec["team_name"] == "default-channel"

    def test_min_dollar_impact_is_float(self, aws_mocks):
        rec = routing.resolve(None)
        assert isinstance(rec["min_dollar_impact"], float)


class TestResolveTagMatch:
    def _seed_team(self, aws_mocks, tag_value, team_name, param, min_impact=0):
        aws_mocks.table.put_item(
            Item={
                "tag_value": tag_value,
                "team_name": team_name,
                "webhook_ssm_param": param,
                "min_dollar_impact": min_impact,
            }
        )

    def test_tag_resolves_to_team_row(self, aws_mocks, monkeypatch):
        self._seed_team(
            aws_mocks,
            "platform-team",
            "platform-team-channel",
            "/cost-events/webhook/platform",
            min_impact=250,
        )
        monkeypatch.setattr(routing, "_account_tag", lambda _acct: "platform-team")

        rec = routing.resolve("123456789012")
        assert rec["tag_value"] == "platform-team"
        assert rec["team_name"] == "platform-team-channel"
        assert rec["webhook_ssm_param"] == "/cost-events/webhook/platform"
        assert rec["min_dollar_impact"] == 250.0

    def test_tag_present_but_no_row_falls_back_to_default(
        self, aws_mocks, monkeypatch
    ):
        # Tag exists on the account but there's no matching routing row.
        monkeypatch.setattr(routing, "_account_tag", lambda _acct: "ghost-team")
        rec = routing.resolve("123456789012")
        # tag_value is still surfaced, but team comes from __default__.
        assert rec["tag_value"] == "ghost-team"
        assert rec["team_name"] == "default-channel"


class TestAccountTagLookup:
    def test_account_tag_reads_workload_owner(self, aws_mocks):
        # Stub Organizations list_tags_for_resource via moto isn't supported for
        # arbitrary account IDs, so exercise the parsing path directly by
        # monkeypatching the orgs client response shape.
        class _Orgs:
            def list_tags_for_resource(self, ResourceId):  # noqa: N803
                return {
                    "Tags": [
                        {"Key": "WorkloadOwner", "Value": "data-team"},
                        {"Key": "Env", "Value": "prod"},
                    ]
                }

        routing._account_tag.cache_clear()
        orig = routing._orgs
        routing._orgs = _Orgs()
        try:
            assert routing._account_tag("123456789012") == "data-team"
        finally:
            routing._orgs = orig
            routing._account_tag.cache_clear()

    def test_account_tag_none_when_tag_absent(self, aws_mocks):
        class _Orgs:
            def list_tags_for_resource(self, ResourceId):  # noqa: N803
                return {"Tags": [{"Key": "Env", "Value": "prod"}]}

        routing._account_tag.cache_clear()
        orig = routing._orgs
        routing._orgs = _Orgs()
        try:
            assert routing._account_tag("123456789012") is None
        finally:
            routing._orgs = orig
            routing._account_tag.cache_clear()
