"""
Unit tests for sinks.py.

post_to_teams (HTTP) is exercised via the `fake_teams` fixture, which
monkeypatches sinks' urllib urlopen so nothing leaves the process.
write_to_s3 is exercised against moto S3 (via `aws_mocks`).

Key contracts:
  * 202 Accepted is success (Workflows commonly returns 202).
  * 200 is success; 4xx/5xx is NOT success.
  * Content-Type: application/json is sent; a timeout is passed.
  * The posted body equals the card envelope from card_builder.
  * S3 envelope embeds the card byte-for-byte under teams_payload.

CODE-1 note: today post_to_teams *returns False* on HTTP error rather than
raising. The dedicated propagation contract (errors must surface so SNS retries
/ DLQ engages) is asserted at the handler level in test_handler.py. Here we pin
the success/failure return contract that handler.py depends on.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

import sinks


def _card() -> dict[str, Any]:
    return {
        "type": "message",
        "attachments": [
            {
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": {
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "type": "AdaptiveCard",
                    "version": "1.5",
                    "body": [{"type": "TextBlock", "text": "hi"}],
                },
            }
        ],
    }


# ===========================================================================
# post_to_teams — HTTP semantics
# ===========================================================================
class TestPostToTeams:
    def test_202_is_success(self, aws_mocks, fake_teams):
        fake_teams.status = 202
        routing = {
            "team_name": "default-channel",
            "webhook_ssm_param": aws_mocks.default_webhook_param,
        }
        assert sinks.post_to_teams(_card(), routing) is True
        assert fake_teams.call_count == 1

    def test_200_is_success(self, aws_mocks, fake_teams):
        fake_teams.status = 200
        routing = {
            "team_name": "default-channel",
            "webhook_ssm_param": aws_mocks.default_webhook_param,
        }
        assert sinks.post_to_teams(_card(), routing) is True

    def test_4xx_is_failure(self, aws_mocks, fake_teams):
        # Simulate a 400 Bad Request (raised as HTTPError by urllib).
        fake_teams.raise_http = (400, b"bad request")
        routing = {
            "team_name": "default-channel",
            "webhook_ssm_param": aws_mocks.default_webhook_param,
        }
        assert sinks.post_to_teams(_card(), routing) is False

    def test_5xx_is_failure(self, aws_mocks, fake_teams):
        fake_teams.raise_http = (503, b"unavailable")
        routing = {
            "team_name": "default-channel",
            "webhook_ssm_param": aws_mocks.default_webhook_param,
        }
        assert sinks.post_to_teams(_card(), routing) is False

    def test_content_type_is_application_json(self, aws_mocks, fake_teams):
        routing = {
            "team_name": "default-channel",
            "webhook_ssm_param": aws_mocks.default_webhook_param,
        }
        sinks.post_to_teams(_card(), routing)
        assert fake_teams.header("Content-Type") == "application/json"

    def test_timeout_is_set(self, aws_mocks, fake_teams):
        routing = {
            "team_name": "default-channel",
            "webhook_ssm_param": aws_mocks.default_webhook_param,
        }
        sinks.post_to_teams(_card(), routing)
        assert fake_teams.calls[-1]["timeout"] is not None
        assert fake_teams.calls[-1]["timeout"] > 0

    def test_posted_body_equals_card(self, aws_mocks, fake_teams):
        routing = {
            "team_name": "default-channel",
            "webhook_ssm_param": aws_mocks.default_webhook_param,
        }
        card = _card()
        sinks.post_to_teams(card, routing)
        assert fake_teams.last_body_json == card

    def test_method_is_post(self, aws_mocks, fake_teams):
        routing = {
            "team_name": "default-channel",
            "webhook_ssm_param": aws_mocks.default_webhook_param,
        }
        sinks.post_to_teams(_card(), routing)
        assert fake_teams.calls[-1]["method"] == "POST"


# ===========================================================================
# post_to_teams — webhook resolution / SSRF guard
# ===========================================================================
class TestWebhookResolution:
    def test_missing_param_returns_false_no_post(self, aws_mocks, fake_teams):
        assert sinks.post_to_teams(_card(), {"team_name": "x"}) is False
        assert fake_teams.call_count == 0

    def test_placeholder_value_skipped(self, aws_mocks, fake_teams):
        aws_mocks.ssm.put_parameter(
            Name="/cost-events/webhook/placeholder",
            Value="PLACEHOLDER_SET_ME",
            Type="SecureString",
            Overwrite=True,
        )
        routing = {
            "team_name": "x",
            "webhook_ssm_param": "/cost-events/webhook/placeholder",
        }
        assert sinks.post_to_teams(_card(), routing) is False
        assert fake_teams.call_count == 0

    def test_non_https_url_refused(self, aws_mocks, fake_teams):
        aws_mocks.ssm.put_parameter(
            Name="/cost-events/webhook/insecure",
            Value="http://evil.example.com/hook",
            Type="SecureString",
            Overwrite=True,
        )
        routing = {
            "team_name": "x",
            "webhook_ssm_param": "/cost-events/webhook/insecure",
        }
        assert sinks.post_to_teams(_card(), routing) is False
        assert fake_teams.call_count == 0


# ===========================================================================
# write_to_s3 — envelope embeds the card byte-for-byte
# ===========================================================================
class TestWriteToS3:
    def _normalized(self) -> dict[str, Any]:
        return {
            "event_type": "cost_anomaly",
            "account_id": "123456789012",
            "severity": "warning",
            "dollar_impact": 1001.0,
        }

    def test_writes_object_and_returns_key(self, aws_mocks):
        routing = {"team_name": "default-channel", "tag_value": "platform-team"}
        key = sinks.write_to_s3(_card(), self._normalized(), routing)
        assert key.startswith("events/cost_anomaly/default-channel/")
        # Object actually exists in the mocked bucket.
        obj = aws_mocks.s3.get_object(Bucket=aws_mocks.bucket, Key=key)
        body = json.loads(obj["Body"].read())
        assert body["teams_payload"] == _card()
        assert body["event_type"] == "cost_anomaly"
        assert body["account_id"] == "123456789012"

    def test_s3_content_type_json(self, aws_mocks):
        routing = {"team_name": "default-channel"}
        key = sinks.write_to_s3(_card(), self._normalized(), routing)
        head = aws_mocks.s3.head_object(Bucket=aws_mocks.bucket, Key=key)
        assert head["ContentType"] == "application/json"
