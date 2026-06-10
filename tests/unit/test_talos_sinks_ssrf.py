"""
Talos remediation tests for sinks.py — webhook host allow-listing (SSRF).

**51f0122b — Webhook URL domain not validated (potential SSRF).** ``post_to_teams``
previously enforced only the ``https://`` scheme. A tampered SSM value could
therefore point the outbound POST at an arbitrary host — the cloud metadata
endpoint (``169.254.169.254``), ``localhost``, an internal RFC-1918 address, or
an attacker domain — turning the Lambda into an SSRF pivot.

The fix adds host/domain ALLOW-LISTING: the webhook host must end in one of the
legitimate Microsoft Teams Workflows endpoint suffixes (Power Automate /
Logic Apps: ``*.logic.azure.com``; Teams Workflows: ``*.webhook.office.com``),
configurable via ``TEAMS_WEBHOOK_ALLOWED_HOSTS``. IP-literal hosts, the metadata
IP, localhost, and non-allow-listed domains are rejected BEFORE any network call.
"""

from __future__ import annotations

from typing import Any

import pytest

import sinks


def _card() -> dict[str, Any]:
    return {"type": "message", "attachments": []}


def _put(aws_mocks, name: str, value: str) -> dict[str, Any]:
    aws_mocks.ssm.put_parameter(
        Name=name, Value=value, Type="SecureString", Overwrite=True
    )
    return {"team_name": "x", "webhook_ssm_param": name}


# ===========================================================================
# Pure host-validation helper (no AWS, no network).
# ===========================================================================
class TestIsAllowedWebhookHost:
    def test_helper_exists(self):
        assert hasattr(sinks, "_is_allowed_webhook_url"), (
            "51f0122b: sinks must expose a webhook URL allow-list validator"
        )

    @pytest.mark.parametrize(
        "url",
        [
            "https://example.webhook.office.com/workflows/abc/triggers/manual/run",
            "https://prod-12.westus.logic.azure.com/workflows/abc/triggers/manual/run",
            "https://tenant.webhook.office.com/IncomingWebhook/abc/def",
        ],
    )
    def test_legitimate_teams_workflows_urls_allowed(self, url):
        assert sinks._is_allowed_webhook_url(url) is True

    @pytest.mark.parametrize(
        "url",
        [
            "http://example.webhook.office.com/x",          # non-https
            "https://evil.example.com/hook",                 # wrong domain
            "https://169.254.169.254/latest/meta-data/",     # cloud metadata
            "https://127.0.0.1/hook",                        # loopback IP
            "https://localhost/hook",                        # loopback name
            "https://10.0.0.5/hook",                         # RFC-1918 IP literal
            "https://[::1]/hook",                            # IPv6 loopback
            "https://webhook.office.com.evil.com/hook",      # suffix-spoof
            "https://internal/hook",                         # bare internal name
            "https://service.local/hook",                    # mDNS .local
        ],
    )
    def test_ssrf_and_non_teams_urls_rejected(self, url):
        assert sinks._is_allowed_webhook_url(url) is False


# ===========================================================================
# post_to_teams integration — rejection happens BEFORE any HTTP call.
# ===========================================================================
class TestPostToTeamsAllowList:
    def test_metadata_ip_rejected_no_post(self, aws_mocks, fake_teams):
        routing = _put(aws_mocks, "/cost-events/webhook/meta", "https://169.254.169.254/x")
        assert sinks.post_to_teams(_card(), routing) is False
        assert fake_teams.call_count == 0, "no HTTP call may be made on rejection"

    def test_attacker_domain_rejected_no_post(self, aws_mocks, fake_teams):
        routing = _put(aws_mocks, "/cost-events/webhook/evil", "https://evil.example.com/hook")
        assert sinks.post_to_teams(_card(), routing) is False
        assert fake_teams.call_count == 0

    def test_ip_literal_rejected_no_post(self, aws_mocks, fake_teams):
        routing = _put(aws_mocks, "/cost-events/webhook/iplit", "https://10.1.2.3/hook")
        assert sinks.post_to_teams(_card(), routing) is False
        assert fake_teams.call_count == 0

    def test_legitimate_workflows_url_still_posts(self, aws_mocks, fake_teams):
        # The conftest default param already holds a *.webhook.office.com URL.
        routing = {
            "team_name": "default-channel",
            "webhook_ssm_param": aws_mocks.default_webhook_param,
        }
        assert sinks.post_to_teams(_card(), routing) is True
        assert fake_teams.call_count == 1


# ===========================================================================
# Allow-list is configurable via env (TEAMS_WEBHOOK_ALLOWED_HOSTS).
# ===========================================================================
class TestAllowListConfigurable:
    def test_env_override_adds_domain(self, monkeypatch):
        # A custom corporate Workflows relay domain can be allow-listed.
        monkeypatch.setenv("TEAMS_WEBHOOK_ALLOWED_HOSTS", ".contoso-relay.example")
        # Reload the module-level allow-list from env.
        sinks._reload_webhook_allow_list()
        try:
            assert sinks._is_allowed_webhook_url(
                "https://hooks.contoso-relay.example/x"
            ) is True
            # The built-in defaults are NOT silently dropped by an override.
            assert sinks._is_allowed_webhook_url(
                "https://t.webhook.office.com/x"
            ) is True
        finally:
            monkeypatch.delenv("TEAMS_WEBHOOK_ALLOWED_HOSTS", raising=False)
            sinks._reload_webhook_allow_list()
