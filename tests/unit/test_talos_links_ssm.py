"""
Talos remediation tests for the SSM-backed SSO portal hostname relocation.

**a1e659fa — SSO portal hostname exposed in Lambda env vars.**
The portal hostname used to be published as the plaintext Lambda environment
variable ``WORKLOAD_SSO_PORTAL`` (visible to anyone with
``lambda:GetFunctionConfiguration``). The final remediation REMOVES that env var
entirely and stores the hostname in SSM Parameter Store
(``/cost-events/config/sso-portal``), read at runtime through a TTL-cached
accessor that REUSES the same stdlib TTL-cache + lazy-client pattern already
added for the account-tag lookup (f92df048). The Lambda env carries only the
parameter NAME (``SSO_PORTAL_PARAM_NAME``) — a name is not sensitive.

These tests use the REAL accessor against moto's SSM (not a stub):
  * SSM SET   → ``routing.get_sso_portal()`` returns the hostname and
                ``links.build_actions`` builds the 1-click SSO deep link.
  * SSM UNSET → the parameter does not exist; the accessor degrades gracefully
                to "" (NO crash, NO raised/leaked exception per 5d523fa8) and
                ``links`` emits direct-console links only.
  * TTL       → within the TTL the parameter is read from SSM exactly once
                (warm containers don't hammer SSM); after the TTL the loader
                re-runs so a rotated hostname propagates.
"""

from __future__ import annotations

from typing import Any

import links
import routing


# ---------------------------------------------------------------------------
# A Cost Anomaly normalized model (the SSO branch needs an account_id).
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


class _CountingSsm:
    """SSM stub that counts get_parameter calls and can simulate ParameterNotFound."""

    def __init__(self, value: str | None):
        self.calls = 0
        self.value = value

    def get_parameter(self, Name, WithDecryption=False):  # noqa: N803
        self.calls += 1
        if self.value is None:
            # Mirror the real boto3/moto behavior for a missing parameter.
            raise routing.ClientError(
                {"Error": {"Code": "ParameterNotFound", "Message": "not found"}},
                "GetParameter",
            )
        return {"Parameter": {"Name": Name, "Value": self.value}}


# ===========================================================================
# Contract: the accessor and its SSM-name env wiring exist.
# ===========================================================================
class TestSsoPortalAccessorContract:
    def test_accessor_exists(self):
        assert callable(getattr(routing, "get_sso_portal", None)), (
            "a1e659fa: routing must expose a get_sso_portal() accessor"
        )

    def test_loader_has_cache_clear(self):
        # Reuses the f92df048 TTL-cache decorator → must expose cache_clear.
        loader = getattr(routing, "_sso_portal_param", None)
        assert callable(getattr(loader, "cache_clear", None)), (
            "a1e659fa: the SSM-backed loader must reuse the TTL cache "
            "(cache_clear API) — do not invent a second cache pattern"
        )

    def test_links_no_longer_reads_env_hostname(self):
        # The env-var read must be GONE: no module-level SSO_PORTAL constant.
        assert not hasattr(links, "SSO_PORTAL"), (
            "a1e659fa: links.SSO_PORTAL (the WORKLOAD_SSO_PORTAL env read) must "
            "be removed; the hostname is sourced from SSM at runtime"
        )


# ===========================================================================
# SSM SET → real read via moto → SSO deep link is built.
# ===========================================================================
class TestSsmSet:
    def test_get_sso_portal_reads_value_from_ssm(self, aws_mocks):
        aws_mocks.ssm.put_parameter(
            Name=aws_mocks.sso_portal_param,
            Value=aws_mocks.sso_portal,
            Type="String",
        )
        routing._sso_portal_param.cache_clear()
        assert routing.get_sso_portal() == aws_mocks.sso_portal

    def test_build_actions_wraps_sso_when_param_set(self, aws_mocks):
        aws_mocks.ssm.put_parameter(
            Name=aws_mocks.sso_portal_param,
            Value=aws_mocks.sso_portal,
            Type="String",
        )
        routing._sso_portal_param.cache_clear()

        actions = links.build_actions(_cad_normalized())
        assert len(actions) == 2, "expected SSO + direct actions when param set"
        titles = [a["title"] for a in actions]
        assert any("(via SSO)" in t for t in titles)
        assert any("(direct)" in t for t in titles)
        sso = next(a for a in actions if "(via SSO)" in a["title"])
        assert sso["url"].startswith(f"https://{aws_mocks.sso_portal}/start/#/console")
        assert "account_id=123456789012" in sso["url"]


# ===========================================================================
# SSM UNSET → parameter absent → graceful degrade (no crash, no leak).
# ===========================================================================
class TestSsmUnset:
    def test_get_sso_portal_empty_when_param_missing(self, aws_mocks):
        # aws_mocks intentionally does NOT provision the SSO portal param.
        routing._sso_portal_param.cache_clear()
        assert routing.get_sso_portal() == "", (
            "a1e659fa: a missing SSM param must degrade to '' (direct links), "
            "not raise"
        )

    def test_build_actions_direct_only_when_param_missing(self, aws_mocks):
        routing._sso_portal_param.cache_clear()
        actions = links.build_actions(_cad_normalized())
        assert len(actions) == 1, "no SSO wrapper when the param is unset"
        assert "(via SSO)" not in actions[0]["title"]

    def test_get_sso_portal_empty_when_name_unset(self, aws_mocks, monkeypatch):
        # No SSO_PORTAL_PARAM_NAME configured at all → no SSM call, returns "".
        monkeypatch.setattr(routing, "SSO_PORTAL_PARAM_NAME", "")
        routing._sso_portal_param.cache_clear()
        assert routing.get_sso_portal() == ""

    def test_missing_param_does_not_raise_or_leak(self, aws_mocks):
        # 5d523fa8: the ParameterNotFound ClientError must be swallowed inside
        # the accessor — it must never propagate out of build_actions.
        routing._sso_portal_param.cache_clear()
        try:
            links.build_actions(_cad_normalized())
        except Exception as exc:  # noqa: BLE001
            raise AssertionError(
                f"a1e659fa/5d523fa8: SSM lookup must not leak an exception: {exc!r}"
            )


# ===========================================================================
# TTL: warm containers read SSM once per TTL; rotation propagates after expiry.
# ===========================================================================
class TestSsoPortalTtl:
    def test_value_reused_within_ttl(self, monkeypatch):
        routing._sso_portal_param.cache_clear()
        stub = _CountingSsm("portal-a.awsapps.com")
        monkeypatch.setattr(routing, "_ssm", stub)
        monkeypatch.setattr(routing, "SSO_PORTAL_PARAM_NAME", "/cost-events/config/sso-portal")

        clock = {"t": 1000.0}
        monkeypatch.setattr(routing, "_now", lambda: clock["t"])

        assert routing.get_sso_portal() == "portal-a.awsapps.com"
        clock["t"] += routing._TAG_CACHE_TTL_SECONDS - 1
        assert routing.get_sso_portal() == "portal-a.awsapps.com"
        assert stub.calls == 1, "within TTL the SSM value must be reused (one read)"
        routing._sso_portal_param.cache_clear()

    def test_loader_reruns_after_ttl_expiry(self, monkeypatch):
        routing._sso_portal_param.cache_clear()
        stub = _CountingSsm("portal-a.awsapps.com")
        monkeypatch.setattr(routing, "_ssm", stub)
        monkeypatch.setattr(routing, "SSO_PORTAL_PARAM_NAME", "/cost-events/config/sso-portal")

        clock = {"t": 1000.0}
        monkeypatch.setattr(routing, "_now", lambda: clock["t"])

        assert routing.get_sso_portal() == "portal-a.awsapps.com"
        assert stub.calls == 1

        # Operator rotates the portal hostname; advance the clock PAST the TTL.
        stub.value = "portal-b.awsapps.com"
        clock["t"] += routing._TAG_CACHE_TTL_SECONDS + 1

        assert routing.get_sso_portal() == "portal-b.awsapps.com", (
            "after TTL expiry the loader must re-run and pick up the rotated host"
        )
        assert stub.calls == 2
        routing._sso_portal_param.cache_clear()
