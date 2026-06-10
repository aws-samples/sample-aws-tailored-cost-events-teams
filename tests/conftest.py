"""
Shared pytest fixtures for the cost-router offline test harness (Phase 1).

Design notes (important — see EXPERT_ANALYSIS.md finding CODE-2):
  * `routing.py` executes `os.environ["ROUTING_TABLE_NAME"]` and creates
    `boto3.resource("dynamodb")` / `boto3.client("organizations")` AT IMPORT TIME.
  * `sinks.py` executes `os.environ["EVENT_BUCKET"]` and creates
    `boto3.client("s3")` / `boto3.client("ssm")` AT IMPORT TIME.
  * `routing.py` reads `SSO_PORTAL_PARAM_NAME` and creates
    `boto3.client("ssm")` AT IMPORT TIME (Talos a1e659fa: the SSO portal
    hostname now lives in SSM, read at runtime — NOT in a Lambda env var).
  * `links.py` reads `WORKLOAD_SSO_ROLE` at import and obtains the SSO portal
    hostname via `routing.get_sso_portal()` (SSM-backed, TTL-cached).

  Therefore we MUST set the env vars here, at conftest module load, BEFORE any
  test module imports the Lambda package. pytest loads conftest.py before
  collecting/importing test files, so setting os.environ at top-level is the
  reliable way to satisfy these import-time reads.

  Because the boto3 clients are created at import (outside any moto context),
  the `aws_mocks` fixture rebinds them to clients created INSIDE `mock_aws()`.

Everything here is fully offline: moto mocks S3/DynamoDB/SSM/Organizations and a
fake captures the outbound Teams HTTP POST. No real AWS, no real network.
"""

from __future__ import annotations

import io
import json
import os
import urllib.error
from pathlib import Path
from types import SimpleNamespace
from typing import Any

# ---------------------------------------------------------------------------
# 1) Env MUST be set before the Lambda modules are imported (CODE-2).
# ---------------------------------------------------------------------------
REGION = "us-east-1"
BUCKET = "cost-events-test-bucket"
TABLE = "cost-events-routing-test"
TAG_KEY = "WorkloadOwner"
DEFAULT_WEBHOOK_PARAM = "/cost-events/webhook/default"
FAKE_WEBHOOK_URL = "https://example.webhook.office.com/workflows/abc123/triggers/manual/run"
# Talos a1e659fa: the SSO portal hostname is no longer a Lambda env var; it lives
# in SSM Parameter Store and is read at runtime via routing.get_sso_portal().
# The Lambda learns only the param NAME (not the value) — mirrored here so the
# routing module's import-time SSO_PORTAL_PARAM_NAME read is satisfied.
SSO_PORTAL_PARAM = "/cost-events/config/sso-portal"
FAKE_SSO_PORTAL = "example-portal.awsapps.com"

os.environ.setdefault("AWS_DEFAULT_REGION", REGION)
os.environ.setdefault("AWS_REGION", REGION)
# Bogus static creds so boto3/moto never reach for real credentials.
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")
os.environ.setdefault("AWS_SECURITY_TOKEN", "testing")
os.environ.setdefault("AWS_SESSION_TOKEN", "testing")

os.environ.setdefault("EVENT_BUCKET", BUCKET)
os.environ.setdefault("ROUTING_TABLE_NAME", TABLE)
os.environ.setdefault("WORKLOAD_OWNER_TAG_KEY", TAG_KEY)
# Talos a1e659fa: routing.py reads SSO_PORTAL_PARAM_NAME at import to know WHICH
# SSM parameter holds the portal hostname. Point it at the test param name; the
# aws_mocks fixture decides whether that param actually EXISTS (set vs unset),
# which is how the SSM-set / SSM-unset behaviors are exercised. Tests that need
# to force the SSO branch monkeypatch `routing.get_sso_portal` (the new seam)
# rather than a module-level hostname constant.
os.environ.setdefault("SSO_PORTAL_PARAM_NAME", SSO_PORTAL_PARAM)
os.environ.setdefault("WORKLOAD_SSO_ROLE", "ReadOnlyAccess")

import boto3  # noqa: E402  (after env is set)
import pytest  # noqa: E402
from moto import mock_aws  # noqa: E402

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def _clear_account_tag_cache(routing_mod) -> None:
    """
    Clear routing._account_tag's lru_cache if it still has one.

    A test may monkeypatch _account_tag with a plain function (no lru_cache).
    monkeypatch tears down AFTER the aws_mocks fixture (it is set up first), so
    the post-yield clear can run while a plain function is installed — guard it.
    """
    fn = getattr(routing_mod, "_account_tag", None)
    cache_clear = getattr(fn, "cache_clear", None)
    if callable(cache_clear):
        cache_clear()


def _clear_sso_portal_cache(routing_mod) -> None:
    """
    Clear routing._sso_portal_param's TTL cache (Talos a1e659fa).

    The SSO portal hostname is read from SSM via a TTL-cached loader. Between
    tests one suite may leave a cached "" (param unset) while another expects a
    freshly-provisioned value (or vice versa), so reset it for determinism. A
    test may monkeypatch the loader with a plain function (no cache_clear), so
    guard the attribute the same way _clear_account_tag_cache does.
    """
    fn = getattr(routing_mod, "_sso_portal_param", None)
    cache_clear = getattr(fn, "cache_clear", None)
    if callable(cache_clear):
        cache_clear()


# ---------------------------------------------------------------------------
# 2) Fixture file loaders
# ---------------------------------------------------------------------------
def load_fixture(name: str) -> Any:
    """Load and parse a JSON fixture from tests/fixtures/."""
    with open(FIXTURES_DIR / name, encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture
def fixtures_dir() -> Path:
    return FIXTURES_DIR


# --- Cost Anomaly Detection (real, works today) ---------------------------
@pytest.fixture
def cad_sns_records() -> dict[str, Any]:
    """Full SNS Records envelope for the Cost Anomaly fixture."""
    return load_fixture("cost_anomaly_sns.json")


@pytest.fixture
def cad_eventbridge_event(cad_sns_records: dict[str, Any]) -> dict[str, Any]:
    """The EventBridge event un-wrapped from Sns.Message (JSON string)."""
    return json.loads(cad_sns_records["Records"][0]["Sns"]["Message"])


# --- AWS Budgets (AWS-1: plain-text SNS) ----------------------------------
@pytest.fixture
def budgets_sns_records() -> dict[str, Any]:
    return load_fixture("budgets_sns_plaintext.json")


@pytest.fixture
def budgets_plaintext(budgets_sns_records: dict[str, Any]) -> str:
    """The raw plain-text Budgets message body (NOT JSON)."""
    return budgets_sns_records["Records"][0]["Sns"]["Message"]


# --- Trusted Advisor (AWS-3: real EventBridge event) ----------------------
@pytest.fixture
def ta_eventbridge_event() -> dict[str, Any]:
    return load_fixture("trusted_advisor_eventbridge.json")


@pytest.fixture
def ta_sns_records(ta_eventbridge_event: dict[str, Any]) -> dict[str, Any]:
    """Wrap the real TA EventBridge event in the SNS envelope (EB→SNS→Lambda)."""
    return {
        "Records": [
            {
                "EventSource": "aws:sns",
                "Sns": {
                    "Type": "Notification",
                    "TopicArn": "arn:aws:sns:us-east-1:123456789012:cost-events-cost-router-topic",
                    "Message": json.dumps(ta_eventbridge_event),
                },
            }
        ]
    }


# --- Cost Optimization Hub (AWS-2: ListRecommendations item) --------------
@pytest.fixture
def coh_recommendation() -> dict[str, Any]:
    """One recommendation object as returned by COH ListRecommendations."""
    return load_fixture("cost_optimization_hub_recommendation.json")


# ---------------------------------------------------------------------------
# 3) moto-backed AWS mocks, with module-level client rebinding (CODE-2)
# ---------------------------------------------------------------------------
@pytest.fixture
def aws_mocks(monkeypatch):
    """
    Start moto, create S3 bucket / DynamoDB routing table / SSM webhook param,
    and rebind the import-time boto3 clients in `routing` and `sinks` so they
    talk to the mocked services.

    Yields a namespace with handles to the mocked resources.
    """
    with mock_aws():
        s3 = boto3.client("s3", region_name=REGION)
        s3.create_bucket(Bucket=BUCKET)

        ddb = boto3.resource("dynamodb", region_name=REGION)
        ddb.create_table(
            TableName=TABLE,
            KeySchema=[{"AttributeName": "tag_value", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "tag_value", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
        )
        table = ddb.Table(TABLE)
        table.wait_until_exists()
        # Seed a __default__ routing row pointing at a webhook param.
        table.put_item(
            Item={
                "tag_value": "__default__",
                "team_name": "default-channel",
                "webhook_ssm_param": DEFAULT_WEBHOOK_PARAM,
                "min_dollar_impact": 0,
            }
        )

        ssm = boto3.client("ssm", region_name=REGION)
        ssm.put_parameter(
            Name=DEFAULT_WEBHOOK_PARAM,
            Value=FAKE_WEBHOOK_URL,
            Type="SecureString",
        )

        orgs = boto3.client("organizations", region_name=REGION)

        # Rebind import-time module clients to the mocked ones.
        import routing
        import sinks

        monkeypatch.setattr(routing, "_dynamo", ddb)
        monkeypatch.setattr(routing, "_orgs", orgs)
        # Talos a1e659fa: routing.py reads the SSO portal hostname from SSM, so
        # rebind its import-time SSM client to the mocked one too. The SSO portal
        # parameter is intentionally NOT provisioned here — the default posture
        # is "unset" (mirrors the default sample, which creates no param), so
        # get_sso_portal() returns "" and links degrade to direct-only. Tests
        # that exercise the SSM-SET path provision the param themselves.
        monkeypatch.setattr(routing, "_ssm", ssm)
        monkeypatch.setattr(sinks, "_s3", s3)
        monkeypatch.setattr(sinks, "_ssm", ssm)

        # The org tag lookup is memoized; clear it so each test starts clean.
        _clear_account_tag_cache(routing)
        # Same for the SSM-backed SSO portal accessor (Talos a1e659fa).
        _clear_sso_portal_cache(routing)

        yield SimpleNamespace(
            s3=s3,
            ddb=ddb,
            table=table,
            ssm=ssm,
            orgs=orgs,
            sso_portal_param=SSO_PORTAL_PARAM,
            sso_portal=FAKE_SSO_PORTAL,
            bucket=BUCKET,
            table_name=TABLE,
            default_webhook_param=DEFAULT_WEBHOOK_PARAM,
            webhook_url=FAKE_WEBHOOK_URL,
        )

        # Teardown: a test may have monkeypatched _account_tag with a plain
        # function (no lru_cache). monkeypatch undoes AFTER this fixture tears
        # down (it is set up first), so guard the cache_clear.
        _clear_account_tag_cache(routing)
        # Same hygiene for the SSM-backed SSO portal accessor (Talos a1e659fa)
        # so a value cached during one test cannot bleed into the next.
        _clear_sso_portal_cache(routing)


# ---------------------------------------------------------------------------
# 4) Fake Teams Workflows endpoint (captures the outbound HTTP POST)
# ---------------------------------------------------------------------------
class _FakeHTTPResponse:
    """Minimal stand-in for the object urllib.request.urlopen returns."""

    def __init__(self, code: int, body: bytes = b""):
        self._code = code
        self._body = body

    def getcode(self) -> int:
        return self._code

    def read(self) -> bytes:
        return self._body

    def __enter__(self) -> "_FakeHTTPResponse":
        return self

    def __exit__(self, *exc: Any) -> bool:
        return False


class FakeTeamsEndpoint:
    """
    Records every POST `sinks.post_to_teams` makes and lets a test choose the
    response: a 2xx/non-2xx status, or an HTTPError to simulate a 4xx/5xx.
    """

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []
        self.status: int = 202  # Workflows commonly returns 202 Accepted
        self.raise_http: tuple[int, bytes] | None = None  # (code, body)

    def urlopen(self, req, timeout: float | None = None, **_kwargs):
        # urllib normalizes header keys via str.capitalize(); store as-sent.
        headers = {k: v for k, v in req.header_items()}
        self.calls.append(
            {
                "url": req.full_url,
                "data": req.data,
                "headers": headers,
                "method": req.get_method(),
                "timeout": timeout,
            }
        )
        if self.raise_http is not None:
            code, body = self.raise_http
            raise urllib.error.HTTPError(
                req.full_url, code, "simulated error", hdrs=None, fp=io.BytesIO(body)
            )
        return _FakeHTTPResponse(self.status)

    # -- convenience accessors -------------------------------------------
    @property
    def call_count(self) -> int:
        return len(self.calls)

    @property
    def last_body_json(self) -> Any:
        return json.loads(self.calls[-1]["data"].decode("utf-8"))

    def header(self, name: str) -> str | None:
        """Case-insensitive header lookup on the last call."""
        if not self.calls:
            return None
        want = name.lower()
        for k, v in self.calls[-1]["headers"].items():
            if k.lower() == want:
                return v
        return None


@pytest.fixture
def fake_teams(monkeypatch) -> FakeTeamsEndpoint:
    """Monkeypatch sinks' urlopen so no real HTTP ever leaves the process."""
    import sinks

    fake = FakeTeamsEndpoint()
    monkeypatch.setattr(sinks.urllib.request, "urlopen", fake.urlopen)
    return fake


# ---------------------------------------------------------------------------
# 5) Routing record helper for card/links tests that don't need moto
# ---------------------------------------------------------------------------
@pytest.fixture
def routing_record() -> dict[str, Any]:
    return {
        "tag_key": TAG_KEY,
        "tag_value": "platform-team",
        "team_name": "platform-team-channel",
        "webhook_ssm_param": DEFAULT_WEBHOOK_PARAM,
        "min_dollar_impact": 0.0,
    }
