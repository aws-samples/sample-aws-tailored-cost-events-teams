"""
Output sinks for the Teams payload.

- S3Sink: always on. Writes the exact card JSON to S3 so the simulator
  (or any consumer later) can replay without a live Teams channel.
- TeamsWebhookSink: optional. Posts to a Teams Workflows webhook URL
  fetched from SSM. Skipped cleanly if no webhook is configured for
  the routing target.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import time
import urllib.parse
import urllib.request
import urllib.error
from typing import Any

import boto3
from botocore.exceptions import ClientError

log = logging.getLogger(__name__)

BUCKET = os.environ["EVENT_BUCKET"]
_s3 = boto3.client("s3")
_ssm = boto3.client("ssm")

# ---------------------------------------------------------------------------
# Talos 51f0122b: webhook URL host allow-listing (SSRF defense).
#
# `post_to_teams` already requires the https scheme, but a tampered SSM value
# could still point the outbound POST at an arbitrary host — the cloud metadata
# endpoint (169.254.169.254), localhost, an internal RFC-1918 address, or an
# attacker domain — turning the Lambda into an SSRF pivot. We additionally
# require the host to end in a legitimate Microsoft Teams Workflows endpoint
# suffix and reject IP-literal / loopback / link-local / internal hosts before
# any network call.
#
# Defaults cover how Teams Workflows webhook URLs are formed today:
#   * Power Automate / Logic Apps triggers -> *.logic.azure.com
#   * Teams "Incoming Webhook" / Workflows  -> *.webhook.office.com
# Operators can extend (not replace) the set via the comma-separated
# TEAMS_WEBHOOK_ALLOWED_HOSTS env var (e.g. a corporate relay domain).
# ---------------------------------------------------------------------------
_DEFAULT_WEBHOOK_ALLOWED_HOST_SUFFIXES = (
    ".logic.azure.com",
    ".webhook.office.com",
)


def _load_webhook_allow_list() -> tuple[str, ...]:
    """Built-in suffixes PLUS any extra suffixes from the env (never replaced)."""
    extra_raw = os.environ.get("TEAMS_WEBHOOK_ALLOWED_HOSTS", "")
    extras = tuple(
        s.strip().lower()
        for s in extra_raw.split(",")
        if s.strip()
    )
    return _DEFAULT_WEBHOOK_ALLOWED_HOST_SUFFIXES + extras


_WEBHOOK_ALLOWED_HOST_SUFFIXES = _load_webhook_allow_list()


def _reload_webhook_allow_list() -> tuple[str, ...]:
    """Re-read the env-configurable allow-list (used by tests / re-config)."""
    global _WEBHOOK_ALLOWED_HOST_SUFFIXES
    _WEBHOOK_ALLOWED_HOST_SUFFIXES = _load_webhook_allow_list()
    return _WEBHOOK_ALLOWED_HOST_SUFFIXES


def _is_allowed_webhook_url(url: str) -> bool:
    """
    True only if ``url`` is an https URL whose host is a legitimate Teams
    Workflows endpoint. Rejects (Talos 51f0122b):
      * any non-https scheme,
      * IP-literal hosts (covers 169.254.169.254, 127.0.0.1, RFC-1918, ::1),
      * loopback / bare-internal / mDNS names (localhost, *.local, internal),
      * hosts not ending in an allow-listed suffix (blocks suffix-spoofing like
        ``webhook.office.com.evil.com`` because that host does NOT end in
        ``.webhook.office.com``).
    """
    try:
        parsed = urllib.parse.urlparse(url)
    except (ValueError, AttributeError):
        return False

    if parsed.scheme.lower() != "https":
        return False

    host = (parsed.hostname or "").lower().rstrip(".")
    if not host:
        return False

    # Reject IP-literal hosts outright (metadata IP, loopback, RFC-1918, IPv6).
    try:
        ipaddress.ip_address(host)
        return False
    except ValueError:
        pass  # not an IP literal — good, continue with name checks

    # Reject obvious internal / loopback names.
    if host == "localhost" or host.endswith(".localhost"):
        return False
    if host.endswith(".local") or host.endswith(".internal"):
        return False
    if "." not in host:  # bare single-label name (e.g. "internal")
        return False

    # Must end in an allow-listed suffix. Endswith on a dotted suffix prevents
    # suffix-spoofing (a.webhook.office.com.evil.com fails this check).
    return any(host.endswith(suffix) for suffix in _WEBHOOK_ALLOWED_HOST_SUFFIXES)


def write_to_s3(card: dict[str, Any], normalized: dict[str, Any], routing: dict[str, Any]) -> str:
    ts = time.strftime("%Y/%m/%d/%H/%M%S", time.gmtime())
    event_type = normalized["event_type"]
    team = routing.get("team_name", "default")
    key = f"events/{event_type}/{team}/{ts}-{int(time.time()*1000)%100000}.json"

    envelope = {
        "team_name": team,
        "tag_value": routing.get("tag_value"),
        "severity": normalized["severity"],
        "event_type": event_type,
        "account_id": normalized["account_id"],
        "dollar_impact": normalized["dollar_impact"],
        "teams_payload": card,
    }
    _s3.put_object(
        Bucket=BUCKET,
        Key=key,
        Body=json.dumps(envelope, indent=2, default=str).encode("utf-8"),
        ContentType="application/json",
    )
    log.info("wrote %s", key)
    return key


def post_to_teams(card: dict[str, Any], routing: dict[str, Any]) -> bool:
    """
    POST the card to the Teams Workflows webhook referenced by the routing
    record. Returns True on 2xx, False otherwise. Absence of a webhook param
    is not an error — returns False quietly.
    """
    param_name = routing.get("webhook_ssm_param")
    if not param_name:
        log.info("no webhook_ssm_param for %s; skipping Teams POST", routing.get("team_name"))
        return False
    try:
        resp = _ssm.get_parameter(Name=param_name, WithDecryption=True)
        url = resp["Parameter"]["Value"]
    except ClientError as e:
        log.error("cannot fetch webhook param %s: %s", param_name, e)
        return False
    if not url or url.startswith("PLACEHOLDER"):
        log.info("webhook param %s is placeholder; skipping POST", param_name)
        return False
    # Defense in depth (T-04, T-17, Talos 51f0122b): SSM is the source of truth,
    # but a tampered value could redirect the POST. Require https AND a host on
    # the Teams Workflows allow-list; reject IP-literal / metadata / loopback /
    # internal / non-allow-listed hosts BEFORE any network call (SSRF guard).
    if not _is_allowed_webhook_url(url):
        # Log only the param NAME, never the URL value (T-06: no webhook leak).
        log.error(
            "webhook param %s resolves to a disallowed/SSRF host; refusing to POST",
            param_name,
        )
        return False

    # nosemgrep: dynamic-urllib-use-detected -- scheme is validated above (https only)
    req = urllib.request.Request(  # nosec B310
        url,
        data=json.dumps(card).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        # nosemgrep: dynamic-urllib-use-detected
        with urllib.request.urlopen(req, timeout=10) as r:  # nosec B310
            code = r.getcode()
            log.info("teams POST status=%s", code)
            return 200 <= code < 300
    except urllib.error.HTTPError as e:
        log.error("teams POST HTTPError %s: %s", e.code, e.read()[:500])
        return False
    except Exception as e:
        log.error("teams POST failed: %s", e)
        return False
