"""
Account-tag-based routing.

Looks up the workload owner tag on the account via Organizations, then
consults a DynamoDB routing table to get the team_name + webhook SSM param
for that tag value. Falls back to a default entry if no match.

Routing table schema (DynamoDB, PK = tag_value):
  tag_value            S    - e.g. "platform-team" or "__default__"
  team_name            S
  webhook_ssm_param    S    - SSM SecureString name, optional for simulator-only
  min_dollar_impact    N    - suppress below this value (default 0)
"""

from __future__ import annotations

import logging
import os
import threading
import time
from typing import Any, Callable

import boto3
from botocore.exceptions import ClientError

log = logging.getLogger(__name__)

TAG_KEY = os.environ.get("WORKLOAD_OWNER_TAG_KEY", "WorkloadOwner")
ROUTING_TABLE = os.environ["ROUTING_TABLE_NAME"]
DEFAULT_KEY = "__default__"

# Talos a1e659fa: the IAM Identity Center portal hostname is NO LONGER published
# as a plaintext Lambda environment variable (WORKLOAD_SSO_PORTAL is gone). It is
# stored in SSM Parameter Store and read at runtime. The Lambda env carries only
# the parameter NAME (SSO_PORTAL_PARAM_NAME) — a name is not sensitive — exactly
# like the webhook param name lives in the routing record, not the URL value.
# When the name is unset (the default sample creates no param), get_sso_portal()
# returns "" and links.py degrades to direct-console links.
SSO_PORTAL_PARAM_NAME = os.environ.get("SSO_PORTAL_PARAM_NAME", "")

_dynamo = boto3.resource("dynamodb")
_orgs = boto3.client("organizations")
_ssm = boto3.client("ssm")

# ---------------------------------------------------------------------------
# Talos f92df048: TTL-based cache invalidation for the account-tag lookup.
#
# The previous @functools.lru_cache never expired, so for the life of a warm
# Lambda container an account's cached WorkloadOwner tag (and thus its routing
# target) could go STALE: re-tagging an account would not take effect until the
# container recycled. We replace it with a small, stdlib-only TTL cache: a value
# is reused only within _TAG_CACHE_TTL_SECONDS (default 300s, configurable via
# WORKLOAD_TAG_CACHE_TTL_SECONDS); after expiry the loader runs again so updated
# tags are honored within the TTL. The decorator preserves the `.cache_clear()`
# API (used by tests / conftest) and reads the clock via the module-level
# `_now()` so expiry can be exercised deterministically in tests.
# ---------------------------------------------------------------------------
_TAG_CACHE_TTL_SECONDS = float(os.environ.get("WORKLOAD_TAG_CACHE_TTL_SECONDS", "300"))
_TAG_CACHE_MAXSIZE = 512


def _now() -> float:
    """Monotonic clock for cache expiry (monkeypatched in tests)."""
    return time.monotonic()


def _ttl_cache(ttl_seconds: float, maxsize: int) -> Callable:
    """
    Minimal thread-safe TTL cache decorator for a single-arg loader.

    Stores ``key -> (value, expiry_ts)``. On access, a non-expired entry is
    reused; an expired one is dropped and the loader re-runs. Bounds growth to
    ``maxsize`` by evicting expired entries first, then the soonest-to-expire.
    Exposes ``cache_clear()`` for test/runtime hygiene. Expiry is measured with
    the module-level ``_now()`` so tests can advance a fake clock.
    """

    def decorator(fn: Callable[[str], "str | None"]) -> Callable[[str], "str | None"]:
        store: dict[str, tuple[Any, float]] = {}
        lock = threading.Lock()

        def wrapper(key: str) -> "str | None":
            now = _now()
            with lock:
                hit = store.get(key)
                if hit is not None:
                    value, expiry = hit
                    if now < expiry:
                        return value
                    store.pop(key, None)  # expired
            # Compute outside the lock (the loader does network I/O).
            value = fn(key)
            with lock:
                if len(store) >= maxsize and key not in store:
                    # Evict expired entries first.
                    for k in [k for k, (_v, e) in store.items() if e <= now]:
                        store.pop(k, None)
                    # Still full? Drop the soonest-to-expire entry.
                    if len(store) >= maxsize:
                        oldest = min(store, key=lambda k: store[k][1])
                        store.pop(oldest, None)
                store[key] = (value, _now() + ttl_seconds)
            return value

        def cache_clear() -> None:
            with lock:
                store.clear()

        wrapper.cache_clear = cache_clear  # type: ignore[attr-defined]
        wrapper.__wrapped__ = fn  # type: ignore[attr-defined]
        return wrapper

    return decorator


@_ttl_cache(ttl_seconds=_TAG_CACHE_TTL_SECONDS, maxsize=_TAG_CACHE_MAXSIZE)
def _account_tag(account_id: str) -> str | None:
    if not account_id:
        return None
    try:
        resp = _orgs.list_tags_for_resource(ResourceId=account_id)
    except ClientError as e:
        log.warning("list_tags_for_resource failed for %s: %s", account_id, e)
        return None
    for tag in resp.get("Tags", []):
        if tag.get("Key") == TAG_KEY:
            return tag.get("Value")
    return None


# ---------------------------------------------------------------------------
# Talos a1e659fa: SSM-backed SSO portal hostname accessor.
#
# The portal hostname is fetched from SSM Parameter Store at runtime instead of
# being baked into a Lambda env var. We REUSE the same TTL-cache + lazy-read
# pattern as the account-tag lookup above (do not invent a second pattern): a
# value is reused only within _TAG_CACHE_TTL_SECONDS so warm containers don't
# hammer SSM, and a rotated hostname propagates within the TTL. The loader is
# keyed by the parameter NAME so cache hygiene / rotation behave like the tag
# cache. Missing param / unset name / any SSM error degrade to "" (direct links
# only) and NEVER raise (5d523fa8: no raw exception leakage).
# ---------------------------------------------------------------------------
@_ttl_cache(ttl_seconds=_TAG_CACHE_TTL_SECONDS, maxsize=_TAG_CACHE_MAXSIZE)
def _sso_portal_param(param_name: str) -> str | None:
    if not param_name:
        return ""
    try:
        resp = _ssm.get_parameter(Name=param_name, WithDecryption=True)
    except ClientError as e:
        # ParameterNotFound (param not provisioned) or any access error: log the
        # param NAME only (never a value) and degrade to "" so links.py emits
        # direct-console links. Do NOT propagate — a config-read failure must not
        # fail event processing or leak internals.
        log.warning("could not read SSO portal param %s: %s", param_name, e)
        return ""
    return resp.get("Parameter", {}).get("Value") or ""


def get_sso_portal() -> str:
    """
    Return the IAM Identity Center portal hostname from SSM, or "" if it is not
    configured (param name unset, parameter missing, or unreadable).

    TTL-cached via the shared _ttl_cache so warm Lambda containers read SSM at
    most once per TTL. links.py consumes this to decide whether to build the
    1-click SSO deep link; "" means "no SSO portal" → direct-console links only.
    """
    return _sso_portal_param(SSO_PORTAL_PARAM_NAME) or ""


def _lookup(tag_value: str) -> dict[str, Any] | None:
    table = _dynamo.Table(ROUTING_TABLE)
    try:
        resp = table.get_item(Key={"tag_value": tag_value})
    except ClientError as e:
        log.warning("routing table get_item failed (%s): %s", tag_value, e)
        return None
    return resp.get("Item")


def resolve(account_id: str | None) -> dict[str, Any]:
    """
    Return a routing record with keys:
      tag_key, tag_value, team_name, webhook_ssm_param, min_dollar_impact
    Always returns a record — falls back to __default__ if no tag match.
    """
    tag_value = _account_tag(account_id) if account_id else None
    lookup_key = tag_value or DEFAULT_KEY
    item = _lookup(lookup_key) or _lookup(DEFAULT_KEY) or {}

    return {
        "tag_key": TAG_KEY,
        "tag_value": tag_value or "(none)",
        "team_name": item.get("team_name", "default-channel"),
        "webhook_ssm_param": item.get("webhook_ssm_param"),
        "min_dollar_impact": float(item.get("min_dollar_impact") or 0),
    }
