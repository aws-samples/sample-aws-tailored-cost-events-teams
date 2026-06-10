"""
Talos remediation tests for routing.py — TTL-based cache invalidation.

**f92df048 — LRU cache never invalidates (stale routing possible).**
``routing._account_tag`` was decorated with ``functools.lru_cache``, which never
expires. For the life of a warm Lambda container, an account's cached
WorkloadOwner tag (and therefore its team routing) could be stale: if an admin
re-tags an account, the change is not picked up until the container recycles.

The fix replaces the unbounded LRU with a TTL cache: a value is reused only
within ``WORKLOAD_TAG_CACHE_TTL_SECONDS`` (default 300s); after expiry the loader
runs again so updated tags are honored. The decorator keeps the ``cache_clear``
API (used by tests / conftest) and uses a monkeypatchable clock (``routing._now``)
so expiry can be exercised deterministically.
"""

from __future__ import annotations

import routing


class _CountingOrgs:
    """Organizations stub that counts list_tags_for_resource calls."""

    def __init__(self, value: str | None = "platform-team"):
        self.calls = 0
        self.value = value

    def list_tags_for_resource(self, ResourceId):  # noqa: N803
        self.calls += 1
        tags = [{"Key": "WorkloadOwner", "Value": self.value}] if self.value else []
        return {"Tags": tags}


class TestTtlCacheContract:
    def test_ttl_constant_exists_and_is_sane(self):
        ttl = getattr(routing, "_TAG_CACHE_TTL_SECONDS", None)
        assert isinstance(ttl, (int, float)), (
            "f92df048: routing must define a numeric _TAG_CACHE_TTL_SECONDS"
        )
        assert ttl > 0

    def test_cache_clear_still_available(self):
        # conftest._clear_account_tag_cache and test_routing.py both call this.
        assert callable(getattr(routing._account_tag, "cache_clear", None))

    def test_clock_is_monkeypatchable(self):
        assert callable(getattr(routing, "_now", None))


class TestTtlInvalidation:
    def test_value_reused_within_ttl(self, monkeypatch):
        """Within the TTL window the loader is called exactly once."""
        routing._account_tag.cache_clear()
        orgs = _CountingOrgs("platform-team")
        monkeypatch.setattr(routing, "_orgs", orgs)

        clock = {"t": 1000.0}
        monkeypatch.setattr(routing, "_now", lambda: clock["t"])

        assert routing._account_tag("123456789012") == "platform-team"
        # Advance, but stay inside the TTL window.
        clock["t"] += routing._TAG_CACHE_TTL_SECONDS - 1
        assert routing._account_tag("123456789012") == "platform-team"

        assert orgs.calls == 1, (
            "f92df048: within TTL the cached value must be reused (loader once)"
        )
        routing._account_tag.cache_clear()

    def test_loader_reruns_after_ttl_expiry(self, monkeypatch):
        """After the TTL elapses the loader runs again and a NEW value wins."""
        routing._account_tag.cache_clear()
        orgs = _CountingOrgs("platform-team")
        monkeypatch.setattr(routing, "_orgs", orgs)

        clock = {"t": 1000.0}
        monkeypatch.setattr(routing, "_now", lambda: clock["t"])

        assert routing._account_tag("123456789012") == "platform-team"
        assert orgs.calls == 1

        # An admin re-tags the account; advance the clock PAST the TTL.
        orgs.value = "data-team"
        clock["t"] += routing._TAG_CACHE_TTL_SECONDS + 1

        assert routing._account_tag("123456789012") == "data-team", (
            "f92df048: after TTL expiry the loader must re-run and pick up the "
            "updated tag (no permanently-stale routing)"
        )
        assert orgs.calls == 2
        routing._account_tag.cache_clear()

    def test_cache_clear_forces_reload(self, monkeypatch):
        routing._account_tag.cache_clear()
        orgs = _CountingOrgs("platform-team")
        monkeypatch.setattr(routing, "_orgs", orgs)
        monkeypatch.setattr(routing, "_now", lambda: 5000.0)

        routing._account_tag("123456789012")
        routing._account_tag.cache_clear()
        routing._account_tag("123456789012")

        assert orgs.calls == 2, "cache_clear must force a fresh load"
        routing._account_tag.cache_clear()

    def test_distinct_accounts_cached_independently(self, monkeypatch):
        routing._account_tag.cache_clear()
        orgs = _CountingOrgs("platform-team")
        monkeypatch.setattr(routing, "_orgs", orgs)
        monkeypatch.setattr(routing, "_now", lambda: 7000.0)

        routing._account_tag("111111111111")
        routing._account_tag("222222222222")
        routing._account_tag("111111111111")  # cached

        assert orgs.calls == 2, "two distinct accounts → two loads; repeat is cached"
        routing._account_tag.cache_clear()
