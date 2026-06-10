"""
Build 1-click actionable deep links scoped to the LINKED account (not the payer).

Two flavors per event:
  - SSO portal link: if an Identity Center portal hostname is CONFIGURED, produces
    a console URL that takes the admin directly into the linked account with the
    target console page pre-filtered. One click, even without prior sign-in.
  - Direct console link: plain console URL. Works if the admin is already signed
    in to the linked account; otherwise redirects to login.

Talos a1e659fa: the portal hostname is NO LONGER read from a Lambda environment
variable (WORKLOAD_SSO_PORTAL is gone). It is stored in SSM Parameter Store and
read at runtime via ``routing.get_sso_portal()`` (TTL-cached, mockable). When the
parameter is unset/missing, the accessor returns "" and we degrade cleanly to
direct-console links only — no crash, no exception leakage.

Env vars:
  WORKLOAD_SSO_ROLE     default role name for the portal link, e.g.
                        "ReadOnlyAccess" (optional, default "ReadOnlyAccess")

Routing-table override (per workload owner) may eventually supply a different
role via the routing record; for now we use the env default.
"""

from __future__ import annotations

import base64
import json
import os
import urllib.parse
from typing import Any

import routing

SSO_ROLE = os.environ.get("WORKLOAD_SSO_ROLE", "ReadOnlyAccess")


def _sso_wrap(account_id: str | None, destination_url: str, role: str | None = None) -> str | None:
    # Talos a1e659fa: portal hostname comes from SSM at runtime, not an env var.
    portal = routing.get_sso_portal()
    if not portal or not account_id:
        return None
    role = role or SSO_ROLE
    dest = urllib.parse.quote(destination_url, safe="")
    return (
        f"https://{portal}/start/#/console"
        f"?account_id={account_id}&role_name={role}&destination={dest}"
    )


def _ce_filter_url(account_id: str, service: str | None, region: str | None,
                   usage_type: str | None, start: str | None, end: str | None) -> str:
    """
    Build a Cost Explorer URL pre-filtered by service/region/usageType/date.
    CE encodes its filter state as base64(JSON) in the URL fragment under the
    `filter` query parameter.
    """
    filters: list[dict[str, Any]] = []
    if service:
        filters.append({"Dimension": "SERVICE", "Values": [service]})
    if region:
        filters.append({"Dimension": "REGION", "Values": [region]})
    if usage_type:
        filters.append({"Dimension": "USAGE_TYPE", "Values": [usage_type]})
    if account_id:
        filters.append({"Dimension": "LINKED_ACCOUNT", "Values": [account_id]})

    payload: dict[str, Any] = {
        "granularity": "Daily",
        "groupBy": ["UsageType"],
        "filter": filters,
    }
    if start and end:
        # AWS-4: real CAD anomalyStartDate/anomalyEndDate are ISO-8601
        # timestamps (e.g. "2026-05-01T00:00:00Z"), but Cost Explorer's
        # startDate/endDate expect date-only YYYY-MM-DD. Trim the time
        # component so the deep-linked CE date range is honored.
        payload["timeRangeOption"] = "Custom"
        payload["startDate"] = start.split("T")[0]
        payload["endDate"] = end.split("T")[0]

    encoded = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    return (
        "https://us-east-1.console.aws.amazon.com/cost-management/home"
        f"#/cost-explorer?filter={encoded}"
    )


def build_actions(normalized: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Return a list of Adaptive Card Action.OpenUrl actions appropriate for
    the event type. Always points into the LINKED account, never the payer.
    """
    etype = normalized["event_type"]
    raw = normalized.get("raw", {}) or {}
    account = normalized.get("account_id")

    direct: str | None = None
    label = "Open in Console"

    if etype == "cost_anomaly":
        root = (raw.get("rootCauses") or [{}])[0]
        linked = root.get("linkedAccount") or account
        direct = _ce_filter_url(
            linked,
            root.get("service"),
            root.get("region"),
            root.get("usageType"),
            raw.get("anomalyStartDate"),
            raw.get("anomalyEndDate"),
        )
        label = "Investigate in Cost Explorer"
        account = linked

    elif etype == "budget_threshold":
        name = raw.get("budgetName") or raw.get("BudgetName")
        if name:
            enc = urllib.parse.quote(name, safe="")
            direct = (
                f"https://us-east-1.console.aws.amazon.com/billing/home"
                f"#/budgets/details?name={enc}"
            )
        label = "Open Budget"

    elif etype == "cost_optimization_recommendation":
        rec_id = raw.get("recommendationId") or raw.get("resourceId")
        if rec_id:
            direct = (
                "https://us-east-1.console.aws.amazon.com/cost-management/home"
                f"#/cost-optimization-hub/recommendation/{urllib.parse.quote(rec_id, safe='')}"
            )
        else:
            direct = "https://us-east-1.console.aws.amazon.com/cost-management/home#/cost-optimization-hub"
        label = "Open Recommendation"

    elif etype == "trusted_advisor_cost_check":
        direct = (
            "https://us-east-1.console.aws.amazon.com/trustedadvisor/home"
            "#/category/cost-optimizing"
        )
        label = "Open Trusted Advisor"

    if not direct:
        return []

    actions: list[dict[str, Any]] = []
    sso_url = _sso_wrap(account, direct)
    if sso_url:
        # TEAMS-1: Microsoft Teams does not support "positive"/"destructive"
        # ActionStyle on Adaptive Cards; it is silently dropped. Differentiate
        # the SSO button by title only ("(via SSO)" vs "(direct)").
        actions.append({
            "type": "Action.OpenUrl",
            "title": f"{label} (via SSO)",
            "url": sso_url,
        })
    actions.append({
        "type": "Action.OpenUrl",
        "title": label if not sso_url else f"{label} (direct)",
        "url": direct,
    })
    return actions
