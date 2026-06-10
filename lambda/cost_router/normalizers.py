"""
Normalize AWS cost-related EventBridge events into a common shape.

Each normalizer returns a dict with:
  event_type       - short label (e.g. "cost_anomaly", "budget_threshold")
  account_id       - the account that incurred the cost
  account_name     - friendly name if known
  title            - headline for the Teams card
  severity         - "info" | "warning" | "critical"
  summary_fields   - list of (label, value) tuples shown in the card
  dollar_impact    - numeric, used for routing thresholds
  investigation    - free-form guidance string for the card footer
  raw              - the original event detail
"""

from __future__ import annotations

import re
from typing import Any


def normalize(event: dict[str, Any]) -> dict[str, Any] | None:
    # AWS-1: a Budgets alert arrives as a PLAIN-TEXT SNS message (not a JSON
    # EventBridge event). handler._extract wraps such a body in a synthetic
    # event carrying the raw text under "_budgets_plaintext"; route it to the
    # dedicated plain-text normalizer.
    if "_budgets_plaintext" in event:
        return normalize_budgets_text(event["_budgets_plaintext"])

    source = event.get("source")
    detail_type = event.get("detail-type", "")
    dispatch = {
        "aws.ce": _cost_anomaly,
        "aws.budgets": _budgets,
        "aws.cost-optimization-hub": _cost_optimization_hub,
        "aws.trustedadvisor": _trusted_advisor,
    }
    handler = dispatch.get(source)
    if not handler:
        return None
    return handler(event, detail_type)


def _cost_anomaly(event: dict[str, Any], detail_type: str) -> dict[str, Any]:
    d = event.get("detail", {})
    impact = d.get("impact", {}) or {}
    total = float(impact.get("totalImpact", 0) or 0)
    pct = float(impact.get("totalImpactPercentage", 0) or 0)
    root = (d.get("rootCauses") or [{}])[0]

    if total >= 5000:
        severity = "critical"
    elif total >= 500:
        severity = "warning"
    else:
        severity = "info"

    fields = [
        ("Account", f"{d.get('accountId','?')} ({d.get('accountName','—')})"),
        ("Service", root.get("service", "—")),
        ("Region", root.get("region", "—")),
        ("Usage type", root.get("usageType", "—")),
        ("Linked account", f"{root.get('linkedAccount','—')} ({root.get('linkedAccountName','—')})"),
        ("Impact", f"${total:,.2f} ({pct:.1f}% increase)"),
        ("Window", f"{d.get('anomalyStartDate','?')} → {d.get('anomalyEndDate','?')}"),
        ("Monitor", d.get("monitorName", "—")),
    ]

    return {
        "event_type": "cost_anomaly",
        "account_id": d.get("accountId") or root.get("linkedAccount"),
        "account_name": d.get("accountName") or root.get("linkedAccountName"),
        "title": f"Cost Anomaly Detected — ${total:,.0f} impact",
        "severity": severity,
        "summary_fields": fields,
        "dollar_impact": total,
        "investigation": (
            "Workload owner steps: (1) sign in to the linked account, "
            "(2) open Cost Explorer, (3) filter by the service, region, and usage type above, "
            "(4) narrow to the anomaly window to identify the driver resource."
        ),
        "raw": d,
    }


def _budgets(event: dict[str, Any], detail_type: str) -> dict[str, Any]:
    """
    Budgets Action + Budgets Alarm events.
    detail-type examples:
      - "Budgets Action Status Change"
      - "Budget Threshold Exceeded"
    """
    d = event.get("detail", {})
    budget_name = d.get("budgetName") or d.get("BudgetName") or "—"
    actual = float(d.get("actualAmount", d.get("ActualAmount", 0)) or 0)
    threshold = float(d.get("thresholdAmount", d.get("ThresholdAmount", 0)) or 0)
    pct = (actual / threshold * 100) if threshold else 0

    severity = "critical" if pct >= 100 else ("warning" if pct >= 80 else "info")

    fields = [
        ("Budget", budget_name),
        ("Account", event.get("account", "—")),
        ("Actual", f"${actual:,.2f}"),
        ("Threshold", f"${threshold:,.2f}"),
        ("Utilization", f"{pct:.1f}%"),
        ("Alert type", detail_type),
    ]

    return {
        "event_type": "budget_threshold",
        "account_id": event.get("account"),
        "account_name": None,
        "title": f"Budget Alert — {budget_name} at {pct:.0f}%",
        "severity": severity,
        "summary_fields": fields,
        "dollar_impact": actual,
        "investigation": (
            "Workload owner steps: (1) review Cost Explorer for the month-to-date breakdown by service, "
            "(2) compare against the same window last month, (3) identify top growth services, "
            "(4) confirm whether spend is expected (launch, migration) or anomalous."
        ),
        "raw": d,
    }


def _cost_optimization_hub(event: dict[str, Any], detail_type: str) -> dict[str, Any]:
    """
    AWS-2: Cost Optimization Hub does NOT publish recommendation events to
    EventBridge — recommendations are obtained via a scheduled
    ``ListRecommendations`` pull. This dispatch branch is retained only so a
    pre-unwrapped recommendation object (carried in ``detail``) can still be
    normalized; the real path is ``normalize_coh_recommendation`` invoked by
    the scheduled handler entrypoint.
    """
    return normalize_coh_recommendation(event.get("detail", {}) or {})


def normalize_coh_recommendation(item: dict[str, Any]) -> dict[str, Any]:
    """
    Normalize a single Cost Optimization Hub recommendation object as returned
    by ``cost-optimization-hub:ListRecommendations``.

    Real field names (AWS-2): ``recommendationId``, ``actionType``,
    ``currentResourceType``/``recommendedResourceType``,
    ``currentResourceSummary``/``recommendedResourceSummary``,
    ``estimatedMonthlySavings``, ``implementationEffort``, ``restartNeeded``,
    ``accountId``. The legacy ``recommendationType``/``resourceType`` names are
    fabrications and are intentionally NOT read.
    """
    savings = float(item.get("estimatedMonthlySavings", 0) or 0)
    action = item.get("actionType") or "—"
    cur_type = item.get("currentResourceType") or "—"
    rec_type = item.get("recommendedResourceType") or "—"
    cur_summary = item.get("currentResourceSummary") or ""
    rec_summary = item.get("recommendedResourceSummary") or ""
    resource = item.get("resourceId") or item.get("resourceArn") or "—"
    account_id = item.get("accountId")

    severity = "warning" if savings >= 500 else "info"

    # Resource label includes the current type and (when a target differs) the
    # current→recommended summary so the card shows the concrete change.
    if cur_summary and rec_summary and cur_summary != rec_summary:
        resource_label = f"{cur_type} ({cur_summary} → {rec_summary})"
    else:
        resource_label = f"{cur_type} / {resource}"

    fields = [
        ("Account", account_id or "—"),
        ("Recommendation", f"{action} ({cur_type} → {rec_type})"),
        ("Resource", resource_label),
        ("Region", item.get("region", "—")),
        ("Est. monthly savings", f"${savings:,.2f}"),
        ("Effort", item.get("implementationEffort", "—")),
        ("Restart required", str(item.get("restartNeeded", "—"))),
    ]

    return {
        "event_type": "cost_optimization_recommendation",
        "account_id": account_id,
        "account_name": None,
        "title": f"Cost Optimization — ${savings:,.0f}/mo savings opportunity",
        "severity": severity,
        "summary_fields": fields,
        "dollar_impact": savings,
        "investigation": (
            "Workload owner steps: (1) open Cost Optimization Hub in the linked account, "
            "(2) validate the recommendation against current workload utilization, "
            "(3) schedule a change window if restart is required."
        ),
        "raw": item,
    }


def _trusted_advisor(event: dict[str, Any], detail_type: str) -> dict[str, Any]:
    """
    AWS-3: the real Trusted Advisor "Check Item Refresh Notification" detail
    has ``check-name``, ``check-item-detail{Region, Status, ...}``, ``status``,
    ``resource_id`` and ``uuid``. There is NO top-level ``check-category`` —
    the previous code read a field that does not exist (always "—"), and read
    region from a non-existent ``resource_region``/top-level ``region``. The
    real region lives at ``detail.check-item-detail.Region``.
    """
    d = event.get("detail", {})
    item = d.get("check-item-detail", {}) or {}
    check_name = d.get("check-name", d.get("checkName", "—"))
    status = d.get("status", "—")
    # Region comes from the nested check-item-detail (AWS-3).
    region = item.get("Region", "—")
    resource = d.get("resource_id", d.get("resourceId", "—"))
    savings = _parse_dollar_amount(item.get("Estimated Monthly Savings"))

    fields = [
        ("Account", event.get("account", "—")),
        ("Check", check_name),
        ("Status", status),
        ("Region", region),
        ("Resource", resource),
        ("Est. monthly savings", f"${savings:,.2f}"),
    ]

    severity = "warning" if status in ("WARN", "ERROR") else "info"

    return {
        "event_type": "trusted_advisor_cost_check",
        "account_id": event.get("account"),
        "account_name": None,
        "title": f"Trusted Advisor — {check_name} ({status})",
        "severity": severity,
        "summary_fields": fields,
        "dollar_impact": savings,
        "investigation": (
            "Workload owner steps: (1) open Trusted Advisor in the linked account, "
            "(2) review the flagged resources for the check above, "
            "(3) remediate or acknowledge."
        ),
        "raw": d,
    }


# ---------------------------------------------------------------------------
# AWS-1: AWS Budgets plain-text SNS parsing.
#
# AWS Budgets does NOT emit JSON threshold events to EventBridge. A real
# threshold alert is delivered to SNS as a human-readable, line-oriented
# PLAIN-TEXT body, e.g.:
#
#     AWS Budget Notification May 04, 2026
#     AWS Account 123456789012
#     ...
#     Budget Name: example-prod-monthly
#     Budget Type: Cost
#     Budgeted Amount: $40,000.00
#     Alert Type: ACTUAL
#     Alert Threshold: > $40,000.00
#     ACTUAL Amount: $42,500.00
#
# handler._extract routes such non-JSON SNS messages here instead of dropping
# them as "non-json SNS message".
# ---------------------------------------------------------------------------
_AMOUNT_RE = re.compile(r"-?\$?\s*[\d,]+(?:\.\d+)?")

# Defense-in-depth (security audit 2026-06-10): the Budgets SNS body is the one
# UNTRUSTED, attacker-*influenceable* plain-text input this Lambda parses (publish
# to the topic is constrained by the SNS topic policy to budgets.amazonaws.com +
# aws:SourceAccount, but we still treat the body as untrusted). A real Budgets
# notification is well under 4 KB; SNS permits up to 256 KB. We cap the body we
# parse so a pathologically large message cannot drive unbounded regex scanning.
# The regexes here are all linear (no nested/overlapping quantifiers → no ReDoS),
# so this is belt-and-suspenders, not a fix for a known catastrophic pattern.
_MAX_BUDGETS_BODY_CHARS = 16384


def _parse_dollar_amount(value: Any) -> float:
    """
    Best-effort parse of a currency-ish string (``"$40,000.00"``,
    ``"> $40,000.00"``, ``"$245.28"``) into a float. Returns 0.0 when no
    numeric component can be found. Used by both the Budgets plain-text parser
    and the Trusted Advisor "Estimated Monthly Savings" field.
    """
    if value is None:
        return 0.0
    if isinstance(value, (int, float)):
        return float(value)
    match = _AMOUNT_RE.search(str(value))
    if not match:
        return 0.0
    cleaned = match.group(0).replace("$", "").replace(",", "").strip()
    try:
        return float(cleaned)
    except ValueError:
        return 0.0


def _parse_budgets_sns_text(body: str) -> dict[str, Any] | None:
    """
    Parse the line-oriented plain-text AWS Budgets SNS body into a dict of the
    salient fields. Returns ``None`` when the body does not look like a Budgets
    notification (no ``Budget Name:`` line), so the caller can fall through.
    """
    if not body:
        return None

    # Defense-in-depth: bound the untrusted input we scan (see
    # _MAX_BUDGETS_BODY_CHARS). Real Budgets bodies are < 4 KB; anything larger
    # is truncated before parsing so regex work stays bounded regardless of input.
    if len(body) > _MAX_BUDGETS_BODY_CHARS:
        body = body[:_MAX_BUDGETS_BODY_CHARS]

    def grab(label: str) -> str | None:
        m = re.search(rf"{re.escape(label)}\s*:?\s*(.+)", body)
        return m.group(1).strip() if m else None

    budget_name = grab("Budget Name")
    if not budget_name:
        return None  # not a Budgets message

    # Account number from the "AWS Account 123456789012" line.
    account_id = None
    m_acct = re.search(r"AWS Account\s*:?\s*(\d{6,})", body)
    if m_acct:
        account_id = m_acct.group(1)

    budget_type = grab("Budget Type")
    alert_type = grab("Alert Type")
    threshold = grab("Alert Threshold")
    budgeted_amount = _parse_dollar_amount(grab("Budgeted Amount"))
    # ACTUAL or FORECASTED amount is the figure that breached the threshold.
    actual_raw = grab("ACTUAL Amount") or grab("FORECASTED Amount") or grab("Actual Amount")
    actual_amount = _parse_dollar_amount(actual_raw)

    return {
        "budget_name": budget_name,
        "account_id": account_id,
        "budget_type": budget_type,
        "alert_type": alert_type,
        "alert_threshold": threshold,
        "budgeted_amount": budgeted_amount,
        "actual_amount": actual_amount,
    }


def normalize_budgets_text(body: str) -> dict[str, Any] | None:
    """
    Turn a plain-text Budgets SNS body into the common normalized model.

    Severity: actual spend at/over the budgeted amount is ``critical``; at/over
    80% is ``warning``; otherwise ``info``. ``dollar_impact`` is the actual
    (breaching) amount so routing thresholds compare against real spend.
    """
    parsed = _parse_budgets_sns_text(body)
    if not parsed:
        return None

    budget_name = parsed["budget_name"]
    actual = parsed["actual_amount"]
    budgeted = parsed["budgeted_amount"]
    pct = (actual / budgeted * 100) if budgeted else 0.0

    if pct >= 100:
        severity = "critical"
    elif pct >= 80:
        severity = "warning"
    else:
        severity = "info"

    fields = [
        ("Budget", budget_name),
        ("Account", parsed.get("account_id") or "—"),
        ("Budget type", parsed.get("budget_type") or "—"),
        ("Budgeted amount", f"${budgeted:,.2f}"),
        ("Actual amount", f"${actual:,.2f}"),
        ("Utilization", f"{pct:.1f}%"),
        ("Alert type", parsed.get("alert_type") or "—"),
        ("Alert threshold", parsed.get("alert_threshold") or "—"),
    ]

    return {
        "event_type": "budget_threshold",
        "account_id": parsed.get("account_id"),
        "account_name": None,
        "title": f"Budget Alert — {budget_name} at {pct:.0f}%",
        "severity": severity,
        "summary_fields": fields,
        "dollar_impact": actual,
        "investigation": (
            "Workload owner steps: (1) review Cost Explorer for the month-to-date breakdown by service, "
            "(2) compare against the same window last month, (3) identify top growth services, "
            "(4) confirm whether spend is expected (launch, migration) or anomalous."
        ),
        # links.build_actions reads raw.budgetName to build the budget deep link.
        "raw": {"budgetName": budget_name, **parsed},
    }
