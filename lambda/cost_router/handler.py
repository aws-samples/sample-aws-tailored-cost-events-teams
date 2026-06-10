"""
Entry point.

Two invocation paths:

1. **SNS fan-out (event-driven).** SNS is fed by EventBridge rules for
   ``aws.ce`` (Cost Anomaly) and ``aws.trustedadvisor`` (Trusted Advisor),
   and by AWS Budgets' native SNS notifications (AWS-1). Each SNS record wraps
   the original payload in ``Message`` — a JSON EventBridge event for CAD/TA,
   or a human-readable PLAIN-TEXT body for Budgets.

2. **Scheduled Cost Optimization Hub pull (AWS-2).** Cost Optimization Hub
   does NOT emit recommendation events to EventBridge, so recommendations are
   obtained on a schedule: an EventBridge Scheduler invocation triggers a
   ``cost-optimization-hub:ListRecommendations`` pull, and each returned item
   is normalized and routed like any other event.

CODE-1: per-record processing failures PROPAGATE (the invocation raises after
logging) so SNS retries and the SQS DLQ engage — events are never silently
lost.
"""

from __future__ import annotations

import logging
import json
from typing import Any

import boto3

from card_builder import build_card
from normalizers import normalize, normalize_coh_recommendation
from routing import resolve
from sinks import post_to_teams, write_to_s3

log = logging.getLogger()
log.setLevel(logging.INFO)

# Lazily-created Cost Optimization Hub client (AWS-2). Created on first use so
# importing this module never requires AWS credentials/network (CODE-2).
_coh = None

# Talos 5276ea22: cap the SNS Message size we will json.loads. SNS messages are
# capped by the service at 256 KB; a body at/under that bound is the natural
# limit. Anything larger is anomalous/crafted and is skipped BEFORE parsing so
# the function never allocates an unbounded parse tree (DoS / memory pressure).
_MAX_SNS_MESSAGE_BYTES = 256 * 1024

# Talos 5d523fa8: generic, caller-facing error. Per-record processing failures
# still PROPAGATE (CODE-1) so SNS retries and the SQS DLQ engage, but the public
# error message carries NO raw exception text, stack frame, or internal path —
# the full detail is logged to CloudWatch via log.exception. The Lambda runtime
# serializes the raised exception's message into the invocation response, so the
# message must be safe to expose.
_GENERIC_ERROR_MESSAGE = "Internal error processing event"


class EventProcessingError(Exception):
    """Sanitized error raised to the caller; see _MAX_SNS_MESSAGE_BYTES note."""


def handler(event: dict[str, Any], _context: Any) -> dict[str, Any]:
    # AWS-2: a scheduled invocation (EventBridge Scheduler) triggers a Cost
    # Optimization Hub ListRecommendations pull rather than processing an SNS
    # record. Detect it before the SNS/EventBridge record loop.
    if _is_coh_pull_event(event):
        return run_coh_pull()

    records = event.get("Records", []) or [event]
    results = []
    errors: list[Exception] = []
    for rec in records:
        try:
            payload = _extract(rec)
            if not payload:
                continue
            results.append(_process(payload))
        except Exception as e:  # noqa: BLE001 — re-raised below (CODE-1)
            log.exception("record failed: %s", e)
            errors.append(e)

    if errors:
        # CODE-1: do NOT swallow per-record failures. Re-raising makes the
        # Lambda invocation fail so SNS retries the message and, after retries
        # are exhausted, the message lands in the SQS DLQ. Returning success
        # here would mean events are silently lost (contradicting T-11/T-12).
        #
        # Talos 5d523fa8: the original exceptions were already logged with full
        # detail via log.exception above. Re-raise a SANITIZED, generic error
        # (`raise ... from None` suppresses the exception chain) so the raw
        # exception text — which may carry internal paths or secrets — never
        # reaches the caller / Lambda invocation response. DLQ/retry semantics
        # are unchanged: the invocation still fails.
        raise EventProcessingError(_GENERIC_ERROR_MESSAGE) from None

    return {"processed": len(results), "results": results}


def _is_coh_pull_event(event: dict[str, Any]) -> bool:
    """
    True when this invocation is the scheduled Cost Optimization Hub pull.

    EventBridge Scheduler / scheduled rules can be configured to send a small
    marker payload; we accept several shapes so the schedule target is easy to
    wire: an explicit ``{"coh_pull": true}`` marker, a Scheduler/Events source,
    or the classic ``"Scheduled Event"`` detail-type.
    """
    if not isinstance(event, dict):
        return False
    if event.get("coh_pull") is True:
        return True
    if event.get("source") in ("aws.scheduler", "aws.events"):
        return True
    if event.get("detail-type") == "Scheduled Event":
        return True
    return False


def _extract(rec: dict[str, Any]) -> dict[str, Any] | None:
    if "Sns" in rec:
        msg = rec["Sns"].get("Message", "")
        # Talos 5276ea22: bound the SNS body BEFORE json.loads. SNS caps messages
        # at 256 KB; a larger body is anomalous/crafted. Measure UTF-8 bytes (the
        # on-the-wire size) and skip parsing entirely if over the cap so we never
        # build an unbounded parse tree. Logged + dropped per the established
        # "non-json SNS message" skip semantics (the record is not processed).
        if len(msg.encode("utf-8")) > _MAX_SNS_MESSAGE_BYTES:
            log.warning(
                "SNS message exceeds %d-byte cap (%d bytes); skipping before parse",
                _MAX_SNS_MESSAGE_BYTES,
                len(msg.encode("utf-8")),
            )
            return None
        try:
            return json.loads(msg)
        except json.JSONDecodeError:
            # AWS-1: a non-JSON SNS Message is (almost certainly) a real AWS
            # Budgets threshold alert, which Budgets delivers as plain text —
            # NOT as a JSON EventBridge event. Wrap the raw body in a synthetic
            # event so `normalize` routes it to the plain-text Budgets parser
            # instead of dropping it as "non-json SNS message".
            from normalizers import _parse_budgets_sns_text

            if _parse_budgets_sns_text(msg):
                return {"source": "aws.budgets", "_budgets_plaintext": msg}
            log.warning("non-json SNS message: %s", msg[:200])
            return None
    if "source" in rec and "detail" in rec:
        return rec
    return None


def _process(eb_event: dict[str, Any]) -> dict[str, Any]:
    normalized = normalize(eb_event)
    if not normalized:
        log.info("no normalizer for source=%s", eb_event.get("source"))
        return {"ok": False, "reason": "unhandled_source"}
    return _emit(normalized)


def _emit(normalized: dict[str, Any]) -> dict[str, Any]:
    """
    Route a normalized event to its team, render the card, archive it to S3,
    and POST it to Teams. Shared by the SNS path (`_process`) and the scheduled
    COH path (`process_coh_recommendation`).
    """
    routing = resolve(normalized.get("account_id"))

    if normalized["dollar_impact"] < routing["min_dollar_impact"]:
        log.info(
            "suppressed: $%.2f < threshold $%.2f for team=%s",
            normalized["dollar_impact"], routing["min_dollar_impact"], routing["team_name"],
        )
        return {"ok": True, "suppressed": True}

    card = build_card(normalized, routing)
    s3_key = write_to_s3(card, normalized, routing)
    posted = post_to_teams(card, routing)

    return {
        "ok": True,
        "event_type": normalized["event_type"],
        "team": routing["team_name"],
        "severity": normalized["severity"],
        "s3_key": s3_key,
        "teams_posted": posted,
    }


# ---------------------------------------------------------------------------
# AWS-2: Cost Optimization Hub scheduled-pull path.
# ---------------------------------------------------------------------------
def _coh_client():
    """Lazily create (and cache) the Cost Optimization Hub boto3 client."""
    global _coh
    if _coh is None:
        _coh = boto3.client("cost-optimization-hub")
    return _coh


def pull_coh_recommendations(page_size: int = 100) -> list[dict[str, Any]]:
    """
    Call ``cost-optimization-hub:ListRecommendations`` and return every
    recommendation item. The API is paginated via ``nextToken``; we follow it
    to completion. Tests intercept this boto3 call via their mock/moto layer.
    """
    client = _coh_client()
    items: list[dict[str, Any]] = []
    next_token: str | None = None
    while True:
        kwargs: dict[str, Any] = {
            "includeAllRecommendations": True,
            "maxResults": page_size,
        }
        if next_token:
            kwargs["nextToken"] = next_token
        resp = client.list_recommendations(**kwargs)
        items.extend(resp.get("items", []) or [])
        next_token = resp.get("nextToken")
        if not next_token:
            break
    return items


def process_coh_recommendation(item: dict[str, Any]) -> dict[str, Any]:
    """
    Normalize a single Cost Optimization Hub recommendation item (as returned
    by ``ListRecommendations``) and route/render/archive/post it — the COH
    analogue of ``_process`` for the SNS path (AWS-2).
    """
    normalized = normalize_coh_recommendation(item)
    return _emit(normalized)


def run_coh_pull() -> dict[str, Any]:
    """
    Scheduled entrypoint: pull all current COH recommendations and process each
    one. Per-item failures propagate (CODE-1) so the scheduled invocation fails
    and is retried rather than silently losing recommendations.
    """
    items = pull_coh_recommendations()
    results = []
    errors: list[Exception] = []
    for item in items:
        try:
            results.append(process_coh_recommendation(item))
        except Exception as e:  # noqa: BLE001 — re-raised below (CODE-1)
            log.exception("COH recommendation failed: %s", e)
            errors.append(e)
    if errors:
        # Talos 5d523fa8: full detail already logged via log.exception above;
        # re-raise a sanitized, generic error (chain suppressed) so no raw
        # exception text reaches the caller. CODE-1 propagation is preserved.
        raise EventProcessingError(_GENERIC_ERROR_MESSAGE) from None
    return {"processed": len(results), "results": results, "source": "coh_pull"}
