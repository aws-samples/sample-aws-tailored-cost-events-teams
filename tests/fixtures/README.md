# Realistic AWS Event Fixtures (Phase 1)

These fixtures are **schema-accurate reproductions of what AWS actually emits**,
captured/derived from the cited AWS documentation. They deliberately differ from
the hand-authored `tests/synthetic_events/*.json`, which the
[`EXPERT_ANALYSIS.md`](../../docs/EXPERT_ANALYSIS.md) found were "authored to pass
the normalizers, not captured from AWS" (finding **TEST-2**).

Several of these fixtures intentionally exercise **dead code paths** today — that
is the point. Phase 2 will implement the corrected ingestion so the tests that
consume these fixtures turn green.

| Fixture | What it represents | Delivery mechanism | EXPERT_ANALYSIS finding(s) | Primary AWS source |
|---------|--------------------|--------------------|----------------------------|--------------------|
| [`cost_anomaly_sns.json`](cost_anomaly_sns.json) | Real Cost Anomaly Detection `Anomaly Detected` EventBridge event, JSON-stringified inside the SNS `Records[].Sns.Message` envelope. `anomalyStartDate`/`anomalyEndDate` are **ISO-8601 timestamps** (`2026-05-01T00:00:00Z`), `impact.totalImpact`, `rootCauses[]`, `monitorArn`, `anomalyDetailsLink` all present. | EventBridge rule → SNS → Lambda (the **one source that works** today) | **AWS-4** (ISO-8601 date must be trimmed to `YYYY-MM-DD` for the CE link), **AWS-5** (CE deep-link format unverified) | CAD EventBridge schema: https://docs.aws.amazon.com/cost-management/latest/userguide/cad-eventbridge.html |
| [`budgets_sns_plaintext.json`](budgets_sns_plaintext.json) | Real AWS Budgets threshold alert: a **plain-text** human-readable `Message` string (NOT JSON) inside the SNS envelope. Includes `Budget Name`, `Budget Type`, `Budgeted Amount`, `Alert Type`, `Alert Threshold`, `ACTUAL Amount`, `AWS Account`. | Budget SNS subscriber → SNS → Lambda. Budgets does **not** publish threshold JSON to EventBridge. | **AWS-1** (Budgets is SNS-native plain text; `handler._extract`'s `json.loads()` drops it today) | Budgets is CloudTrail-only on EventBridge: https://docs.aws.amazon.com/eventbridge/latest/ref/events-ref-budgets.html · Real plain-text body: https://aws.amazon.com/blogs/messaging-and-targeting/establishing-finops-management-integrating-aws-budgets-with-whatsapp-using-aws-end-user-messaging |
| [`trusted_advisor_eventbridge.json`](trusted_advisor_eventbridge.json) | Real `Trusted Advisor Check Item Refresh Notification` EventBridge event. Genuine `detail` shape: `check-name`, `check-item-detail{Region, Status, ...}`, `status` (`WARN`), `resource_id`, `uuid`. **No top-level `check-category`** (the field the current rule/normalizer invent). | EventBridge rule → SNS → Lambda (event is real; the **rule filter is broken**) | **AWS-3** (region lives at `detail.check-item-detail.Region`; `check-category` does not exist) | TA EventBridge schema: https://docs.aws.amazon.com/eventbridge/latest/ref/events-ref-trustedadvisor.html · Real detail (no `check-category`): https://aws.amazon.com/blogs/mt/auto-remediate-best-practice-deviations-detected-by-aws-trusted-advisor |
| [`cost_optimization_hub_recommendation.json`](cost_optimization_hub_recommendation.json) | One recommendation **object** as returned by the COH `ListRecommendations` API (NOT an EventBridge event). Real field names: `recommendationId`, `actionType`, `currentResourceType`, `recommendedResourceType`, `estimatedMonthlySavings`, `recommendedResourceSummary`, `implementationEffort`, `restartNeeded`, `estimatedSavingsPercentage`. | **Scheduled pull** (EventBridge Scheduler → Lambda → `ListRecommendations`). COH publishes **no** recommendation events to EventBridge. | **AWS-2** (real field names + scheduled-pull entrypoint) | COH is CloudTrail-only on EventBridge: https://docs.aws.amazon.com/eventbridge/latest/ref/events-ref-cost-optimization-hub.html · Real recommendation fields: https://aws.amazon.com/blogs/aws/new-cost-optimization-hub-to-find-all-recommended-actions-in-one-place-for-saving-you-money |

## Why these are wrapped the way they are

- **Cost Anomaly** and **Trusted Advisor** are genuine EventBridge service events.
  In production they fan out EventBridge → SNS → Lambda, so the Lambda receives
  them inside an SNS `Records` envelope where `Sns.Message` is the
  JSON-stringified EventBridge event. `cost_anomaly_sns.json` shows the full SNS
  envelope; `trusted_advisor_eventbridge.json` stores the bare EventBridge event
  (the E2E test wraps it in the SNS envelope so we can also exercise the raw
  EventBridge shape that [`handler._extract`](../../lambda/cost_router/handler.py:47)
  accepts via the `"source" in rec and "detail" in rec` branch).
- **Budgets** is **not** an EventBridge event at all — it arrives as a plain-text
  SNS notification, so the fixture is the SNS envelope with a plain-text
  `Sns.Message`.
- **Cost Optimization Hub** is **not** an event — it is data pulled from an API,
  so the fixture is a single recommendation object exactly as
  `ListRecommendations` returns it.

## Phase-2 contract (what must become true)

1. **AWS-1:** [`handler._extract`](../../lambda/cost_router/handler.py:39) routes a
   non-JSON SNS `Message` to a Budgets plain-text parser instead of dropping it,
   and a normalizer maps the parsed fields into the common model.
2. **AWS-2:** a COH entrypoint normalizes a `ListRecommendations` item using the
   real field names (`actionType`, `currentResourceType`, `recommendationId`,
   `estimatedMonthlySavings`).
3. **AWS-3:** [`normalizers._trusted_advisor`](../../lambda/cost_router/normalizers.py:155)
   reads region from `detail.check-item-detail.Region`.
4. **AWS-4:** [`links._ce_filter_url`](../../lambda/cost_router/links.py:43) trims the
   ISO-8601 time component (`split("T")[0]`) before building the CE date range.
