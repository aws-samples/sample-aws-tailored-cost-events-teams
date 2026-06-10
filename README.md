# cost-events-to-teams

[![License: MIT-0](https://img.shields.io/badge/License-MIT--0-yellow.svg)](LICENSE)

Route AWS cost/FinOps events (Cost Anomaly Detection, Budgets, Cost Optimization Hub, Trusted Advisor) from an organization's payer account to the right Microsoft Teams channel based on account tags, with **1-click actionable deep links into the linked account** (not the payer).

Solves the well-known UX gap where Cost Anomaly deep links only open in the originating account — workload owners in a payer-based org would otherwise have to interpret the alert, switch accounts, and manually reproduce the filter.

> **This is sample code, for non-production usage.** You should work with your security and legal teams to meet your organizational security, regulatory, and compliance requirements before deployment. See [SECURITY.md](SECURITY.md) for vulnerability reporting and [THREAT_MODEL.md](THREAT_MODEL.md) for the full security analysis.

## Why this exists (differentiation vs. existing OSS)

A scan of `aws-samples`, `awslabs`, `aws-solutions`, and the wider GitHub ecosystem found **no public repository covering this combination**. The closest matches each implement one slice; none implement the union. Differentiators:

- **Multi-source fan-in of all 4 cost signals** in one pipeline — Cost Anomaly Detection (`aws.ce` EventBridge event), AWS Budgets (native plain-text SNS), Cost Optimization Hub (scheduled `ListRecommendations` pull), and Trusted Advisor (`aws.trustedadvisor` EventBridge event, cost-check allow-list). These four arrive by three different mechanisms because AWS does not emit them all to EventBridge — the pipeline normalizes them into a single shape regardless. Most existing repos cover one source; a few cover two. Zero cover all four.
- **Org-aware tag routing** — looks up the linked account's `WorkloadOwner` tag via Organizations and dispatches to a DynamoDB-backed channel map. Found in zero surveyed repos.
- **Linked-account console deep linking** via IAM Identity Center start URL with pre-filtered destinations (Cost Explorer with service/region/usageType/date filter, Budgets by name, Cost Optimization Hub by recommendation ID, Trusted Advisor by category). Zero prior art — solves the well-known UX gap where built-in CAD deep links only open in the originating account.
- **Post-Connector Teams Workflows + Adaptive Card v1.5** — Microsoft retired the classic O365 "Incoming Webhook" Connector by end of 2025. The only public Teams cost-alert repo I found still uses the retired Connector. This repo uses the supported Workflows (Power Automate) trigger and emits Adaptive Card **v1.5** — the current Teams ceiling ("v1.5 or earlier"). The card uses only widely-supported 1.0-era elements (`TextBlock`, `FactSet`, `Action.OpenUrl`), so it renders on older clients too; positive/destructive `ActionStyle` is intentionally omitted because Teams does not support it.

Closest public references (architectural prior art, none drop-in):

- [`fivexl/terraform-aws-slack-alerts`](https://github.com/fivexl/terraform-aws-slack-alerts) — multi-source Terraform aggregator, **Slack via AWS Chatbot**, no COH, no tag routing, no deep links.
- [`kgautams-123/aws-cost-optimization-hub-summarizer`](https://github.com/kgautams-123/aws-cost-optimization-hub-summarizer) — the only public COH consumer I found; weekly batch, email not Teams.

---

## Contents

- [cost-events-to-teams](#cost-events-to-teams)
  - [Why this exists (differentiation vs. existing OSS)](#why-this-exists-differentiation-vs-existing-oss)
  - [Contents](#contents)
  - [Architecture](#architecture)
    - [Data flow in detail](#data-flow-in-detail)
    - [Actionable deep links](#actionable-deep-links)
  - [How it works](#how-it-works)
  - [Features](#features)
  - [Event sources wired in](#event-sources-wired-in)
  - [Repository layout](#repository-layout)
  - [Configuration \& deployment (start here)](#configuration--deployment-start-here)
    - [Step 1 — Deploy the Terraform stack](#step-1--deploy-the-terraform-stack)
    - [Step 2 — Create the Teams Workflows webhook](#step-2--create-the-teams-workflows-webhook)
    - [Step 3 — Store the webhook URL in SSM Parameter Store](#step-3--store-the-webhook-url-in-ssm-parameter-store)
    - [Step 4 — Configure routing (tags → channels)](#step-4--configure-routing-tags--channels)
    - [Step 5 — Wire each event source](#step-5--wire-each-event-source)
    - [Step 6 — Send a test event](#step-6--send-a-test-event)
    - [Step 7 — Verify delivery](#step-7--verify-delivery)
  - [Variables](#variables)
  - [Wiring AWS Budgets to the topic](#wiring-aws-budgets-to-the-topic)
  - [Adding workload-owner channels](#adding-workload-owner-channels)
    - [Teardown](#teardown)
  - [Local UAT with the simulator](#local-uat-with-the-simulator)
  - [Operating in a real payer account](#operating-in-a-real-payer-account)
  - [Projected AWS cost for ~150 accounts](#projected-aws-cost-for-150-accounts)
    - [Event volume assumptions](#event-volume-assumptions)
    - [Per-component cost](#per-component-cost)
  - [Security + IAM](#security--iam)
  - [Troubleshooting](#troubleshooting)
  - [Security posture](#security-posture)
  - [Handoff checklist](#handoff-checklist)

---

## Architecture

```
 ┌─────────────────────────── Payer account ─────────────────────────────────┐
 │                                                                            │
 │  PUSH sources (event-driven)                                               │
 │                                                                            │
 │  EventBridge default bus                                                   │
 │  ├─ rule: aws.ce / "Anomaly Detected"            ──┐                        │
 │  └─ rule: aws.trustedadvisor                       │  (WARN/ERROR +         │
 │       "Check Item Refresh Notification"            │   cost check-name      │
 │                                                    │   allow-list)          │
 │                                                    ▼                        │
 │  AWS Budgets ── native plain-text SNS notify ──▶ SNS  cost-events topic     │
 │   (customer points budget's SNS at this topic)     │  (CMK-encrypted)       │
 │                                                    ▼                        │
 │            ┌──────────────────────────┐                                    │
 │            │ Lambda: cost-router      │                                    │
 │            │ 1. normalize event       │                                    │
 │            │ 2. Organizations tag     │   ─> org:ListTagsForResource        │
 │            │    lookup (WorkloadOwner)│                                    │
 │            │ 3. DDB routing lookup    │   ─> DynamoDB: routing              │
 │            │ 4. build Adaptive Card   │                                    │
 │            │    + deep-link actions   │                                    │
 │            │    (SSO + direct URLs)   │                                    │
 │            │ 5. write to S3 (always)  │   ─> S3: archive                    │
 │            │ 6. POST to Teams         │   ─> SSM SecureString               │
 │            │    (if webhook set)      │      /cost-events/webhook/*         │
 │            └──────────────────────────┘                                    │
 │                  ▲             │                                           │
 │  PULL source     │             │                                           │
 │  EventBridge ────┘ {"coh_pull":true}  (direct Lambda invoke, daily)        │
 │  Scheduler  ── calls cost-optimization-hub:ListRecommendations             │
 │  (var.coh_pull_schedule, default rate(1 day))                              │
 │                                │                                           │
 └────────────────────────────────┼───────────────────────────────────────────┘
                                  │
                                  ▼
                      Teams channel (per workload owner)
                       — via Teams Workflows webhook
                       — Adaptive Card v1.5 with action buttons
```

Dual-sink design. S3 archive is always written (90-day lifecycle by default, source of truth for audit + UAT), Teams POST is conditional on whether the routing record has a real webhook URL in SSM. Switching Teams on for a new channel is a one-line SSM update — no code changes.

The four sources reach the Lambda by **three different mechanisms** because AWS does not emit all of them to EventBridge the same way (see [Event sources wired in](#event-sources-wired-in) for the full per-source matrix):

- **Cost Anomaly Detection** and **Trusted Advisor** are genuine EventBridge service events → SNS → Lambda (push).
- **AWS Budgets** does **not** emit threshold events to EventBridge; it publishes **plain-text** alerts straight to SNS, which the Lambda parses (push).
- **Cost Optimization Hub** emits **no** recommendation events at all; a daily **EventBridge Scheduler** invokes the Lambda directly with `{"coh_pull": true}`, which then calls `cost-optimization-hub:ListRecommendations` (pull).

### Data flow in detail

1. **EventBridge** rules filter the two genuine event-driven sources (Cost Anomaly Detection, Trusted Advisor) on the default bus; matching events fan out to a single SNS topic. **AWS Budgets** publishes its plain-text alerts directly to the same SNS topic (no EventBridge rule). **Cost Optimization Hub** is pulled on a schedule (no EventBridge rule); see step 7.
2. **SNS → Lambda** is the classic fanout pattern. Using SNS instead of direct EventBridge-to-Lambda lets future consumers (e.g., Splunk forwarder, second Lambda for alerting history) subscribe without extra rules. The SNS `Message` is a JSON EventBridge event for Cost Anomaly / Trusted Advisor, and a human-readable plain-text body for Budgets — `handler._extract` detects the difference and routes plain text to the Budgets parser.
3. **Lambda normalization** — each source has a dedicated handler in `normalizers.py` that produces a common shape (`account_id`, `severity`, `summary_fields`, `dollar_impact`, `investigation`, `raw`).
4. **Routing resolution** — the linked account ID from the event is looked up in Organizations for the `WorkloadOwner` tag (key is configurable). The tag value keys into a DynamoDB table that holds `{team_name, webhook_ssm_param, min_dollar_impact}`. A `__default__` row catches anything unmatched. Results are LRU-cached per warm invocation.
5. **Card building** — the Adaptive Card v1.5 payload is assembled with:
   - title styled by severity (info/warning/critical → color)
   - routing breadcrumb (tag key/value + channel)
   - fact set (account, service, region, usage type, $ impact, time window, etc.)
   - investigation text
   - **action buttons** with two URLs per event type
6. **Sinks** — the exact card JSON is written to S3 at `events/<type>/<team>/YYYY/MM/DD/HH/MMSS-<hash>.json`. If a non-placeholder Teams URL exists in SSM, the same JSON is POSTed to Teams.

### Actionable deep links

Every card carries two URLs per event (where available):

- **SSO portal link** — `https://<portal>.awsapps.com/start/#/console?account_id=<linked>&role_name=<role>&destination=<encoded console URL>`. When the SSO portal hostname is configured (stored in SSM at `/cost-events/config/sso-portal` — see [Variables](#variables); Talos a1e659fa relocated it out of the Lambda env var), this appears as the primary "via SSO" button. One click from the Teams card takes the admin into the **linked account** with the target console page pre-loaded.
- **Direct console link** — unwrapped console URL. Works if the admin is already signed in to the linked account; otherwise redirects through normal AWS sign-in.

The link targets are event-type-aware:

| Event (`event_type`)             | Link target                                                                                      |
|----------------------------------|--------------------------------------------------------------------------------------------------|
| `cost_anomaly`                   | Cost Explorer pre-filtered by the anomaly's service, region, usage type, and date window         |
| `budget_threshold`               | The specific budget details page by name                                                         |
| `cost_optimization_recommendation` | The specific recommendation by `recommendationId` (falls back to the Cost Optimization Hub home) |
| `trusted_advisor_cost_check`     | The Trusted Advisor cost-optimizing category page                                                |

All URLs use the **linked account ID** from the event payload, never the payer — solving the root problem that built-in CAD deep links only work in the originating account.

---

## How it works

**In one minute**: an anomaly fires in the payer. EventBridge matches it, drops it on SNS, the Lambda extracts the linked account ID (e.g. `123456789012`), looks up that account's `WorkloadOwner` tag via `organizations:ListTagsForResource`, finds the routing row for that tag value (say `platform-team`), builds a card with two buttons pointing into `123456789012`'s Cost Explorer (not the payer's), writes the card JSON to S3, and POSTs it to the Teams Workflows URL for `#cost-alerts-platform`. The platform admin sees a Teams card with a FactSet showing what, where, when, and how much, and clicks a button that takes them straight into their own account's filtered Cost Explorer view. No payer access required.

---

## Features

- Four AWS cost signals wired in out of the box (via three delivery mechanisms — see [Event sources wired in](#event-sources-wired-in)), extensible by adding a normalizer plus either an EventBridge rule (for genuine EventBridge sources) or a scheduled pull.
- Per-account-tag routing to different Teams channels (shared account? pick the workload-owner tag that matches the driving workload).
- **1-click deep links into the linked account** via IAM Identity Center portal URL and/or direct console URL.
- Dollar-impact suppression per routing target (`min_dollar_impact` per row).
- Dual sink: S3 archive (always) + Teams webhook (optional) — gives you UAT-from-day-one and clean audit.
- Severity mapping (info/warning/critical) drives card coloring consistently across event types.
- No external Python dependencies in the Lambda — stdlib + boto3 (Lambda-provided).
- Fully Terraform-managed; `terraform destroy` removes every resource.
- Graceful degradation: non-Organizations accounts, missing tags, missing webhooks all handled without failing the pipeline.

---

## Event sources wired in

All four sources are implemented and tested offline against **real-shape** AWS
payloads. They do **not** all arrive the same way: AWS only emits two of them as
EventBridge service events. AWS Budgets publishes plain text directly to SNS, and
Cost Optimization Hub emits nothing — it must be pulled on a schedule. The table
below describes the **real** mechanism for each.

| Source | Delivery mechanism | Trigger | Requirements |
|---|---|---|---|
| **Cost Anomaly Detection** (`event_type=cost_anomaly`) | EventBridge rule (`source=aws.ce`, `detail-type="Anomaly Detected"`) → SNS topic → Lambda (**push**). | A monitor detects an anomaly; CAD emits the EventBridge event automatically. | At least one Cost Anomaly Detection monitor enabled in the payer. |
| **AWS Budgets** (`event_type=budget_threshold`) | Budgets publishes a **plain-text** alert **directly to the SNS topic** → Lambda (**push**). Budgets does **not** emit threshold events to EventBridge, so there is no EventBridge rule; the Lambda parses the human-readable text body. | A budget's alert threshold is breached (ACTUAL or FORECASTED). | The customer must point their budget's SNS notification at this topic — use the `budgets_sns_topic_arn` output. See [Wiring AWS Budgets](#wiring-aws-budgets-to-the-topic). |
| **Trusted Advisor** (`event_type=trusted_advisor_cost_check`) | EventBridge rule (`source=aws.trustedadvisor`, `detail-type="Trusted Advisor Check Item Refresh Notification"`, filtered on `detail.status ∈ {WARN, ERROR}` **and** `detail.check-name ∈ var.trusted_advisor_cost_checks`) → SNS topic → Lambda (**push**). | A cost-optimizing check refreshes into a WARN/ERROR state (e.g. low-utilization EC2, idle RDS). | Business or Enterprise Support (Trusted Advisor cost checks are gated by support tier). |
| **Cost Optimization Hub** (`event_type=cost_optimization_recommendation`) | **NOT event-driven.** An **EventBridge Scheduler** (`var.coh_pull_schedule`, default `rate(1 day)`) invokes the Lambda **directly** with `{"coh_pull": true}`; the Lambda then calls `cost-optimization-hub:ListRecommendations` and routes each recommendation (**pull**). COH emits no recommendation events to EventBridge, so there is no EventBridge rule. | The daily schedule fires (cadence is configurable — set `coh_pull_schedule` to any `rate()`/`cron()` expression). | Cost Optimization Hub enabled at the organization level. |

> **Why three mechanisms?** Per AWS, only Cost Anomaly Detection and Trusted
> Advisor publish the cost signals this pipeline needs to EventBridge. AWS Budgets
> reaches EventBridge only as `AWS API Call via CloudTrail` (management calls,
> not threshold breaches) and delivers threshold alerts via SNS/email/Chatbot as
> plain text. Cost Optimization Hub likewise reaches EventBridge only via
> CloudTrail and has no recommendation event, so recommendations are obtained by
> a scheduled `ListRecommendations` pull. (Citations: [AWS Budgets EventBridge ref](https://docs.aws.amazon.com/eventbridge/latest/ref/events-ref-budgets.html), [real Budgets SNS plain-text body](https://aws.amazon.com/blogs/messaging-and-targeting/establishing-finops-management-integrating-aws-budgets-with-whatsapp-using-aws-end-user-messaging), [Cost Optimization Hub EventBridge ref](https://docs.aws.amazon.com/eventbridge/latest/ref/events-ref-cost-optimization-hub.html), [Trusted Advisor EventBridge ref](https://docs.aws.amazon.com/eventbridge/latest/ref/events-ref-trustedadvisor.html), [Cost Anomaly Detection + EventBridge](https://docs.aws.amazon.com/cost-management/latest/userguide/cad-eventbridge.html).)

Adding a fifth EventBridge source is: write a new normalizer function in
`normalizers.py`, add an entry to `local.event_rules` in `terraform/main.tf`, and
re-apply. A non-EventBridge source (like the COH pull) instead adds a scheduled
or SNS-native entrypoint plus its normalizer.

---

## Repository layout

```
cost-events-to-teams/
├── README.md                       this file
├── terraform/
│   ├── versions.tf                 providers, versions
│   ├── variables.tf                all tunables
│   ├── main.tf                     stack (S3, DDB, SNS, Lambda, EB rules, IAM, SSM)
│   └── outputs.tf                  names/ARNs for scripts + simulator
├── lambda/cost_router/
│   ├── handler.py                  entrypoint (SNS → process)
│   ├── normalizers.py              per-source → common shape
│   ├── routing.py                  Organizations + DynamoDB lookup
│   ├── links.py                    SSO + direct URL builders
│   ├── card_builder.py             Adaptive Card v1.5 assembly
│   └── sinks.py                    S3 + Teams webhook POST
├── simulator/
│   └── teams_receiver.py           local terminal renderer
├── tests/
│   ├── synthetic_events/*.json     one fixture per event type
│   └── send_test_event.sh          direct-invoke tester
└── scripts/                        (reserved for future ops tooling)
```

---

## Configuration & deployment (start here)

This is the end-to-end guide a brand-new user can follow start to finish. Do the
steps **in order**. Steps 1–4 stand up the pipeline and turn on Teams delivery;
step 5 wires whichever of the four event sources you want; steps 6–7 prove it
works. Throughout, replace placeholders like `your-profile`, `123456789012`, and
`your-portal.awsapps.com` with your own values.

**Prerequisites:**
- Terraform ≥ 1.5 (tested on 1.5.7).
- AWS CLI configured for the **payer** account. The provider profile is
  caller-supplied via the `aws_profile` variable (default `""`, which uses the
  default credential chain — env vars, SSO, or an instance role).
- `jq`, `uv` (for the local simulator), and a standard `bash` shell.
- A Microsoft Teams team/channel where you can create a Workflow, plus
  permission to run Power Automate "Workflows" in your tenant.

### Step 1 — Deploy the Terraform stack

```bash
cd terraform
terraform init

# Review the plan (optional but recommended)
terraform plan \
  -var aws_profile=your-profile \
  -var region=us-east-1

# Apply
terraform apply \
  -var aws_profile=your-profile \
  -var region=us-east-1 \
  -var workload_owner_tag_key=WorkloadOwner \
  -var sso_portal=your-portal.awsapps.com \
  -var sso_role=ReadOnlyAccess
```

> **SSO portal hostname is stored in SSM, not a Lambda env var (Talos a1e659fa).**
> `-var sso_portal=...` is **opt-in**. When set, Terraform creates the SSM
> parameter `/cost-events/config/sso-portal` (a `String`) with that value, and the
> Lambda reads it at runtime via `routing.get_sso_portal()`. The hostname is **not**
> placed in the function's environment — only the parameter *name* is. Leave
> `sso_portal` empty (the default) to emit direct-console links only and create no
> parameter. To set or rotate the hostname out-of-band later (without re-applying),
> use the AWS CLI:
>
> ```bash
> aws ssm put-parameter \
>   --name /cost-events/config/sso-portal \
>   --type String \
>   --value your-portal.awsapps.com \
>   --overwrite
> ```
>
> The change is picked up within the runtime cache TTL (default 300s).

`aws_profile` defaults to `""` (the default credential chain); pass it only if
you use a named profile. All variables and their defaults are listed under
[Variables](#variables).

When the apply completes, capture the outputs you will need below:

```bash
terraform output sns_topic_arn          # the topic Budgets/EventBridge publish to
terraform output budgets_sns_topic_arn  # same ARN, Budgets-oriented alias (AWS-1)
terraform output webhook_ssm_param      # the seeded default SSM webhook parameter name
terraform output routing_table          # DynamoDB routing table name
terraform output lambda_name            # the router Lambda function name
terraform output log_group              # CloudWatch log group
terraform output dlq_url                # SQS dead-letter queue URL
terraform output coh_pull_schedule_name # the EventBridge Scheduler that pulls COH (AWS-2)
```

The S3 archive bucket uses `force_destroy = true` so `terraform destroy` removes
archived events with the stack; flip it to `false` in `main.tf` for a production
payer deployment.

### Step 2 — Create the Teams Workflows webhook

Microsoft **retired** the classic Office 365 "Incoming Webhook" connector
(end-of-life 2025). The supported path is **Power Automate "Workflows"**. Create
one webhook per Teams channel you want to alert:

1. Open the target Teams **channel**, click the **⋯** (More options) next to the
   channel name, and choose **Workflows**.
2. Choose the template **"Post to a channel when a webhook request is
   received"**.
3. Sign in / confirm the connection if prompted, then pick the **team** and
   **channel** the alerts should post to. Give the flow a recognizable name (for
   example `cost-alerts-platform`) and select **Create flow**.
4. Copy the generated **HTTP POST URL**. This is the webhook the Lambda will POST
   to.

> **The webhook URL is a secret.** Anyone who knows it can post to that channel.
> Treat it like a credential — store it only in SSM (next step), never in source
> control, and never in logs.
>
> **Add a co-owner.** The Workflow is owned by the Teams *user* who created it,
> not by a service. If that user leaves the organization the flow stops. Add a
> co-owner so delivery survives staff changes.

The prebuilt "Post to a channel when a webhook request is received" template
already posts the Adaptive Card from the request body, so no extra mapping is
needed for the default flow. (If you build a *custom* flow instead, add a "Post
card in a chat or channel" / "Post adaptive card" action that reads the card from
`attachments[0].content`.) Microsoft docs:
[Post a workflow when a webhook request is received](https://support.microsoft.com/en-us/office/post-a-workflow-when-a-webhook-request-is-received-in-microsoft-teams-8ae491c7-0394-4861-ba59-055e33f75498)
and [Send Adaptive Cards using an Incoming Webhook](https://learn.microsoft.com/en-us/microsoftteams/platform/webhooks-and-connectors/how-to/connectors-using).

### Step 3 — Store the webhook URL in SSM Parameter Store

The Lambda reads the webhook URL from an **SSM SecureString** parameter at POST
time — the URL is never an environment variable and is never logged. The Lambda
role can read only parameters under the path **`/cost-events/webhook/*`** (see
[Security + IAM](#security--iam)), so your parameter name **must** start with
that prefix.

`terraform apply` already created one placeholder SecureString parameter for the
default channel: **`/cost-events/webhook/test-aws-notify`** (value
`PLACEHOLDER-replace-with-teams-workflows-url`, encrypted with the project's
customer-managed KMS key). Overwrite it — or create an additional parameter per
channel — with the real URL from step 2:

```bash
aws ssm put-parameter \
  --profile your-profile \
  --region us-east-1 \
  --name /cost-events/webhook/test-aws-notify \
  --type SecureString \
  --key-id "alias/cost-events-123456789012" \
  --overwrite \
  --value "https://prod-NN.westus.logic.azure.com:443/workflows/.../triggers/manual/paths/invoke?..."
```

Notes:
- `--type SecureString` encrypts the value at rest. `--key-id` selects the KMS
  key; use the project's customer-managed key alias
  (`alias/<name_prefix>-<account-id>`, e.g. `alias/cost-events-123456789012`) so
  the Lambda's `kms:Decrypt` grant covers it. If you omit `--key-id` AWS uses the
  account default `alias/aws/ssm` instead — the Lambda's KMS grant is scoped to
  the project key, so prefer the project key.
- For an **additional** channel, pick a new name under the same prefix, e.g.
  `/cost-events/webhook/cost-alerts-platform`, and reference that exact name in
  the routing row (step 4).
- The placeholder is protected by `ignore_changes = [value]` in Terraform, so
  setting the real URL out-of-band here will **not** be reverted on the next
  `terraform apply`.

### Step 4 — Configure routing (tags → channels)

Routing maps an account's **`WorkloadOwner` tag value** to a Teams channel. The
mapping lives in the DynamoDB routing table; each row has:

| Field | Type | Meaning |
|---|---|---|
| `tag_value` | S | The `WorkloadOwner` tag value to match (or `__default__` for the catch-all). |
| `team_name` | S | Friendly channel/team label shown on the card and used in the S3 key. |
| `webhook_ssm_param` | S | The **exact** SSM parameter name from step 3 (must start with `/cost-events/webhook/`). |
| `min_dollar_impact` | N | Suppress events whose dollar impact is below this value (0 = never suppress). |

Seed rows at deploy time with the **`routing_seed`** variable (the default seeds a
single `__default__` row pointing at `/cost-events/webhook/test-aws-notify`), or
add/update rows out-of-band (see [Adding workload-owner channels](#adding-workload-owner-channels)).

Concrete example — route the `platform-team` workload to its own channel and keep
a catch-all:

```hcl
# in a .tfvars file or -var 'routing_seed=...'
routing_seed = [
  {
    tag_value         = "__default__"
    team_name         = "test-aws-notify"
    webhook_ssm_param = "/cost-events/webhook/test-aws-notify"
    min_dollar_impact = 0
  },
  {
    tag_value         = "platform-team"
    team_name         = "cost-alerts-platform"
    webhook_ssm_param = "/cost-events/webhook/cost-alerts-platform"
    min_dollar_impact = 100
  },
]
```

At runtime the Lambda looks up the linked account's `WorkloadOwner` tag via
`organizations:ListTagsForResource`, finds the matching row, and falls back to
`__default__` when there is no tag or no match. Accounts outside Organizations
fall back cleanly too.

### Step 5 — Wire each event source

The four sources reach the Lambda by three mechanisms (full detail in
[Event sources wired in](#event-sources-wired-in)). After the stack is deployed:

- **Cost Anomaly Detection** — no extra wiring. The EventBridge rule is created by
  Terraform; just confirm at least one anomaly **monitor** exists in the payer
  (Billing & Cost Management → Cost Anomaly Detection).
- **Trusted Advisor** — no extra wiring. The EventBridge rule is created by
  Terraform and matches cost checks in `WARN`/`ERROR` against the
  `trusted_advisor_cost_checks` allow-list. Requires **Business or Enterprise
  Support**.
- **AWS Budgets** — **one manual step**: point your budget's SNS notification at
  the topic ARN from `terraform output budgets_sns_topic_arn`. See
  [Wiring AWS Budgets to the topic](#wiring-aws-budgets-to-the-topic). Budgets
  sends a **human-readable plain-text** alert (not JSON); the Lambda parses it.
- **Cost Optimization Hub** — no extra wiring. The EventBridge **Scheduler**
  created by Terraform (`coh_pull_schedule_name`) invokes the Lambda daily by
  default. Change the cadence with `var.coh_pull_schedule` (any `rate()`/`cron()`
  expression). Requires COH enabled at the org level.

### Step 6 — Send a test event

Fire a synthetic event through the **whole** Lambda pipeline (normalize → route →
card → S3 → optional Teams POST). The helper wraps the fixture in the exact SNS
envelope the Lambda receives:

```bash
AWS_PROFILE=your-profile ./tests/send_test_event.sh cost_anomaly
# also available: budget_threshold
```

> The `send_test_event.sh` harness exercises the SNS-delivered sources (Cost
> Anomaly Detection and the Budgets plain-text path). Trusted Advisor and Cost
> Optimization Hub are validated by the offline pytest suite
> (`uv run pytest`) and, in a live account, by their own triggers (a TA check
> refresh and the daily COH Scheduler). To force a COH pull on demand in a live
> account, invoke the Lambda directly with `{"coh_pull": true}`.

### Step 7 — Verify delivery

A successful Teams delivery looks like this:

- **Teams Workflows returns `202 Accepted`** on the POST. The Lambda treats any
  `2xx` as success and logs `teams POST status=202`. The card appears in the
  channel as an Adaptive Card with a severity-colored title, a FactSet, and the
  action button(s).
- **S3 always has the card**, even if Teams is not yet wired: look under
  `events/<event_type>/<team>/YYYY/MM/DD/HH/MMSS-<n>.json` in the archive bucket
  (`terraform output event_bucket`). You can also render it locally with the
  [simulator](#local-uat-with-the-simulator).

If nothing arrives in Teams:

1. **Check the Lambda logs** — `terraform output log_group` (or
   `/aws/lambda/<lambda_name>`). Look for `teams POST status=...`,
   `webhook param ... is placeholder; skipping POST` (you didn't set the real URL
   in step 3), or `no webhook_ssm_param for ...` (the routing row has no webhook).
2. **Check the DLQ** — `terraform output dlq_url`. Terminal failures (after SNS
   retries) land here, because per-record errors now propagate (they are no
   longer swallowed). A non-empty DLQ means the invocation raised — inspect the
   message and the correlated log entry.
3. **Check the card shape on a 4xx** — Teams rejects a malformed envelope with
   `4xx`. The archived S3 JSON must be
   `{"type":"message","attachments":[{"contentType":"application/vnd.microsoft.card.adaptive","content":{...}}]}`.
   Keep the serialized card under the **28 KB** Incoming-Webhook payload limit
   (this card is far smaller). See
   [Format cards](https://learn.microsoft.com/en-us/microsoftteams/platform/task-modules-and-cards/cards/cards-format).

---

## Variables

All in [`terraform/variables.tf`](terraform/variables.tf):

| Variable | Default | Purpose |
|---|---|---|
| `aws_profile` | `""` | Named profile for the AWS provider. Empty uses the default credential chain (env vars, SSO, instance role). |
| `owner` | `""` | Value for the `Owner` default tag. Empty leaves the tag value blank. |
| `region` | `us-east-1` | Deploy region. Cost Anomaly events land here. |
| `name_prefix` | `cost-events` | Prefix for every resource name (e.g. KMS alias `alias/<name_prefix>-<account-id>`). |
| `workload_owner_tag_key` | `WorkloadOwner` | Account-level tag key consulted for routing. |
| `sso_portal` | `""` | IAM Identity Center portal hostname (e.g. `your-portal.awsapps.com`). Opt-in: when set, the value is stored in the SSM parameter `/cost-events/config/sso-portal` (read at runtime) — **not** in a Lambda env var (Talos a1e659fa). Empty disables the SSO button and creates no parameter. |
| `sso_role` | `ReadOnlyAccess` | Permission-set name used when wrapping URLs in the SSO portal link. |
| `reserved_concurrency` | `5` | Lambda reserved concurrency cap. Bounds invocation rate. |
| `routing_seed` | one `__default__` row → `/cost-events/webhook/test-aws-notify` | List of routing rows seeded into DynamoDB on apply. Each row: `tag_value`, `team_name`, `webhook_ssm_param`, `min_dollar_impact`. |
| `coh_pull_schedule` | `rate(1 day)` | EventBridge Scheduler cadence for the Cost Optimization Hub `ListRecommendations` pull (**AWS-2**). Accepts any `rate()` or `cron()` expression. |
| `trusted_advisor_cost_checks` | 11 documented cost-optimizing TA check names | Allow-list of `detail.check-name` values the Trusted Advisor EventBridge rule forwards (**AWS-3**), combined with `detail.status ∈ {WARN, ERROR}`. Override to narrow/extend without code changes. |

**Outputs** (in [`terraform/outputs.tf`](terraform/outputs.tf)): `event_bucket`,
`sns_topic_arn`, `lambda_name`, `routing_table`, `webhook_ssm_param`,
`log_group`, `dlq_url`, plus `coh_pull_schedule_name` (the COH pull schedule,
AWS-2) and `budgets_sns_topic_arn` (the topic ARN to wire your budget's SNS
notification at, AWS-1).

---

## Wiring AWS Budgets to the topic

AWS Budgets does **not** emit threshold events to EventBridge — it delivers
threshold alerts to **SNS as plain text** (or email/Chatbot). This pipeline
therefore ingests Budgets natively over SNS: the topic policy already authorizes
`budgets.amazonaws.com` to publish, and the topic's customer-managed KMS key
grants Budgets the data-key access it needs. You only have to point a budget's
SNS notification at the topic.

1. Get the topic ARN:

   ```bash
   terraform output -raw budgets_sns_topic_arn
   # e.g. arn:aws:sns:us-east-1:123456789012:cost-events-123456789012-topic
   ```

2. On an **existing or new budget** (Billing & Cost Management → Budgets), add an
   **alert** and choose **Amazon SNS topic** as a notification target, pasting the
   ARN above. (Equivalent CLI: set the budget's `Notification` +
   `Subscriber` of type `SNS` to this ARN via `aws budgets
   create-notification`.) No EventBridge rule is involved.

3. When the threshold breaches, Budgets publishes a human-readable body like:

   ```
   AWS Budget Notification May 04, 2026
   AWS Account 123456789012
   ...
   Budget Name: example-prod-monthly
   Budget Type: Cost
   Budgeted Amount: $40,000.00
   Alert Type: ACTUAL
   Alert Threshold: > $40,000.00
   ACTUAL Amount: $42,500.00
   ```

   `handler._extract` detects this non-JSON body and routes it to the Budgets
   plain-text parser, which extracts the name/account/amounts and emits a
   `budget_threshold` card. (Citation:
   [real Budgets SNS plain-text body](https://aws.amazon.com/blogs/messaging-and-targeting/establishing-finops-management-integrating-aws-budgets-with-whatsapp-using-aws-end-user-messaging).)

---

## Adding workload-owner channels

To add a channel after the initial deploy (the out-of-band equivalent of
seeding it via `routing_seed`):

1. Create the Teams channel, create its Workflows webhook, and store the URL in
   SSM — [Step 2](#step-2--create-the-teams-workflows-webhook) and
   [Step 3](#step-3--store-the-webhook-url-in-ssm-parameter-store) above.
2. Add a row to the routing table (table name from
   `terraform output routing_table`):

   ```bash
   aws dynamodb put-item --profile your-profile \
     --table-name cost-events-123456789012-routing \
     --item '{
       "tag_value":         {"S": "platform-team"},
       "team_name":         {"S": "cost-alerts-platform"},
       "webhook_ssm_param": {"S": "/cost-events/webhook/cost-alerts-platform"},
       "min_dollar_impact": {"N": "100"}
     }'
   ```

3. Ensure member accounts in that workload carry the account tag `WorkloadOwner=platform-team` (Organizations → Accounts → Tags).

Accounts whose tag doesn't match any row fall back to `__default__`. Accounts outside Organizations, or without tags, also fall back cleanly.

### Teardown

```bash
terraform -chdir=terraform destroy -var aws_profile=your-profile
```

The S3 archive bucket uses `force_destroy = true`, so archived events are deleted
with the stack. Flip that to `false` in [`terraform/main.tf`](terraform/main.tf)
for a production payer deployment so the audit archive survives a `destroy`.

---

## Local UAT with the simulator

The simulator reads the exact card JSON the Lambda wrote to S3 and renders it to your terminal as it would appear in Teams (severity colors, FactSet, action buttons + URLs).

```bash
# fire any fixture through the full Lambda pipeline
./tests/send_test_event.sh cost_anomaly
./tests/send_test_event.sh budget_threshold
./tests/send_test_event.sh cost_optimization_hub
./tests/send_test_event.sh trusted_advisor

# render
AWS_PROFILE=your-profile uv run --with boto3 python simulator/teams_receiver.py           # today
AWS_PROFILE=your-profile uv run --with boto3 python simulator/teams_receiver.py --tail    # live follow
AWS_PROFILE=your-profile uv run --with boto3 python simulator/teams_receiver.py --all     # everything

# render a single local JSON file, no AWS call
uv run --with boto3 python simulator/teams_receiver.py --file some-card.json
```

`--tail` polls S3 every 5 seconds for new objects and prints them as they arrive. Useful during a demo — fire a fixture in one terminal, watch the render in another.

---

## Operating in a real payer account

Everything above was designed for deploy into a payer. The one consideration:

- **Organizations `ListTagsForResource`** requires the Lambda to be running *inside* the Organizations master account, or in a delegated-admin account with the appropriate IAM setup. In a standalone sandbox it fails cleanly (tag lookup returns `None`, routing falls through to `__default__`).
- **SNS topic policy** grants publish to `events.amazonaws.com` (EventBridge — Cost Anomaly / Trusted Advisor), `costalerts.amazonaws.com` (Cost Anomaly Detection's direct SNS delivery path), and `budgets.amazonaws.com` (AWS Budgets' native plain-text notifications — AWS-1). The `aws:SourceAccount` condition keeps all three scoped to the deploying account.
- **EventBridge rules** are on the default bus. If the payer already routes these sources elsewhere, add additional targets rather than replace — EventBridge supports up to 5 targets per rule.
- **Cost Optimization Hub pull** runs on the EventBridge Scheduler (`coh_pull_schedule_name`). If you operate in multiple Regions, COH `ListRecommendations` is an account-wide aggregation reached from `us-east-1`; one schedule in the deploy Region is sufficient.

---

## Projected AWS cost for ~150 accounts

Assumes a typical payer org with 150 linked accounts, broad CAD coverage, budgets on the top 30 accounts, and Cost Optimization Hub + Trusted Advisor enabled.

### Event volume assumptions

| Source | Events/day (est.) | Delivery | Notes |
|---|---|---|---|
| Cost Anomaly Detection | 5–15 | EventBridge → SNS → Lambda | CAD aggregates and sends ~daily; spikes during migration months |
| Budgets | 2–10 | Budgets → SNS → Lambda (plain text) | Driven by threshold breaches; correlates with MTD |
| Cost Optimization Hub | 1–5 recommendations | Daily scheduled pull (1 invocation/day; each pull may route several recommendations) | The Scheduler fires once/day (`rate(1 day)`) ≈ **30 invocations/month**; recommendation *volume* is what produces cards |
| Trusted Advisor (cost) | 5–20 | EventBridge → SNS → Lambda | Refreshes weekly + on-demand; higher on check-refresh days |
| **Total** | **~13–50 cards/day**, peak ~100/day during migrations, **plus ~30 scheduled COH pull invocations/month** |

Plan to ~**1,500 routed events/month** (cards) plus the **~30 daily COH-pull Lambda
invocations** as a working estimate.

### Per-component cost

Prices below are **AWS list / on-demand rates for US East (N. Virginia) — `us-east-1`**, as of **2026-06-09**. They are list prices and are **subject to change**; always confirm against the live AWS pricing pages for your Region before relying on them. Per-unit prices are shown with full precision (not rounded to the cent) so that genuinely tiny non-zero rates do not collapse to `$0.00`. The "Monthly cost" column is the **list-price** cost computed from the stated volume (~1,500 routed events/month plus the ~30 daily COH-pull invocations); see the free-tier note below for why the *effective* bill is even lower.

The volumes below include the **Phase-3 additions**: the daily **EventBridge Scheduler** that drives the Cost Optimization Hub pull (~30 invocations/month), the resulting ~30 extra Lambda invocations, and the `cost-optimization-hub:ListRecommendations` calls. They are all negligible but are represented honestly rather than omitted.

Source pricing pages: [Lambda](https://aws.amazon.com/lambda/pricing/) · [SNS](https://aws.amazon.com/sns/pricing/) · [DynamoDB](https://aws.amazon.com/dynamodb/pricing/) · [S3](https://aws.amazon.com/s3/pricing/) · [CloudWatch (Logs)](https://aws.amazon.com/cloudwatch/pricing/) · [KMS](https://aws.amazon.com/kms/pricing/) · [EventBridge + Scheduler](https://aws.amazon.com/eventbridge/pricing/) · [Systems Manager (Parameter Store)](https://aws.amazon.com/systems-manager/pricing/) · [Cost Optimization Hub](https://aws.amazon.com/aws-cost-management/cost-optimization-hub/) (no charge for the service/API).

| Component | Monthly volume | Unit cost (list price, `us-east-1`) | Monthly cost (at list price) |
|---|---|---|---|
| EventBridge (default bus, custom rules) | ~1,500 events | AWS-service-source events on the default bus are **free** ($0.00/event); custom events would be $1.00/M = $0.000001/event | **$0.00** (free, not a rounding artifact) |
| EventBridge **Scheduler** (COH daily pull) | ~30 invocations | First 14,000,000 scheduler invocations/month **free**; thereafter $1.00/M = $0.000001/invocation | **$0.00** (free at this volume) |
| SNS (Standard, Lambda subscription) | ~1,500 requests | $0.50/M = **$0.0000005/request**; first 1M requests/month free; SNS→Lambda delivery is free | **$0.00075** |
| Lambda invocations (SNS-driven) | ~1,500 | $0.20/M = **$0.0000002/request**; first 1M requests/month free | **$0.00030** |
| Lambda invocations (COH daily pull) | ~30 | $0.20/M = **$0.0000002/request**; first 1M requests/month free | **$0.000006** |
| Lambda duration | ~1,530 × ~200 ms × 256 MB ≈ 76.5 GB-s | **$0.0000166667/GB-s**; first 400,000 GB-s/month free | **$0.00128** |
| DynamoDB (on-demand / PAY_PER_REQUEST) | ~1,500 read request units, ~0 writes post-seed | $0.125/M reads = **$0.000000125/RRU**; $0.625/M writes = $0.000000625/WRU (50% lower since 2024-11-01) | **$0.00019** |
| Cost Optimization Hub `ListRecommendations` | ~30 calls (1/day) | Cost Optimization Hub has **no service or API charge** | **$0.00** (free) |
| S3 PUT | ~1,500 | $0.005/1,000 PUTs = **$0.000005/PUT** | **$0.00750** |
| S3 storage | ~1,500 × 3 KB × 90-day retention ≈ 0.014 GB-months | **$0.023/GB-month** | **$0.00032** |
| S3 GET (simulator usage) | ~500/month est. | $0.0004/1,000 GETs = **$0.0000004/GET** | **$0.00020** |
| SSM SecureString (standard parameters) | 1 per channel | Standard parameters & standard-throughput API are **free** (≤10,000 standard params) | **$0.00** (free) |
| SSM `GetParameter` (1 per event) | ~1,500 | Standard throughput is **free**; advanced/higher-throughput would be $0.05/1,000 = $0.00005/call | **$0.00** (free at standard throughput) |
| CloudWatch Logs ingest | ~1,530 × 1 KB ≈ 0.00149 GB | $0.50/GB ingest (Standard log class); first 5 GB/month free | **$0.00075** |
| CloudWatch Logs storage | ~0.0015 GB/mo accruing under **365-day** retention ≈ ≤0.018 GB-months at year-end | **$0.03/GB-month** | **$0.00005** (rising to ~$0.0005 after a full year of retention) |
| KMS — customer-managed key (CMK) **monthly fee** | 1 CMK (encrypts S3, DynamoDB, SNS, SSM, Lambda env, Logs) | **$1.00/customer-managed key/month** (flat); rotation included at no extra key fee | **$1.00** |
| KMS requests (Decrypt / GenerateDataKey across all CMK uses) | ~5,000 (SSM decrypt, S3/DDB/SNS/Logs data keys) | $0.03/10,000 requests = **$0.000003/request**; first 20,000 requests/month free | **$0.00** (within free request allowance) |
| **Total (at list price, before AWS Free Tier credits)** | | | **≈ $1.02/month** |

**The dominant line is the customer-managed KMS key (CMK) flat fee of $1.00/month.** This is a deliberate security choice (TF-4): every stateful resource is encrypted with one project CMK rather than the no-monthly-fee AWS-managed keys. It buys key-policy control, rotation, and a single audit point; the trade-off is the flat $1.00/key/month.

**Free-tier reality:** SNS, Lambda (requests + duration), EventBridge + Scheduler, CloudWatch Logs ingest, KMS *requests*, and the SSM lines all fall within the AWS Always-Free or 12-month free-tier allowances at this volume. Cost Optimization Hub itself is free. So beyond the **$1.00 CMK fee**, the only charges that persist in steady state are the three S3 lines (~$0.008/month combined) plus negligible DynamoDB. **Effective steady-state cost is ~$1.01/month, essentially all of it the CMK.**

**Realistic steady-state: ~$1/month (the CMK), even if event volume grows 10×** — the per-event lines stay within free tier far past 10× this volume.

Cost risks to watch:
- **Lambda duration** if you add expensive enrichment (Cost Explorer API calls at $0.01/call can add up fast — 1,500 calls/month = $15). If you wire CE enrichment in later, cache aggressively at the Lambda level (DynamoDB or Lambda `/tmp`).
- **CloudWatch Logs** if someone bumps logging to DEBUG and leaves it. Current INFO level at ~1 KB/invoke keeps this negligible; note the **365-day** retention means log storage slowly accrues over a year (still pennies at this volume).
- **S3 storage** if lifecycle expiration is extended beyond 90 days without compression — still pennies.
- **Additional CMKs** — adding separate keys per service would add $1.00/key/month each. This sample deliberately uses one shared CMK.

**Not a meaningful line item on the bill beyond the $1.00 CMK fee.** The only non-trivial variable is if you later add Cost Explorer enrichment per event, in which case rate-limit + cache.

---

## Security + IAM

Lambda execution role (least privilege):

- `s3:PutObject` on the archive bucket (objects only, no list/delete).
- `dynamodb:GetItem` on the routing table (no write — routing rows are managed via Terraform or deliberate out-of-band updates).
- `ssm:GetParameter` on `/cost-events/webhook/*` (SecureString requires KMS decrypt on the project's customer-managed key, granted via the `UseKmsKey` statement).
- `organizations:ListTagsForResource` on `*` — Organizations APIs don't support resource-level scoping for account tags.
- `cost-optimization-hub:ListRecommendations` on `*` — the scheduled COH pull (AWS-2); the API is an account-wide aggregation with no resource-level scoping. This is the only COH action granted (no `GetRecommendation`).
- `sqs:SendMessage` on the dead-letter queue (terminal-failure capture).
- `kms:Decrypt`/`GenerateDataKey`/`Encrypt`/`DescribeKey` on the project's customer-managed key only (`UseKmsKey`).
- `logs:CreateLogStream`, `logs:PutLogEvents` via the managed `AWSLambdaBasicExecutionRole`.

No Lambda egress to anything other than the Teams Workflows URL (stored as SecureString) and AWS service endpoints.

The SNS topic policy allows `sns:Publish` only from `events.amazonaws.com`, `costalerts.amazonaws.com`, and `budgets.amazonaws.com` (AWS-1), each with an `aws:SourceAccount` condition scoped to the deploying account. The EventBridge Scheduler invokes the Lambda through a dedicated role whose inline policy grants `lambda:InvokeFunction` on **only** the router function.

S3 bucket: public access fully blocked, **`aws:kms` SSE with the project's customer-managed KMS key (CMK)**, TLS-only bucket policy, 90-day lifecycle.

---

## Troubleshooting

**Simulator shows nothing.** Make sure events have been fired today, or use `--all`. Check `AWS_PROFILE` is set to the deploy profile.

**Lambda returns `ok: false, reason: unhandled_source`.** The event's `source` isn't in the normalizer dispatch. Add a handler in `normalizers.py`.

**`list_tags_for_resource failed ... TargetNotFoundException`**. Expected when running in a non-Organizations account or when the account ID in the event isn't an org member. Pipeline continues, routing falls through to `__default__`.

**`webhook param ... is placeholder; skipping POST`**. The SSM parameter still holds its placeholder value. Run `aws ssm put-parameter` (see [Step 3](#step-3--store-the-webhook-url-in-ssm-parameter-store)) with the real URL.

**Teams returns 4xx on POST.** The Workflows trigger format has changed recently. Inspect the archived S3 card JSON — it must be `{type: "message", attachments: [{contentType: "application/vnd.microsoft.card.adaptive", content: {...}}]}` (keep it under the 28 KB Incoming-Webhook limit). If MS updates the expected shape, adjust `card_builder.build_card`. A successful POST returns `202 Accepted`.

**Budgets alert never arrives.** Confirm the budget's SNS notification points at `budgets_sns_topic_arn` and that the alert actually breached. Budgets sends **plain text** (not JSON); the Lambda parses it via `normalizers._parse_budgets_sns_text`. A body without a `Budget Name:` line is logged as `non-json SNS message` and dropped.

**COH recommendations never arrive.** The daily EventBridge Scheduler (`coh_pull_schedule_name`) invokes the Lambda with `{"coh_pull": true}`; confirm Cost Optimization Hub is enabled at the org level and check the Lambda logs after the schedule fires. To test on demand, invoke the function directly with `{"coh_pull": true}`.

**Events disappear / land in the DLQ.** Per-record failures now propagate (they are no longer swallowed), so a failed record fails the invocation → SNS retries → terminal failures reach the SQS DLQ (`dlq_url`). A growing DLQ means processing is erroring — inspect a message and its correlated log entry.

**CloudWatch Logs empty.** Check `/aws/lambda/cost-events-<accountid>-router` log group in the same region (retention is **365 days**, encrypted with the project CMK). SNS → Lambda wiring requires both the subscription and the Lambda permission (both are in `main.tf`).

---

## Security posture

This sample applies a defense-in-depth baseline. **All stateful resources are
encrypted with a single customer-managed KMS key (CMK)** — `aws_kms_key.main`,
alias `alias/<name_prefix>-<account-id>`, with key rotation enabled — not the
AWS-managed default keys:

- **KMS** — One customer-managed CMK with rotation enabled encrypts S3, DynamoDB, SNS, the Lambda environment, the SSM SecureString, and the CloudWatch log group. The key policy grants data-key access to the SNS publishers (`events`, `costalerts`, `budgets`) and data-plane access to the Lambda role only.
- **S3** — Public access fully blocked, **`aws:kms` SSE with the CMK** (bucket-key enabled), bucket policy denies non-TLS requests (`aws:SecureTransport=true`), versioning on, 90-day lifecycle, server access logging to a separate bucket.
- **SNS** — Encrypted at rest with the **customer-managed CMK** (`kms_master_key_id = aws_kms_key.main.arn`). Topic policy restricts publishers to `events.amazonaws.com`, `costalerts.amazonaws.com`, and `budgets.amazonaws.com`, scoped by `aws:SourceAccount`.
- **DynamoDB** — Encrypted at rest with the **customer-managed CMK**; point-in-time recovery enabled. Lambda role has `GetItem` only; writes go through Terraform.
- **SSM SecureString** — Webhook URLs encrypted with the **customer-managed CMK** (`key_id = aws_kms_key.main.key_id`). Lambda role scoped to `/cost-events/webhook/*`.
- **Lambda** — No external Python dependencies. Reserved concurrency cap. SQS dead-letter queue for terminal failures (per-record errors propagate so the DLQ actually engages). X-Ray tracing enabled. CMK-encrypted environment variables. Inline IAM policy least-privilege per service interaction.
- **CloudWatch Logs** — **365-day retention**, encrypted with the **customer-managed CMK**. Log statements never include the webhook URL itself, only its SSM parameter name and the HTTP status code.

The full STRIDE-style threat model with 20 enumerated threats and their mitigations lives in [THREAT_MODEL.md](THREAT_MODEL.md). Update it whenever a change touches a trust boundary, IAM policy, or external dependency.

For production hardening beyond the sample baseline, customers should consider: Lambda code signing, GuardDuty Lambda Protection, AWS Config rules for the routing table and webhook parameter, and a CloudWatch alarm on Lambda errors and DLQ depth. (The customer-managed KMS key, TLS-only S3, PITR, and 365-day log retention are already part of this sample's baseline.)

## Handoff checklist

For any team picking this up:

- [ ] Clone the repo.
- [ ] Set `aws_profile` (pass `-var aws_profile=your-profile`, or leave empty for the default credential chain).
- [ ] Confirm `workload_owner_tag_key` matches your Organizations tagging standard.
- [ ] (Optional) Set `sso_portal` to your Identity Center portal hostname to enable 1-click SSO links — Terraform stores it in the SSM parameter `/cost-events/config/sso-portal` (not a Lambda env var; Talos a1e659fa). Leave empty for direct-console links only.
- [ ] Seed `routing_seed` with one row per workload owner.
- [ ] `terraform apply` ([Step 1](#step-1--deploy-the-terraform-stack)).
- [ ] For each channel: create the Teams Workflows webhook ([Step 2](#step-2--create-the-teams-workflows-webhook)), then `aws ssm put-parameter` the URL as a SecureString under `/cost-events/webhook/...` ([Step 3](#step-3--store-the-webhook-url-in-ssm-parameter-store)).
- [ ] Confirm Cost Anomaly Detection is enabled at the payer with at least one monitor (no extra wiring).
- [ ] Point each AWS Budget's SNS notification at `budgets_sns_topic_arn` ([Wiring AWS Budgets](#wiring-aws-budgets-to-the-topic)).
- [ ] Confirm Cost Optimization Hub is enabled at org level (the daily Scheduler `coh_pull_schedule_name` pulls it — adjust `coh_pull_schedule` if needed).
- [ ] Confirm Business or Enterprise Support for Trusted Advisor cost checks (no extra wiring; tune `trusted_advisor_cost_checks` if desired).
- [ ] Fire synthetic events via `./tests/send_test_event.sh` to verify end-to-end ([Step 6](#step-6--send-a-test-event)); confirm a `202` and the S3 archive / DLQ ([Step 7](#step-7--verify-delivery)).
- [ ] Walk the playbook with one workload-owner team before broad rollout.
