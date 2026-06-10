# Threat Model

This document captures the security threats considered for this sample and the
mitigations applied. It uses a STRIDE-aligned analysis (Spoofing, Tampering,
Repudiation, Information disclosure, Denial of service, Elevation of privilege).
It is a living artifact — when changes touch a trust boundary, IAM policy, or
external dependency, this file MUST be updated.

## System overview

This sample deploys a pipeline that consumes AWS cost-related signals (Cost
Anomaly Detection, AWS Budgets, Cost Optimization Hub, Trusted Advisor) in an
organization's payer account, fans them out through SNS to a Lambda router,
enriches them with account-tag-based routing, and posts Adaptive Cards to
Microsoft Teams via a Workflows webhook. Every processed card is also archived to
S3. The four signals arrive by **three** mechanisms (AWS does not emit them all
the same way): Cost Anomaly Detection and Trusted Advisor are EventBridge service
events (→ SNS → Lambda); AWS Budgets publishes plain-text alerts directly to the
SNS topic; and Cost Optimization Hub is obtained by a daily EventBridge Scheduler
that invokes the Lambda to call `ListRecommendations`.

### Components and trust boundaries

| Component | Trust zone | Notes |
|---|---|---|
| EventBridge default bus | AWS service | Receives only AWS-service-emitted events (`aws.*` source prefix). Reserved namespace; cannot be impersonated by IAM principals. |
| SNS topic | AWS service | Topic policy restricts publishers to `events.amazonaws.com`, `costalerts.amazonaws.com`, and `budgets.amazonaws.com` (AWS Budgets' native plain-text notifications), scoped by `aws:SourceAccount`. Encrypted at rest with the **customer-managed CMK** (`aws_kms_key.main`). |
| Lambda router | AWS service / customer code | Python 3.12, stdlib + boto3 only. Egress is to AWS service endpoints and the Teams Workflows URL. |
| DynamoDB routing table | AWS service | Encrypted at rest with the **customer-managed CMK**; point-in-time recovery enabled. Read-only from the Lambda role. Writes only via Terraform or a deliberate operator. |
| S3 archive bucket | AWS service | **`aws:kms` SSE with the customer-managed CMK** (bucket-key enabled), public access blocked, `aws:SecureTransport=true` enforced via bucket policy, versioning on, 90-day lifecycle, access logging to a separate bucket. |
| SSM Parameter Store (SecureString) | AWS service | Stores the Teams Workflows webhook URL. Encrypted with the **customer-managed CMK** (`key_id = aws_kms_key.main.key_id`). Lambda decrypts via its scoped `kms:Decrypt` grant. |
| EventBridge Scheduler | AWS service | Invokes the Lambda on a schedule (`var.coh_pull_schedule`, default `rate(1 day)`) with `{"coh_pull": true}` to drive the Cost Optimization Hub `ListRecommendations` pull. Assumes a dedicated role permitted to invoke only the router function. |
| KMS customer-managed key | AWS service | Single CMK (`aws_kms_key.main`, rotation enabled) encrypts S3, DynamoDB, SNS, SSM, Lambda env, and CloudWatch Logs. Key policy grants data-key access to the SNS publishers and data-plane use to the Lambda role only. |
| Microsoft Teams Workflows webhook | External (Microsoft) | URL is a bearer secret (knowledge of URL = ability to post). Treated as such throughout. |

### Data classification

- **Event payloads**: AWS account IDs, service names, region, usage type, dollar
  impact, account names, anomaly metadata. Considered AWS-account-internal,
  not regulated PII/PHI.
- **Webhook URL**: bearer secret. Disclosure allows arbitrary posting to the
  Teams channel, but does not grant Teams tenant access.

## Threats and mitigations

| ID | STRIDE | Threat | Mitigation | Evidence |
|---|---|---|---|---|
| T-01 | Spoofing | Unauthorized principal publishes forged events to the SNS topic, causing fake alerts in Teams. | SNS topic policy restricts `sns:Publish` to the `events.amazonaws.com`, `costalerts.amazonaws.com`, and `budgets.amazonaws.com` service principals with an `aws:SourceAccount` condition scoped to the deploying account. No IAM users/roles permitted to publish. | `terraform/main.tf` `data "aws_iam_policy_document" "sns_policy"` (statements `AllowEventBridge`, `AllowCostAnomalyDetection`, `AllowBudgetsPublish`) |
| T-02 | Spoofing | Lambda invoked directly by an unprivileged principal, bypassing SNS routing. | Lambda permission grants `lambda:InvokeFunction` only to `sns.amazonaws.com` constrained by the topic ARN. Operators with full Lambda invoke permission are intentional. | `aws_lambda_permission "sns"` |
| T-03 | Tampering | Routing table modified to redirect a workload owner's events to the wrong channel. | DynamoDB write permissions are NOT in the Lambda role — only Terraform / IAM-authorized operators may write. CloudTrail audits all PutItem calls. Recommend operators enable AWS Config rule `dynamodb-table-deletion-protection-enabled` and AWS CloudTrail data events for the routing table in production. | Lambda inline policy grants only `dynamodb:GetItem` |
| T-04 | Tampering | Webhook URL replaced in SSM with attacker-controlled URL, exfiltrating event metadata or pivoting via SSRF. | SSM Parameter is `SecureString`. `ssm:PutParameter` is NOT in the Lambda role. CloudTrail audits all parameter changes. **Defense-in-depth (Talos 51f0122b)**: even if the SSM value is tampered, `sinks.post_to_teams` validates the URL through `_is_allowed_webhook_url` before any HTTP call — requiring https AND a host on the Teams Workflows allow-list (`*.logic.azure.com`, `*.webhook.office.com`; extensible via `TEAMS_WEBHOOK_ALLOWED_HOSTS`) and rejecting IP-literal/metadata/loopback/RFC-1918/internal hosts — so a tampered value cannot redirect the POST to an attacker or internal endpoint. Recommend an EventBridge rule on `ssm.amazonaws.com:PutParameter` for `/cost-events/webhook/*`. | Lambda inline policy grants only `ssm:GetParameter`; `sinks._is_allowed_webhook_url`; `tests/unit/test_talos_sinks_ssrf.py` |
| T-05 | Repudiation | Operator changes routing without an audit trail. | All resource changes go through Terraform (state in source control) or AWS APIs (CloudTrail). No interactive write paths. | Terraform-managed; documented in README |
| T-06 | Information Disclosure | Webhook URL or internal detail leaked via Lambda logs, environment variables, or exception traces / responses. | URL is fetched from SSM at request time, never logged. `sinks.post_to_teams` logs only HTTP status code and parameter name (not value), including on the SSRF-rejection path. Lambda environment contains only the SSM *path*, not the URL. **Talos 5d523fa8**: per-record processing failures still propagate (CODE-1 → SNS retry / DLQ) but the handler re-raises a generic `EventProcessingError("Internal error processing event")` (`raise ... from None`); raw exception text/stack/internal paths are written only to CloudWatch via `log.exception`, never to the invocation response. **Talos a1e659fa**: the SSO portal hostname is no longer a plaintext env var by default — `WORKLOAD_SSO_PORTAL` is set only when a customer opts in (`var.sso_portal != ""`). | `lambda/cost_router/sinks.py`; `handler.EventProcessingError`; `terraform/main.tf` env `merge()`; `tests/unit/test_talos_handler.py` |
| T-07 | Information Disclosure | S3 archive readable by unauthorized parties. | Bucket has `BlockPublicAccess` (all four flags), **`aws:kms` SSE with the customer-managed CMK** (bucket-key enabled), versioning, and a bucket policy that denies any request not using TLS (`aws:SecureTransport=true`). Bucket grants no cross-account read. | `aws_s3_bucket_public_access_block`, `aws_s3_bucket_server_side_encryption_configuration "events"` (CMK), `aws_s3_bucket_policy "events_https_only"` |
| T-08 | Information Disclosure | CloudWatch Logs contain sensitive event data accessible to anyone with `logs:GetLogEvents`. | Event payloads contain AWS account metadata (account IDs, service names, dollar amounts) — not PII/secrets. The log group is encrypted with the **customer-managed CMK** (`aws_kms_key.main`) and has **365-day retention**. The KMS key policy grants `logs.<region>.amazonaws.com` data-key access scoped to this log group's ARN via an encryption-context condition. | `aws_cloudwatch_log_group.router` (`retention_in_days = 365`, `kms_key_id`); `data.aws_iam_policy_document.kms_key` `AllowCloudWatchLogs` |
| T-09 | Information Disclosure | Adaptive Card sent to wrong Teams channel due to routing misconfiguration, leaking spend data to unintended audience. | Tag-based routing has a `__default__` fallback, ensuring no event is silently dropped. Operators are responsible for correct tag→channel mappings. **Customer responsibility**: review routing seed before each apply; subscribe to a low-traffic admin channel during onboarding. | Documented in README "Adding workload-owner channels" |
| T-10 | Information Disclosure | Card content includes injected HTML/JS through a malicious account name or service string. | Adaptive Card v1.5 renders as native Teams UI, not HTML; Teams sanitizes text fields. All event fields originate from AWS-emitted events (account names set by AWS Organizations admins, not attackers). No user-input fields. | Teams native rendering; AC schema enforced |
| T-11 | Denial of Service | Event flood overwhelms the Lambda or Teams Workflows rate limits, causing alert loss. | Lambda has a reserved concurrency cap (default 5) bounding cost and per-second invocation. Per-record processing failures **propagate** (the handler re-raises after logging — CODE-1), so the invocation fails, SNS retries, and terminal failures land in the SQS dead-letter queue (DLQ) for replay. Teams Workflows has rate limits documented by Microsoft (~6000 actions/5 min by license tier); under cost-event volume (<100/day expected), this is not a meaningful risk. | `aws_lambda_function.router.reserved_concurrent_executions`, `aws_lambda_function.router.dead_letter_config`, `aws_sqs_queue.dlq`; `handler.handler` re-raises (CODE-1) |
| T-12 | Denial of Service | S3 archive write fails, causing Lambda errors and event loss. | S3 PUT is reliable; on failure the Lambda **re-raises** (CODE-1) rather than returning success, so SNS retries the message (delivery retries built in) and persistent failures land in the SQS DLQ — events are not silently lost. | `handler.handler` propagates per-record errors (CODE-1); SNS→Lambda retries; DLQ captures terminal failures |
| T-13 | Elevation of Privilege | Lambda role over-permissioned, enabling lateral movement. | Inline IAM policy grants only: `s3:PutObject` on the archive bucket, `dynamodb:GetItem` on the routing table, `ssm:GetParameter` on `/cost-events/webhook/*`, `organizations:ListTagsForResource` (resource-level scoping NOT supported by the Organizations API — required for tag-based routing). No `iam:*`, no `sts:AssumeRole`, no other service permissions. | `data "aws_iam_policy_document" "lambda_inline"` |
| T-14 | Elevation of Privilege | Lambda code is replaced via `lambda:UpdateFunctionCode` by an unauthorized principal. | Code updates go through Terraform; the Lambda function is deployed by the operator's CI/CD identity. Recommend customers enable AWS Lambda code signing and a permissions boundary on the Lambda role for production deployment. | Documented as a hardening recommendation |
| T-15 | Confused Deputy | Cross-account principal tricks the Lambda's Organizations call into leaking tags from another org. | The Organizations API only returns tags for resources within the same organization as the caller. The Lambda runs in the payer account where the events originate; cross-org access is not possible by service design. | Organizations service-side enforcement |
| T-16 | Confused Deputy | EventBridge (or Budgets/Cost Anomaly) in a different account publishes to this SNS topic, polluting alerts. | Every `sns:Publish` statement (EventBridge, Cost Anomaly Detection, Budgets) includes an `aws:SourceAccount` condition matching the deploying account ID. Cross-account events carry a different `SourceAccount` and are denied. | `data "aws_iam_policy_document" "sns_policy"` Condition blocks on all three publisher statements |
| T-17 | Phishing surface | The Teams card contains AWS console URLs the user is encouraged to click. A malicious actor with write access to the bucket or routing table could try to substitute a phishing URL. | URL construction is purely server-side in `links.py` from event-derived fields and operator-controlled SSM config. Bucket and table have no public write paths. The IAM Identity Center portal URL pattern is canonical AWS (`*.awsapps.com`); customers can verify the hostname before clicking. **Talos a1e659fa (FINAL)**: the portal hostname is no longer a Lambda environment variable at all — it is stored in SSM (`/cost-events/config/sso-portal`, opt-in via `var.sso_portal`) and read at runtime by `routing.get_sso_portal()` (TTL-cached). The hostname is therefore absent from `lambda:GetFunctionConfiguration` output; the Lambda env carries only the non-sensitive param NAME, and IAM grants `ssm:GetParameter` on just that one parameter ARN (`ReadSsoPortalConfig`). | `lambda/cost_router/links.py`, `lambda/cost_router/routing.py` (`get_sso_portal`); `terraform/main.tf` (`aws_ssm_parameter.sso_portal`, `ReadSsoPortalConfig` SID; env carries only `SSO_PORTAL_PARAM_NAME`) |
| T-18 | Resource exhaustion / cost | Lambda invocation cost balloons under abnormal event volume. | Reserved concurrency cap (5) bounds peak invocation rate. Cost projection in README: <$0.10/month at 1,500 events; even at 10× volume, sub-dollar. CloudWatch alarm on `Errors > 0` for 5 min recommended (documented). | `aws_lambda_function.router.reserved_concurrent_executions` |
| T-19 | Supply chain | Compromise of a Python package pulled into the Lambda zip. | Lambda has zero external Python dependencies (stdlib + boto3, where boto3 is provided by the AWS Lambda runtime). No `requirements.txt` is shipped to the function. | Inspect `lambda/cost_router/`; no third-party imports |
| T-20 | Supply chain | Terraform provider tampering. | `versions.tf` pins `hashicorp/aws ~> 5.60` and `hashicorp/archive ~> 2.4`. `terraform init` records provider checksums in `.terraform.lock.hcl`, which is **committed to source control** (un-ignored in `.gitignore` as of Phase 3 / TF-2) so checksums are pinned. Operators apply via authorized accounts. | `terraform/versions.tf`, `terraform/.terraform.lock.hcl` (committed), `.gitignore` |

## Out-of-scope items (customer responsibility)

The following are explicitly the customer's responsibility, not the sample's:

1. Tagging discipline. The pipeline routes by `WorkloadOwner` account tag; if
   tags are wrong or missing, alerts go to `__default__`. Customers must
   maintain accurate Organizations-level tagging.
2. SSO permission set design. The sample's deep links assume a `ReadOnlyAccess`
   permission set is assigned to the workload owner's user. Customers must
   ensure permission set names exist and are assigned correctly.
3. Teams workflow ownership. The Workflows trigger is owned by a Teams user
   account. Customers must add a co-owner so the flow survives that user
   leaving the org.
4. Production hardening: customer-managed KMS keys for SSM/SNS/CloudWatch Logs,
   Lambda code signing, GuardDuty Lambda Protection, AWS Config rules. The
   sample includes commented hooks; customers turn them on per their
   compliance posture.

## Disclaimer

This sample code is provided as-is for educational and reference purposes. It
should not be deployed in production environments without additional security
testing, configuration to meet your organizational requirements, and review by
your security and legal teams.
