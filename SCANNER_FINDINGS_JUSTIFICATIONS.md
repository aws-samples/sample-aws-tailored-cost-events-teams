# Static Analysis Findings — Justifications

This document records the rationale for each `checkov` finding suppressed in the Terraform code via `checkov:skip` directives. It is intended to be read alongside the suppression comments themselves and serves as the auditable record for security review.

All four findings below are documented [Checkov false positives](https://github.com/bridgecrewio/checkov) against AWS-recommended IAM and KMS patterns. The compensating controls are listed under each. The full security analysis is in [THREAT_MODEL.md](THREAT_MODEL.md).

---

## Finding 1 — `CKV_AWS_109` on `terraform/main.tf` `data.aws_iam_policy_document.kms_key`

**Title**: "Ensure IAM policies do not allow permissions management / resource exposure without constraints."

### Why this is a false positive

The flagged statement (`EnableRootAccountAdmin`) delegates `kms:*` to the account root principal (`arn:aws:iam::<account>:root`). This is the [AWS-recommended default key policy pattern](https://docs.aws.amazon.com/kms/latest/developerguide/key-policy-default.html) and is the only mechanism AWS provides for IAM-attached policies in the same account to grant access to a customer-managed KMS key.

Without this delegation, the key is unmanageable: `terraform apply` fails on state refresh, IAM-issued grants do not work, and key rotation breaks. This was verified empirically — see the project commit history where action-list tightening was attempted and reverted because Terraform's own state refresh hit `kms:Decrypt AccessDenied` on the deploying admin's role.

The permissions-management actions included in `kms:*` (e.g. `kms:PutKeyPolicy`, `kms:CreateGrant`) are accessible only to principals **in the same AWS account** that already have explicit IAM permissions for those actions. Root delegation does not expose them externally. The principal here is the account trust anchor, not a wildcard.

### Compensating controls

- Lambda role data-plane access is scoped via an explicit `AllowLambdaRoleDataPlane` statement on the key policy (`Decrypt`, `GenerateDataKey`, `Encrypt`, `DescribeKey` only) **and** via a scoped IAM inline policy (`UseKmsKey` SID).
- Service principals (CloudWatch Logs, EventBridge, Cost Anomaly Detection) are granted only the actions they require, with `kms:EncryptionContext` conditions where the service supports them.
- Annual key rotation enabled (`enable_key_rotation = true`).
- Account-level controls (CloudTrail, IAM admin auditing) apply to anyone who could exercise the root delegation.

### Evidence

- AWS KMS documentation: <https://docs.aws.amazon.com/kms/latest/developerguide/key-policy-default.html>
- Threat model: [THREAT_MODEL.md](THREAT_MODEL.md), threat T-13.
- Code: `terraform/main.tf`, `data "aws_iam_policy_document" "kms_key"` and `resource "aws_kms_key" "main"`.

---

## Finding 2 — `CKV_AWS_111` on `terraform/main.tf` `data.aws_iam_policy_document.kms_key`

**Title**: "Ensure IAM policies do not allow write access without constraints."

### Why this is a false positive

Same root cause as `CKV_AWS_109`. The flagged statement is the AWS-recommended default key policy that delegates `kms:*` to the account root principal. The "write access" Checkov is concerned about (Encrypt, Decrypt, GenerateDataKey, ScheduleKeyDeletion, etc.) is not actually granted to any usable principal by this statement; it requires an additional IAM-attached policy referencing the key, which only account admins can issue.

Tightening the action list to omit data-plane actions was attempted in this repo's commit history and broke Terraform's own state refresh — the deploying admin role lost the ability to read encrypted DynamoDB items and SSM SecureStrings during plan/apply. Reverted.

### Compensating controls

- Data-plane access for the runtime is granted **only** via the explicit `AllowLambdaRoleDataPlane` key policy statement, scoped to the Lambda role ARN.
- Service principals (CloudWatch Logs, EventBridge, `costalerts.amazonaws.com`) are scoped to `kms:Decrypt` + `kms:GenerateDataKey` with `kms:EncryptionContext` and `aws:SourceAccount` conditions where the service supports them.
- The Lambda IAM inline policy independently scopes `kms:Decrypt/GenerateDataKey/Encrypt/DescribeKey` to this specific key ARN.

### Evidence

- AWS KMS documentation: <https://docs.aws.amazon.com/kms/latest/developerguide/key-policy-default.html>
- Threat model: [THREAT_MODEL.md](THREAT_MODEL.md), threats T-04, T-06, T-13.

---

## Finding 3 — `CKV_AWS_356` on `terraform/main.tf` `data.aws_iam_policy_document.kms_key`

**Title**: "Ensure no IAM policies documents allow `*` as a statement's resource for restrictable actions."

### Why this is a false positive

This is a categorical false positive for KMS key policies. In a KMS key policy, `Resource: "*"` is not a wildcard — it is intrinsically scoped to the key the policy is attached to. KMS does not permit a key policy to reference its own ARN as a resource, nor any other key. AWS rejects every other value at API validation time. This is functionally identical to an S3 bucket policy where the resource is implicitly scoped to that bucket, except KMS makes the scoping implicit rather than explicit.

All other policy documents in this repo use specific resource ARNs (S3 bucket policy, Lambda inline policy, SNS topic policy). The KMS key policy is the only one with `Resource: "*"`, and it is required by the AWS KMS specification.

### Compensating controls

The principal scoping is what enforces least privilege here, not the resource scoping (which is fixed by the KMS spec). The key policy explicitly enumerates principals:

- Account root (for IAM delegation)
- The Lambda role ARN (for data-plane access)
- `logs.<region>.amazonaws.com` (for Logs encryption, with `kms:EncryptionContext:aws:logs:arn` condition)
- `events.amazonaws.com`
- `costalerts.amazonaws.com`

No wildcard principals.

### Evidence

- AWS KMS Developer Guide on key policy structure: <https://docs.aws.amazon.com/kms/latest/developerguide/key-policies.html>
- The `Resource: "*"` constraint is documented under "Specifying resources in a key policy".
- Threat model: [THREAT_MODEL.md](THREAT_MODEL.md), threat T-13.

---

## Finding 4 — `CKV_AWS_356` on `terraform/main.tf` `data.aws_iam_policy_document.lambda_inline`

**Title**: "Ensure no IAM policies documents allow `*` as a statement's resource for restrictable actions."

### Why this is a false positive

The flagged statement is `ReadAccountTags`, which permits the Lambda role to call `organizations:ListTagsForResource` on `*`. The AWS Organizations API does not support resource-level scoping for `ListTagsForResource` — there is no AWS-defined way to scope this action by account ID, organizational unit, or any other dimension. The action returns tags only for resources within the caller's organization (enforced by the Organizations service), so cross-organization access is impossible by service design.

All other statements in `data.aws_iam_policy_document.lambda_inline` are properly resource-scoped:

- `WriteEventArchive` — scoped to `${aws_s3_bucket.events.arn}/*`
- `ReadRoutingTable` — scoped to the routing table ARN
- `ReadWebhookSecrets` — scoped to `arn:aws:ssm:<region>:<account>:parameter/cost-events/webhook/*`
- `DeadLetter` — scoped to the DLQ ARN
- `UseKmsKey` — scoped to the project KMS key ARN

The wildcard is exclusively on the one action that the AWS API itself does not allow scoping for. The action is also read-only and returns only metadata (account tags), not customer data.

### Compensating controls

- Read-only action — cannot be used to modify any account or organization state.
- Service-side scoping by AWS Organizations — only returns tags for resources within the caller's own organization.
- Lambda invocation path is restricted (SNS topic policy + Lambda permission scope inbound to `events.amazonaws.com` and `costalerts.amazonaws.com`).
- The action is functionally required for the project's tag-based routing feature.

### Evidence

- AWS Organizations API reference for `ListTagsForResource`: <https://docs.aws.amazon.com/organizations/latest/APIReference/API_ListTagsForResource.html>
- AWS Service Authorization Reference confirms no resource-level support for this action.
- Threat model: [THREAT_MODEL.md](THREAT_MODEL.md), threat T-13.

---

## Finding 5 — `CKV_AWS_356` on `terraform/main.tf` `data.aws_iam_policy_document.lambda_inline` (`ReadCostOptimizationHub`)

**Title**: "Ensure no IAM policies documents allow `*` as a statement's resource for restrictable actions."

**Added**: 2026-06-10 (post-remediation security audit — NEW attack surface from the AWS-2 Cost Optimization Hub scheduled-pull path).

### Why this is a false positive

The flagged statement is `ReadCostOptimizationHub`, which permits the Lambda role to call `cost-optimization-hub:ListRecommendations` on `*`. Per the AWS Service Authorization Reference, `ListRecommendations` is an **account-wide / cross-Region aggregation API** (the Cost Optimization Hub service aggregates recommendations from Compute Optimizer, Cost Explorer, etc. across the organization's accounts and Regions, served from the `us-east-1` global endpoint). The action does **not** support resource-level scoping — there is no recommendation/resource ARN that can be named in the `Resource` element for `ListRecommendations`. This is the same class of constraint as the already-documented `organizations:ListTagsForResource` grant (Finding 4): the wildcard is on the one action whose AWS API does not permit scoping.

The handler uses **only** `list_recommendations` (verified in [`handler.pull_coh_recommendations`](lambda/cost_router/handler.py:164) — no `GetRecommendation`, no write actions), so the grant is a single, read-only, metadata-returning action.

### Compensating controls

- Single read-only action — cannot modify any account, recommendation, or resource state.
- All other statements in `data.aws_iam_policy_document.lambda_inline` remain resource-scoped (S3 prefix, routing table ARN, SSM webhook path, DLQ ARN, project KMS key ARN).
- The Lambda invocation path is restricted (SNS topic policy + EventBridge Scheduler with a dedicated role limited to invoking only this function).
- The action returns only cost-optimization recommendation metadata for the caller's own account/organization (service-side scoping), not customer data.

### Evidence

- AWS Service Authorization Reference — *Actions, resources, and condition keys for AWS Cost Optimization Hub*: `ListRecommendations` lists no resource types (no resource-level permissions).
- Inline rationale: [`terraform/main.tf`](terraform/main.tf) `ReadCostOptimizationHub` statement (`checkov:skip=CKV_AWS_356`).
- Analysis: [`docs/EXPERT_ANALYSIS.md`](docs/EXPERT_ANALYSIS.md) AWS-2; [`docs/PHASE3_TERRAFORM.md`](docs/PHASE3_TERRAFORM.md) (ReadCostOptimizationHub SID).

---

## Finding 6 — `CKV_AWS_297` on `terraform/main.tf` `aws_scheduler_schedule.coh_pull`

**Title**: "Ensure EventBridge Scheduler Schedule uses Customer Managed Key (CMK)."

**Added**: 2026-06-10 (post-remediation security audit — NEW resource from AWS-2).

### Why this is accepted (documented, not a code defect)

The schedule's target `input` is a fixed, non-sensitive marker — `{"coh_pull": true}` — that carries no event, account, or customer data. A customer-managed KMS key on the Scheduler payload therefore adds no confidentiality value: there is nothing sensitive in the payload to protect. The recommendations that the resulting invocation fetches travel over TLS to the Cost Optimization Hub API, and the Lambda's own environment, logs, DynamoDB state, and SNS/S3 outputs are all encrypted with the project CMK (`aws_kms_key.main`).

### Compensating controls

- Schedule input is a static literal with no secrets/PII.
- Invocation is least-privileged: a dedicated `aws_iam_role.scheduler` trusted only by `scheduler.amazonaws.com` (with an `aws:SourceAccount` condition) and permitted to invoke **only** the router Lambda ARN; `aws_lambda_permission.scheduler` is bound to the specific schedule ARN.
- Customers who require CMK on the schedule itself can set `kms_key_arn = aws_kms_key.main.arn` on the resource (noted inline).

### Evidence

- Inline rationale: [`terraform/main.tf`](terraform/main.tf) `aws_scheduler_schedule.coh_pull` (`checkov:skip=CKV_AWS_297`).
- Design: [`docs/PHASE3_TERRAFORM.md`](docs/PHASE3_TERRAFORM.md) (COH schedule discriminator); [`THREAT_MODEL.md`](THREAT_MODEL.md) (EventBridge Scheduler component).

---

## Finding 7 — `CKV_AWS_144` on `aws_s3_bucket.events` and `aws_s3_bucket.access_logs` (cross-region replication)

**Title**: "Ensure that S3 bucket has cross-region replication enabled."

**Note**: For the `events` bucket this was already documented as a Checkov false-positive/accepted item; the inline `checkov:skip` comment was previously placed **above** the resource block, where Checkov does not honor it. The audit (2026-06-10) **moved the comment inside** the resource block so the suppression is actually applied, and added the equivalent skip on the `access_logs` bucket.

### Why this is accepted

Cross-region replication (CRR) is operationally heavy (a second bucket, replication IAM role, ongoing replication cost) and is **not warranted for a short-retention sample**: the `events` archive has a 90-day lifecycle and the `access_logs` bucket is an S3 server-access-log destination. Neither holds long-lived system-of-record data that would justify multi-Region durability for this reference implementation. Customers with a DR requirement can add `aws_s3_bucket_replication_configuration`.

### Compensating controls

- Both buckets have versioning enabled, `BlockPublicAccess` (all four flags), and lifecycle expiry.
- The `events` bucket enforces TLS-only access and CMK SSE; durability within the Region is provided by S3's native 11-nines design.

### Evidence

- Inline rationale: [`terraform/main.tf`](terraform/main.tf) `aws_s3_bucket.events` and `aws_s3_bucket.access_logs` (`checkov:skip=CKV_AWS_144`).

---

## Finding 8 — `CKV2_AWS_62` on `aws_s3_bucket.events` and `aws_s3_bucket.access_logs` (event notifications)

**Title**: "Ensure S3 buckets should have event notifications enabled."

**Note**: Same comment-placement fix as Finding 7 — the `events` skip was moved inside the resource block, and the `access_logs` skip was added (2026-06-10).

### Why this is a false positive

S3 event notifications are out of this pipeline's scope. The `events` archive bucket is consumed by the simulator and by operators reviewing archived cards — there is **no downstream automation that needs to be triggered on object creation**. The `access_logs` bucket is purely an S3 server-access-log sink. Enabling event notifications with no consumer would create dead configuration.

### Compensating controls

- All write paths into the buckets are server-side (the Lambda's scoped `s3:PutObject` on the archive prefix; S3 log delivery for the logs bucket). No public write paths exist.
- Object lifecycle and versioning provide retention/audit without a notification consumer.

### Evidence

- Inline rationale: [`terraform/main.tf`](terraform/main.tf) `aws_s3_bucket.events` and `aws_s3_bucket.access_logs` (`checkov:skip=CKV2_AWS_62`).

---

## Finding 9 — `CKV_AWS_145` on `aws_s3_bucket.access_logs` (KMS-by-default encryption)

**Title**: "Ensure that S3 buckets are encrypted with KMS by default."

**Added**: 2026-06-10 (post-remediation security audit).

### Why this is accepted (deliberate design)

The S3 **server-access-log destination** bucket intentionally uses SSE-S3 (`AES256`), not the project customer-managed CMK. This is a deliberate, documented design choice:

1. Access logs contain only **request metadata** (requester, bucket, object key, operation, response code) — not the event payloads or any sensitive data, which live in the CMK-encrypted `events` bucket.
2. The S3 **log-delivery service** writes these logs; pointing the log bucket at a CMK would require granting the S3 log-delivery service principal `kms:GenerateDataKey` on the project key, widening the key policy for no confidentiality benefit on already-non-sensitive metadata.

The primary data bucket (`events`) **does** use the CMK (`CKV_AWS_145` passes there). This matches the documented architecture (separate AES256 access-logs bucket).

### Compensating controls

- Access logs are still encrypted at rest (SSE-S3 / AES256), public access fully blocked, versioned, and lifecycle-expired.
- No sensitive data is written to this bucket by design (T-07 keeps event payloads in the CMK-encrypted archive bucket).

### Evidence

- Inline rationale: [`terraform/main.tf`](terraform/main.tf) `aws_s3_bucket.access_logs` (`checkov:skip=CKV_AWS_145`).
- Threat model: [`THREAT_MODEL.md`](THREAT_MODEL.md) T-07 (separate AES256 access-logs bucket).

---

## Talos Security Review (2026-06-10) — 5 Medium findings remediated

These are **code/IaC fixes** (not Checkov suppressions). Full per-finding detail, before/after, and proving tests are in [`docs/TALOS_REMEDIATION.md`](docs/TALOS_REMEDIATION.md). Mapping:

| Talos ID | Title | What was done | Evidence |
|---|---|---|---|
| `5d523fa8` | Exception messages exposed in Lambda response | Per-record failures still PROPAGATE (CODE-1 / DLQ), but the handler now re-raises a generic `EventProcessingError("Internal error processing event")` with `raise ... from None`; full detail logged via `log.exception` only. | [`handler.py`](lambda/cost_router/handler.py:55) `EventProcessingError`; raises at [`:94`](lambda/cost_router/handler.py:94) and [`:254`](lambda/cost_router/handler.py:254); [`test_talos_handler.py`](tests/unit/test_talos_handler.py) |
| `a1e659fa` | SSO portal hostname exposed in Lambda env vars | **FINAL (SSM-backed):** `WORKLOAD_SSO_PORTAL` is **removed** from the Lambda env entirely. The hostname is stored in SSM (`/cost-events/config/sso-portal`, `type=String`, opt-in via `var.sso_portal`) and read at runtime by `routing.get_sso_portal()` (TTL-cached, reuses the f92df048 cache). The Lambda env carries only the non-sensitive param NAME (`SSO_PORTAL_PARAM_NAME`); IAM adds a least-privilege `ssm:GetParameter` SID scoped to that one ARN. Missing/unset param degrades to direct links with no exception leak. | [`terraform/main.tf`](terraform/main.tf) `aws_ssm_parameter.sso_portal` + `ReadSsoPortalConfig` SID + env `SSO_PORTAL_PARAM_NAME`; [`routing.py`](lambda/cost_router/routing.py) `get_sso_portal`; [`links.py`](lambda/cost_router/links.py); [`test_talos_links_ssm.py`](tests/unit/test_talos_links_ssm.py) |
| `51f0122b` | Webhook URL domain not validated (SSRF) | Added host allow-list (`*.logic.azure.com`, `*.webhook.office.com`; extensible via `TEAMS_WEBHOOK_ALLOWED_HOSTS`) + SSRF blocks (IP-literals incl. `169.254.169.254`, loopback, RFC-1918, `*.local`/`*.internal`, bare names), evaluated before any HTTP call. | [`sinks.py`](lambda/cost_router/sinks.py:76) `_is_allowed_webhook_url`; wired at [`:167`](lambda/cost_router/sinks.py:167); [`test_talos_sinks_ssrf.py`](tests/unit/test_talos_sinks_ssrf.py) |
| `f92df048` | LRU cache never invalidates (stale routing) | Replaced `functools.lru_cache` with a stdlib TTL cache (default 300s, `WORKLOAD_TAG_CACHE_TTL_SECONDS`); preserves `.cache_clear()`; loader re-runs after TTL so re-tagged accounts are picked up. | [`routing.py`](lambda/cost_router/routing.py:57) `_ttl_cache`; [`test_talos_routing_ttl.py`](tests/unit/test_talos_routing_ttl.py) |
| `5276ea22` | No size limit on SNS message JSON parsing | Cap `_MAX_SNS_MESSAGE_BYTES = 256 KB` enforced BEFORE `json.loads` in `_extract`; oversized bodies skipped (reuses the `_MAX_BUDGETS_BODY_CHARS` pattern). | [`handler.py`](lambda/cost_router/handler.py:47) cap; check at [`:127`](lambda/cost_router/handler.py:127); [`test_talos_handler.py`](tests/unit/test_talos_handler.py) |

**Validation**: full suite `120 passed, 1 xfailed` (only the pre-existing AWS-5 Cost-Explorer-deep-link xfail; includes the +11 `a1e659fa` SSM-relocation tests in [`test_talos_links_ssm.py`](tests/unit/test_talos_links_ssm.py)); `terraform validate` Success; `py_compile` clean; Lambda runtime remains stdlib + boto3 only.

**Resolved (was open for product review)**: `a1e659fa` previously offered a UX tradeoff (opt-in env var vs. SSM relocation). The reviewer chose the SSM-backed relocation — the hostname now lives in SSM Parameter Store and the `WORKLOAD_SSO_PORTAL` env var is removed entirely. See the FINAL design in [`docs/TALOS_REMEDIATION.md`](docs/TALOS_REMEDIATION.md) (Finding 2).

---

## Notes for the security reviewer

If a reviewer pushes back on any of these:

- **`CKV_AWS_109`, `CKV_AWS_111`, `CKV_AWS_356` on the KMS key policy** — point them at the AWS KMS documentation linked above and the empirical revert recorded in this repo's commit history. The only viable alternative is to drop the customer-managed KMS key entirely and revert to AWS-managed service keys (`alias/aws/s3`, `alias/aws/dynamodb`, etc.). That is *less* secure and only shifts the same class of finding to a different rule.
- **`CKV_AWS_356` on the Organizations call** — point them at the API reference. The only alternative is to drop tag-based routing entirely, which would gut the project's per-workload-owner channel feature. Not recommended.

## How to verify

```bash
# Re-run checkov against the repo
checkov -d terraform/

# The four findings above should be suppressed by inline directives.
# Other findings should be addressed or have their own checkov:skip
# directive with rationale.
```
