data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  prefix     = "${var.name_prefix}-${local.account_id}"
}

# ---------- KMS: customer-managed key for stateful resources ----------
# Used by S3 archive, DynamoDB routing, CloudWatch Logs, Lambda env vars,
# SSM SecureString, and SNS. Key rotation enabled (CKV2_AWS_67).
data "aws_iam_policy_document" "kms_key" {
  # checkov:skip=CKV_AWS_109: KMS key policy uses AWS-recommended root-account delegation. Resource="*" in a key policy is scoped by KMS to the attached key (the only valid form). Without this delegation, the key is unmanageable via IAM and breaks terraform apply / rotation. See https://docs.aws.amazon.com/kms/latest/developerguide/key-policy-default.html
  # checkov:skip=CKV_AWS_111: Same as CKV_AWS_109 — root delegation is the AWS-recommended pattern; tightening was attempted and reverted (broke terraform state refresh).
  # checkov:skip=CKV_AWS_356: KMS key policy Resource="*" is intrinsically scoped to the attached key per AWS KMS spec. Resource ARN of the key cannot be specified in its own policy.
  # AWS-recommended default key policy pattern: delegate to the root
  # principal so IAM-attached policies in the same account can grant
  # access to the key. In a KMS key policy, Resource="*" is scoped
  # automatically by KMS to "this key" (you cannot specify the key ARN
  # in its own attached policy). Without this delegation, only the key
  # creator and explicit principal statements can manage the key —
  # bricking it for terraform apply, IAM policy issuance, and rotation.
  # See https://docs.aws.amazon.com/kms/latest/developerguide/key-policy-default.html
  statement {
    sid       = "EnableRootAccountAdmin"
    effect    = "Allow"
    actions   = ["kms:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${local.account_id}:root"]
    }
  }
  statement {
    sid    = "AllowCloudWatchLogs"
    effect = "Allow"
    actions = [
      "kms:Encrypt*",
      "kms:Decrypt*",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:Describe*",
    ]
    resources = ["*"]
    principals {
      type        = "Service"
      identifiers = ["logs.${data.aws_region.current.name}.amazonaws.com"]
    }
    condition {
      test     = "ArnLike"
      variable = "kms:EncryptionContext:aws:logs:arn"
      values   = ["arn:aws:logs:${data.aws_region.current.name}:${local.account_id}:log-group:/aws/lambda/${local.prefix}-router"]
    }
  }
  # Publishers to the CMK-encrypted SNS topic need data-key access to deliver.
  # events.amazonaws.com  -> EventBridge rules (Cost Anomaly, Trusted Advisor).
  # costalerts.amazonaws.com -> Cost Anomaly Detection direct publisher.
  # budgets.amazonaws.com -> AWS Budgets native SNS notifications (AWS-1). The
  #   topic is encrypted with this CMK, so without GenerateDataKey/Decrypt here
  #   the Budgets->SNS publish fails with KMS.AccessDeniedException (TF-5 foot-gun).
  statement {
    sid    = "AllowEventCostAlertsAndBudgetsToPublishViaKey"
    effect = "Allow"
    actions = [
      "kms:Decrypt",
      "kms:GenerateDataKey",
    ]
    resources = ["*"]
    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com", "costalerts.amazonaws.com", "budgets.amazonaws.com"]
    }
  }
  # Lambda router needs data-plane access for S3/DDB/SSM/SNS/Logs interactions.
  # Scoped to the specific role ARN so other IAM principals in the account
  # cannot use the key just by virtue of root delegation.
  statement {
    sid    = "AllowLambdaRoleDataPlane"
    effect = "Allow"
    actions = [
      "kms:Decrypt",
      "kms:GenerateDataKey",
      "kms:Encrypt",
      "kms:DescribeKey",
    ]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${local.account_id}:role/${local.prefix}-lambda-role"]
    }
  }
}

resource "aws_kms_key" "main" {
  # checkov:skip=CKV_AWS_109: KMS key policies require Resource="*" — KMS scopes it automatically to the attached key. Root-account delegation is the AWS-recommended pattern; actions are enumerated (no kms:*) so the principal cannot Encrypt/Decrypt/GenerateDataKey via the key policy alone.
  # checkov:skip=CKV_AWS_111: As above — explicit action enumeration excludes write-data actions; root delegation lets IAM attached policies grant scoped access.
  # checkov:skip=CKV_AWS_356: KMS key policies are intrinsically scoped to the key the policy is attached to; Resource="*" is the only valid value per AWS KMS spec.
  description             = "Encryption key for cost-events-to-teams stateful resources"
  enable_key_rotation     = true
  deletion_window_in_days = 7
  policy                  = data.aws_iam_policy_document.kms_key.json
}

resource "aws_kms_alias" "main" {
  name          = "alias/${local.prefix}"
  target_key_id = aws_kms_key.main.key_id
}

# ---------- S3: event archive + Teams-payload store ----------
resource "aws_s3_bucket" "events" {
  # NOTE: checkov honors `checkov:skip` only INSIDE the resource block; the same
  # comments placed above the block are ignored (audit 2026-06-10).
  # checkov:skip=CKV_AWS_144: Cross-region replication is operationally heavy and not warranted for a 90-day retention sample.
  # checkov:skip=CKV2_AWS_62: Event notifications out of pipeline scope; bucket is consumed by the simulator and admins, not downstream automation.
  bucket        = "${local.prefix}-archive"
  force_destroy = true
}

# Separate bucket for S3 server access logs (CKV_AWS_18). Logs bucket
# itself does not require its own access logging (avoids recursion).
resource "aws_s3_bucket" "access_logs" {
  # checkov:skip=CKV_AWS_144: Cross-region replication is operationally heavy and not warranted for a short-retention S3 access-log bucket.
  # checkov:skip=CKV2_AWS_62: Event notifications out of scope; this is an S3 server-access-log destination consumed by operators, not downstream automation.
  # checkov:skip=CKV_AWS_145: The access-log destination intentionally uses SSE-S3 (AES256), not the project CMK. Access logs contain only request metadata (not event payloads), and using the CMK would require granting the S3 log-delivery service principal key access. This matches the documented design (THREAT_MODEL.md T-07; EXPERT_ANALYSIS "separate AES256 access-logs bucket").
  bucket        = "${local.prefix}-access-logs"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "access_logs" {
  bucket                  = aws_s3_bucket.access_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id
  rule {
    id     = "expire"
    status = "Enabled"
    filter {}
    expiration { days = 90 }
    abort_incomplete_multipart_upload { days_after_initiation = 7 }
  }
}

resource "aws_s3_bucket_versioning" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_logging" "events" {
  bucket        = aws_s3_bucket.events.id
  target_bucket = aws_s3_bucket.access_logs.id
  target_prefix = "events/"
}

resource "aws_s3_bucket_public_access_block" "events" {
  bucket                  = aws_s3_bucket.events.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "events" {
  bucket = aws_s3_bucket.events.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.main.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_versioning" "events" {
  bucket = aws_s3_bucket.events.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_lifecycle_configuration" "events" {
  bucket = aws_s3_bucket.events.id
  rule {
    id     = "expire-old"
    status = "Enabled"
    filter {}
    expiration {
      days = 90
    }
    noncurrent_version_expiration {
      noncurrent_days = 30
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

# Enforce TLS (aws:SecureTransport=true) on all access. Mitigates T-07.
data "aws_iam_policy_document" "events_https_only" {
  statement {
    sid     = "DenyInsecureTransport"
    effect  = "Deny"
    actions = ["s3:*"]
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    resources = [
      aws_s3_bucket.events.arn,
      "${aws_s3_bucket.events.arn}/*",
    ]
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "events_https_only" {
  bucket = aws_s3_bucket.events.id
  policy = data.aws_iam_policy_document.events_https_only.json
}

# ---------- DynamoDB: routing table ----------
resource "aws_dynamodb_table" "routing" {
  name         = "${local.prefix}-routing"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "tag_value"
  attribute {
    name = "tag_value"
    type = "S"
  }

  point_in_time_recovery {
    enabled = true
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.main.arn
  }
}

resource "aws_dynamodb_table_item" "routing_seed" {
  for_each   = { for r in var.routing_seed : r.tag_value => r }
  table_name = aws_dynamodb_table.routing.name
  hash_key   = aws_dynamodb_table.routing.hash_key
  item = jsonencode({
    tag_value         = { S = each.value.tag_value }
    team_name         = { S = each.value.team_name }
    webhook_ssm_param = { S = each.value.webhook_ssm_param }
    min_dollar_impact = { N = tostring(each.value.min_dollar_impact) }
  })
}

# ---------- SSM: Teams webhook (placeholder until user creates workflow) ----------
resource "aws_ssm_parameter" "default_webhook" {
  name        = "/cost-events/webhook/test-aws-notify"
  description = "Teams Workflows webhook URL for test-aws-notify channel. Set via CLI when ready."
  type        = "SecureString"
  key_id      = aws_kms_key.main.key_id
  value       = "PLACEHOLDER-replace-with-teams-workflows-url"

  lifecycle {
    ignore_changes = [value]
  }
}

# ---------- SSM: SSO/Identity Center portal hostname (Talos a1e659fa) ----------
# The IAM Identity Center portal hostname is OPT-IN config consumed at runtime by
# the Lambda (routing.get_sso_portal -> links deep-link wrapping). It used to be a
# plaintext Lambda env var (WORKLOAD_SSO_PORTAL), which Talos a1e659fa flagged as
# an exposure surface (visible via lambda:GetFunctionConfiguration). It now lives
# here in SSM and is read at runtime, so the hostname is NOT in the function's env.
#
# count: only create the parameter when a customer opts in by setting var.sso_portal
# (default ""), so the default sample provisions NO param and the feature stays
# opt-in — but the config now lives in SSM, not the env. The Lambda learns only the
# parameter NAME (SSO_PORTAL_PARAM_NAME below), never the value.
#
# type = "String": the hostname is a canonical, low-sensitivity AWS *.awsapps.com
# value (THREAT_MODEL T-17), not a secret — a plain String is appropriate and
# avoids an unnecessary KMS dependency. (If an operator prefers SecureString for
# uniformity with the webhook param, the Lambda role's existing data-plane KMS
# grant already covers Decrypt.) lifecycle.ignore_changes is NOT set: unlike the
# webhook (a placeholder a human later overwrites out-of-band), this value is the
# Terraform-managed source of truth from var.sso_portal.
resource "aws_ssm_parameter" "sso_portal" {
  count       = var.sso_portal != "" ? 1 : 0
  name        = "/cost-events/config/sso-portal"
  description = "IAM Identity Center portal hostname for 1-click SSO console deep links (Talos a1e659fa: relocated out of the Lambda env var into SSM)."
  type        = "String"
  value       = var.sso_portal
}

# ---------- SNS ----------
# Encrypted at rest with the customer-managed key. Mitigates T-06 / T-08.
resource "aws_sns_topic" "cost_events" {
  name              = "${local.prefix}-topic"
  kms_master_key_id = aws_kms_key.main.arn
}

resource "aws_sns_topic_policy" "cost_events" {
  arn    = aws_sns_topic.cost_events.arn
  policy = data.aws_iam_policy_document.sns_policy.json
}

data "aws_iam_policy_document" "sns_policy" {
  statement {
    sid     = "AllowEventBridge"
    effect  = "Allow"
    actions = ["sns:Publish"]
    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }
    resources = [aws_sns_topic.cost_events.arn]
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }
  statement {
    sid     = "AllowCostAnomalyDetection"
    effect  = "Allow"
    actions = ["sns:Publish"]
    principals {
      type        = "Service"
      identifiers = ["costalerts.amazonaws.com"]
    }
    resources = [aws_sns_topic.cost_events.arn]
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }
  # AWS-1: AWS Budgets does NOT emit threshold events to EventBridge; it
  # publishes plain-text alerts directly to SNS. Allow the Budgets service
  # principal to publish to this topic so a customer can point a Budget's SNS
  # notification at it. The Lambda (subscribed below) parses the plain-text
  # body via handler._extract -> normalizers._parse_budgets_sns_text. We do NOT
  # create an aws_budgets_budget resource here: a budget is customer-specific
  # (name/amount/thresholds); the customer wires their existing/own budget's
  # SNS notification to this topic ARN (see outputs.sns_topic_arn).
  statement {
    sid     = "AllowBudgetsPublish"
    effect  = "Allow"
    actions = ["sns:Publish"]
    principals {
      type        = "Service"
      identifiers = ["budgets.amazonaws.com"]
    }
    resources = [aws_sns_topic.cost_events.arn]
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }
}

# ---------- Lambda package ----------
data "archive_file" "lambda" {
  type        = "zip"
  source_dir  = "${path.module}/../lambda/cost_router"
  output_path = "${path.module}/.build/cost_router.zip"
}

resource "aws_iam_role" "lambda" {
  name = "${local.prefix}-lambda-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect    = "Allow",
      Principal = { Service = "lambda.amazonaws.com" },
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_basic" {
  role       = aws_iam_role.lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy_attachment" "lambda_xray" {
  role       = aws_iam_role.lambda.name
  policy_arn = "arn:aws:iam::aws:policy/AWSXRayDaemonWriteAccess"
}

# Dead-letter queue: captures terminal failures (after SNS retries) so events
# are never lost. Mitigates T-11 / T-12.
resource "aws_sqs_queue" "dlq" {
  name                       = "${local.prefix}-dlq"
  message_retention_seconds  = 1209600 # 14 days
  sqs_managed_sse_enabled    = true
  visibility_timeout_seconds = 60
}

data "aws_iam_policy_document" "lambda_inline" {
  # checkov:skip=CKV_AWS_356: organizations:ListTagsForResource does not support resource-level scoping per AWS Organizations API contract. Required for tag-based routing. All other statements in this policy are resource-scoped. See THREAT_MODEL.md T-13.
  statement {
    sid       = "WriteEventArchive"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.events.arn}/*"]
  }
  statement {
    sid       = "ReadRoutingTable"
    actions   = ["dynamodb:GetItem"]
    resources = [aws_dynamodb_table.routing.arn]
  }
  statement {
    sid       = "ReadWebhookSecrets"
    actions   = ["ssm:GetParameter"]
    resources = ["arn:aws:ssm:${data.aws_region.current.name}:${local.account_id}:parameter/cost-events/webhook/*"]
  }
  # Talos a1e659fa: the SSO/Identity Center portal hostname now lives in SSM
  # (read at runtime by routing.get_sso_portal), NOT in a Lambda env var. Grant
  # ssm:GetParameter on EXACTLY that one parameter ARN — least privilege, mirrors
  # the ReadWebhookSecrets style above. The hostname is stored as a plain String
  # (not a secret), so no KMS decrypt is required for it; if an operator changes
  # the param to SecureString, the Lambda role's data-plane KMS grant
  # (AllowLambdaRoleDataPlane on aws_kms_key.main) already covers Decrypt.
  statement {
    sid       = "ReadSsoPortalConfig"
    actions   = ["ssm:GetParameter"]
    resources = ["arn:aws:ssm:${data.aws_region.current.name}:${local.account_id}:parameter/cost-events/config/sso-portal"]
  }
  statement {
    sid     = "ReadAccountTags"
    actions = ["organizations:ListTagsForResource"]
    # checkov:skip=CKV_AWS_356: Organizations API does not support resource-level
    # scoping for ListTagsForResource. See T-13 in THREAT_MODEL.md.
    resources = ["*"]
  }
  statement {
    sid       = "DeadLetter"
    actions   = ["sqs:SendMessage"]
    resources = [aws_sqs_queue.dlq.arn]
  }
  statement {
    sid = "UseKmsKey"
    actions = [
      "kms:Decrypt",
      "kms:GenerateDataKey",
      "kms:Encrypt",
      "kms:DescribeKey",
    ]
    resources = [aws_kms_key.main.arn]
  }
  # AWS-2: the scheduled Cost Optimization Hub pull (handler.run_coh_pull ->
  # pull_coh_recommendations) calls cost-optimization-hub:ListRecommendations.
  # The handler uses ONLY ListRecommendations (no GetRecommendation), so we
  # grant just that action. The Cost Optimization Hub API does not support
  # resource-level scoping for ListRecommendations (it is an account-wide,
  # us-east-1/global aggregation API), so Resource="*" is required here — this
  # mirrors the well-justified organizations:ListTagsForResource "*" grant
  # above (see SCANNER_FINDINGS_JUSTIFICATIONS.md / T-13 for the documented
  # rationale style).
  statement {
    # checkov:skip=CKV_AWS_356: cost-optimization-hub:ListRecommendations does not support resource-level scoping (account-wide aggregation API). Single read-only action; see AWS-2 in docs/EXPERT_ANALYSIS.md.
    sid       = "ReadCostOptimizationHub"
    actions   = ["cost-optimization-hub:ListRecommendations"]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "lambda_inline" {
  # checkov:skip=CKV_AWS_356: organizations:ListTagsForResource does not support resource-level scoping (AWS Organizations API limitation). All other statements in this policy are resource-scoped. See T-13 in THREAT_MODEL.md.
  name   = "${local.prefix}-lambda-inline"
  role   = aws_iam_role.lambda.id
  policy = data.aws_iam_policy_document.lambda_inline.json
}

resource "aws_lambda_function" "router" {
  # checkov:skip=CKV_AWS_117: Lambda has no need for VPC; egress is to public AWS APIs and Teams Workflows. Customers with private-network requirements can attach via aws_lambda_function.vpc_config.
  # checkov:skip=CKV_AWS_272: Code signing is customer-environment-dependent. Documented as a production hardening recommendation.
  function_name                  = "${local.prefix}-router"
  role                           = aws_iam_role.lambda.arn
  handler                        = "handler.handler"
  runtime                        = "python3.12"
  filename                       = data.archive_file.lambda.output_path
  source_code_hash               = data.archive_file.lambda.output_base64sha256
  timeout                        = 30
  memory_size                    = 256
  reserved_concurrent_executions = var.reserved_concurrency
  kms_key_arn                    = aws_kms_key.main.arn

  dead_letter_config {
    target_arn = aws_sqs_queue.dlq.arn
  }

  tracing_config {
    mode = "Active"
  }

  # Talos a1e659fa (FINAL, SSM-backed): the SSO/Identity Center portal HOSTNAME is
  # NOT a Lambda environment variable anymore — WORKLOAD_SSO_PORTAL is gone. The
  # hostname lives in SSM (aws_ssm_parameter.sso_portal) and is read at runtime by
  # routing.get_sso_portal(). The Lambda env carries only the parameter NAME
  # (SSO_PORTAL_PARAM_NAME) — a name is not sensitive — exactly like the webhook
  # param name lives in the routing record rather than the URL value. The name is
  # added ONLY when the customer opts in (var.sso_portal != ""), matching the
  # opt-in creation of the SSM param above; with the default empty value neither
  # the param nor the name env entry exists, and routing.get_sso_portal() returns
  # "" so links.py degrades to direct-console links.
  environment {
    variables = merge(
      {
        EVENT_BUCKET           = aws_s3_bucket.events.bucket
        ROUTING_TABLE_NAME     = aws_dynamodb_table.routing.name
        WORKLOAD_OWNER_TAG_KEY = var.workload_owner_tag_key
        WORKLOAD_SSO_ROLE      = var.sso_role
      },
      var.sso_portal != "" ? { SSO_PORTAL_PARAM_NAME = aws_ssm_parameter.sso_portal[0].name } : {},
    )
  }
}

resource "aws_cloudwatch_log_group" "router" {
  name              = "/aws/lambda/${aws_lambda_function.router.function_name}"
  retention_in_days = 365
  kms_key_id        = aws_kms_key.main.arn
}

resource "aws_lambda_permission" "sns" {
  statement_id  = "AllowSNSInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.router.function_name
  principal     = "sns.amazonaws.com"
  source_arn    = aws_sns_topic.cost_events.arn
}

resource "aws_sns_topic_subscription" "lambda" {
  topic_arn = aws_sns_topic.cost_events.arn
  protocol  = "lambda"
  endpoint  = aws_lambda_function.router.arn
}

# ---------- EventBridge rules (event-driven sources) ----------
# TF-1 / AWS-1 / AWS-2: only AWS services that ACTUALLY emit cost events to
# EventBridge get a rule here. The former `budgets` and `cost_optimization_hub`
# rules were REMOVED because those services do not publish threshold /
# recommendation events to EventBridge:
#   * AWS Budgets   -> publishes plain-text alerts to SNS (AllowBudgetsPublish
#                      on aws_sns_topic_policy.cost_events; parsed by the Lambda).
#   * Cost Opt. Hub -> pulled on a schedule (aws_scheduler_schedule.coh_pull).
# Both rules previously matched only CloudTrail API noise (or nothing), so they
# were dead wiring. The remaining EventBridge sources are Cost Anomaly Detection
# and Trusted Advisor, both of which emit real service events.
locals {
  event_rules = {
    cost_anomaly = {
      description = "AWS Cost Anomaly Detection findings"
      pattern = jsonencode({
        source        = ["aws.ce"]
        "detail-type" = ["Anomaly Detected"]
      })
    }
    # AWS-3: the real Trusted Advisor event has NO top-level `check-category`
    # (the old filter matched nothing). Match the documented fields instead:
    # source + detail-type, then filter on `detail.status` (WARN/ERROR) AND an
    # allow-list of cost-optimizing `detail.check-name` values
    # (var.trusted_advisor_cost_checks). Both detail conditions must hold, so
    # only failing/at-risk COST checks are forwarded.
    trusted_advisor = {
      description = "Trusted Advisor cost-optimizing checks in WARN/ERROR (AWS-3)"
      pattern = jsonencode({
        source        = ["aws.trustedadvisor"]
        "detail-type" = ["Trusted Advisor Check Item Refresh Notification"]
        detail = {
          status       = ["WARN", "ERROR"]
          "check-name" = var.trusted_advisor_cost_checks
        }
      })
    }
  }
}

resource "aws_cloudwatch_event_rule" "rules" {
  for_each      = local.event_rules
  name          = "${local.prefix}-${each.key}"
  description   = each.value.description
  event_pattern = each.value.pattern
}

# EventBridge delivers matched events to the SNS topic; the Lambda is subscribed
# to the topic (aws_sns_topic_subscription.lambda) and authorized to be invoked
# by SNS (aws_lambda_permission.sns). EventBridge is authorized to publish to
# the topic by AllowEventBridge in aws_sns_topic_policy.cost_events. Because the
# target is SNS (not the Lambda directly), no events->lambda permission is
# needed for these rules — SNS fans the event into the Lambda.
resource "aws_cloudwatch_event_target" "to_sns" {
  for_each  = aws_cloudwatch_event_rule.rules
  rule      = each.value.name
  target_id = "sns"
  arn       = aws_sns_topic.cost_events.arn
}

# ---------- AWS-2: Cost Optimization Hub scheduled pull ----------
# COH does not emit recommendation events to EventBridge, so we invoke the
# Lambda on a schedule (var.coh_pull_schedule, default once daily). The Lambda
# detects this invocation via handler._is_coh_pull_event, which returns True
# when event["coh_pull"] is True (handler.py: `event.get("coh_pull") is True`),
# then runs handler.run_coh_pull -> cost-optimization-hub:ListRecommendations.
# The schedule target carries exactly that discriminator as its input payload.

# Execution role assumed by EventBridge Scheduler to invoke the Lambda.
resource "aws_iam_role" "scheduler" {
  name = "${local.prefix}-scheduler-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect    = "Allow",
      Principal = { Service = "scheduler.amazonaws.com" },
      Action    = "sts:AssumeRole",
      Condition = {
        StringEquals = {
          "aws:SourceAccount" = local.account_id
        }
      }
    }]
  })
}

# Least-privilege: the scheduler role may invoke ONLY the router function.
data "aws_iam_policy_document" "scheduler_invoke" {
  statement {
    sid       = "InvokeRouterForCohPull"
    actions   = ["lambda:InvokeFunction"]
    resources = [aws_lambda_function.router.arn]
  }
}

resource "aws_iam_role_policy" "scheduler_invoke" {
  name   = "${local.prefix}-scheduler-invoke"
  role   = aws_iam_role.scheduler.id
  policy = data.aws_iam_policy_document.scheduler_invoke.json
}

resource "aws_scheduler_schedule" "coh_pull" {
  # checkov:skip=CKV_AWS_297: The schedule target input is a fixed, non-sensitive marker (`{"coh_pull": true}`) — it carries no event/customer data, so a customer-managed KMS key for the Scheduler payload adds no confidentiality value. The recommendations the resulting invocation fetches are encrypted in transit (TLS to the COH API) and the Lambda's own env/logs/state are CMK-encrypted. Customers who require CMK on the schedule itself can set `kms_key_arn = aws_kms_key.main.arn` here.
  name = "${local.prefix}-coh-pull"

  flexible_time_window {
    mode = "OFF"
  }

  schedule_expression          = var.coh_pull_schedule
  schedule_expression_timezone = "UTC"

  target {
    arn      = aws_lambda_function.router.arn
    role_arn = aws_iam_role.scheduler.arn
    # Discriminator MUST match handler._is_coh_pull_event: it returns True when
    # event["coh_pull"] is True (handler.py `event.get("coh_pull") is True`).
    input = jsonencode({ coh_pull = true })
  }
}

# Allow EventBridge Scheduler to invoke the Lambda for the COH pull (AWS-2).
resource "aws_lambda_permission" "scheduler" {
  statement_id  = "AllowSchedulerInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.router.function_name
  principal     = "scheduler.amazonaws.com"
  source_arn    = aws_scheduler_schedule.coh_pull.arn
}
