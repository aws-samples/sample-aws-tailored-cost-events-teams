variable "aws_profile" {
  type        = string
  default     = ""
  description = "Named AWS CLI/SDK profile for the provider. Caller-supplied; empty uses the default credential chain (env vars, SSO, instance role)."
}

variable "owner" {
  type        = string
  default     = ""
  description = "Value for the Owner default tag. Caller-supplied; empty leaves the tag value blank."
}

variable "region" {
  type    = string
  default = "us-east-1"
}

variable "name_prefix" {
  type    = string
  default = "cost-events"
}

variable "workload_owner_tag_key" {
  type        = string
  default     = "WorkloadOwner"
  description = "Account-level tag key used to route events to a Teams channel"
}

# Seed rows for the routing table. Leave webhook_ssm_param as PLACEHOLDER to
# disable Teams POST and rely on S3 + simulator for UAT.
variable "reserved_concurrency" {
  type        = number
  default     = 5
  description = "Lambda reserved concurrency cap. Bounds invocation rate (cost + Teams rate-limit safety). Mitigates T-11/T-18."
}

variable "sso_portal" {
  type    = string
  default = ""
  # Talos a1e659fa (FINAL, SSM-backed): OPT-IN only. When empty (the default), NO
  # SSM parameter is created (aws_ssm_parameter.sso_portal has count = 0) and the
  # Lambda gets NO SSO_PORTAL_PARAM_NAME env entry, so the portal hostname is not
  # present anywhere in the function's config. When set, the hostname is stored in
  # SSM at /cost-events/config/sso-portal and read at runtime by
  # routing.get_sso_portal(); only the param NAME (not the value) reaches the
  # Lambda env. The hostname is a low-sensitivity, canonical AWS *.awsapps.com
  # value (T-17). See docs/TALOS_REMEDIATION.md (a1e659fa) for the design.
  description = "IAM Identity Center portal hostname (e.g. 'your-portal.awsapps.com'). OPT-IN: leave empty (default) to emit direct-console links only and create no SSM param. If set, the value is stored in the SSM parameter /cost-events/config/sso-portal (NOT in a Lambda env var) and read at runtime to add a 1-click SSO link."
}

variable "sso_role" {
  type        = string
  default     = "ReadOnlyAccess"
  description = "Default SSO permission set name used when wrapping console URLs in the portal link."
}

variable "routing_seed" {
  type = list(object({
    tag_value         = string
    team_name         = string
    webhook_ssm_param = string
    min_dollar_impact = number
  }))
  default = [
    {
      tag_value         = "__default__"
      team_name         = "test-aws-notify"
      webhook_ssm_param = "/cost-events/webhook/test-aws-notify"
      min_dollar_impact = 0
    }
  ]
}

# AWS-2: Cost Optimization Hub does NOT emit recommendation events to
# EventBridge, so recommendations are obtained on a schedule. This cadence
# drives the EventBridge Scheduler that invokes the Lambda's COH pull path
# (handler.run_coh_pull). Accepts a rate() or cron() schedule expression.
variable "coh_pull_schedule" {
  type        = string
  default     = "rate(1 day)"
  description = "EventBridge Scheduler cadence for the Cost Optimization Hub ListRecommendations pull (AWS-2). rate() or cron(). Default: once daily."
}

# AWS-3: the Trusted Advisor EventBridge event carries no top-level
# `check-category`; we instead filter on `detail.status` (WARN/ERROR) plus an
# allow-list of COST-optimizing `detail.check-name` values. These are the
# documented AWS Trusted Advisor cost-optimization check names. Override to
# narrow/extend the set without code changes.
variable "trusted_advisor_cost_checks" {
  type        = list(string)
  description = "Allow-list of Trusted Advisor cost-optimizing check names the EventBridge rule forwards (AWS-3), combined with detail.status = WARN/ERROR."
  default = [
    "Low Utilization Amazon EC2 Instances",
    "Idle Load Balancers",
    "Underutilized Amazon EBS Volumes",
    "Unassociated Elastic IP Addresses",
    "Amazon RDS Idle DB Instances",
    "Amazon EC2 Reserved Instances Optimization",
    "Amazon EC2 Reserved Instance Lease Expiration",
    "Savings Plan",
    "Amazon Redshift Reserved Node Optimization",
    "Amazon ElastiCache Reserved Node Optimization",
    "Amazon OpenSearch Service Reserved Instance Optimization",
  ]
}
