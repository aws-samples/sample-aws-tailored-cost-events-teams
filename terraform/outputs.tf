output "event_bucket" {
  value = aws_s3_bucket.events.bucket
}

output "sns_topic_arn" {
  value = aws_sns_topic.cost_events.arn
}

output "lambda_name" {
  value = aws_lambda_function.router.function_name
}

output "routing_table" {
  value = aws_dynamodb_table.routing.name
}

output "webhook_ssm_param" {
  value = aws_ssm_parameter.default_webhook.name
}

# Talos a1e659fa: name of the SSM parameter holding the SSO portal hostname (only
# created when var.sso_portal is set). Null when the SSO feature is not opted in.
output "sso_portal_ssm_param" {
  value       = var.sso_portal != "" ? aws_ssm_parameter.sso_portal[0].name : null
  description = "SSM parameter name for the IAM Identity Center portal hostname (Talos a1e659fa: relocated from the Lambda env var). Null when SSO deep links are not enabled."
}

output "log_group" {
  value = aws_cloudwatch_log_group.router.name
}

output "dlq_url" {
  value = aws_sqs_queue.dlq.url
}

# AWS-2: name of the EventBridge Scheduler that triggers the Cost Optimization
# Hub ListRecommendations pull (handler.run_coh_pull).
output "coh_pull_schedule_name" {
  value = aws_scheduler_schedule.coh_pull.name
}

# AWS-1: customers point their Budget's SNS notification at this topic ARN so
# Budgets plain-text alerts reach the Lambda (this is the same topic EventBridge
# Cost Anomaly / Trusted Advisor publish to). Already exposed as sns_topic_arn
# above; re-surfaced here with a Budgets-oriented name for the README/runbook.
output "budgets_sns_topic_arn" {
  value       = aws_sns_topic.cost_events.arn
  description = "Wire your AWS Budget's SNS notification to this topic ARN (AWS-1)."
}
