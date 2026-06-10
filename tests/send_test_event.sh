#!/usr/bin/env bash
# Invoke the cost-router Lambda directly with a synthetic event wrapped in
# the SNS envelope it would normally receive.
#
# Why direct invoke: EventBridge reserves source="aws.*" for AWS services, so
# we can't inject anomaly events via `aws events put-events`. Invoking Lambda
# with the exact Records[].Sns.Message shape tests every path (normalize ->
# routing -> card -> S3 -> optional Teams POST) end to end.
#
# Usage: ./tests/send_test_event.sh <fixture-name>
#   e.g. ./tests/send_test_event.sh cost_anomaly
set -euo pipefail

# Profile is caller-supplied via the AWS_PROFILE env var (or leave unset to use
# the default credential chain: env vars, SSO, instance role, etc.).
AWS_PROFILE="${AWS_PROFILE:-}"
REGION="${AWS_DEFAULT_REGION:-us-east-1}"
FIXTURE="${1:-cost_anomaly}"
HERE="$(cd "$(dirname "$0")" && pwd)"
FILE="$HERE/synthetic_events/${FIXTURE}.json"

if [[ ! -f "$FILE" ]]; then
  echo "fixture not found: $FILE" >&2
  echo "available:"; ls "$HERE/synthetic_events/"
  exit 1
fi

LAMBDA=$(terraform -chdir="$HERE/../terraform" output -raw lambda_name)

# Convert put-events-style fixture (Source/DetailType/Detail-string) into the
# EventBridge-on-the-wire shape (source/detail-type/detail-object), then wrap
# in an SNS Records envelope.
EB_EVENT=$(jq '{
  source: .Source,
  "detail-type": .DetailType,
  account: "000000000000",
  region: "us-east-1",
  detail: (.Detail | fromjson)
}' "$FILE")

PAYLOAD=$(jq -n --argjson eb "$EB_EVENT" '{
  Records: [{
    EventSource: "aws:sns",
    Sns: {
      Message: ($eb | tostring)
    }
  }]
}')

# Only pass --profile when the caller supplied one; otherwise fall back to the
# default credential chain.
PROFILE_ARG=()
if [[ -n "$AWS_PROFILE" ]]; then
  PROFILE_ARG=(--profile "$AWS_PROFILE")
fi

TMP=$(mktemp)
echo "# invoking $LAMBDA with fixture=$FIXTURE"
aws lambda invoke \
  ${PROFILE_ARG[@]+"${PROFILE_ARG[@]}"} \
  --region "$REGION" \
  --function-name "$LAMBDA" \
  --cli-binary-format raw-in-base64-out \
  --payload "$PAYLOAD" \
  --log-type Tail \
  "$TMP" \
  --query 'LogResult' --output text | base64 -D 2>/dev/null || true

echo "# response:"
cat "$TMP"; echo
rm -f "$TMP"
