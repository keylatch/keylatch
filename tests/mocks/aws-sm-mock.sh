#!/bin/sh
# aws-sm-mock.sh — mock AWS CLI for EPIC-10 integration tests.
#
# Simulates `aws secretsmanager get-secret-value` and returns a canary SecretString.
# All other invocations exit 1.
#
# Usage (on PATH as `aws`):
#   aws secretsmanager get-secret-value --region us-east-1 --secret-id my-secret --query SecretString --output text
#   → prints AWSSM_MOCK_CANARY_VALUE_TEST and exits 0

AWSSM_CANARY="AWSSM_MOCK_CANARY_VALUE_TEST"

if [ $# -lt 1 ]; then
    echo "mock aws: unexpected invocation: $*" >&2
    exit 1
fi

service="$1"
shift

if [ "$service" != "secretsmanager" ]; then
    echo "mock aws: unsupported service: $service" >&2
    exit 1
fi

subcommand="$1"
shift

if [ "$subcommand" != "get-secret-value" ]; then
    echo "mock aws secretsmanager: unsupported subcommand: $subcommand" >&2
    exit 1
fi

# Parse remaining flags to confirm --secret-id is present.
secret_id=""
output_fmt="json"
query=""
while [ $# -gt 0 ]; do
    case "$1" in
        --secret-id)
            secret_id="$2"
            shift 2
            ;;
        --output)
            output_fmt="$2"
            shift 2
            ;;
        --query)
            query="$2"
            shift 2
            ;;
        --region)
            shift 2
            ;;
        *)
            shift
            ;;
    esac
done

if [ -z "$secret_id" ]; then
    echo "mock aws: get-secret-value requires --secret-id" >&2
    exit 1
fi

# When --output text --query SecretString: return plain canary.
if [ "$output_fmt" = "text" ] && [ "$query" = "SecretString" ]; then
    printf '%s\n' "$AWSSM_CANARY"
    exit 0
fi

# Otherwise return JSON envelope.
printf '{"SecretString":"%s"}\n' "$AWSSM_CANARY"
exit 0
