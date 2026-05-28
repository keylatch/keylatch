#!/bin/sh
# op-mock.sh — mock 1Password CLI for EPIC-10 integration tests.
#
# Simulates `op read --no-newline op://...` and exits 0 with a canary value.
# All other invocations exit 1 to guard against unexpected usage.
#
# Usage (on PATH as `op`):
#   op read --no-newline op://Private/Anthropic/api_key
#   → prints OP_MOCK_CANARY_VALUE_TEST and exits 0

OP_CANARY="OP_MOCK_CANARY_VALUE_TEST"

# Require at least two arguments: <subcommand> <arg>
if [ $# -lt 2 ]; then
    echo "mock op: unexpected invocation: $*" >&2
    exit 1
fi

subcommand="$1"
shift

case "$subcommand" in
    read)
        # Accept: op read [--no-newline] op://...
        # Skip flags.
        ref=""
        for arg in "$@"; do
            case "$arg" in
                --*) ;;
                op://*) ref="$arg" ;;
                *) ;;
            esac
        done
        if [ -z "$ref" ]; then
            echo "mock op: read requires an op:// reference" >&2
            exit 1
        fi
        printf '%s' "$OP_CANARY"
        exit 0
        ;;
    whoami)
        # Used by doctor external check.
        echo "mock-user@example.com"
        exit 0
        ;;
    *)
        echo "mock op: unsupported subcommand: $subcommand" >&2
        exit 1
        ;;
esac
