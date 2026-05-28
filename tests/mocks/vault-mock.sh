#!/bin/sh
# vault-mock.sh — mock HashiCorp Vault CLI for EPIC-10 integration tests.
#
# Simulates `vault kv get -field=<field> <path>` and returns a canary value.
# Also handles `vault token lookup` for doctor external checks.
# All other invocations exit 1.
#
# Usage (on PATH as `vault`):
#   vault kv get -field=api_key secret/myapp/config
#   → prints VAULT_MOCK_CANARY_VALUE_TEST and exits 0

VAULT_CANARY="VAULT_MOCK_CANARY_VALUE_TEST"

if [ $# -lt 1 ]; then
    echo "mock vault: unexpected invocation: $*" >&2
    exit 1
fi

subcommand="$1"
shift

case "$subcommand" in
    kv)
        action="$1"
        shift
        if [ "$action" != "get" ]; then
            echo "mock vault kv: unsupported action: $action" >&2
            exit 1
        fi
        # Parse -field=<name> or -field <name> and path.
        field="value"
        path=""
        for arg in "$@"; do
            case "$arg" in
                -field=*)
                    field="${arg#-field=}"
                    ;;
                -format=*)
                    # Accept -format=raw or -format=json — always return plain text.
                    ;;
                -*)
                    # Skip other flags.
                    ;;
                *)
                    path="$arg"
                    ;;
            esac
        done
        if [ -z "$path" ]; then
            echo "mock vault kv get: requires a path argument" >&2
            exit 1
        fi
        printf '%s\n' "$VAULT_CANARY"
        exit 0
        ;;
    token)
        action="$1"
        if [ "$action" = "lookup" ]; then
            printf 'Key                 Value\n---                 -----\naccessor            mock-accessor\ndisplay_name        mock-token\n'
            exit 0
        fi
        echo "mock vault token: unsupported action: $action" >&2
        exit 1
        ;;
    *)
        echo "mock vault: unsupported subcommand: $subcommand" >&2
        exit 1
        ;;
esac
