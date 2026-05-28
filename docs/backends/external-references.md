---
title: External Store References
since: 0.9.0
epic: EPIC-10
---

# External Store References

Keylatch supports **deferred credential resolution** via external secret managers. Instead of storing a plaintext credential in the keylatch vault, you store a URI that points to the credential in an external provider. The credential is resolved at runtime — each time it is needed — so the external PM is always the authoritative source.

Supported URI schemes:

| Scheme | Provider | Required binary |
|--------|----------|----------------|
| `op://` | 1Password | `op` v2+ |
| `aws-sm://` | AWS Secrets Manager | `aws` CLI v2+ |
| `hashivault://` | HashiCorp Vault | `vault` CLI v1.17+ |

---

## How it works

```
keylatch connect anthropic --provider-ref api_key=op://Private/Anthropic/api_key
```

1. Keylatch validates the URI format (dry-run, no external calls at connect time).
2. The URI `op://Private/Anthropic/api_key` is stored verbatim in the keylatch vault.
3. At runtime (`keylatch run`, `keylatch gateway`), keylatch invokes `op read --no-newline op://Private/Anthropic/api_key` and injects the resolved value into the child process environment.
4. The plaintext is never written to disk or retained in memory after the run completes.

### Security invariants

- **S-EXT-3**: No plaintext copy lives in the keylatch vault — the URI is the only artifact stored.
- **S-EXT-4**: Credential rotation in the upstream PM is picked up automatically on next use (no re-enrollment needed).
- **S-EXT-2**: CLI binaries are resolved from PATH; absolute paths may be injected in tests.
- **LLM-session guard**: In a Claude Code / LLM session, all value-bearing commands are blocked. The resolver is never called in an LLM context.

---

## 1Password — `op://`

### URI format

```
op://<vault>/<item>/<field>
```

Examples:
```
op://Private/Anthropic/api_key
op://TeamVault/prod-openai/credential
```

### Prerequisites

```bash
brew install 1password-cli     # macOS
# or download from developer.1password.com/docs/cli/get-started/

op signin                      # authenticate
op whoami                      # verify
```

### Connect

```bash
keylatch connect anthropic --provider-ref api_key=op://Private/Anthropic/api_key
keylatch connect openai    --provider-ref api_key=op://Private/OpenAI/credential
keylatch connect github    --provider-ref token=op://Private/GitHub/token
```

### How keylatch resolves the value

At runtime, keylatch runs:

```
op read --no-newline op://Private/Anthropic/api_key
```

The output is injected into the child process as `ANTHROPIC_API_KEY` (per the provider template).

### Doctor check

```
keylatch doctor
...
  [ ok ] external.op: op_bin=/usr/local/bin/op version=2.30.0
```

If `op` is not signed in:
```
  [warn] external.op: op binary found but authentication status unknown — run: op signin
         fix: op signin
```

---

## AWS Secrets Manager — `aws-sm://`

### URI format

```
aws-sm://<region>/<secret-id>
aws-sm://<region>/<secret-id>#<json-key>
```

- `<region>` is the AWS region (e.g. `us-east-1`, `eu-west-2`).
- `<secret-id>` is the secret name or full ARN.
- `#<json-key>` (optional) extracts a single key from a JSON-encoded SecretString.

Examples:
```
aws-sm://us-east-1/prod/anthropic-api-key
aws-sm://eu-west-1/myapp/credentials#api_key
aws-sm://us-east-1/arn:aws:secretsmanager:us-east-1:123456789012:secret:prod-key-abc123
```

### Prerequisites

```bash
brew install awscli      # macOS
pip install awscli       # or via pip

aws configure            # set credentials + region
aws sts get-caller-identity  # verify
```

Or configure via environment:
```bash
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
export AWS_REGION=us-east-1
```

### Connect

```bash
# Plain secret (SecretString is the full value)
keylatch connect anthropic \
  --provider-ref api_key=aws-sm://us-east-1/prod/anthropic-api-key

# JSON secret (extract a specific key)
keylatch connect openrouter \
  --provider-ref api_key=aws-sm://eu-west-1/myapp/credentials#api_key
```

### How keylatch resolves the value

For a plain secret:
```
aws secretsmanager get-secret-value \
  --region us-east-1 \
  --secret-id prod/anthropic-api-key \
  --query SecretString \
  --output text
```

For a JSON secret with `#api_key` fragment:
1. Retrieve the full SecretString (JSON blob).
2. Unmarshal and extract the `api_key` field.

### Doctor check

```
  [ ok ] external.aws-sm: aws_bin=/usr/local/bin/aws version=2.15.0 — verify credentials: aws sts get-caller-identity
```

If `aws` is not configured:
```
  [warn] external.aws-sm: aws binary found; verify credentials with: aws sts get-caller-identity
         fix: aws configure
```

---

## HashiCorp Vault — `hashivault://`

### URI format

```
hashivault://<mount>/<path>
hashivault://<mount>/<path>#<field>
```

- `<mount>/<path>` is the KV path (e.g. `secret/myapp/config`).
- `#<field>` (optional) specifies which field to read. Defaults to `value`.

Examples:
```
hashivault://secret/myapp/config
hashivault://secret/myapp/config#api_key
hashivault://kv/prod/github#token
```

### Prerequisites

```bash
brew install vault          # macOS
# or download from developer.hashicorp.com/vault/install

export VAULT_ADDR=https://vault.example.com:8200
vault login                 # authenticate (VAULT_TOKEN set)
vault token lookup          # verify
```

### Connect

```bash
keylatch connect anthropic \
  --provider-ref api_key=hashivault://secret/prod/anthropic#api_key

keylatch connect openrouter \
  --provider-ref api_key=hashivault://kv/prod/openrouter
```

### How keylatch resolves the value

```
vault kv get -field=api_key -format=raw secret/prod/anthropic
```

If no `#field` fragment is specified, `value` is used as the field name.

### Doctor check

```
  [ ok ] external.hashivault: vault_bin=/usr/local/bin/vault version=1.17.0 — verify: vault token lookup
```

If `vault` is not authenticated:
```
  [warn] external.hashivault: vault binary found but authentication status unknown — run: vault token lookup
         fix: vault login
```

---

## Combining with other flags

`--provider-ref` and `--field` can be used together on the same `keylatch connect` command:

```bash
keylatch connect myapp \
  --field model=gpt-4o \
  --provider-ref api_key=op://Private/OpenAI/credential
```

Each field can use a different source. A field set by both `--field` and `--provider-ref` is an error.

---

## Updating a reference URI

Re-run `keylatch connect` with `--replace`:

```bash
keylatch connect anthropic \
  --replace \
  --provider-ref api_key=op://Private/Anthropic/new-key
```

Or use the UI at `keylatch ui` → Connections → Edit.

---

## Checking external store health

```bash
keylatch doctor
```

The `External Stores (EPIC-10)` section shows the binary check result for each scheme found in your connections. If no `--provider-ref` connections are configured, the section is skipped.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|-------------|-----|
| `store: required CLI binary not found on PATH` | `op`/`aws`/`vault` not installed | Install the CLI and add it to PATH |
| `op read exited 1: not signed in` | 1Password session expired | `op signin` |
| `aws secretsmanager exited 254: access denied` | IAM policy missing | Add `secretsmanager:GetSecretValue` permission |
| `vault kv get exited 2: permission denied` | Vault token lacks policy | Check VAULT_TOKEN and policy |
| `store: invalid provider-ref URI` | Malformed URI | Check URI format; must match `scheme://something/something` |

---

## Related

- [CLI reference — `keylatch connect`](../cli-reference.md#connect)
- [Doctor reference](../cli-reference.md#doctor)
- [Security model](../security.md)
