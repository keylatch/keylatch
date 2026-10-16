# Keylatch

**Keylatch keeps API keys out of model context and out of casual agent reach.** It stores credentials in an encrypted backend (1Password, Bitwarden, or an encrypted file) and injects them into subprocesses at run time. On Linux with systemd, the broker daemon keeps the keys under a separate OS user: agents get capabilities, never keys.

> **In-user mode is not a security boundary.** Without the broker, Keylatch runs as the same user as your agent. Detection, the guard hook and the policy file raise the cost of leaking a key; a determined agent running as you can still read what you can read. On Linux, `sudo keylatch broker install` and `keylatch broker adopt` move the keys out of your account (see [the broker guide](docs/guides/broker-linux.md)). See [SECURITY.md](SECURITY.md) and [docs/security.md](docs/security.md) for what is and is not protected.

```
Encrypted store (1Password / Bitwarden / file)
  -> Keylatch core (policy + audit)
    -> keylatch run injects scoped values into a subprocess
      -> (gateway modes) local gateway -> provider API
```

## Using Keylatch with Claude Code?

```bash
keylatch install-guard claude-code
```

This wires a `PreToolUse` hook into Claude Code that blocks credential-access patterns before they run. See [docs/integrations/claude-code.md](docs/integrations/claude-code.md). The guard ships for Claude Code in v0.10.0; guards for the other agents arrive in v0.13.0.

## Install

Keylatch ships as a **CLI** (macOS, Windows, Linux) and a **Docker image**. `keylatch ui` opens the browser GUI. No desktop installer is shipped.

### Homebrew (macOS / Linux)

```bash
brew install keylatch/tap/keylatch
```

### Scoop (Windows)

```powershell
scoop bucket add keylatch https://github.com/keylatch/scoop
scoop install keylatch
```

### Binary download

Download `keylatch_<version>_<os>_<arch>.tar.gz` (`.zip` on Windows) from the [releases page](https://github.com/keylatch/keylatch/releases) and verify it against `keylatch-<version>_checksums.txt`:

```bash
sha256sum --check --ignore-missing keylatch-<version>_checksums.txt
```

Verify the checksums file with cosign (keyless signing through GitHub Actions OIDC):

```bash
cosign verify-blob \
  --certificate-identity-regexp '^https://github\.com/keylatch/keylatch/\.github/workflows/(release\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+(-(alpha|beta|rc)\.[0-9]+)?|attest-release\.yml@refs/heads/main)$' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  --certificate keylatch-<version>_checksums.txt.pem \
  --signature keylatch-<version>_checksums.txt.sig \
  keylatch-<version>_checksums.txt
```

v0.9.7 shipped without signatures, SBOMs or provenance; see the [advisory](docs/security/advisory-v0.9.7-unsigned-release.md) and [Verifying releases](docs/verifying-releases.md). The CLI is not OS code-signed: install through Homebrew or Scoop, or for a raw macOS download run `xattr -dr com.apple.quarantine ./keylatch`.

### Docker

```bash
docker pull ghcr.io/keylatch/keylatch:latest
docker run --rm ghcr.io/keylatch/keylatch:latest --help
```

### Build from source

```bash
go install github.com/keylatch/keylatch/cmd/keylatch@latest
```

A `go install` build has no embedded browser UI (`keylatch ui` serves a placeholder page) and takes its version from the Go build information. Release builds embed the UI and the tag version.

## Quickstart

```bash
keylatch setup                              # backend, default-deny policy, doctor report
keylatch connect openrouter                 # store a credential
keylatch run openrouter --dry-run -- node script.js   # preview what would be injected
keylatch run openrouter -- node script.js   # run with credentials injected
keylatch doctor                             # verify the setup
```

A step-by-step walk-through lives in [docs/guides/secure-agent-setup.md](docs/guides/secure-agent-setup.md); configuration examples are in [examples/](examples/).

## Core concepts

### Backends

`keylatch backend list` prints every backend with its support tier.

| Backend | Tier | Notes |
|---------|------|-------|
| `bw` | supported | Bitwarden CLI, including Vaultwarden servers |
| `op` | supported | 1Password CLI |
| `file` | supported | encrypted in-user file store |
| `vault` | community | HashiCorp Vault KV; Go SDK, no live suite yet |
| `awssm` | community | AWS Secrets Manager; no live suite yet |
| `gcpsm` | community | Google Cloud Secret Manager; no live suite |
| `azurekv` | community | Azure Key Vault; no live suite |
| `doppler` | community | Doppler; no live suite |
| `infisical` | community | Infisical; no live suite |
| `opconnect` | community | 1Password Connect server; no live suite |
| `keychain` | deprecated | macOS Keychain secrets; reads the value from stdin; the Keychain stays a key store, not a backend |
| `keeper` | deprecated | vendor CLI sessions are directly callable by an agent |
| `lastpass` | deprecated | vendor CLI sessions are directly callable by an agent |
| `proton-pass` | deprecated | vendor CLI sessions are directly callable by an agent |

Set the backend with `keylatch config set backend <name>`. `KEYLATCH_BACKEND` is read only when `backend` is unset in `config.json`: the config value wins. The configuration directory is `~/.config/keylatch` on Linux and `~/.keylatch` on macOS and Windows; `keylatch paths` prints the locations, and [docs/configuration.md](docs/configuration.md) lists every key.

### Runtime modes

`keylatch run` controls how credentials reach a child process. Run `keylatch modes` for what is available now.

| Mode | Flag | Description |
|------|------|-------------|
| `gateway_typed` | `--runtime gateway_typed` | Default. The child gets a session token and a gateway URL; the gateway holds the real key. |
| `gateway_sdk` | `--runtime gateway_sdk` | Same exchange for SDKs that accept a custom base URL. |
| `direct_brokered` | `--runtime direct_brokered` | A scoped, short-lived token from a provider that supports minting. |

`gateway_proxy` (CONNECT interception, `keylatch proxy up`) is experimental and not a run mode you can rely on yet. See [docs/runtime-modes.md](docs/runtime-modes.md).

### LLM session guard

Keylatch recognises these agent harnesses:

| Harness | Detected by |
|---------|-------------|
| [Claude Code](docs/integrations/claude-code.md) | `CLAUDECODE`, `CLAUDE_CODE_ENTRYPOINT` |
| Codex CLI | `CODEX_SANDBOX`, `CODEX_SANDBOX_NETWORK_DISABLED` |
| Cursor | `CURSOR_AGENT`, `CURSOR_TRACE_ID` |
| Gemini CLI | `GEMINI_CLI` |
| OpenCode | `OPENCODE` |
| Aider | none; set `CREDENTIALS_LLM_SESSION=aider` in your shell rc |
| GitHub Copilot CLI | none; set `CREDENTIALS_LLM_SESSION=copilot` in your shell rc |

Any tool that sets `CREDENTIALS_LLM_SESSION` to a non-empty value is treated as an agent session. Run `keylatch env` for the full list of variables.

> **Detection is a convenience, not a security boundary.** These variables live in the agent's own environment: an agent can unset them, and editor terminals can carry them for a human, in which case Keylatch errs toward restricting. Human-only commands (`approve`, `deny`) additionally need an interactive terminal on stdin. A boundary that holds against a same-user agent needs a broker running outside the agent's account plus proof of human presence; that arrives from v0.11.0.

When a session is detected, `keylatch get` is blocked (exit 2), `keylatch run` is allowed for the available modes, `keylatch ui` is limited to read-only status, and `keylatch gateway token create` rejects unlimited tokens.

### Local gateway

Agent processes receive a short-lived session token and a gateway URL, not the provider key.

```bash
keylatch gateway init                       # generate the signing key
keylatch gateway up --detach                # listen on 127.0.0.1:7878
keylatch gateway token create claude-code --allow openrouter.chat --ttl 1h
keylatch gateway status
keylatch gateway down
```

### Browser UI

```bash
keylatch ui            # 127.0.0.1:7890
keylatch ui --no-open  # print the URL only
```

## CLI reference

The full reference is [docs/cli-reference.md](docs/cli-reference.md). The common commands:

```bash
keylatch setup                               # guided first-time setup
keylatch bootstrap [--dry-run] [--json]      # scriptable initialisation
keylatch doctor [--json]                     # diagnose configuration and environment
keylatch connect <provider>                  # store a credential
keylatch connect <provider> --provider-ref api_key=op://vault/item/field
keylatch list                                # list connections
keylatch status                              # dashboard
keylatch test <connection>                   # test one connection
keylatch run <connection> -- <cmd>           # run with credentials injected
keylatch run <connection> --clean-env -- <cmd>
keylatch call <connection> <action>          # one provider action
keylatch policy init                         # write the default-deny policy
keylatch install-guard claude-code           # install the guard hook
keylatch audit                               # view the audit log
keylatch backend list                        # backends and support tiers
keylatch backup                              # encrypted backup (no restore command)
keylatch completion zsh                      # shell completion
```

## Exit codes

| Code | Name | Meaning |
|------|------|---------|
| `0` | OK | Success |
| `1` | UserError | Invalid input or configuration |
| `2` | SecurityBlock | Blocked by the LLM-session guard |
| `3` | Missing | Resource not found |
| `4` | BackendUnavailable | Credential backend unreachable |
| `5` | OperationFailed | Internal or unrecoverable error |

## Backends in CI

```bash
export OP_SERVICE_ACCOUNT_TOKEN="ops_..."
keylatch bootstrap --backend op
```

Keylatch refuses a backend credential exported in the environment unless
`backends.<id>.allow_env_credentials` is `true`, so a CI job that exports one sets
that in its config. On a workstation, store the credential with
`keylatch backend login <id>` instead; it is kept wrapped by the KEK.

Keylatch never needs `BW_SESSION` in your shell, and it removes it (with other
backend credentials) from the environment of every command it runs.

| Variable | Purpose |
|----------|---------|
| `KEYLATCH_OP_VAULT` | 1Password vault name (default `Keylatch`) |
| `KEYLATCH_OP_BIN` | Path to the `op` binary |
| `KEYLATCH_BW_SERVER` | Vaultwarden server URL (`https://` only) |
| `KEYLATCH_BW_BIN` | Path to the `bw` binary |

More in [docs/backends/index.md](docs/backends/index.md) and [docs/integration/ci.md](docs/integration/ci.md).

## External store references (`--provider-ref`)

Resolve a field from an external store instead of typing it:

| URI scheme | Store |
|------------|-------|
| `op://vault/item/field` | 1Password |
| `bw://<org-or-personal>/<collection>/<item>/<field>` | Bitwarden |
| `aws-sm://region/secret[#key]` | AWS Secrets Manager |
| `hashivault://mount/path[#field]` | HashiCorp Vault |

```bash
keylatch connect openrouter --provider-ref api_key=op://Keylatch/openrouter/api_key
```

## Child environment hygiene

`keylatch run` strips `KEYLATCH_*` configuration variables from the child. `--clean-env` reduces it further to `PATH`, `HOME`, `USER`, `SHELL`, `TERM`, `LANG` and the injected variables; `--extra NAME` keeps one more.

## Security

- Secret values are never echoed to stdout or stderr.
- The audit log records every read, write and injection without values.
- Detection blocks casual extraction; it does not stop a same-user agent that tries to evade it.
- Releases are cosign-signed with SLSA provenance, except v0.9.7; see [SECURITY.md](SECURITY.md).
- Keylatch sends no telemetry ([docs/telemetry.md](docs/telemetry.md)).

For vulnerability disclosure, SBOMs and artifact verification see [SECURITY.md](SECURITY.md).

## Docker

The image ships only the `keylatch` CLI. It runs as the `nonroot` user (UID 65532), so point `KEYLATCH_CONFIG_DIR` at a persisted directory under that user's home:

```bash
docker run --rm \
  -e KEYLATCH_CONFIG_DIR=/home/nonroot/.keylatch \
  -v keylatch-data:/home/nonroot/.keylatch \
  ghcr.io/keylatch/keylatch:latest doctor --json
```

Backends that call a vendor CLI (`op`, `bw`) do not work in the image, which has no shell and no libc; use a native install for them.

## Development

```bash
# Prerequisites: Go 1.26+, Bun 1.3+ (for web)
make build
make test
make lint
make check
```

Features that are not finished compile only with the `experimental` build tag; see [docs/experimental.md](docs/experimental.md).

## Documentation

- [Getting started](docs/getting-started.md), [Installation](docs/installation.md), [CLI reference](docs/cli-reference.md)
- [Configuration](docs/configuration.md), [Environment variables](docs/cli/environment.md)
- [Operating modes](docs/operating-modes.md), [Runtime modes](docs/runtime-modes.md), [Proxy](docs/proxy.md), [Call](docs/call.md)
- [Security](docs/security.md), [Threat model](docs/security/threat-model.md), [Verifying releases](docs/verifying-releases.md)
- [Secure agent setup guide](docs/guides/secure-agent-setup.md), [The Linux broker](docs/guides/broker-linux.md)
- [Integration guides](docs/integration/README.md) and [per-agent guard guides](docs/integrations/)
- [Desktop app](docs/desktop-app.md), [Desktop parity](docs/desktop-parity.md), [Telemetry](docs/telemetry.md), [Experimental features](docs/experimental.md)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Apache-2.0, see [LICENSE](LICENSE).
