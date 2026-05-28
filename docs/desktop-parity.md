# Desktop–CLI Parity Matrix (EPIC-27)

This document enumerates all CLI commands and Desktop pages/panels, classifying each as `parity`, `cli-only`, or `desktop-only`.

**Legend**

| Status | Meaning |
|--------|---------|
| `parity` | Feature is available on both surfaces |
| `cli-only` | CLI only — rationale documented |
| `desktop-only` | Desktop only — rationale documented |

---

## Feature Matrix

| Feature | CLI Command | Desktop Page/Panel | Status | Rationale |
|---------|------------|-------------------|--------|-----------|
| Doctor / Diagnostics | `keylatch doctor` | Diagnostics (`/diagnostics`) | parity | Desktop Diagnostics panel added in EPIC-27 |
| Setup wizard | `keylatch setup` | First-run wizard (`/first-run`) | parity | Both offer backend selection (external ref vs local AEAD) and provider connect |
| Connect a provider | `keylatch connect` | Connections → Add Provider | parity | |
| List connections | `keylatch list` | Connections page (`/connections`) | parity | |
| Approval inbox | `keylatch approve list` | Approval Inbox (`/approvals`) | parity | Visual inbox is preferred on Desktop; CLI uses `approve list` |
| Approve request | `keylatch approve <id>` | Approval Inbox → Approve button | parity | |
| Deny request | `keylatch deny <id>` | Approval Inbox → Deny button | parity | |
| Settings / Config | `keylatch config` | Settings (`/settings`) | parity | Desktop exposes operating mode, telemetry, experimental, and approval policy |
| Operating mode | `keylatch modes` | Settings → Operating mode | parity | EPIC-27: mode radio added to Settings |
| Approval TTL | `keylatch config set approval_ttl` | Settings → Approval TTL | parity | |
| Advanced mode toggle | — | Settings → Advanced mode | desktop-only | Visual affordance; no CLI equivalent needed — power settings are individually addressable via CLI flags and env vars |
| Telemetry kill-switch | `KEYLATCH_TELEMETRY_DISABLE=1` | Settings → Telemetry → kill-switch toggle | parity | EPIC-27: toggle added to Desktop |
| Experimental opt-in | `KEYLATCH_EXPERIMENTAL=1` | Settings → Experimental toggle | parity | EPIC-27: toggle added to Desktop |
| Approval policy default | `keylatch policy` | Settings → Approval policy | parity | EPIC-27: policy radio added to Desktop |
| Gateway up/down | `keylatch gateway up/down` | — (stub endpoint exists) | cli-only | Gateway lifecycle management is an infrastructure operation better suited to the terminal; Desktop shows gateway status via ReadinessPill |
| Proxy | `keylatch proxy` | — | cli-only | Low-level runtime plumbing; no interactive UI value |
| Sandbox | `keylatch sandbox` | — | cli-only | Developer/debug feature; terminal-native |
| Call | `keylatch call` | — | cli-only | Direct credential invocation is a scripting primitive |
| Broker | `keylatch broker` | — (dry-run stub exists) | cli-only | Broker lifecycle is a background service operation |
| Run | `keylatch run` | — | cli-only | Shell command wrapping; not meaningful in a GUI |
| Share | `keylatch share` | — | cli-only | Generates shareable references; output is a string — CLI is more ergonomic |
| Allow | `keylatch allow` | — | cli-only | Policy allowlist management; CLI sufficient |
| Get (credential) | `keylatch get` | — | cli-only | Credential retrieval for scripts; would display secrets in GUI — security risk |
| Get masked | `keylatch get --masked` | — | cli-only | Same rationale as `get` |
| Status | `keylatch status` | Dashboard (`/`) | parity | Dashboard surface equivalent of `status` |
| Agent setup | `keylatch agent` | Agent Setup (`/agent`) | parity | |
| Registry | `keylatch registry` | — | cli-only | Provider registry management is a developer workflow |
| Runtime doctor | `keylatch runtime doctor` | Diagnostics → section filter | parity | Diagnostics panel accepts connection filter (existing API) |
| Audit | `keylatch audit` | — | cli-only | Log streaming and compliance export; better as CLI or dedicated tool |
| Security | `keylatch security` | — | cli-only | Security policy management is a sysadmin/CI workflow |
| Verify | `keylatch verify` | — | cli-only | Release verification via cosign; requires binary |
| Keyring | `keylatch keyring` | — | cli-only | Low-level keyring debugging |
| Sessions | `keylatch sessions` | — | cli-only | Session inspection for developers |
| Receipts | `keylatch receipts` | Dashboard (receipt feed) | parity | Dashboard receipt feed shows the same data |
| Trust | `keylatch trust` | — | cli-only | Backend trust pinning is a setup-time CLI operation |
| Grant | `keylatch grant` | — | cli-only | Capability grant management; CLI sufficient |
| Actors | `keylatch actors` | — | cli-only | Actor list is an advanced administrative view |
| Migrate | `keylatch migrate` | — | cli-only | Data migration is a one-time CLI operation |
| Rollback | `keylatch rollback` | — | cli-only | Version rollback is a CLI/CI operation |
| Backup | `keylatch backup` | — | cli-only | Backup is a CLI/scheduled operation |
| Projects | `keylatch projects` | — | cli-only | Project scoping is a CLI multi-tenancy feature |
| Shared secret | `keylatch shared-secret` | — | cli-only | Low-level cryptographic primitive |
| Rules | `keylatch rules` | — | cli-only | Rule management is an administrative CLI workflow |
| Token | `keylatch token` | — | cli-only | Token lifecycle management; scripting use case |
| MCP | `keylatch mcp` | — | cli-only | Model Context Protocol integration is a developer/CLI feature |
| Paths | `keylatch paths` | — | cli-only | Shows filesystem paths; terminal-native |
| Env | `keylatch env` | — | cli-only | Shows environment variables; terminal-native |
| Completion | `keylatch completion` | — | cli-only | Shell completion generation; terminal-native |
| Install guard | `keylatch install-guard` | — | cli-only | One-time shell guard installation |
| Bootstrap | `keylatch bootstrap` | Wizard step 2 (backend bootstrap) | parity | |
| UI | `keylatch ui` | — (launches the Desktop app) | cli-only | `keylatch ui` is the CLI entry point to open Desktop |
| Init | `keylatch init` | — | cli-only | One-time project initialization |
| Versions | `keylatch versions` | — | cli-only | Version management for pinned credentials |
| Destroy version | `keylatch destroy-version` | — | cli-only | Destructive version operation; CLI-only for safety |
| Check expiry | `keylatch check-expiry` | — | cli-only | Expiry scanning; automation/CI use case |
| Backend | `keylatch backend` | Wizard step 2 (backend choice) | parity | Backend selection is part of the wizard |
| Set | `keylatch set` | Settings (various fields) | parity | Desktop Settings exposes the same writable fields |
| Validate | `keylatch validate` | — | cli-only | Template validation; developer workflow |
| Keychain (lifecycle) | `keylatch keychain *` | — | cli-only | Low-level keychain lifecycle; not meaningful in GUI |
| 1Password commands | `keylatch op *` | Connections (ref browser) | parity | PM browse modal provides equivalent discovery |
| Bitwarden commands | `keylatch bw *` | Connections (ref browser) | parity | PM browse modal provides equivalent discovery |

---

## Summary

| Status | Count |
|--------|-------|
| parity | ~20 |
| cli-only | ~35 |
| desktop-only | 1 (Advanced mode toggle) |

Most CLI-only features are either low-level plumbing (proxy, sandbox, broker), security-sensitive (get, get-masked), administrative/CI operations (audit, rollback, backup), or developer utilities (paths, env, completion). These have no interactive GUI value or would be a security regression to expose in the Desktop.

---

## Desktop-only features

### Advanced mode toggle

The **Advanced mode** toggle in Desktop Settings has no direct CLI equivalent. The rationale is that the Desktop surfaces many settings simultaneously in a single panel, and the toggle suppresses power-user options by default to reduce visual noise. On the CLI, power settings are individually addressable via flags, environment variables, and `keylatch config` — there is no need for a global "advanced mode" concept in a terminal context.
