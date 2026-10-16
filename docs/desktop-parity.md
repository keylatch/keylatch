# Desktop and CLI parity

The desktop shell is built from source; **no desktop installer is shipped in a release**. This
page lists each CLI command and each desktop page and says whether a feature exists on both
surfaces (`parity`), on the CLI only (`cli-only`) or on the desktop only (`desktop-only`). The
browser UI that `keylatch ui` opens serves the same pages.

## Feature matrix

| Feature | CLI command | Desktop page or panel | Status | Rationale |
|---------|------------|-----------------------|--------|-----------|
| Doctor and diagnostics | `keylatch doctor` | Diagnostics (`/diagnostics`) | parity | |
| Setup wizard | `keylatch setup` | First-run wizard (`/first-run`) | parity | Both offer backend selection (external reference or local encrypted storage) and provider connect |
| Connect a provider | `keylatch connect` | Connections, Add Provider | parity | |
| List connections | `keylatch list` | Connections (`/connections`) | parity | |
| Approval inbox | `keylatch approve list` | Approval Inbox (`/approvals`) | parity | The visual inbox is preferred on the desktop |
| Approve a request | `keylatch approve <id>` | Approval Inbox, Approve | parity | |
| Deny a request | `keylatch deny <id>` | Approval Inbox, Deny | parity | |
| Settings and config | `keylatch config` | Settings (`/settings`) | parity | The desktop exposes operating mode, experimental opt-in and approval policy |
| Operating mode | `keylatch modes` | Settings, Operating mode | parity | |
| Approval TTL | `keylatch config set approval_ttl` | Settings, Approval TTL | parity | |
| Advanced mode toggle | none | Settings, Advanced mode | desktop-only | A visual affordance; power settings are individually addressable by flag and variable on the CLI |
| Experimental opt-in | `KEYLATCH_EXPERIMENTAL=1` | Settings, Experimental | parity | |
| Approval policy default | `keylatch policy` | Settings, Approval policy | parity | |
| Gateway up and down | `keylatch gateway up`, `keylatch gateway down` | none | cli-only | An infrastructure operation suited to the terminal; the desktop shows gateway status |
| Proxy | `keylatch proxy` | none | cli-only | Low-level plumbing |
| Call | `keylatch call` | none | cli-only | A scripting primitive |
| Broker | `keylatch broker` | none | cli-only | A background service operation |
| Run | `keylatch run` | none | cli-only | Shell command wrapping |
| Allow | `keylatch allow` | none | cli-only | Policy allowlist management |
| Get a credential | `keylatch get` | none | cli-only | Would display secrets in a GUI |
| Status | `keylatch status` | Dashboard (`/`) | parity | |
| Agent setup | `keylatch agent` | Agent Setup (`/agent`) | parity | |
| Registry | `keylatch registry` | none | cli-only | A developer workflow |
| Runtime doctor | `keylatch runtime doctor` | Diagnostics, section filter | parity | |
| Audit | `keylatch audit` | none | cli-only | Log inspection and verification |
| Security | `keylatch security` | none | cli-only | A sysadmin and CI workflow |
| Verify | `keylatch verify` | none | cli-only | Release verification with cosign |
| Keyring | `keylatch keyring` | none | cli-only | Low-level debugging |
| Grant | `keylatch grant` | none | cli-only | Capability grant management |
| Actors | `keylatch actors` | none | cli-only | An administrative view |
| Migrate | `keylatch migrate` | none | cli-only | A one-time operation |
| Rollback | `keylatch rollback` | none | cli-only | A CLI and CI operation |
| Backup | `keylatch backup` | none | cli-only | A CLI or scheduled operation |
| Token | `keylatch token` | none | cli-only | Token lifecycle for scripts |
| MCP | `keylatch mcp` | none | cli-only | A developer feature |
| Paths | `keylatch paths` | none | cli-only | Terminal-native |
| Env | `keylatch env` | none | cli-only | Terminal-native |
| Completion | `keylatch completion` | none | cli-only | Terminal-native |
| Install guard | `keylatch install-guard` | none | cli-only | One-time guard installation |
| Bootstrap | `keylatch bootstrap` | Wizard step 2 | parity | |
| UI | `keylatch ui` | launches the browser UI | cli-only | The CLI entry point |
| Init | `keylatch init` | none | cli-only | One-time project initialization |
| Versions | `keylatch versions` | none | cli-only | Version management for pinned credentials |
| Destroy version | `keylatch destroy-version` | none | cli-only | Destructive; CLI only for safety |
| Check expiry | `keylatch check-expiry` | none | cli-only | An automation use case |
| Backend | `keylatch backend list` | Wizard step 2 | parity | |
| Set | `keylatch set` | Settings | parity | |
| Validate | `keylatch validate` | none | cli-only | Template validation |
| 1Password commands | `keylatch op-list` | Connections, reference browser | parity | The reference browser gives the same discovery |
| Bitwarden commands | `keylatch bw-list` | Connections, reference browser | parity | The reference browser gives the same discovery |

## Desktop-only feature

The **Advanced mode** toggle in Settings has no CLI equivalent. It hides power-user options by
default to reduce noise. On the CLI those options are individual flags, variables and
`keylatch config` keys, so a global switch has no purpose.
