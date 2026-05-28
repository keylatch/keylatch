# Desktop App

The KeyLatch desktop app (Tauri) bundles the Go backend and a React SPA into a single native window. All API routes are served locally on `127.0.0.1:7890`.

## Connections page

The **Connections** page (`/connections`) replaces the old single-provider `<select>` with a multi-provider card grid.

### ProviderList

`ProviderList` renders all wired provider connections simultaneously — there is no "active" provider. Multiple providers can be connected at once (matching `keylatch modes`).

- Cards are ordered by last-modified descending (server-controlled).
- Clicking **+ Add Provider** opens the `ProviderWizard` sheet.
- Each card shows per-field storage mode badges: `direct` (encrypted in vault) or `ref:<scheme>` (resolved from a password manager at runtime).

### ProviderWizard

A two-step slide-in wizard (Sheet) for adding a new connection:

1. **Choose provider** — select from the provider template catalogue (`GET /v1/providers`).
2. **Configure fields** — set each field to `Store directly` (password input) or `From password manager` (reference URI + Browse button).

### PMBrowseModal

Clicking **Browse** on a reference field opens `PMBrowseModal`. The modal calls `GET /api/pm-browse?pm=op|aws_sm|hashivault` and shows one of three states:

| State | What is shown |
|-------|--------------|
| Loading | Spinner with `aria-busy` |
| Authenticated | Scrollable item list. Clicking an item builds the reference URI and places it in the manual input. |
| Unauthenticated | Sign-in hint (`op signin`, `aws configure`, `vault login`) with a Copy button. |

A manual URI input is always available as a fallback regardless of auth state. Entering a URI directly and clicking **Use this URI** validates the format client-side before passing it upstream.

### Reference URI format

Valid reference URIs must match the pattern `^(op|aws-sm|hashivault)://[^/][^/]*/[^/].*`:

| Scheme | Example |
|--------|---------|
| 1Password | `op://Personal/MyItem/api_key` |
| AWS Secrets Manager | `aws-sm://us-east-1/my-secret-id` |
| HashiCorp Vault | `hashivault://secret/myapp/config#api_key` |

Malformed URIs are rejected client-side with an inline error. The server also validates and returns HTTP 422 with a field-level error object on invalid submissions.

### Doctor health indicator

Each `ProviderCard` shows a coloured status dot in the top-right corner:

| Colour | Meaning |
|--------|---------|
| Grey | Health check pending |
| Green | All checks passed (exit 0) |
| Yellow | Warnings detected (exit 1) |
| Red | Errors detected (exit 2) |

The dot polls `GET /api/doctor?connection=<provider>&json=true` on mount and every 60 seconds. Polls are debounced: a new request is never started while one is in flight. Clicking the dot expands an inline table of check results with fix hints.

## Approval inbox

The **Approval Inbox** page (`/approvals`) lists pending agent approval requests. Each request shows:

- The agent name and requested action
- A risk label and readiness pill
- Approve / Deny buttons

Approved requests generate a signed receipt visible on the **Dashboard**.

## Settings

### Approval TTL

Controls how long a pending request waits before being auto-denied (server-enforced upper bound: 3 600 s). Navigate to **Settings > Approval TTL**.

### Advanced mode

The **Advanced mode** toggle (`Settings > Advanced mode`) enables additional settings and diagnostic panels across the SPA. The state is persisted server-side and round-trips across sessions (`PUT /api/settings` with `{"advanced_mode": true|false}`).

When `advanced_mode` is off (default), power-user and developer settings are hidden to reduce visual noise for standard users.

Settings gated behind Advanced mode:

| Setting | When hidden | CLI equivalent |
|---------|-------------|----------------|
| Canary operating mode | Advanced off | `keylatch modes` |
| Custom operating mode | Advanced off | `keylatch modes` |
| Telemetry kill-switch | Advanced off | `KEYLATCH_TELEMETRY_DISABLE=1` |
| Experimental opt-in | Advanced off | `KEYLATCH_EXPERIMENTAL=1` |

Settings always visible:

| Setting | Section | CLI equivalent |
|---------|---------|----------------|
| Operating mode (standard / telemetry) | Settings | `keylatch modes` |
| Approval policy default | Settings | `keylatch policy` |
| Approval TTL | Settings | `keylatch config set approval_ttl` |

### Operating mode

Four operating modes are available:

| Mode | Advanced only | Description |
|------|:---:|-------------|
| `standard` | | Stable production mode |
| `telemetry` | | Standard plus anonymous usage telemetry |
| `canary` | yes | Pre-release features; may be unstable |
| `custom` | yes | Fully custom configuration |

Mode changes are persisted via `PUT /api/settings` with `{"operating_mode": "<mode>"}`.

### Telemetry kill-switch

The **Telemetry** toggle disables all usage telemetry collection. Equivalent to exporting `KEYLATCH_TELEMETRY_DISABLE=1`. Only visible when Advanced mode is on.

Changes take effect immediately for the current process. Set `KEYLATCH_TELEMETRY_DISABLE=1` in your shell environment for persistence across restarts.

### Experimental features

The **Experimental features** toggle enables gated pre-release functionality. Equivalent to exporting `KEYLATCH_EXPERIMENTAL=1`. Only visible when Advanced mode is on.

Changes take effect immediately for the current process. Set `KEYLATCH_EXPERIMENTAL=1` in your shell environment for persistence across restarts.

### Approval policy

The **Approval policy** radio sets the default action when an agent requests credential access:

| Policy | Description |
|--------|-------------|
| `prompt` | Always ask before approving (default) |
| `first-run` | Auto-approve once per session; deny subsequent requests |
| `trust` | Auto-approve all requests from this connection |

## API surface

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/connections` | List all wired connections (value-free) |
| `POST` | `/api/connections` | Create a new connection |
| `POST` | `/api/connections/clear` | Delete all connections (requires `"delete all"` confirmation) |
| `PUT` | `/api/connections/:name` | Update field modes / values |
| `DELETE` | `/api/connections/:name` | Remove a connection |
| `GET` | `/api/password-managers` | Detect available PM CLIs (cached per session) |
| `GET` | `/api/pm-browse?pm=op\|aws_sm\|hashivault` | List items from a PM CLI |
| `GET` | `/api/settings` | Load current settings |
| `PUT` | `/api/settings` | Update settings (`approval_ttl_seconds`, `advanced_mode`, `operating_mode`, `telemetry_disable`, `experimental`, `approval_policy`) |
| `GET` | `/api/doctor` | Run health checks (optionally filtered by `connection=` and `verbose=true`) |
| `GET` | `/diagnostics` | Diagnostics page — full doctor report with section grouping and quiet-mode toggle |
