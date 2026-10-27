# Desktop App

The Keylatch desktop app (Tauri) bundles the Go backend and a React SPA into a single native window. All API routes are served locally on `127.0.0.1:7890`.

> **Availability:** No desktop installer is shipped in a release. The desktop shell can be built from the `src-tauri` directory. Everywhere else use the CLI; `keylatch ui` serves the same UI in your browser.

## Desktop sign-in

The shell first loads a credential-free `/__bootstrap` page from the sidecar's exact HTTP loopback origin. After that page finishes loading, it requests a single-use token over authenticated local IPC and posts the token in a JSON body. The server sets the HttpOnly session cookie and returns HTTP 204; the WebView then opens `/`. Tokens are absent from the navigation URL and sidecar ready message.

Both platforms use an AF_UNIX socket for IPC. The shell sends the IPC authentication key through an inherited pipe: a dedicated file descriptor on Unix and child stdin on Windows. The Windows key is never passed through an environment variable. Native installed-host verification remains required before shipping an installer.

The sidecar announces readiness after both IPC and HTTP listeners bind. Native approval notifications use a separate IPC-issued bootstrap token and an in-memory session cookie. Polling follows no redirects, bypasses environment proxies, and limits response size and request duration. Only pending, unexpired requests produce notifications; polling errors set the tray error state. Shutdown stops polling and joins its worker before stopping the sidecar.

Before opening the WebView, the shell checks the bootstrap response's enforced Content-Security-Policy and stops the sidecar if the policy is missing or unsafe. After the eight-hour UI session expires, authenticated native IPC can create a replacement session. Old cookies and pending bootstrap tokens stay invalid. Native polling reconnects and the WebView reloads through the one-time bootstrap flow; unsaved form edits can be lost. No approval decision or other mutation is replayed. Ordinary HTTP requests cannot renew an expired session.

The shell launches the bundled `keylatchd` executable beside the application (`keylatchd.exe` on Windows), without searching the working directory or PATH. A missing, linked, or non-executable sidecar is an error. The sidecar binds an available loopback port and reports it after both listeners are ready. Native CI exercises the actual Go/Rust bootstrap exchange, one-use token rejection, IPC key rotation on restart, and shutdown.

The desktop checks its owned sidecar every five seconds. After three failed checks, it stops approval polling, blocks the previous origin and shows the bundled error page while recovering. Recovery permits five attempts with increasing delays; sixty seconds of healthy operation resets that budget. Each replacement gets fresh IPC keys, a newly validated CSP and a new bootstrap exchange before the WebView reconnects. Requests and unsaved edits are not replayed. Quitting interrupts retry delays, joins the workers and stops the owned process.

Each sidecar startup attempt allows 15 seconds and at most 64 KiB of output before a valid ready message. Silence and incomplete lines cannot extend that deadline. Failed startup kills and reaps the child. Shutdown requests the authenticated IPC shutdown method, waits for exit, and escalates only while the child remains unobserved as exited.

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
| Experimental opt-in | Advanced off | `KEYLATCH_EXPERIMENTAL=1` |

Settings always visible:

| Setting | Section | CLI equivalent |
|---------|---------|----------------|
| Operating mode (standard) | Settings | `keylatch modes` |
| Approval policy default | Settings | `keylatch policy` |
| Approval TTL | Settings | `keylatch config set approval_ttl` |

### Operating mode

Three operating modes are available:

| Mode | Advanced only | Description |
|------|:---:|-------------|
| `standard` | | Stable production mode |
| `canary` | yes | Pre-release features; may be unstable |
| `custom` | yes | Fully custom configuration |

Mode changes are persisted via `PUT /api/settings` with `{"operating_mode": "<mode>"}`.

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
| `PUT` | `/api/settings` | Update settings (`approval_ttl_seconds`, `advanced_mode`, `operating_mode`, `experimental`, `approval_policy`) |
| `GET` | `/api/doctor` | Run health checks (optionally filtered by `connection=` and `verbose=true`) |
| `GET` | `/diagnostics` | Diagnostics page — full doctor report with section grouping and quiet-mode toggle |
