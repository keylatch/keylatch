# Sandbox Mode (EPIC-24)

The `direct_classic_sandboxed` runtime mode injects raw credentials into a child subprocess that is locked inside an OS sandbox. This provides isolation at the process boundary: the child process can use the credential but cannot read `~/.keylatch/` or exfiltrate it through the filesystem.

Related: [Runtime modes](./runtime-modes.md), `keylatch sandbox doctor`, `keylatch sandbox run`

## Platform Support

| Platform | Sandbox primitive |
|----------|------------------|
| Linux | [bubblewrap](https://github.com/containers/bubblewrap) (`bwrap`) |
| macOS | `sandbox-exec` (built-in, no install required) |
| Windows | Not supported — returns `ErrModeNotAvailable` |

## Installing bwrap (Linux)

```bash
# Debian / Ubuntu
sudo apt-get install -y bubblewrap

# Fedora / RHEL
sudo dnf install -y bubblewrap

# Arch Linux
sudo pacman -S bubblewrap
```

Verify installation:

```bash
bwrap --version
keylatch sandbox doctor
```

## Deny-List Contract

The following paths are **always** denied inside the sandbox, regardless of manifest configuration:

- `~/.keylatch/` — the keylatch config and vault directory

Denied paths are bind-mounted read-only to `/dev/null` equivalent inside the sandbox so that accidental reads fail with a clear error rather than silently returning empty data.

The deny list is enforced by `internal/sandbox/manifest.go` (`ValidateBindMounts`) and the platform driver before execing the child process.

## Executable Hash Check

Before launching the sandbox, keylatch computes the SHA-256 digest of the target executable and verifies it against a pre-configured expected hash (when provided via the sandbox manifest). This prevents the credential from being injected into a replaced or tampered binary.

Hash computation is streaming (no full-file buffer) so it is safe for large executables.

If the hash does not match, the launch is refused and an audit event (`sandbox.launch_refused`) is emitted with the `expected` and `actual` digests.

To compute the expected hash for a binary:

```bash
sha256sum /path/to/your-binary
```

## Diagnosing Sandbox Health

```bash
keylatch sandbox doctor
keylatch sandbox doctor --json
```

Sample output (macOS):

```
sandbox doctor

  Platform:  darwin/arm64
  Primitive: sandbox-exec (built-in)
  Status:    available

  [ok  ] Sandbox primitive detected
  [ok  ] ~/.keylatch deny-list enforced
```

Sample output (Linux, bwrap missing):

```
sandbox doctor

  Platform:  linux/amd64
  Primitive: bwrap (bubblewrap)
  Status:    NOT AVAILABLE

  [FAIL] bwrap not found in PATH or /usr/bin/bwrap, /usr/local/bin/bwrap
         fix: sudo apt-get install bubblewrap
```

## Running a Command in the Sandbox

```bash
keylatch sandbox run --provider openrouter -- node app.js
```

This is equivalent to `keylatch run --runtime direct_classic_sandboxed openrouter -- node app.js` but with sandbox-specific flag support.

## Audit Events

All sandbox lifecycle events appear in `~/.keylatch/audit.log`:

| Action | Emitted when |
|--------|-------------|
| `sandbox.launched` | Child process started inside sandbox |
| `sandbox.launch_refused` | Hash mismatch or feature flag off |
| `sandbox.deny_applied` | Deny-listed path blocked at mount time |

Audit fields for `sandbox.launched`: `provider`, `runtime`, `executable`, `executable_sha256`.

Audit fields for `sandbox.launch_refused`: `provider`, `runtime`, `expected`, `actual`, `reason`.
