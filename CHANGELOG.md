# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> **Historical note**: the tag `v1.0.0-rc.1` predates a 2026-05-28 history
> rewrite and has no merge-base with current `main`. It is kept (not deleted)
> as a pointer into the pre-rewrite history, but does not correspond to any
> entry in this changelog and is not part of the `v0.9.x` release train
> below — do not treat it as "ahead of" or otherwise related to the current
> version numbering.

## [Unreleased]

### Added

- `keylatch guard hook --harness claude-code` is the Claude Code `PreToolUse` guard. It parses each Bash command into a syntax tree (so a heredoc or `echo` that only mentions `printenv` is allowed), looks through `bash -c`, `eval`, command and process substitution, here-strings and wrappers such as `env -C`, `sudo`, `nice`, `xargs`, `find -exec`, `mise exec` and `direnv exec`, and denies reads of Keylatch state and credential directories, `.env` files, secret-manager CLIs, environment and history dumps (`env`, `printenv`, `export -p`, `/proc/*/environ`, interpreter one-liners, `direnv`, `mise`, `atuin`, `tmux show-environment`, `sops -d`, `age -d`, shell history files) and writes to the harness settings and the Keylatch binary. The `Read`, `Grep`, `Glob`, `Edit`, `Write`, `MultiEdit`, `NotebookEdit` and `NotebookRead` tools are checked the same way, with symlinks resolved. Input it cannot parse, and any internal error, is a deny (exit 2 plus the deny JSON). `internal/guard/hook/testdata/deny_corpus.txt` and `allow_corpus.txt` hold the commands the tests run, and `FuzzHookDecision` checks the guard never panics.
- `keylatch install-guard claude-code` merges the hook (`"matcher": "*"`, a 10 second timeout, the absolute `keylatch` path) into `~/.claude/settings.json` and `$CLAUDE_CONFIG_DIR/settings.json`, keeping every other key and hook, and saves the previous file as `settings.json.keylatch.bak`. `--config-dir <dir>` (repeatable) adds directories, `--upgrade` rewrites an installed entry in place (new binary path, matcher, timeout), and `--dry-run` prints a unified diff and writes nothing. An entry that runs the old shell script is replaced where it stood.
- Bitwarden organization collections: `bw.organization_id` and `bw.namespaces` (`{"work": "Work/infra"}`) place each namespace's items in a named organization collection. Items are created with the organization and collection IDs and looked up only in their collection; a namespace with no entry fails with `ErrNamespaceUnmapped` before any `bw` call. `keylatch setup --backend bw --organization-id <id> --namespace work=Work/infra` (repeatable) writes the map; a plain `--namespace` is still the default namespace.
- When a Bitwarden server is configured, `bw config server` must name it or the backend refuses (`ErrServerMismatch`) before sending anything.
- `bw.session_ttl` and `keylatch bw unlock --ttl` set how long a Bitwarden session is kept: 1 hour by default, at most 8.
- A conformance test build of keylatch (Go build tag `mint_test_endpoint`) takes the GitHub API root for GitHub App requests from `KEYLATCH_TEST_GITHUB_API_URL`, so `keylatch mint` can run against a stub server; its `keylatch version` ends with `testendpoint`. The default build ignores the variable. Releases publish it as `keylatch-testendpoint_<version>_linux_amd64.tar.gz`, listed in the checksums and signed, with a note that it is for conformance testing only; `release-checks/verify-release-assets.sh` requires it. `mint-smoke` mints a `contents: read` token for one test repository every night and checks its JSON and scope (skipped without the `MINT_SMOKE_*` secrets); see `docs/mint-conformance.md`.
- `keylatch run --tier D5 <connection> -- <command>` runs the command in a Keylatch sandbox the daemon starts and hands it the real value in its environment. The sandbox uses Go-native user, mount, PID, IPC, UTS, cgroup and network namespaces, a private root with Keylatch state, `~/.ssh` and other credential stores absent, Landlock (including TCP connect rules on ABI 4), a seccomp filter, emptied capability sets and a cgroup v2 leaf. The namespace has only loopback; a forwarder reaches the daemon's egress proxy, which allows only the policy's hosts, resolves names itself and refuses private, link-local and metadata ranges. Output is redacted for the value and its base64, hex, URL and JSON encodings, a PTY is relayed with resizes and signals, and files written under the project are scanned afterwards: a hit exits 3 and writes `contained.leak_suspected`. Agent and host callers need an approval. The manifest entry `contained` is Supported on Linux. See `docs/contained-runtime.md`.
- `keylatch doctor --sandbox` reports namespace, seccomp, Landlock and cgroup capabilities for the contained tier and exits 2 when D5 cannot run.
- Audit actions `contained.leak_suspected`, `sandbox.degraded` and `canary.tripped`, and `sandbox_sha256` on `run.decided`.
- Policy documents (`schema_version` 2) gain `tiers`, `approval`, `ttl` and `max_requests` in caller entries and, per document, `hosts`, `egress`, `fs` and `commands`. A kind gets D1 to D4 (agent, host), D1 to D5 (service) or D1 to D6 (human) by default; D6 is for humans only. `auto_if_contained` makes containment the approval for D1 to D4, while D5 needs an approval unless a command rule pins the executable's path and SHA-256 in a location only root can write. Argv patterns are compared with the executable a command resolves to, with `*`, `?` and a final `**`. `hosts` can only remove hosts from the provider template's. Run, session and contained requests ask `enforce.Decide` for their tier, and a D2 or D3 request that needs an approval is refused when the daemon cannot collect one.
- `keylatch policy import <file.yaml>` compiles a one-file policy (`defaults`, `connections`, `commands`) into one document per connection and refuses binding keys such as `secret` or `slots`.
- `keylatch policy import --from claude-code|codex|gemini [--settings <file>...] [--connection <name>...] [--dry-run]` records the harness's sandbox limits (allowed domains, writable paths, denied paths) in the stored documents. It only narrows: egress becomes the intersection, writes must lie inside the harness's paths and its denies are added. It fails when the harness excludes `keylatch` or a program that can start it.
- Canaries: every D3 session and every contained run carries a decoy `KEYLATCH_CANARY_<PROVIDER>` variable, and a contained run also gets honey files in its home (`~/.aws/credentials`, `~/.config/gh/hosts.yml`, `~/.npmrc`). The D3 proxy and the egress proxy look for the decoys, in any common encoding, in the request target, head and body; the first request that carries one is refused, the session is suspended or the contained run ended, and `canary.tripped` records the host and where it was seen.
- Contained approvals: the daemon opens a signed approval request that names the exact argv, tier, hosts and lifetime, and `keylatch approve <token>` shows that plan and requires presence bound to the request hash. Creating or widening a custom connection's hosts and weakening a local-only mode now need presence even for a human caller (`binding.change`, `local_only.weaken`); a refusal writes `binding.refused` and changes nothing.
- Tier D4 for Postgres: `keylatch run --tier D4 <connection> --target <host:port> [--db-user <role>] [--database <name>] -- <command>` opens an adapter session. The child gets a loopback address and a session token as its password (`PGHOST`, `PGPORT`, `PGUSER`, `PGPASSWORD`, `DATABASE_URL`); the adapter logs in to the database with the stored password (SCRAM-SHA-256 or cleartext, over verified TLS; a server that asks for MD5 is refused) and relays the stream, so `psql` and the `pg` driver run with no database password in the child. The target must match the template's adapter hosts. `adapter.connection` audit events record each connection without the token or password. See `docs/protocol-adapters.md`.
- `docker-credential-keylatch`, the Docker credential helper behind `"credsStore": "keylatch"`, answers with a placeholder for the registries a connection's `docker_credential` adapter names and with nothing for any other, sharing the daemon operation the git helper uses. A Docker session writes a temporary config and puts the helper first on `PATH`. It is built as its own executable for releases.
- `keylatch explain` reports tier D4 for connections with a protocol adapter.
- `keylatch explain` reads hosts and slots from the connection's binding (a provider template's, or the one a custom connection declared) instead of the allowed-hosts table, adds a `binding` block to its JSON, and reports a connection without one as `no_binding` with the `keylatch connect <name> --provider custom --host ...` fix on the D3 entry of `rejected_tiers`. D3 and D5 now name the `placeholder` and `contained` runtimes.
- Custom connections are served at D3 and D5 by the daemon from their stored binding, with their value read from the store.
- `keylatch connect --provider custom --test-url <url> [--expect <status>]` requests a URL inside the connection's hosts through the placeholder tier with only a placeholder in the request and fails unless the status matches. Human only.
- `keylatch scan [path...] [--redact]` reports the lines of files or standard input that hold a known credential format or a Keylatch canary without printing them, and exits 2 on a finding; `--redact` writes the filtered text instead.
- Linux broker: `sudo keylatch broker install` creates the `keylatch` system user, installs the `keylatchd` service and socket units and the polkit policy, seals a device root with `systemd-creds` and starts the socket. `keylatchd broker` runs under that user with a strict systemd sandbox (`systemd-analyze security` scores 1.6), holds a key hierarchy (device root, broker master key, HKDF-derived store, audit and token keys, wrapped Ed25519 keys), a per-secret-key store whose authenticated data is partition, path and version, the policy and the audit log, and serves `/run/keylatch/broker.sock`. It identifies each peer from the kernel (`SO_PEERCRED`, a pidfd, the start time and the cgroup), re-checks the pidfd before acting, and serves every user from a private partition. The wire protocol stays the control socket's JSON framing, extended with strictly decoded broker operations; gRPC is not used.
- Presence is verified by the daemon: it asks polkit (`dev.keylatch.privileged`, `auth_self`) for the calling process, builds the sentence the human reads from the request, and issues a proof bound to the request digest that is valid 60 seconds and single use. A privileged request without a proof is refused, and an agent session cannot ask. Accepted policy is signed with the daemon's own key and the presence digest; a stored policy that is edited, added to or unsigned is ignored, the daemon denies and records `security.block`.
- `keylatch broker adopt` moves an in-user install into the broker (secrets, policy, audit position), checks a keyed hash of every secret, revokes in-user gateway tokens and shreds the in-user key material; `keylatch broker export-to-user` reverses it, `keylatch broker rotate-keys` rotates the master key without re-encrypting values, and `keylatch broker status --json` reports the daemon. With the broker installed, `set`, `policy import|export`, `audit head` and `run` go through the daemon and open no local key file, and the client does not fall back to local files when the daemon does not answer.
- `keylatch launch` registers a new agent session with the broker and starts the harness in a transient systemd scope `keylatch-agent-<id>.scope`; the daemon classifies processes in that scope as agents from their control group, and a process that leaves it as `host`.
- `keylatch doctor` reports the active mode (`mode.deployment`: PASS in daemon mode, WARN in in-user mode on Linux), whether the daemon answers, version drift, TPM binding, in-user key files left behind and the upstream keys adopted from an in-user install ("rotate recommended").
- `.deb` and `.rpm` packages carry the units, the system user definition and the polkit policy; the postinstall script creates the user and reloads systemd, and enabling the socket stays with `keylatch broker install`.
- Nightly fuzzing of broker requests, control frames, peer identity parsing, policy files and provider templates.
- `docs/guides/broker-linux.md`, a Linux broker section in the threat model, and updates to `SECURITY.md`, the README and `docs/daemon-socket.md`.
- `keylatch audit export|head|verify`: `export --since/--until --format jsonl` verifies the chain while exporting, `head --json` prints `{seq, hash, time, key_id}` and `verify --anchor <file>` checks the chain and that the anchor's entry is in the log, so a truncated log fails. The gateway writes the head hash to the OS log (journald `keylatch-audit`, `os_log`, Windows Event Log) at start and every 1000 events.
- `keylatchd serve` opens an owner-only Unix control socket. The `keylatch` client holds no key material and sends `status`, `list`, `doctor`, `describe`, `explain`, `call` and `run` to the daemon when it is reachable, so they work by bare name inside a sandbox that hides Keylatch state and exposes only the socket. The daemon checks the peer's user, classifies the caller as human, agent or host, runs an agent's or host's verbs as an agent session, and refuses `get`, `export`, `backup` and `mint` for them.
- `keylatch run --tier D2 <connection> -- <command>` through the daemon: the daemon issues the session token, the client starts the child in its own sandbox and relays the gateway through a loopback forwarder, and the provider key never reaches the child. Other tiers are refused as unavailable; `D6` is never served.
- `keylatch run --repo <owner/name> [--permission <name>=<level>] github-app -- <command>` through the daemon gives the child placeholders in `GH_TOKEN` and `GITHUB_TOKEN`. The daemon mints a scoped installation token on first use, holds it only in memory, refreshes it before expiry, revokes it when the run ends, and the proxy substitutes it toward `api.github.com`, `uploads.github.com` and git over HTTPS on `github.com`. `mint.github_app.placeholder_callers` in the operator's config lists the caller kinds allowed to do this; agents are never allowed to print a token with `keylatch mint`.
- `keylatch git-credential` is a git credential helper that returns the session's placeholder for the template's git hosts and nothing else. Templates may declare `minted_fields` and an adapter `username`; the `github-app` template now declares its hosts, slots, placeholder shape and git adapter.
- `keylatch key sign|verify|encrypt|decrypt|jwt-sign <connection>` performs HMAC-SHA256/384/512, Ed25519, ECDSA P-256/P-384, RSA-PSS and RSA PKCS#1 v1.5 (SHA-256) and AES-256-GCM operations, and signs compact JWTs (HS256, ES256, EdDSA), with a key that stays in the daemon. Each connection field allows only the operations and algorithms on its allowlist; anything else is refused. The allowlist lives in Keylatch state sealed with a MAC, is changed only through `keylatch key allow|revoke|list` (adding or widening is refused for agent and host callers and audited with before and after; revoking is open to any caller), and a hand-edited file is refused and reported by `keylatch doctor`. Decrypt returns plaintext, so agent and host callers are refused unless the field sets `agent_decrypt`. Every request is audited with the operation, algorithm, connection, caller kind and the SHA-256 of the input.
- `keylatchd serve` also serves an ssh-agent endpoint (`ssh-agent.sock` beside the control socket) that lists and signs with the keys whose allowlist entry sets `ssh_agent`. Keys cannot be added, removed or exported, SHA-1 RSA signatures are refused, and `host_keys` limits a key to sessions bound (session-bind) to listed server host key fingerprints. Git commit signing works through it with `gpg.format=ssh`.
- The daemon decides the caller kind from the peer itself: it walks the peer's process ancestry and classifies an agent when a known harness is an ancestor, regardless of the signals the client sends, which can only tighten. The control socket, the ssh-agent socket, key operations and the mint policy share one classifier (`internal/callerkind`).
- Every decision on the control socket writes one value-free audit event: `run.decided` (tier, child location, caller kind, harness, argv and cwd digests, hosts) for allows and refusals, and `run.exited` (exit, duration, bytes relayed). `keylatchd serve` refuses to start without an audit log, and refuses a decision it cannot record.
- Daemon-served verbs stream stdout and stderr as they are produced and forward stdin; the 8 MiB reply cap is gone.
- `keylatch-relay` is a separate binary for harnesses whose sandbox cannot reach a Unix socket: it forwards request bytes to the daemon, never starts a process and ignores its arguments. `keylatch doctor` warns when it is writable by the user. See `docs/daemon-socket.md`.
- `make test-containment` runs the thin client inside a bubblewrap sandbox with Keylatch state hidden.
- `keylatch mint <connection> --repo <owner/name> --permission <name>=<level> … --format json` mints a GitHub App installation token for exactly one repository and the listed permissions, and prints `{"token","expires_at","repository","permissions"}`. The App JWT is signed inside Keylatch; the private key never leaves it. Exit codes: 1 usage, 2 agent session or no audit log, 3 policy, 4 store unavailable, 5 GitHub refused or the token was revoked, 6 connection field missing.
- `github-app` provider template: `private_key` (secret), `app_id` and one `installation_<owner>` field per account the App is installed on. `keylatch connect github-app` tests the connection with a signed App JWT against `GET /app`.
- Per-connection policy `connections.<name>.mint.github_app` in `config.json`: `callers` (default `service` and `host`), `deny_owners`, `allow_owners`, `allow_repos`, `permission_ceiling` and `max_ttl` (1–3600 seconds, default 3600). A connection without the policy cannot mint.
- Audit action `mint` with connection, namespace, repository, permissions, `expires_at`, caller kind and, on failure, the reason. The token is never recorded.
- Privileged commands need a human: `backup`, `grant create` and `revoke`, `gateway token create` with any `--allow`, `config set` for `policy.`, `gateway.`, `backends.` and `guard.` keys, `ui` with a scope above `read`, and `install-guard --uninstall`. Each asks at a terminal that no agent harness owns (stdin and stderr are terminals and no ancestor process is a known harness), then asks the platform where one is available: polkit on Linux when the `dev.keylatch.privileged` action from `packaging/linux/polkit/` is installed, Touch ID or the account password on macOS, Windows Hello on Windows. No environment variable changes the outcome. In-user presence is friction, not a boundary: see `docs/security/threat-model.md`.
- `keylatch install-guard <agent> --uninstall` removes the hook for Claude Code, Cursor, Codex, Gemini CLI, Copilot, Antigravity and OpenCode, and removes the shared guard script only when no other agent's configuration still runs it.
- Audit event types `presence.decision`, `policy.change` and `backup.export` are reserved with their allowlisted fields.
- Per-connection policy documents (`policy.d/<connection>.json`, schema `schemas/connection-policy.schema.json`, `schema_version` 2) say which caller kind (`agent`, `host`, `service`, `human`) may use a connection, under which `runtimes`, `exe` and `units`, for which `capabilities` and up to which `max_ttl`. A kind with no entry is denied, and unknown keys are rejected. Examples are in `examples/policy.d/`; `docs/policy.md` describes the model.
- `keylatch policy init` writes a default-deny policy (no rules, a fallback document that lets only a human use a connection) and examples. `policy import <dir>` validates every file, shows the diff and replaces the set atomically after a human approves; `policy export <dir>` writes it back; `policy check <connection> --as agent|host|service|human [--runtime <r>] [--action <a>] --json` is a read-only dry run that gives the answer `run`, `call` and the gateway would; `policy deny <connection> --as <kind>` narrows a document. `policy allow`, `deny`, `remove`, `import` and `init --force` need presence.
- `keylatch bootstrap` run from a terminal wraps the vault key under an Argon2id passphrase when no OS keyring is usable (`--kek passphrase` asks for one even where a keyring exists, `--kek keystore` never falls back to one). The passphrase is asked on the terminal on every use and is never read from a file, a pipe or the environment.
- `keylatch keys status [--json]` reports where the vault key is held and `plaintext_kek`. `keylatch keys rewrap --to keystore|passphrase` generates a fresh key, re-wraps the vault's data keys under it, proves the new key alone opens the keyring and reads every secret, and only then overwrites the plaintext identity with random bytes and removes it; a failed proof leaves the vault under its previous key. It needs presence.
- A gateway token records the caller kind it was issued for in its signed claims. An agent's token is an LLM-session token, so the gateway's agent route restrictions apply to `run` tokens minted for agents (they were minted as non-LLM tokens before).
- `keylatch migrate inventory --map <yaml>` scans `.env` globs, the Secret Service, the macOS keychain, `gh` hosts and password-manager item names and prints a JSON plan of names, sources and target namespaces; it never holds a value. `keylatch migrate import --plan <json> --to bw|op|broker [--dry-run] [--manifest-out <file>]` writes the planned items under the namespace-to-collection mapping after a presence check, writes nothing that is already there, and records `HMAC-SHA256(key, value)` per item under a key derived from a recovery passphrase with Argon2id. `keylatch migrate verify --manifest <file>` and `keylatch drill restore --manifest <file> --report <file>` check a backend against the manifest on any host and report `{ok, failed, missing, duration}` with paths and counts only. Schemas: `schemas/migrate-map.schema.json`, `schemas/migrate-plan.schema.json`. See `docs/guides/restore-drill.md`.
- `keylatch sync` keeps Vercel environment variables, GitHub Actions secrets and local env files in step with the connections they come from, as declared in `keylatch.sync.yaml` (`schemas/sync.schema.json`, `examples/keylatch.sync.yaml`). `sync check` validates the manifest offline and names the key path of a violation; `sync diff` and `sync drift` report adds, updates and extras by name, target, environment and reason without reading or printing a value (`drift` exits 1 on any difference); `sync apply [--prune]` and `sync rotate <name> [--target <t>] [--keep-old <d>] [--no-rollback]` need presence and run inside the broker daemon, so a value never crosses the socket, the CLI's arguments or an agent's environment. An env file is written by the daemon through descriptors the CLI passes and renamed into place as `0600`; GitHub secrets are sealed to the repository key; a rotation verifies every target, rolls back on failure and retires the old value last. The daemon keeps a keyed hash per written entry to find changed values, and emits `sync.write`, `sync.delete`, `sync.rotate.verify`, `sync.rotate.rollback` and `sync.rotate.complete` audit events with no value and no hash. `keylatch doctor` reports drift for the repository's manifest and warns about env files the guard does not protect and GitHub targets reached with a long-lived token. A conformance build (`sync_test_endpoint`) takes the Vercel and GitHub API roots from `KEYLATCH_TEST_VERCEL_API_URL` and `KEYLATCH_TEST_GITHUB_API_URL`; the default build ignores them. See `docs/guides/sync-deploy-secrets.md`.
- `keylatch service enroll <connection> --unit <unit>... [--scope system|user] [--allow-transient]` (presence), `service revoke`, `service list --json` and `service render-unit-lines <connection> --format json|ini` give systemd units their credentials through the broker. Enrollment records each unit's name, scope, a SHA-256 over its file and drop-ins read through the service manager, `ExecStart` and whether transient units are allowed, and seals a random 256-bit capability (stored only as a keyed hash) into `/etc/credstore.encrypted/keylatch-<connection>.cred` or `~/.config/credstore.encrypted/` with `systemd-creds`; the file never holds the secret. Inside the unit, `keylatch run <connection> --runtime service -- <command>` presents the capability and the broker releases the connection only when the peer's control group is the enrolled unit, the unit is not transient (unless enrolled so) and its files and `ExecStart` still equal the enrollment. Any mismatch is refused and audited as `security.block`; a release is audited as `release` with the unit and caller kind `service`. System accounts outside the broker's user range are served for this one request. `keylatch doctor` fails for an enrolled unit that changed and prints the re-enroll command. See `docs/guides/service-credentials-systemd.md`.
- `keylatch machine issue --domain <ns> --name <n> --caps call --ttl <d> --out <file>`, `machine revoke <name>` and `machine list --json` give a remote guest a credential: an Ed25519 key made on this host and a certificate from the broker's machine CA that carries the domain, capabilities and expiry. `keylatch config set gateway.machine_listen <host:port>` (presence; wildcard addresses need `--allow-wildcard`) starts a TLS 1.3 listener that accepts only that CA's certificates and checks revocation on every request, and `keylatch call --remote <addr> --machine-key <file> <connection> <action>` runs an action there. The domain is the certificate's, a cross-domain request is refused and audited, and calls are audited with caller kind `machine`. See `docs/guides/machine-credentials.md`.
- Verbs the Linux broker runs for a user (`call`, `mint`) read that user's partition through a socket the daemon passes them, so `call` reaches stored secrets through the broker; `mint` is served by the daemon for human callers. With the broker installed, `connect`, `disconnect` and deletes write through its presence-gated operations.

### Changed

- Claude Code runs the Go guard instead of `block-keylatch-exfiltration.sh`. `keylatch doctor` reports an entry that still runs the script as `guard.current` failing, with `keylatch install-guard claude-code --upgrade` as the fix, and also fails when the binary named in the hook is missing. The Codex, Cursor, Gemini CLI, Copilot, Antigravity and OpenCode installers keep the shared shell guard until each has a structured installer; they still write only their own hook entry.
- Policy is deny by default and has one decision point. `keylatch run`, `keylatch call` and every gateway request are denied with ``no policy for <connection>: run `keylatch policy init` `` until a policy allows them; before, a missing policy file allowed the request. A rules file without `default_deny` denies what no rule allows (an explicit `false` still allows), a policy file or document that cannot be read denies, and a grant overrides a denial only when it was issued with presence. Run `keylatch policy init` to restore access for yourself; agents need a document that names them.
- **Breaking:** `keylatch bootstrap --insecure-file-kek` and `KEYLATCH_INSECURE_FILE_KEK` are removed and grant nothing. With neither a keyring nor a terminal, bootstrap fails and says what to do. A plaintext vault key is allowed only by `allow_insecure_file_kek` in the operator's own config file (the default config path under the account's home, owned by the user and not writable by others); an existing plaintext identity is no longer protected from the move into the keyring by an environment variable. CI runners run `scripts/ci-operator-config.sh`.
- `docs/security/threat-model.md` is rewritten: it opens by saying in-user mode is not a boundary against an agent running as your own user, gives the protection per mode and per attacker, links each claim to the test behind it and lists the residual risks. Invariant 1 is now "Agents use secrets only through brokered actions" with a per-mode statement and invariant 5 is "The raw credential is sent only to the allowlisted provider endpoint"; `keylatch security` prints the new wording.
- Command patterns in `policy.json` match exactly unless they end in `*`: `pnpm test` no longer allows `pnpm test -- anything`.
- `keylatch ui` opens with the `read` scope. Any wider scope (`setup`, `admin`, `token-minting`) needs presence. The one-time bootstrap URL is printed only when stdout is a terminal and is otherwise handed only to the OS browser opener; `--no-open` without a terminal is refused.
- The deny corpus covers environment and history managers: `direnv exec <dir> env`, `direnv export`, `direnv dump`, `mise env`, `mise exec -- env`, a bare `mise set`, `atuin search`, `atuin history`, and reads of `~/.*_history` and `~/.local/share/atuin`.

### Security

- The Bitwarden session is no longer written to disk in plaintext. `keylatch bw unlock` seals it under the vault key (`sessions/bw.session.enc`, expiry in a separate file), for 1 hour unless told otherwise; `keylatch bw lock` and the next unlock remove a `sessions/bw.session` file an earlier version left, and `keylatch doctor` fails (`backend.bw_session_file`) while one exists. `keylatch bw status` warns about it. The default lifetime was 8 hours and is now the maximum.
- With a Bitwarden folder configured, only that folder is listed or read; before, any item that sat in some folder was listed.
- `keylatch mint` refuses agent sessions, and the mint policy is read only from the operator's default config file (owner-only, not writable by group or others), never from `KEYLATCH_CONFIG` or other overrides. Caller, owner, repository, permission and lifetime checks all run before the key is read, and minting refuses to start without a working audit log.
- `keylatch backup` no longer takes `--passphrase-file`: a human approves the export, which names the credential count, and the passphrase is read from the terminal only. `docs/cli-reference.md` no longer documents a `keylatch restore` command that does not exist.
- A grant carries the digest of the presence proof it was issued under.
- The file backend compares the stored binding of a secret with the requested partition, path and version, so swapped secret files fail with `ErrAADMismatch`, and takes a cross-process lock (`flock` on Unix, `LockFileEx` on Windows) around writes, reloading the manifest under it so concurrent writers lose no update.
- On Windows the keyring file must be owned by the current user and its DACL may grant access only to that user, SYSTEM and Administrators.
- A caller counts as a `service` only when its cgroup is a non-transient systemd service unit that systemd confirms has a unit file. The `INVOCATION_ID` variable, which any process can set, no longer makes a caller a service and so no longer opens `mint` to it. Service classification is advisory in this release; the broker daemon enrolls units.
- GitHub's reply must name only the requested repository, grant exactly the requested permissions and expire within `max_ttl`; otherwise the token is revoked with `DELETE /installation/token` and mint fails. A token whose audit line cannot be written is revoked too.

### Fixed

- Gateway tokens take capabilities, caller kind, maximum uses and expiry from their signed claims; the token store can only narrow them (revoked) and every record carries a MAC, so editing the store can no longer widen a token. Revoking a token revokes all of its descendants.
- The audit chain MAC key is derived from a KEK-wrapped secret (`audit-key.enc`) and the audit salt instead of the readable salt alone, so a log edited by someone who can read the salt cannot be re-chained. A log written under the old key is moved to `audit.log.1` the first time the secret is created.
- `keylatch run` and `keylatch call` write exactly one value-free audit event each (`run`, `call`) and refuse to run while the audit log cannot record it; blocked LLM-session attempts and finished backups write `security.block` and `backup.export` events.
- The gateway never follows a provider redirect, so the credential injected for the validated host cannot reach another host; it connects only to the addresses its SSRF check resolved (a DNS answer that changes between check and dial is not used); it inspects request bodies in full up to `gateway.max_body` (default 10 MiB) and rejects larger ones with 413 instead of truncating.
- The gateway and `keylatchd` clear the process dumpable flag and core limit on Linux (so `/proc/<pid>/environ` and `mem` are unreadable by the same user), deny debugger attach on macOS and restrict extension points and image loading on Windows.
- Provider templates gain `deny_routes` (routes that create, read or list credentials or keys, refused by the gateway and by `keylatch call`) and `forward_headers` (extra inbound headers the gateway forwards). Every core template lists its credential routes, and `keylatch registry validate` fails a template that exposes such a route in an action.
- Remote backends (`op`, `opconnect`, `vault`, `awssm`, `gcpsm`, `azurekv`, `doppler`, `infisical`) read their credential from `backends.<id>.credential_ref` first. `keylatch backend login <id>` takes it from an interactive terminal (never a flag or pipe, never an agent session) and stores it wrapped by the KEK. Credentials found only in the environment are refused unless `backends.<id>.allow_env_credentials` is `true`, and `keylatch doctor` warns while it is.
- Every runtime removes `BW_SESSION`, `BW_CLIENTSECRET`, `BWS_ACCESS_TOKEN`, `OP_SERVICE_ACCOUNT_TOKEN`, `OP_CONNECT_TOKEN`, `OP_SESSION_*`, `VAULT_TOKEN`, `VAULT_ROLE_ID`, `VAULT_SECRET_ID`, the AWS key variables, `AZURE_CLIENT_SECRET`, `GOOGLE_APPLICATION_CREDENTIALS`, `DOPPLER_TOKEN`, `INFISICAL_CLIENT_ID`, `INFISICAL_CLIENT_SECRET` and `KEYLATCH_*` from the child environment. The README no longer tells you to export `BW_SESSION`.
- The macOS keychain backend passes the keychain password and secret values to `security` through `security -i` on stdin, hex-encoded for values, instead of as `-p` and `-w` arguments that any local user can list.
- MCP `keylatch_run` matches the allowed executable by exact name and argument pattern instead of a string prefix, and runs the command through the runtime dispatcher as an agent caller, after connection policy has allowed agents the connection: the gateway runtimes with a scoped session token, a scrubbed child environment and one audit event. It refuses when the gateway signing key or the audit log is unavailable. The MCP socket transport is disabled on Windows; stdio still works.
- `audit.retain_files` (default 20) and `audit.retain_days` (default 365, replaces `audit.retention_days`, which is still read) control audit log rotation and retention.
- The gateway signing key is stored wrapped by the KEK (`gateway/signing.key.enc`) instead of a raw `signing.key` file; the raw file is migrated and deleted the first time the gateway starts.
- Session tokens from `keylatch run` live 10 minutes by default (1 hour at most), carry the caller's LLM classification, are limited to the actions the template declares, allow at most 1000 requests, and are revoked when the child exits.
- The Claude Code exfiltration guard allows `env` when it runs a command (`env -C /abs/dir cmd`, `env NAME=value cmd`, `env -i`, `env -u NAME`). Bare `env`, `env` with no command, other `env` options (`-0`, `-S`, …), a relative `-C` directory and `printenv` stay blocked, and the command after `env` is checked like any other.
- Every shipped agent guard now denies with exit 2 plus the harness's deny JSON (exit 1 does not block in most harnesses). One guard script serves Claude Code, Codex, Gemini CLI, Cursor, Windsurf, Copilot and Antigravity; the hook command selects the stdin payload and deny contract with `--harness <id>`. Re-run `keylatch install-guard <agent>` to pick it up.
- The Cursor installer writes `~/.cursor/hooks.json` (`beforeShellExecution`, fail-closed) instead of `settings.json`; the Codex and Gemini installers write the nested matcher-group schema their harnesses read; Copilot gets a native `PreToolUse` hook in `~/.copilot/hooks/` instead of a shell wrapper.
- Windsurf and Antigravity have hook APIs: `keylatch install-guard windsurf|antigravity` now installs a hook.
- Antigravity denies with exit 0 plus `{"decision":"deny","reason":...}` because its hooks are documented as stdout JSON only; the matcher also covers `view_file`. Windsurf registers `pre_read_code` and Cursor registers `beforeReadFile` (fail-closed). Read hooks and shell readers (`cat`, `head`, `cp`, ...) deny direct reads of paths that are, are inside, or contain `~/.keylatch`, `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.local/share/atuin`, `~/.kube`, `~/.config/gcloud`, `~/.docker/config.json`, `~/.netrc`, `~/.config/gh/hosts.yml`, `~/.git-credentials`, `~/.npmrc`, `~/.pypirc`, `~/.azure` and `~/.terraform.d/credentials.tfrc.json`; tools reading their own config as child processes (`kubectl`, `gh`, `docker`) are unaffected. Cursor does not currently enforce a `beforeReadFile` deny for agent reads, so add the `.cursorignore` entries that `install-guard cursor` prints.
- The guard fails closed: an unset `HOME` or any other unexpected error inside it now denies (exit 2 plus the deny JSON; exit 0 plus `{"decision":"deny"}` for Antigravity) instead of exiting 1. Without `jq` it extracts file paths and scans the raw payload for protected paths, and it no longer uses the GNU-only `\|` in `sed`, which broke the env-dump check on macOS.
- Path comparison works on macOS: `.`, `..`, repeated slashes and symlinks are resolved without `realpath -m`, and the comparison is case-insensitive on macOS and Windows.
- Any shell command that names a protected path through `~`, `~user`, `$HOME`, `${HOME}`, `$USERPROFILE`, `%USERPROFILE%` or the absolute home is denied, except `ls`, `stat`, `ssh`, `scp -i`, `ssh-add`, `ssh-keygen`, `git` transport commands, `chmod`, `chown`, `mkdir` and `touch` as the whole command, and `kubectl`, `helm` and `gh` with the path as `--kubeconfig` or `--config`. Redirections into protected files stay denied. Recursive reads of the whole home directory remain a known gap, covering `/bin/cat`, quoted and `//` spellings, `cd ~ && cat .ssh/...`, `tar`, `dd`, `diff`, redirections and `python3 -c` with a literal path. Claude Code `Grep` and `Glob`, Gemini `read_many_files`, `glob` and `search_file_content`, and Copilot `view` and `grep` are guarded as file reads. `mise set` with only flags is denied. Known gaps are listed in the guard README.
- Claude Code on Windows installs the `bash "<path>"` hook command, every installer quotes the script path (a home directory with a space works), the contrib Cursor installer registers `beforeReadFile`, and installs replace entries and scripts left by older versions (`*-guard.sh`, the Cursor `settings.json` entry, a bare script path). `keylatch-hook-version` is now `6`.
- Contracts follow [Claude Code](https://code.claude.com/docs/en/hooks), [Cursor](https://cursor.com/docs/hooks), [Windsurf/Devin](https://docs.devin.ai/desktop/cascade/hooks.md), [Antigravity](https://antigravity.google/docs/hooks/) and [Gemini CLI](https://geminicli.com/docs/hooks/reference/) docs; none of it has been exercised in the real applications.

### Removed

- The Aider guard installer: Aider has no hook API. Use `keylatch launch -- aider`.

### Removed

- Commands that did nothing: `get --masked`, `get-masked`, `share`, `receipts`, `rules`, `sessions`, `projects`, `sandbox run`, and the `gateway up --with-proxy` listener. The duplicate `verify` registration and `runner.OK` are gone too.
- Telemetry in every form: the `telemetry` operating mode, `KEYLATCH_TELEMETRY_*` variables, the setup prompt and the telemetry settings in the UI. Keylatch sends no telemetry.
- The classic sandboxed runtime (`direct_classic_sandboxed`), its driver and its documentation. Selecting it now fails as an unknown runtime mode. Three runtime modes remain.
- Windsurf: the guard script, `install-guard windsurf`, the integration pages and the harness marker. Windsurf exposes no hook API.

### Changed

- Features that are not finished (`team`, `trust` and its hardware adapters, the vault team backend) compile only with the `experimental` build tag; release binaries contain none of them.
- `keylatch backend list [--json]` prints every backend with its support tier: supported (`bw`, `op`, `file`), community, deprecated.
- The version comes from the release tag; builds made with `go install` read it from the Go build information. `scripts/set-version.sh` stamps the desktop shell and web package from the same tag.
- `keylatch doctor` reports the root cause first and marks dependent checks skipped. New checks cover the guard hook, the default-deny policy, agent-readable backend credentials, the audit chain, the backend tier and the deployment mode. `--json` follows `schemas/doctor.schema.json`.
- `keylatch setup` recommends a backend (Bitwarden, then 1Password, else the file store), writes a default-deny policy and ends with a doctor report. Headless flags: `--server`, `--organization-id`, `--namespace`, `--install-guard`.
- Every GitHub Action is pinned to a commit SHA, golangci-lint is pinned, Dependabot covers Docker, and CodeQL runs on every push and weekly. A scenario harness with fake agent processes runs the attacker scenarios on three operating systems.
- The README, SECURITY.md and the documentation state that in-user mode is not a security boundary, and a test checks every documented command and flag against the command tree.

## [0.9.9] - 2026-10-05

### Added

- `keylatch launch [--harness <name>] -- <command>` starts an agent harness with a signed session ticket bound to the launcher process; every process below it is treated as an agent session.
- Connection fields can be marked local-only (`keylatch connect --class dev --local-only FIELD=ephemeral`, `keylatch local-only set`). An `ephemeral` field gets a random value per `keylatch run` session and its stored secret is never read; `operation` and `contained` are accepted but refused at run time until they ship.
- `keylatch doctor --json` reports `agent_session.detected`, `agent_session.signals` and `agent_session.harness`.
- `keylatch explain [--json] run <connection> -- <command>` and `keylatch explain policy` report the delivery tier, approval need, hosts, scope, containment and residual risk for a run without executing it. The JSON output is versioned (`schema_version`), ships with a JSON Schema (`keylatch explain schema`) and is documented for host guards in `docs/integration/host-guards.md`.
- Output of every child process Keylatch launches is streamed through an exact-value redactor: injected tokens are replaced with `[REDACTED]` in raw, base64 (standard and URL alphabets, padded or not, at any alignment), hex, percent-encoded and JSON-escaped form, including when split across writes. Files the child wrote in its working directory are scanned afterwards and reported; the receipt carries `leaked_files`.

### Security

- The gateway's `/approve/` and `/approvals` routes are removed. Approvals and denials need a terminal, no detected agent session and the approver passphrase (`keylatch approve init`). They are signed with a key derived from that passphrase, and unsigned or tampered approvals are rejected. Approval tokens are validated strictly and confined to the approvals directory.
- Approval decisions sign exactly the reviewed request, display strips control characters, requests are capped at one hour, approvals are single-use within 15 minutes (verification is hardened ahead of enablement), and every `/approve*` path returns 404.
- The untrusted-write gate ignores caller-supplied approval headers.
- Unverified session claims (`KEYLATCH_LLM_TICKET`, an unanswered daemon socket, `KEYLATCH_ALLOW_UNVERIFIED_SESSION`) no longer open raw-credential access, and `allow_unverified_session` is read only from the user's own default config file.
- Audit rotation no longer recurses past the size cap, and it keeps 20 numbered generations. The `keylatchd` retention sweep deletes only rotated audit logs.
- The audit logger finds the keyring bootstrap creates, so audit is on right after bootstrap.
- `gateway up`, `set` and `list --raw` require a working audit log, and the broker and vault refuse secret operations that cannot be audited.
- The gateway forwards an allowlist of request headers and redacts decoded responses; unsupported encodings are refused.
- Bitwarden and 1Password backends pass secret values on stdin, never on the command line, and 1Password writes are verified.
- Team invites, org policy and registry bundles are signed with Ed25519, and unsigned or legacy bundles are refused.
- Admins can no longer take ownership. Role changes and invites cannot grant owner or a role at or above the caller's, duplicate member IDs are refused, and joining keeps an existing team. Team membership changes are disabled until authenticated member identity ships. Registry rollbacks and unpinned org policy are refused.
- The admin handler takes the role from the authenticated session only (hardened ahead of enablement).
- Masking redacts credential-named fields, name/value pairs, `KEY=value` lines, XML elements, PEM keys and URL passwords in every format; strict masking covers `password` and standard base64; untrusted content is never returned unprocessed.
- `grant create` needs a human terminal and caps TTL at 30 days; agent-issued grants are ignored; grant scope matching is hardened ahead of enablement.
- Sandbox mounts cannot expose Keylatch state, and deny paths are enforced or the sandbox refuses to start.
- The broker's cached credentials stay independent of the results it returns.
- v0.9.7 was published without cosign signatures, SBOMs or SLSA provenance while the docs said every artifact was signed. See the [v0.9.7 advisory](docs/security/advisory-v0.9.7-unsigned-release.md); the docs now state what each release carries.
- Releases are created as drafts and published only after every archive, the checksums file, both SBOMs and the release manifest are cosign-signed and SLSA provenance covers every archive. Homebrew and Scoop are updated afterwards, from the signed checksums, and never for pre-releases.
- Release tags must point at a commit on `main` whose required checks passed.
- New `attest-release.yml` workflow rebuilds a published release from its tag and either signs and attests it or marks it unverified.
- syft and trivy are downloaded at pinned versions and verified against committed SHA-256 digests instead of piping install scripts to `sh`; goreleaser is pinned.
- Agent detection also walks the process ancestry: a process started below a harness executable (`claude`, `codex`, `cursor-agent`, `gemini`, `opencode`, `aider`, `copilot`) is an agent session even with its environment cleared.
- No environment variable relaxes a decision any more: `KEYLATCH_ALLOW_UNVERIFIED_SESSION` is removed, and the presence of a session ticket no longer opens raw-credential paths. Only `allow_unverified_session` in the user's own default `config.json` does.

### Changed

- `keylatch doctor` check names drop their internal prefixes: `bootstrap.keyring`, `bootstrap.config` and `plaintext_retention`.
- `keylatch scope` no longer prints a milestone line, and its JSON output no longer has a `Milestone` field.
- The release check scripts moved from `release-gates/` to `release-checks/`.
- CI runs `release-checks/naming-scan.sh`, which rejects internal work-item labels and finding ids in file names, code, docs and commit subjects.
- Harness signals come from one table (`internal/harness`); `keylatch env` lists every one, and actor inference names Cursor, Gemini CLI, OpenCode and Aider sessions. `KEYLATCH_AGENT_SESSION=1` is the documented manual label.
- `keylatch setup` names the agent signals it detected and no longer suggests unsetting them.

### Known limitations

- The bwrap sandbox (not enabled in production) still shares the host PID namespace and `/proc`, passes credentials with `--setenv` and skips deny paths no mount covers; fix before enabling it.
- The approver public key lives in the user-writable config directory; pin it elsewhere before approvals are consumed.
- The audit log assumes a single writer, and a failed restore after rotation starts a new chain.
- `migrate cipher` is not crash-safe per version; back up the vault first.

### Removed

- `keylatchd --llm-session-socket`, `KEYLATCH_DAEMON_SOCKET` and `KEYLATCH_LLM_TICKET`: nothing registered sessions with the daemon, and the query used the CLI's own PID.

### Fixed

- Every CLI error is printed once, never with flag values, and keeps its exit code.
- `migrate cipher` re-encrypts every stored version.
- Policy commands work without a policy file.
- `setup` in reference mode works on a fresh install.
- `keylatch gateway up` now reads credentials from the configured backend. It used to start without a vault and forward credentialed requests upstream with no credential; it now fails at startup when the backend is unusable, and the gateway answers 503 `vault_not_configured` for a credentialed route without a vault.
- The file backend refuses to decrypt a secret whose stored binding names a different path, so ciphertext copied between secrets no longer decrypts. AES-GCM nonce allocation now shares the keyring's single lock with KEK rotation, and a reload can no longer move the nonce counter backwards.
- The sidecar IPC socket is created owner-only without changing the process umask, which could leave files created concurrently by other goroutines unreadable.

## [0.9.8] - 2026-10-04

### Fixed

- Environment detection matches the variables agent harnesses actually set (`CLAUDECODE`, `CLAUDE_CODE_ENTRYPOINT`, `CODEX_SANDBOX`, `CURSOR_AGENT`, `GEMINI_CLI`, `OPENCODE`).
- Release claims in the documentation match what each release carries; pre-release tags verify under cosign.

### Security

- A release is published only after signing, SBOMs and provenance verify; signatures already attached are kept when a release is attested. Go 1.26.8 is required; `google.golang.org/grpc` is bumped to v1.83.2 and `govulncheck` is pinned.

## [0.9.7] - 2026-08-11

### Security

- Gateway request handling now evaluates a real request policy (`internal/policy`) at Step 6 instead of an unconditional pass-through. When `keylatch gateway up` is started with a configured policy file, matching rules are enforced and violations are denied (403 `policy_denied`) with an audit event; requests requiring approval (`rule.Approval`/`ApprovalRootReq`) are denied (403 `policy_approval_required`) since the gateway has no synchronous approval mechanism. Operators who have never configured a policy see no behavior change (pass-through allow is preserved).
- `keylatch doctor`'s 1Password auth checks (`backend.op.auth`, `external.op`) previously reported OK based only on `OP_SERVICE_ACCOUNT_TOKEN` being non-empty (`backend.op.auth`) or `op --version` succeeding (`external.op`) — neither actually confirmed the token/session authenticates. A revoked or expired token reported a false OK. Both checks now run `op whoami --format=json` and report failure/warn on a non-zero exit.
- `keylatch gateway down` sent SIGTERM to whatever process currently held the gateway's PID with no identity verification — unlike `gateway up --force`, which refuses to act on an unverified/mismatched PID. A stale PID file (confirmed to occur in practice) could cause `gateway down` to signal an unrelated process. `down` now runs the same process-identity verification as `up`: a confirmed mismatch is treated as a stale PID (cleaned up, nothing signaled); inconclusive evidence refuses by default (new `--force` to override), rather than guessing.

### Fixed

- `bw`/`op`/`keeper`/`lastpass`/`proton-pass` backends could report a cryptic `"unexpected end of JSON input"` instead of actionable unlock/signin guidance when the CLI exits 0 with empty stdout (a locked vault or expired session that does not always surface as a non-zero exit). All five backends' `Get`/`List` (and bw's `resolveFolderID`) now detect empty stdout before decoding and return the same locked/auth-failure guidance already used for non-zero exits.
- `keylatch setup`'s backend-setup step (`[2/5]`) silently configured `bw` and `op` with zero readiness validation — unlike `keychain`, which already verified/initialized before proceeding. A locked Bitwarden vault or signed-out 1Password session would sail through setup and only surface as a confusing failure at step 4 (connect provider). `bw` now prompts to unlock and caches a session inline; `op` checks auth readiness and warns clearly if not signed in. Both fall back to the encrypted file backend on decline/failure, matching the existing `keychain` UX. Scoped to fresh/changed backend selection only — resuming setup with an already-configured, unchanged backend is unaffected.
- `keylatch connect custom` could silently orphan a stored secret: the connection-metadata write (needed for `list`/`doctor` to recognize the connection) had its error discarded, so a failure there left the secret stored-but-invisible while `connect` still reported success. The metadata write's error is now checked, with rollback of the just-stored secret on failure.

### Changed

- `keylatch trust` is now marked experimental in its help text. `trust enroll <type>` (all five root types) and `trust approve <challenge-id>`'s signing step are unimplemented hardware-root ceremonies — they are hidden from `trust --help`, still directly runnable, and now exit with a distinct code (`NotImplemented`, 10) and a message pointing at this entry and `docs/experimental.md`, instead of a generic error. `trust list`, `trust doctor`, and `trust challenge` remain fully functional and visible. `docs/cli-reference.md`'s `keylatch trust` section previously documented commands that do not exist (`trust status`, `trust add`, `trust remove`) — corrected to match the real command surface.

## [0.9.6] - 2026-08-11

### Fixed

- Backend auth and session checks are stricter, and gateway signal handling no longer acts on the wrong process.
- `gateway up --force` verifies the process identity of a stale PID file and refuses when the evidence is inconclusive; setup does the same and no longer treats an already-running gateway as a failure.
- A config file that cannot be read because of permissions or an I/O error is no longer reset; only unusable content is.
- Policy rules that carry commands or working directories are rejected at load time, and `policy.Check` no longer panics on a permissive policy in an LLM session.
- `gateway install` is safe to repeat.

## [0.9.5] - 2026-07-31

### Added

- **Canonical backend-name catalog** (`internal/backend/catalog.go`). Backend identifiers are now normalized to a single canonical form at every entry point (dispatch settings resolution, bootstrap config validation, `config` CLI): `awssm`/`aws-secrets` → `aws-sm`, `protonpass` → `proton-pass`, `hashivault` → `vault`, `opconnect` → `op-connect`, `gcpsm` → `gcp-sm`, `azurekv`/`azure-keyvault` → `azure-kv`. Old aliases are still accepted as input for backwards compatibility, but `config.json` should persist the canonical name going forward.
- Per-backend environment-variable wiring for the external/cloud backends (`vault`, `aws-sm`, `gcp-sm`, `azure-kv`, `doppler`, `infisical`, `op-connect`), including fallback to each provider's own conventional env vars (e.g. `VAULT_ADDR`, `AWS_REGION`, `AZURE_TENANT_ID`) when the `KEYLATCH_*`-prefixed var and config field are both unset. See [Environment Variables](docs/cli/environment.md#backend-variables).
- `embedded_ui` build tag: release builds (`goreleaser`, GitHub Actions) now embed the real web UI bundle via `go:embed` when compiled with `-tags embedded_ui`; source/dev builds without the tag continue to serve a diagnostic fallback page.

### Changed

- **Setup wizard is now resumable.** `keylatch setup` no longer aborts when `~/.keylatch/config.json` already exists with an incomplete backend — it repairs/continues onboarding instead of requiring a manual reset.
- Removed OS-daemon auto-spawn (launchd/systemd) plumbing from the setup wizard in favor of starting the local gateway directly in step 3 ("Gateway setup"). No user-facing change to the wizard's step count or flow, only to how the gateway process is brought up.

### Removed

- **NordPass backend stub removed** (`internal/backend/nordpass`). The stub was never imported by `internal/backend/all` or listed in the backend catalog, so it could never actually be selected — even with `KEYLATCH_EXPERIMENTAL=1` set. Removed rather than half-wired; see [Experimental Features](docs/experimental.md) for the removal note. No functional change for any user, since the backend was already unreachable.

### Fixed

- Documentation: the README "Desktop app" section and `docs/` no longer describe the desktop app as macOS/Windows/Linux. Corrected to match the MVP — the desktop app ships for Linux; macOS/Windows are deferred (use the CLI's `keylatch ui`).
- Documentation: corrected config-vs-env precedence claims across `docs/configuration.md`, `docs/cli/environment.md`, and `docs/troubleshooting.md` — precedence differs per subsystem (backend selection is config-over-env; operating mode is env-over-config) rather than a single global rule. Removed two dead documented variables with no code reader (`KEYLATCH_AUDIT__ENABLED`, `KEYLATCH_GATEWAY__ENDPOINT`) and fixed a typo'd variable name (`KEYLATCH_AUDIT__PATH` → `KEYLATCH_AUDIT_PATH`).
- Documentation: `docs/cli/environment.md` now documents previously-undocumented active variables (`KEYLATCH_DAEMON_SOCKET`, proxy child-injected `KEYLATCH_SESSION_TOKEN`/`KEYLATCH_CA_CERT`, `KEYLATCH_PKCS11_PIN`, Windows `KEYLATCH_IPC_KEY`) and the non-`KEYLATCH_*` provider aliases accepted by cloud backends. Marked `KEYLATCH_DAEMON_STATE_PATH` deprecated (no remaining code reader). Corrected the proxy-mode child-env summary, which previously claimed no `KEYLATCH_*` vars are forwarded and listed `SHELL` in the base env (`internal/runner/driver_proxy.go` does not include `SHELL`).
- Documentation: Docker instructions (`README.md`, `docs/installation.md`) previously showed mounting `~/.keylatch` to `/root/.keylatch`, which does not work — the image runs as the distroless `nonroot` user (UID 65532), not root. Corrected to use `KEYLATCH_CONFIG_DIR=/home/nonroot/.keylatch` with a matching volume mount, documented the new `KEYLATCH_UI_LISTEN` opt-in for reaching the browser UI from outside the container, replaced a broken example that published a port without passing a subcommand (the entrypoint just prints `--help` and exits), and corrected `docs/installation.md` calling the image a "`keylatchd` sidecar image" — it ships only the `keylatch` CLI. Documented which backends actually work inside the distroless container (file, `aws-sm`, `vault`) versus which require a CLI binary the image doesn't ship (`op`, `bw`, `keychain`, `lastpass`, `keeper`, `proton-pass`).
- Documentation: `docs/getting-started.md` setup-wizard step labels were stale (`[3/5] Daemon setup...`, `[5/5] Open Keylatch app (optional)...`) — updated to match current CLI output (`[3/5] Gateway setup...`, `[5/5] Open Keylatch UI (optional)...`).

### Security

- Gateway proxy mode (`gateway_proxy`) now enforces per-session bearer authentication by default on the local MITM proxy, closing a gap where an unauthenticated caller on the loopback proxy port could act as the child process. Scoped to `gateway_proxy` runs.
- Raw-credential commands now require a verified session. `keylatch get` and `keylatch run` in a raw-credential-exposure mode (`direct_brokered`, `direct_classic_sandboxed` — the modes that place a real secret in the child's environment) now require positive corroboration that the caller is trusted: a signed session ticket (`KEYLATCH_LLM_TICKET`) or a reachable `keylatchd`. Without either, the command **fails closed** with exit code 2 — for *every* session, including one that has unset all LLM-detection signals to look human (this closes the prior spoof-to-human bypass). Gateway modes (`gateway_typed`, `gateway_sdk`, `gateway_proxy`) are **never** gated by this check, for any session, because the child there only ever receives a scoped session token, never a raw secret.
  - **Potentially breaking**: a user who runs `keylatch get` or a direct-mode `keylatch run` *without* `keylatchd` running will now be refused unless they opt out. Opt out permanently by setting `allow_unverified_session: true` in `config.json`, or per-invocation with `KEYLATCH_ALLOW_UNVERIFIED_SESSION=1`. Running `keylatchd`, or using a gateway/proxy run, requires no change.
- `keylatch run --extra` now withholds credential-shaped variables from the child. In addition to the existing exact-name provider-key denylist, any `--extra` name whose (case-insensitive) form ends in or contains `_KEY`, `_TOKEN`, `_SECRET`, `_PASSWORD`, `_PASSWD`, `_CREDENTIAL(S)`, or `_PRIVATE_KEY` is no longer copied into the `gateway_proxy` child; a warning naming each withheld variable is printed to stderr. Prevents a caller from leaking a real provider secret into the agent by requesting it via `--extra`.
- `--listen` / `KEYLATCH_UI_LISTEN` / `KEYLATCH_GATEWAY_LISTEN` values are now validated as `host:port` before binding, returning a clear error instead of a raw `net.Listen` failure. (Non-loopback binds remain refused inside a detected LLM session regardless.)
- Container images are now scanned and signed in CI as part of the release pipeline: per-arch Trivy vulnerability scanning plus cosign signing and a CycloneDX SBOM attestation on the multi-arch **manifest-list digest** (what `docker pull` resolves), in addition to the existing CLI-archive/SBOM blob signing.
- **Claude Code exfiltration guard hardened against command-boundary and tokenizer bypasses** (`contrib/agent-guards/claude-code/block-keylatch-exfiltration.sh`, mirrored at `internal/guard/scripts/block-keylatch-exfiltration.sh`). Closed a quote-wrapped command-boundary bypass (a `bash -c '...'` / `sh -c "..."` wrapper previously evaded detection of `keylatch get`, `security find-*-password`, `op read`/`item get`, `bw get`/`list`, `keylatch run -- env`, and reads of `.keylatch`/`.env` files). Rewrote bare `env`/`printenv` detection from a regex to a structural shell-word tokenizer, closing several further bypass classes (bundled `-c` flag clusters, backslash-newline continuation inside both unquoted and double-quoted text, bare ANSI-C `$'...'` quoting, brace expansion, and positional-parameter default expansion). `keylatch-hook-version` is now `4` — installations should re-run `keylatch install-guard claude-code` to pick up the fix.
- **Aider, Copilot, Cursor, and Windsurf exfiltration guards hardened to match Claude Code's v4 guard.** Bare `env`/`printenv` invocations and `keylatch run -- env` were not detected by these four guards, letting an agent dump loaded secrets via a plain environment listing instead of a flagged read command. Ported the structural `env`/`printenv` tokenizer and the quote-wrapped command-boundary fix into all four guards and their `go:embed`'d `internal/guard/scripts/*-guard.sh` copies. `keylatch-hook-version` is now `3` for these guards — re-run `keylatch install-guard <agent>` to pick up the fix.
- Bumped `google.golang.org/grpc` v1.80.0 → v1.82.1 (GO-2026-6061), `golang.org/x/text` v0.37.0 → v0.39.0 (GO-2026-5970, infinite loop on invalid input), and the Go toolchain 1.26.4 → 1.26.5 (GO-2026-5856, Encrypted Client Hello privacy leak in `crypto/tls`) — all three were reachable from `keylatch`'s TLS proxy and cloud-backend code paths per `govulncheck`.

## [0.9.4] - 2026-06-24

First MVP-scoped release: ships the self-contained CLI (macOS/Windows/Linux), the Docker image, and the Linux desktop app (AppImage/.deb). macOS and Windows desktop apps are deferred to a post-MVP release — use the CLI on those platforms (`keylatch ui` provides the browser GUI).

### Changed

- **MVP distribution scope.** Release builds ship the **Linux desktop bundle (AppImage/.deb) only**; the macOS `.dmg` and Windows `.exe` desktop apps are deferred to a post-MVP release to avoid code-signing certificate costs. The Tauri code stays in the repo — re-enable macOS/Windows desktop builds by setting the `DESKTOP_OS_MATRIX` repo variable (no code change). On macOS/Windows, use the self-contained CLI; `keylatch ui` provides the same browser GUI.

### Added

- Linux desktop bundle is now **cosign-signed** alongside the CLI archives, checksums, and SBOM.
- `docs/architecture/signing.md` — explains the three signing systems and how keyless cosign works.

## [0.9.3] - 2026-06-23

Maintenance release on the 0.9.x public-alpha line. No behavioural changes to the vault, gateway, or guard — this release fixes how the installers are versioned and how the release is published so external testers get a correct, unambiguous build.

> **Note on code-signing (0.9.3):** Unchanged from 0.9.2 — desktop binaries are not code-signed. On macOS, run `xattr -dr com.apple.quarantine keylatch.app` if Gatekeeper blocks the app. On Windows, dismiss the SmartScreen prompt.

### Fixed

- **Desktop installers now carry the release version.** Previously the `.dmg`, `.exe`, `.AppImage`, and `.deb` were stamped with the static manifest version rather than the release tag (e.g. an `0.9.3` release shipping `0.9.2`-labelled installers). The release pipeline now stamps the desktop bundle version from the git tag, matching the CLI artifacts.
- **Pre-release tags are no longer published as "Latest".** Hyphenated tags (`-alpha`/`-beta`/`-rc`) are now flagged as GitHub pre-releases, so a clean `0.9.x` tag is the default download for testers and internal alphas no longer shadow it.

### Changed

- Substantial test-coverage hardening across credential backends (1Password, Bitwarden, Infisical, NordPass, GCP SM, Azure KV), IPC, exec, and agent presets — `internal/exec` now enforced at the 85% coverage gate.
- CI hygiene: longer `go-test` timeout, untracked the stray `release-manifest` binary, and cosign identity verification now accepts pre-release tags.

## [0.9.2] - 2026-06-11

*Originally drafted as 1.0.0; re-versioned — 1.0.0 ships after the alpha cycle.*

> **Note on code-signing (0.9.2):** Desktop binaries are not code-signed in this release. On macOS, run `xattr -dr com.apple.quarantine keylatch.app` if Gatekeeper blocks the app. On Windows, dismiss the SmartScreen prompt. Code-signing will be added in a future release.

### Zero-trust credential vault

Keylatch 0.9.2 is the stabilization release before the v1.0.0-alpha cycle. It is designed for security-conscious developers who run AI coding agents and need to keep API keys out of model context, MCP tool outputs, and agent logs.

### What you get

- **LLM session blocking** — Claude Code, Codex, Cursor, Aider, Gemini CLI, and OpenCode are auto-detected. Direct credential reads (`keylatch get`) are blocked with exit code 2 inside any detected session.
- **4 credential backends** — macOS Keychain (hardware-backed), 1Password CLI, Bitwarden CLI, and an encrypted file (XChaCha20-Poly1305 / AES-256-GCM). Backend can be switched at runtime with live key migration.
- **Desktop app** — macOS, Windows, and Linux. Includes a first-run wizard, tray icon, approval inbox, and agent profile setup — no terminal required for day-to-day use.
- **Full web UI** — connections list, per-connection approval policy override, diagnostics, settings, and a live receipt stream.
- **Per-connection approval policy override** — set Trust, Prompt, or First-run per provider without touching the global default.
- **Credential backend switcher** — switch between Keychain, 1Password, Bitwarden, and encrypted file in Settings (Advanced mode). Vault key is migrated automatically; app restarts on completion.
- **Gateway middlewares enforced** — `authBlockerMiddleware`, `hostOverrideBlockerMiddleware`, and `SSRFGate` are now active at runtime. Agent-supplied `api_key` query params, `X-Forwarded-Host` headers, and SSRF-class upstream hosts are blocked.
- **MCP server** — 5 tools for AI agent integration via the MCP protocol.

### Security fixes (wired for the first time in 0.9.2)

- Gateway middlewares (`authBlockerMiddleware`, `hostOverrideBlockerMiddleware`, `SSRFGate`) were implemented in earlier alpha phases but never invoked at runtime. They are now wired. Upgrading from 0.1.0-alpha is strongly recommended.
- Token cache is now bounded (1000 entries, FIFO eviction) — eliminates unbounded-map memory growth under sustained load.
- Strict Content-Security-Policy with no `'unsafe-inline'` in `script-src` and no wildcard in `connect-src`.

### Release pipeline

- SBOM published in CycloneDX and SPDX formats for every release.
- Release artifacts signed with cosign via GitHub Actions OIDC (keyless).
- Dependabot enabled for Go modules, npm, Cargo, and GitHub Actions (weekly, conventional-commit prefix).

## [0.9.3-alpha.2] - 2026-06-12

### Fixed

- Release verification accepts pre-release tags in the cosign identity.

## [0.9.1] - 2026-06-03

### Fixed

- First-run onboarding initialises the keychain, writes connection metadata and fixes the doctor checks; the web wizard bootstraps correctly.
- Mock binaries in tests no longer race with exec on Linux, and CI caches Go and bun builds.

## [0.9.0] - 2026-06-02

First release of the 0.9 line, cut after the history rewrite described above.

## [0.1.0-alpha] - 2026-05-13

### Added — Phase 0 — Go CLI skeleton with LLM session guard
- Zero-trust LLM session guard: `CLAUDE_CODE`, `CODEX_ENV`, `CREDENTIALS_LLM_SESSION`, `CURSOR_SESSION`, `AIDER_SESSION`, `GEMINI_SESSION`, `OPENCODE_SESSION` env detection.
- Portable bootstrap and doctor commands for setup and diagnostics.

### Added — Phase 1 — Credential backends
- File backend with AEAD-encrypted at-rest storage.
- macOS Keychain backend (custom keychain at `~/.keylatch/keylatch.keychain-db` with item-level entries).

### Added — Phase 2 — Password-manager backends
- 1Password CLI (`op`) backend with passphrase-derived KEK.
- Bitwarden CLI (`bw`) backend with passphrase-derived KEK.

### Added — Phase 3 — Registry, MCP, agent snippets
- Provider connection registry with template YAML format.
- MCP server exposing 5 tools for AI agent integration via `modelcontextprotocol/go-sdk` v1.6.0.
- Agent snippet generation for Claude, Cursor, Codex, and Aider.

### Added — Phase 4 — Metadata, versions, expiry
- Versioned secret storage with rollback support.
- Per-secret metadata (TTL, expiry, tags, notes).
- `keylatch set`, `versions`, `destroy-version`, `rollback`, and `check-expiry` CLI commands.

### Added — Phase 5 — Envelope crypto + audit
- AEAD envelope primitives (XChaCha20-Poly1305 default, AES-GCM under FIPS).
- KEK providers: passphrase (Argon2id), keychain, op, bw, age.
- HMAC-chained audit log with rotation and tamper-resistance.
- Keyring init / rotate-term / rotate-kek / destroy-term / status CLI commands.

### Added — Phase 6 — Test suite
- Canary leak detection package (`internal/canary`).
- Audit chain HMAC verification (`internal/auditverify`).
- MockRunner for deterministic CLI tests.
- Cross-platform CI workflows (ubuntu, macos, windows).

### Added — Phase 7 — Packaging, docs, release
- `goreleaser` config producing tar.gz (Linux/macOS) and zip (Windows) archives, with `brews`, `scoops`, and `dockers` stanzas.
- `release-gates/` shell scripts (sbom-verify, docs-scan, provider-template-validate, secret-format-check, reproducible-build).
- Contributor docs: README, CONTRIBUTING, SECURITY, examples, and `docs/` site.

### Added — Phase 8 — Policy, actors, grants
- Policy engine with actor + capability matching and TTL-bound grants.
- Persistent grant lifecycle with file-backed storage.
- `keylatch policy`, `actor`, `grant` CLI commands.

### Added — Phase 9 — Local typed gateway
- Local gateway HTTP server (default `127.0.0.1:7878`) with a 12-step request lifecycle: JWT verify → route match → capability check → LLM-session gate → policy check → substitution prevention → vault.Get → broker.Exchange → upstream call → redact → audit → respond.
- Sub-packages: `token` (JWT), `redact`, `substitution`, `broker`, `approval`, `route`.
- Docker mode for sandboxed gateway runs.

### Added — Phase 10 — Localhost UI
- `keylatch ui` command launches a local browser dashboard at `127.0.0.1:7890`.
- Bootstrap-token + HttpOnly session cookie + CSRF double-submit pattern.
- Strict Content-Security-Policy with no `'unsafe-inline'` or wildcards.
- Embedded SPA (Vite + React) served from the Go binary.
- Connections, approvals, gateway, broker, audit, and agent API endpoints.

### Added — Phase 11 — Roots of trust
- Pluggable trust adapter layer with 7 backends: keychain (macOS Secure Enclave hooks), file, FIDO2, GPG card, PKCS#11, SSH agent, HashiCorp Vault, and fallback.
- Attestation infrastructure for trust roots.

### Added — Phase 12 — Team governance
- Organization policy layer with SCIM-style user/group sync.
- Org-level decision composition (deny-filter; capability-ceiling work tracked separately).
- Shared-secret rotation infrastructure.
- CI claims for headless team workloads.

### Added — Phase 13 — Token broker, masking, proxy
- Token broker with cache, lease, and revocation lifecycle.
- Masking/redaction layer for credential values in responses.
- Advanced proxy controls (per-route TTL, allowed params, max body size).

### Added — Phase 14 — Desktop product shell
- Tauri-based desktop app (`keylatch-app`) with a Rust shell + embedded keylatch sidecar.
- IPC channel using key-via-FD handoff (no key bytes in CLI args or env).
- Approval flow with system-tray notifications.
- OAuth callback handler for browser-based flows.
- Single-instance lock to prevent racing sidecar processes.
- Auto-update infrastructure (currently disabled — `active: false` in `tauri.conf.json` pending signing-key provisioning).

### Security
- Canary sentinel infrastructure (`internal/canary`) for leak detection in tests.
- Audit chain HMAC verification (`internal/auditverify`).
- LLM session blocking on all value-bearing CLI commands.
- Agent-guard hook: `contrib/agent-guards/claude-code/block-keylatch-exfiltration.sh`.
