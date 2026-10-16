---
title: The Linux broker
description: Install the system broker, adopt your in-user secrets, approve privileged changes, rotate its keys and go back.
---

# The Linux broker

On Linux with systemd, Keylatch can run as a broker daemon under its own OS user. Agents get capabilities, never keys: the keys, the secret store, the policy and the audit log belong to the `keylatch` account, and a process running as you cannot read them.

Without the broker, Keylatch runs in **in-user mode**: the same commands, but everything lives in your account, so it raises the cost of a leak and is not a boundary against a determined process running as you. `keylatch doctor` says which mode is active and warns while you are in in-user mode on a machine where the broker is available. See [Security](../security.md) and the [threat model](../security/threat-model.md).

## What you need

- systemd 250 or newer (encrypted credentials), on Linux 5.3 or newer.
- polkit, for presence: your own password, asked through the desktop's authentication dialog every time. Without it the daemon refuses every privileged request.
- Root for the one-time install.

## Install

From the `.deb` or `.rpm` package, or from the release archive, run once:

```bash
sudo keylatch broker install
```

It creates the `keylatch` system user, places the `keylatchd` service and socket units and the polkit policy (a package already ships them), seals a fresh device root with `systemd-creds encrypt --with-key=auto` and starts `keylatchd.socket`. The device root is sealed to the TPM2 plus the host key when the machine has a TPM, and to the host key alone otherwise; `keylatch doctor` warns "no TPM binding" in the second case. The command never replaces an existing root, because every key is wrapped by it.

Check the result:

```bash
keylatch broker status --json
keylatch doctor
```

## Adopt your existing secrets

```bash
keylatch broker adopt
```

Adopt reads the secrets, policy and audit position of your in-user install and sends them to the daemon. The daemon shows you a polkit prompt describing exactly what moves; approving it is the proof of presence. Then:

1. every secret is stored in the daemon and read back, and the daemon answers with a keyed hash of each value, which Keylatch compares with its own;
2. your policy is signed by the daemon (a second prompt);
3. your in-user gateway tokens are revoked;
4. only after all of that matched, your in-user key material (the vault identity, `keyring.json`, `signing.key`, `audit-salt`) is overwritten and removed.

If any hash differs, nothing of your in-user install is touched. Every upstream key that sat in your account is listed afterwards, and `keylatch doctor` keeps listing it as **rotate recommended**: a process of your account could have read it before the move. Rotate each one at its provider and store the new value with `keylatch set <path>`; `set` resolves the same shorthand paths it does in in-user mode.

## Day to day

The commands you know keep working; they go through the daemon and open no key file.

```bash
keylatch set openai.api_key
keylatch run openai -- ./script.sh
keylatch policy import ./policy.d
keylatch audit head --json
keylatch launch -- claude
```

- `set` and `policy import` change policy or secrets, so the daemon asks for presence first. The text in the prompt is built by the daemon from the request, not supplied by the client, and the proof is bound to that request: it works once, within 60 seconds, for that request only.
- `run`, `call`, `status`, `list`, `doctor`, `describe`, `explain` and `policy check` are served by the daemon. `get`, `export`, `backup` and `mint` to a terminal are not available through the broker.
- `launch` registers a new agent session with the daemon and starts the harness in a transient systemd scope, `keylatch-agent-<id>.scope`. The daemon classifies every process in that scope as an agent from its control group alone, so clearing the environment does not hide it. A process that leaves the scope (for example with `systemd-run --user --scope`) is classified as `host`, never `human` or `service`.

If the broker socket exists but the daemon does not answer, Keylatch says so and stops. It does not fall back to local key files, which are not where the keys are any more.

## Rotate

```bash
keylatch broker rotate-keys
```

Replaces the broker master key after a presence prompt. Every wrapped key and every stored data key is rewrapped; no stored value is re-encrypted. If the daemon is interrupted in the middle, it finishes the rotation when it starts.

## Go back

```bash
keylatch broker export-to-user
```

After a presence prompt, copies every secret the broker holds for you into an in-user install (creating one if you have none). The broker keeps its copy.

## How it protects

| Piece | What it does |
|---|---|
| Socket and peer identity | `/run/keylatch/broker.sock` accepts any local user. The daemon reads the peer's uid, pid and a pidfd from the kernel (`SO_PEERCRED`, `SO_PEERPIDFD`), the process start time and its cgroup. It checks the pidfd again before acting, so a request from a recycled PID is refused. |
| Per-user partitions | Each user has `/var/lib/keylatch/users/<uid>/` with its own store, policy and control server. Data keys are authenticated with partition, path and version, so a record copied into another user's directory does not open. |
| Key hierarchy | A device root handed over by systemd wraps one broker master key. Store keys, audit keys and the token key derive from it with HKDF; the signing keys are random and stored wrapped by it. Key pages are locked in memory. |
| Presence | The daemon asks polkit (`dev.keylatch.privileged`, `auth_self`, never retained) with the calling process as the subject. A proof is bound to the request digest, valid 60 seconds and single use. A raw client that skips the prompt gets a refusal. An agent session cannot even ask. |
| Signed policy | Accepted policy is stored with an Ed25519 signature and the digest of the presence proof. A file edited afterwards, or added, is ignored: the daemon denies and records a `security.block` event. |
| Hardening | The unit runs as `keylatch` with a strict filesystem view, no capabilities, a system call filter and no write-and-execute memory; the process is not dumpable and has no core dumps. `systemd-analyze security keylatchd.service` scores below 2.0. |

## Why the wire protocol is not gRPC

The broker speaks the control socket's JSON frames, extended with the broker operations. The socket is local, the kernel identifies the peer, and every frame is size-bounded, strictly decoded and fuzzed (`FuzzBrokerRequest`, `FuzzControlFrame`). gRPC would add a code-generation step and a second framing for no gain in security, and the thin client already speaks the JSON protocol. If a future need requires gRPC, it replaces the framing, not the operations.

## Limits of this release

- The `file` backend's metadata flags on `set` (`--expires-at`, `--owner`, and so on) are not stored by the broker; `set` refuses them instead of dropping them.
- Secrets reach a command through `run`: the daemon hosts a gateway for each partition, reads the partition's store itself and issues the session token. The other served verbs (`call`, `status`, `list`, `describe`, `explain`, `doctor`) run as the `keylatch` user against the partition's configuration, and the broker store is not yet a backend for that child, so `call` does not reach stored secrets through the broker in this release; use `run`.
- Presence uses polkit. A FIDO2 security-key path is not part of this release.
- Root on the host, and a compromised daemon, are outside the model: the daemon is the trusted computing base.
- macOS and Windows keep in-user mode; their brokers are separate work.
