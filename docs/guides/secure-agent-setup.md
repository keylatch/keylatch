---
title: Secure agent setup
description: Install Keylatch, set a default-deny policy, install the guard, launch an agent and verify the result.
---

# Secure agent setup

This guide takes a machine from nothing to an agent that can use a credential without ever holding it. Keylatch runs as your user in this release, so the result keeps keys out of model context and out of casual reach; it is not a boundary against a determined agent running as you. See [Security](../security.md).

## 1. Install

```bash
brew install keylatch/tap/keylatch
```

Other platforms and checksum verification: [Installation](../installation.md), [Verifying releases](../verifying-releases.md).

## 2. Set up

```bash
keylatch setup
```

Setup picks the recommended backend (Bitwarden, then 1Password, else the encrypted file), writes a default-deny policy and ends with a doctor report. For scripts use the headless form, for example `keylatch setup --non-interactive --backend op`. Ready-made configs are in [examples/config](https://github.com/keylatch/keylatch/tree/main/examples/config).

## 3. Connect a provider

```bash
keylatch connect openrouter --provider-ref api_key=op://Keylatch/openrouter/api_key
```

Referencing an external store keeps the value out of Keylatch's own storage.

## 4. Check the policy

```bash
keylatch policy init
```

The default policy denies everything. Allow only what a run needs, then review it with `keylatch policy`.

## 5. Install the guard

```bash
keylatch install-guard claude-code
```

The hook blocks the common ways an agent reads credentials. Other agents get guards in v0.13.0.

## 6. Launch the agent

```bash
keylatch gateway up --detach
keylatch gateway token create claude-code --allow openrouter.chat --ttl 1h
keylatch run openrouter --clean-env -- <agent-command>
```

The agent receives a short-lived token and the gateway URL, never the provider key.

## 7. Verify

```bash
keylatch doctor
keylatch audit
```

`doctor` names the root cause first and skips the checks that depend on it. Fix what it reports from the top. `audit` shows each read and injection without values.
