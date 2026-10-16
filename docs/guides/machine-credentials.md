---
title: Machine credentials for remote guests
description: Let a VM or CI runner call a domain's connections through the broker over mutual TLS, without it ever holding a secret.
---

# Machine credentials for remote guests

A build VM or a remote runner needs to call a provider as one of your connections, but it should not store the secret. `keylatch machine` issues it a credential that lets it ask the [system broker](broker-linux.md) to make the call. The broker holds the secret, makes the request and returns the redacted answer.

## How it works

1. **Issue** (you, with presence). `keylatch machine issue --domain apps --name ci-1 --caps call --ttl 24h --out ci-1.pem` makes an Ed25519 key pair on this host, sends only the public key to the broker, and writes the private key, the certificate and the CA certificate to `ci-1.pem` with mode 0600. The certificate is signed by the broker's machine CA and carries the name, the domain (a namespace) and the capabilities as extensions, and expires after `--ttl` (a minute to a year). Copy the file to the guest.
2. **Listen** (you, with presence). `keylatch config set gateway.machine_listen 10.0.0.5:7443` makes the broker serve TLS 1.3 on that address. A wildcard address (`0.0.0.0`, `::` or no host) is refused unless you also pass `--allow-wildcard`. The listener accepts only client certificates signed by the machine CA.
3. **Call** (the guest). `keylatch call --remote 10.0.0.5:7443 --machine-key ci-1.pem openai list-models` sends the connection and the action over mutual TLS. The response is redacted before it is printed.

## What the broker enforces

- The domain comes from the certificate, never from the request. A request that names another namespace is refused with `cross_domain` and audited as `security.block`.
- Every request is checked against the broker's record of the certificate, so a revoked or expired credential stops working at once, not at the next handshake.
- The certificate needs the `call` capability. Other capabilities in it are reserved.
- Calls are audited as `call` with caller kind `machine`; the connection, the action and the status are recorded, never the value.
- Issuing, revoking and changing the listener ask for your presence and are audited. A coding agent cannot run them.

## Revoke and list

```bash
keylatch machine list --json
keylatch machine revoke ci-1
```

Names are unique among active credentials; revoke one before issuing the same name again. Each user sees only the credentials they issued.

## Limits

- The guest must trust the broker's address: the server certificate names the host given to `gateway.machine_listen` and `localhost`, so connect to that address.
- Only `call` is served remotely. A guest cannot read, set or list secrets.
- Run the listener on a private network or behind a firewall; the certificate check is the only gate.
- The machine CA key is held by the broker, wrapped like its other keys.
