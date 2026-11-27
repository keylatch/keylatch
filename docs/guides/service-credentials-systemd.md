---
title: Service credentials for systemd units
description: Give a systemd service its secret through the broker, so the unit gets it and nothing else does.
---

# Service credentials for systemd units

A long-running service needs its secret at start-up, and nobody is at the keyboard to approve it. `keylatch service` enrolls the unit once, with your presence, and from then on the [system broker](broker-linux.md) releases the connection to that unit and to nothing else. It needs the broker: the broker is what can tell a unit from a shell.

## How it works

1. **Enroll** (you, once). `keylatch service enroll` asks the broker to look the unit up through the service manager and record: the unit name, the scope, a SHA-256 over the unit file and its drop-ins, `ExecStart`, and whether a transient unit is allowed. The broker draws a random 256-bit capability, stores only a keyed hash of it, and hands the capability to the command, which seals it with `systemd-creds encrypt` into `/etc/credstore.encrypted/keylatch-<connection>.cred`.
2. **The unit loads the credential.** `keylatch service render-unit-lines` prints the two lines to add: `LoadCredentialEncrypted=keylatch-<connection>:<path>` and `Environment=KEYLATCH_SERVICE_CONNECTION=<connection>`. systemd decrypts the file into `$CREDENTIALS_DIRECTORY` for that unit.
3. **The unit runs its command.** Inside the unit, `keylatch run <connection> --runtime service -- <command>` reads the credential file and presents its content to the broker. The broker releases the connection only when all of these hold:
   - the peer's control group is the enrolled unit (read from the kernel, not from the environment);
   - the capability matches;
   - the unit is not transient, unless it was enrolled with `--allow-transient`;
   - the unit file, the drop-ins and `ExecStart` still equal what was enrolled, checked again at every release.

   The command then starts with the values in its environment, as the connection's runtime contract names them. Output is redacted for the values. Any mismatch is refused and audited as `security.block`; a release is audited as `release` with the connection, the unit and caller kind `service`, never the value.

**The sealed file holds the capability, not the secret.** Anyone who can decrypt it learns a number that is useless outside the unit: from a shell, a transient unit (`systemd-run`), another unit or a unit whose file was edited, the broker refuses it.

## Enroll a unit

```bash
sudo systemctl cat app.service
keylatch service enroll app-db --unit app.service
keylatch service render-unit-lines app-db --format ini
```

Put the printed lines in a drop-in (`systemctl edit app.service`), and start the service with an `ExecStart` such as `keylatch run app-db --runtime service -- /usr/local/bin/app`. Enrolling again replaces the connection's earlier enrollment and capability, so name every unit that should keep receiving it. Check the result with:

```bash
keylatch service list --json
```

`keylatch doctor` fails for an enrolled unit whose file, drop-in or `ExecStart` changed, and prints the command to enroll it again once you reviewed the change. Remove a unit with `keylatch service revoke app-db --unit app.service`, or every unit of a connection by leaving `--unit` out; delete the credential file when no unit loads it any more.

## System scope or user scope

**System scope (the default, recommended).** The unit is a system service, its file is root's and the credential store `/etc/credstore.encrypted` is root's. Sealing writes there, so the command asks for sudo for that one write. Services running as system accounts are served for this one request even though the broker serves no other request from those accounts.

**User scope (`--scope user`).** The unit belongs to your own user manager and the credential goes to `~/.config/credstore.encrypted`. This is weaker in one way you should know: your unit files are writable by your account, and so are by an agent running as you. That is why the unit is pinned by digest, a changed file is refused, and the capability is useless outside the unit. It does not stop a process that can change the unit file *and* have you re-enroll it, which needs your presence. Use system scope for anything important.

For both scopes the broker reads the unit's state from the service manager (`systemctl show`, which uses D-Bus). For a user unit that needs the broker to reach your user manager; when it cannot, the release is refused rather than guessed.

## What is not covered

- A process that can run as the unit's own user inside the unit's control group is the unit. Harden the unit itself (`NoNewPrivileges=`, `ProtectSystem=` and the rest of `systemd-analyze security`).
- A transient unit is a unit nobody wrote down: enrolling one (`--allow-transient`) pins `ExecStart` and nothing else. Prefer a unit file.
