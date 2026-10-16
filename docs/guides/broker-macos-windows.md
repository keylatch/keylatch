---
title: The macOS and Windows broker
description: Install the system broker as a LaunchDaemon on macOS or a service on Windows, enroll your presence key, adopt your in-user secrets and see what each platform protects.
---

# The macOS and Windows broker

The broker works the same way on every platform: the keys, the secret store, the policy and the audit log belong to a service account, and a process running as you cannot read them. Only the platform layer differs. This guide covers what is different on macOS and Windows; [the Linux guide](broker-linux.md) explains adopting, rotating and going back, and those commands behave identically here.

Without the broker, Keylatch runs in **in-user mode**, which raises the cost of a leak and is not a boundary against a determined process running as you. `keylatch doctor` says which mode is active and warns while you are in in-user mode.

## What you need

| | macOS | Windows |
|---|---|---|
| Service | LaunchDaemon `dev.keylatch.broker` running as the hidden account `_keylatch` | Service `keylatch` running as `NT SERVICE\keylatch`, a virtual account with no password |
| Endpoint | Unix socket `/var/db/keylatch/run/broker.sock` | Named pipe `\\.\pipe\keylatch-broker` |
| State | `/var/db/keylatch` | `%ProgramData%\keylatch`, readable by the service and SYSTEM only |
| Presence | Touch ID through a Secure Enclave key | Windows Hello |
| Install rights | root | an elevated prompt |

## Install

From the release package, run once:

```bash
sudo keylatch broker install        # macOS
```

```powershell
keylatch broker install             # Windows, elevated prompt
```

On macOS it creates the `_keylatch` account in the service id range, the state directory, seals a fresh device root in the System keychain, writes the daemon and presence property lists and loads them with `launchctl`. On Windows it creates the state directory with a protected ACL, seals the device root with a CNG key whose ACL names only the service, registers and starts the service and adds the presence helper to the logon entries. Running it again keeps everything that exists. The command never replaces a device root, because every key is wrapped by it.

Check the result:

```bash
keylatch broker status --json
keylatch doctor
```

## Enroll your presence key

Privileged changes (storing a secret, importing policy, adopting, rotating) need proof that a person is at the machine. The broker does not take your word for it: the presence helper, which runs in your login session, signs a challenge with a key that Touch ID or Windows Hello guards, and the broker checks the signature against the public key an administrator enrolled for your account. Only root or an administrator can enroll, so a program running as you cannot register a key of its own and approve itself.

```bash
sudo keylatch broker enroll-presence --user alice     # macOS: asks the helper in alice's session for its key
```

```powershell
keylatch-presence.exe public-key > key.pem                                   # as the user
keylatch broker enroll-presence --user DOMAIN\alice --key-file key.pem       # elevated prompt
```

Each proof is bound to the digest of one request, is valid for 60 seconds and works once.

## Adopt your existing secrets

```bash
keylatch broker adopt
```

Adopt moves your in-user secrets, policy and audit position into the broker exactly as on Linux, and asks for presence through Touch ID or Windows Hello. Every upstream key that sat in your account is listed afterwards and stays marked **rotate recommended** in `keylatch doctor`.

## How it protects

| Piece | macOS | Windows |
|---|---|---|
| Peer identity | The daemon reads the connecting process from the socket (`LOCAL_PEERPID`, the audit token with its PID version) and its start time, so a recycled PID is refused. The code identity and parent are recorded. | The daemon reads the pipe client's process id, the SID of its token and its session. Only user SIDs are served: SYSTEM, service accounts and built-in groups are refused. |
| Endpoint trust | The client refuses a socket owned by any account except you, root or `_keylatch`. | The client refuses a pipe that another account serves; the server must run as `NT SERVICE\keylatch`. |
| Per-user partitions | One partition per user id | One partition per account SID |
| Device root | System keychain, readable by the daemon's code identity | CNG key whose ACL names the service |
| Presence | Signed challenge from the Secure Enclave key | Signed challenge from the Windows Hello key |

Policy signing, the key hierarchy, the secret store and the audit log are shared code with the Linux broker.

## Contained commands

Tier D5 (`keylatch run --tier D5 <connection> -- <command>`) runs a command in a sandbox that hands it the real secret value and gives it no way out except through the daemon's egress proxy. See [the contained runtime](../contained-runtime.md). The mechanism depends on the platform:

| | Linux | macOS | Windows |
|---|---|---|---|
| Isolation | user, mount, PID, IPC, UTS, network and cgroup namespaces, Landlock, seccomp | a Seatbelt profile run by `sandbox-exec` | an AppContainer with no capabilities |
| Files | a private root with the project, the listed paths and an empty home | read access to system directories and the listed paths, write access to the project, a private home and a private temporary directory | the same, granted to the AppContainer for the length of the run |
| Network | none except the forwarder to the egress proxy | none except loopback ports the profile names | none except loopback, which is exempted for the container |
| Limits | cgroup memory, process and CPU limits | not applied | job object limits on memory, processes and CPU; the job also ends the run when it closes |

`keylatch doctor --sandbox` reports what the host supports.

## Limits of this release

- Socket activation is a systemd feature. The macOS daemon and the Windows service open their own endpoint.
- Terminal (PTY) runs are not available in the contained tier on macOS and Windows. Run the command without a terminal.
- A contained run holds the forwarder's loopback port (3128) for its lifetime on macOS and Windows, so only one contained run can be active at a time.
- On Linux the secret reaches the sandbox over an inherited pipe. On macOS and Windows there is no helper process to hand it to, so it is placed directly in the command's environment block by the daemon.
- The macOS sandbox profile allows only the mach services a command-line tool needs. A tool that needs another system service fails inside the sandbox.
- Windows loopback exemption for an AppContainer is a machine-wide setting that only an elevated account can change; the daemon removes the entry when the run ends.
- The user's Windows Hello key and Secure Enclave key cannot be exported or used by another account. Replacing a Mac or reinstalling Windows means enrolling a new key.
- Root on the host and a compromised daemon are outside the model: the daemon is the trusted computing base.
