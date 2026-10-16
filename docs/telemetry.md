---
title: Telemetry
since: 1.0.0
---

# Telemetry

Keylatch sends no telemetry. No command, daemon, desktop shell or gateway reports usage,
errors, install identifiers or any other data to a remote service, and there is no setting that
turns that on.

Earlier builds contained an opt-in usage-metrics mode (the `telemetry` operating mode, the
`--telemetry` flag of `keylatch setup` and `KEYLATCH_TELEMETRY_DISABLE`). It has been removed. A
config file that still names the `telemetry` operating mode is rejected with an error that lists
the modes that exist (`standard`, `canary`, `custom`); run `keylatch config set mode standard`.

What Keylatch writes stays on your machine: the [audit log](architecture/audit-log.md) in the
config directory, which never contains secret values. Network traffic Keylatch makes is limited to
what you ask for: the gateway forwarding a request to the provider you called, and the backends you
configured (for example `bw` or `op`) talking to their own servers.
