#!/bin/sh
# Create the keylatch system user and let systemd see the new units. Enabling
# the socket is left to 'sudo keylatch broker install', which also seals the
# device root; a package install never starts a daemon by itself.
set -e

if command -v systemd-sysusers >/dev/null 2>&1; then
  systemd-sysusers keylatch.conf || true
fi
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
  systemctl daemon-reload || true
fi
