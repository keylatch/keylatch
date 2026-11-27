#!/bin/sh
# Let systemd forget the removed units. The keylatch user, /var/lib/keylatch
# and /etc/keylatch/root.cred stay: they hold the user's secrets and the key
# that unwraps them, so removing the package must not destroy them.
set -e

if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
  systemctl daemon-reload || true
fi
