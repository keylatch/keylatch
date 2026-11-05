// Package linuxpkg carries the files `keylatch broker install` places on a
// Linux host: the systemd units, the system user definition and the polkit
// policy. The same files go into the deb and rpm packages.
package linuxpkg

import "embed"

// Files holds the broker's system files by their path under packaging/linux.
//
//go:embed systemd/keylatchd.service systemd/keylatchd.socket sysusers.d/keylatch.conf polkit/dev.keylatch.policy
var Files embed.FS
