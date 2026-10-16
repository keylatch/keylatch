// Package macospkg carries the files `keylatch broker install` places on a Mac:
// the LaunchDaemon of the broker and the LaunchAgent of the presence helper.
// The same files go into the installer package.
package macospkg

import "embed"

// Files holds the launchd property lists by their path under packaging/macos.
//
//go:embed dev.keylatch.broker.plist dev.keylatch.presence.plist
var Files embed.FS
