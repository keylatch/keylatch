//go:build !linux

package callerkind

// Service classification needs systemd. launchd programs and Windows services
// are enrolled by designated requirement and service SID with the broker
// daemon.
func detectServiceUnit() (string, bool) { return "", false }
