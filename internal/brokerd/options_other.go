//go:build !darwin && !windows

package brokerd

// applyPlatform leaves Linux to systemd credentials and polkit.
func (*Options) applyPlatform() error { return nil }
