//go:build !linux && !darwin && !windows

package proc

func harden() error { return nil }
