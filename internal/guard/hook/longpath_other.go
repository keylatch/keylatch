//go:build !windows

package hook

func platformExpandShortNames(p string) string { return p }
