//go:build !(linux || freebsd || openbsd || netbsd)

package kek

func newSecretServiceIdentityStore() IdentityStore { return nil }

func sessionBusConfigured(func(string) string) bool { return false }
