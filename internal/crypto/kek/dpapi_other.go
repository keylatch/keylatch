//go:build !windows

package kek

func platformIdentityStore() IdentityStore { return nil }
