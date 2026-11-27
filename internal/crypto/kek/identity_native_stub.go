//go:build !darwin || !cgo

package kek

func newMacOSIdentityStore() IdentityStore { return nil }
