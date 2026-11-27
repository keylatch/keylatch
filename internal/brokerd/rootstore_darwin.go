package brokerd

import "github.com/keylatch/keylatch/internal/brokerd/keys"

func defaultRootStore(stateDir, daemon string, own func(string) error) keys.RootStore {
	return keys.DefaultRootStore(stateDir, daemon, own)
}
