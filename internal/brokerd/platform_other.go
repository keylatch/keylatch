//go:build !linux && !darwin && !windows

package brokerd

// DefaultStateRoot is where the daemon keeps its state.
const DefaultStateRoot = "/var/lib/keylatch"

// DefaultSocket is the socket the clients connect to.
const DefaultSocket = "/run/keylatch/broker.sock"

const presenceHint = "no presence method exists for this platform"
