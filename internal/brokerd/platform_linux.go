package brokerd

// DefaultStateRoot is where the daemon keeps its state (StateDirectory=keylatch).
const DefaultStateRoot = "/var/lib/keylatch"

// DefaultSocket is the socket the clients connect to.
const DefaultSocket = "/run/keylatch/broker.sock"

const presenceHint = "install polkit"
