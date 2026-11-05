//go:build !darwin && !windows

package paths

// BrokerUser is the OS account the system broker runs under.
const BrokerUser = "keylatch"

const defaultBrokerSocket = "/run/keylatch/broker.sock"
