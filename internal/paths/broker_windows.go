package paths

// BrokerUser is the service account the system broker runs under
// (NT SERVICE\keylatch).
const BrokerUser = "keylatch"

// defaultBrokerSocket is the named pipe the broker service listens on.
const defaultBrokerSocket = `\\.\pipe\keylatch-broker`
