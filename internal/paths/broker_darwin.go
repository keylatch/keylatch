package paths

// BrokerUser is the OS account the system broker runs under. macOS reserves
// the leading underscore for service accounts.
const BrokerUser = "_keylatch"

const defaultBrokerSocket = "/var/db/keylatch/run/broker.sock"
