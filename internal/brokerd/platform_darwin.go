package brokerd

// DefaultStateRoot is where the LaunchDaemon keeps its state. The directory is
// owned by the _keylatch account; every directory inside it is private to that
// account except run/, which holds the socket.
const DefaultStateRoot = "/var/db/keylatch"

// DefaultSocket is the socket the clients connect to. launchd would pass a
// socket only through liblaunch, so the daemon binds its own.
const DefaultSocket = "/var/db/keylatch/run/broker.sock"

const presenceHint = "install the presence helper with 'sudo keylatch broker enroll-presence'"
