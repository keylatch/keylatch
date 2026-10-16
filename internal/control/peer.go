package control

// Peer is the kernel-attested identity of the process on the other end of a
// Unix socket.
type Peer struct {
	UID uint32
	// PID is 0 when the peer lives in a PID namespace the daemon cannot see.
	PID int
	// Cgroup is the peer's control group path. Only a broker that pinned the
	// process sets it.
	Cgroup string
	// Start is the process start time in clock ticks since boot, set with
	// Cgroup.
	Start string
	// Verify, when set, confirms that the process is still the one identified
	// at connect time. The server calls it once the request has been read.
	Verify func() error
}
