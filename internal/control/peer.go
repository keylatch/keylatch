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
	// SID is the account SID of the peer's token, set by the Windows broker.
	SID string
	// Exe is the peer's executable path when the broker could read it.
	Exe string
	// Code is the peer's code identity: the signing identifier and team the
	// macOS broker read from the process.
	Code string
	// ParentPID is the peer's parent process, 0 when unknown.
	ParentPID int
	// Verify, when set, confirms that the process is still the one identified
	// at connect time. The server calls it once the request has been read.
	Verify func() error
}
