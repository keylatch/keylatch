package brokerd

import (
	"strings"

	"github.com/keylatch/keylatch/internal/winpipe"
)

// ServiceSID returns the SID Windows derives for the service account
// NT SERVICE\<name>.
func ServiceSID(name string) string { return winpipe.ServiceSID(name) }

// Access masks. The pipe grants clients read and write on the data stream but
// not FILE_CREATE_PIPE_INSTANCE, which generic write would include and which
// would let a client open extra instances of the daemon's pipe.
const pipeClientMask = "0x120183"

// PipeSDDL is the security descriptor of the broker pipe: SYSTEM and the
// service have full access, interactive users can read and write, and network
// logons are refused outright.
func PipeSDDL(serviceSID string) string {
	return "D:P(D;;GA;;;NU)(A;;GA;;;SY)(A;;GA;;;" + serviceSID + ")(A;;" + pipeClientMask + ";;;IU)"
}

// DirSDDL is the security descriptor of the state directory: protected from
// inheritance, full control for SYSTEM and the service SID, nobody else.
func DirSDDL(serviceSID string) string {
	return "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;" + serviceSID + ")"
}

// IsUserSID reports whether sid names a person's account: a local or domain
// user (authority 5, sub-authority 21) or an Entra ID user (authority 12,
// sub-authority 1). SYSTEM, the service accounts and the built-in groups are not
// users of the broker.
func IsUserSID(sid string) bool {
	return strings.HasPrefix(sid, "S"+"-1-5-21-") || strings.HasPrefix(sid, "S"+"-1-12-1-")
}
