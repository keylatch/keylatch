package control

import (
	"fmt"
	"strings"
	"time"

	"github.com/keylatch/keylatch/internal/winpipe"
)

// pipePrefix starts the path of every Windows named pipe.
const pipePrefix = `\\.\pipe\`

func isPipePath(path string) bool { return strings.HasPrefix(path, pipePrefix) }

func pipeExists(path string) bool { return winpipe.Exists(path) }

// brokerServiceSID is the SID of the account the Windows broker service runs
// as (NT SERVICE\keylatch): the client talks to nothing else on the broker pipe.
var brokerServiceSID = winpipe.ServiceSID("keylatch")

// processSID returns the account SID of a process, for checking who serves a
// pipe. Tests replace it; it is implemented on Windows only.
var processSID = func(pid uint32) (string, error) { return "", winpipe.ErrUnsupported }

// dialPipe connects to the broker pipe and checks that the service answers on
// it, so a pipe planted by another account is never trusted.
func (c *Client) dialPipe() (Conn, error) {
	conn, err := winpipe.Dial(c.socket, 2*time.Second)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNoDaemon, err)
	}
	if c.broker {
		pid, err := conn.ServerProcess()
		if err == nil {
			var sid string
			if sid, err = processSID(pid); err == nil && sid != brokerServiceSID {
				err = fmt.Errorf("pipe served by %s", sid)
			}
		}
		if err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("control: refusing a pipe not served by the broker service: %w", err)
		}
	}
	return conn, nil
}
