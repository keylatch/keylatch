//go:build unix

package control

import (
	"bufio"
	"errors"
	"os"
	"syscall"

	"github.com/keylatch/keylatch/internal/brokerapi"
)

// CallWithFiles sends a broker request that is followed by file descriptors.
// The daemon answers the request with CodeSendFiles when it accepts it and is
// ready for them; any other first answer, a refusal for instance, is the reply.
func (c *Client) CallWithFiles(req brokerapi.Request, files []*os.File) (brokerapi.Response, error) {
	if req.Signals == nil {
		req.Signals = c.signals
	}
	if req.Ticket == "" {
		req.Ticket = c.ticket
	}
	conn, err := c.dial()
	if err != nil {
		return brokerapi.Response{}, err
	}
	defer func() { _ = conn.Close() }()
	if err := writeFrame(conn, req); err != nil {
		return brokerapi.Response{}, err
	}
	r := bufio.NewReader(conn)
	var resp brokerapi.Response
	if err := readFrame(r, &resp, maxResponse); err != nil {
		return brokerapi.Response{}, err
	}
	if resp.Code != brokerapi.CodeSendFiles {
		return resp, nil
	}
	fds := make([]int, len(files))
	for i, f := range files {
		fds[i] = int(f.Fd()) //nolint:gosec // G115: a descriptor is a small non-negative int
	}
	if _, _, err := conn.WriteMsgUnix([]byte{0}, syscall.UnixRights(fds...), nil); err != nil {
		return brokerapi.Response{}, err
	}
	if r.Buffered() > 0 {
		return brokerapi.Response{}, errors.New("control: unexpected data before the descriptors were sent")
	}
	resp = brokerapi.Response{}
	if err := readFrame(r, &resp, maxResponse); err != nil {
		return brokerapi.Response{}, err
	}
	return resp, nil
}
