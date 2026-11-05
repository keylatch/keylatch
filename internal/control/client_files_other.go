//go:build !unix

package control

import (
	"errors"
	"os"

	"github.com/keylatch/keylatch/internal/brokerapi"
)

// CallWithFiles is not available where descriptors cannot be passed.
func (c *Client) CallWithFiles(brokerapi.Request, []*os.File) (brokerapi.Response, error) {
	return brokerapi.Response{}, errors.New("control: file descriptor passing is not available on this platform")
}
