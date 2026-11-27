//go:build !unix

package socketrelay

import "errors"

func checkOwned(string, uint32) error {
	return errors.New("the relay is not supported on this platform")
}
