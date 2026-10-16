package winpipe

import "errors"

// ErrUnsupported is returned where named pipes are not the broker transport.
var ErrUnsupported = errors.New("winpipe: named pipes are only used on Windows")
