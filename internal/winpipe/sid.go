// Package winpipe is the Windows named pipe transport of the broker: a
// listener whose pipe carries a DACL, and a connection type that supports
// deadlines and cancellation through overlapped I/O. Off Windows the package
// compiles to stubs that report ErrUnsupported.
package winpipe

import (
	"crypto/sha1" //nolint:gosec // G505: SHA-1 is how Windows derives a service SID; it is not a security primitive here
	"encoding/binary"
	"fmt"
	"strings"
	"unicode/utf16"
)

// ServiceSID returns the SID Windows derives for the service account
// NT SERVICE\<name>: SHA-1 of the upper-cased name in UTF-16LE, split into five
// little-endian 32-bit sub-authorities under the service base 5-80.
func ServiceSID(name string) string {
	units := utf16.Encode([]rune(strings.ToUpper(name)))
	raw := make([]byte, 2*len(units))
	for i, u := range units {
		binary.LittleEndian.PutUint16(raw[2*i:], u)
	}
	sum := sha1.Sum(raw) //nolint:gosec // G401: see the import
	parts := make([]string, 5)
	for i := range parts {
		parts[i] = fmt.Sprint(binary.LittleEndian.Uint32(sum[4*i:]))
	}
	return "S" + "-1-5-80-" + strings.Join(parts, "-")
}
