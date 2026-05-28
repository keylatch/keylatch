package file

import (
	"crypto/rand"
	"encoding/json"
	"time"
)

// cryptoRandRead fills b with cryptographically random bytes.
func cryptoRandRead(b []byte) (int, error) {
	return rand.Read(b)
}

// currentTimeUTC returns the current UTC time formatted as RFC3339.
func currentTimeUTC() string {
	return time.Now().UTC().Format(time.RFC3339)
}

// marshalJSON marshals v to JSON bytes.
func marshalJSON(v any) ([]byte, error) {
	return json.Marshal(v)
}
