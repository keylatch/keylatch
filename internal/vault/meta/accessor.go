package meta

import (
	"crypto/rand"
	"encoding/base32"
)

// NewAccessor generates a new random opaque ID using 16 bytes from crypto/rand
// encoded with base32 (no-padding). Returns a 26-character ID.
func NewAccessor() ID {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand failure is a fatal programming error — panic is correct.
		panic("meta: crypto/rand.Read failed: " + err.Error())
	}
	return ID(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b))
}
