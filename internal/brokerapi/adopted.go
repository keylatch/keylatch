package brokerapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Adopted records that a user's secrets were moved into the broker. Doctor
// lists the upstream keys it names: while they lived in the user's account, a
// process of that account could have read them, so rotating them is advised.
type Adopted struct {
	At          time.Time `json:"adopted_at"`
	UpstreamKey []string  `json:"upstream_keys"`
}

// ReadAdopted reads the marker at path. A missing marker is not an error.
func ReadAdopted(path string) (Adopted, bool, error) {
	b, err := os.ReadFile(path) //nolint:gosec // G304: the marker path comes from the config directory
	if errors.Is(err, os.ErrNotExist) {
		return Adopted{}, false, nil
	}
	if err != nil {
		return Adopted{}, false, err
	}
	var a Adopted
	if err := json.Unmarshal(b, &a); err != nil {
		return Adopted{}, false, fmt.Errorf("broker adoption marker: %w", err)
	}
	return a, true, nil
}

// WriteAdopted writes the marker at path.
func WriteAdopted(path string, a Adopted) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	b, err := json.Marshal(a)
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}
