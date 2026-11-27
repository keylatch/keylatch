package sync

import (
	"errors"
	"fmt"
	"strings"
)

// ErrNoSecret means no stored path matches a connection and field.
var ErrNoSecret = errors.New("sync: the connection has no stored value")

// CredentialFields are the fields tried, in order, for the credential a target
// API is called with.
var CredentialFields = []string{"token", "api_key", "access_token", "value", ""}

// FindPath maps a connection name and candidate fields to a stored path, by the
// first rule that matches: the exact path (field ""), connection/field, or
// the one stored path that ends in /connection/field. Two stored paths that
// match the same suffix are ambiguous, never guessed between.
func FindPath(have []string, connection string, fields []string) (string, error) {
	set := make(map[string]bool, len(have))
	for _, p := range have {
		set[p] = true
	}
	for _, f := range fields {
		cand := connection
		if f != "" {
			cand = connection + "/" + f
		}
		if set[cand] {
			return cand, nil
		}
	}
	for _, f := range fields {
		if f == "" {
			continue
		}
		var hit []string
		for _, p := range have {
			if strings.HasSuffix(p, "/"+connection+"/"+f) {
				hit = append(hit, p)
			}
		}
		if len(hit) == 1 {
			return hit[0], nil
		}
		if len(hit) > 1 {
			return "", fmt.Errorf("the connection %q is ambiguous: %d stored fields match", connection, len(hit))
		}
	}
	return "", fmt.Errorf("%w: %q", ErrNoSecret, connection)
}
