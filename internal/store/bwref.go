package store

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"unicode"
)

const (
	// BWPersonal is the scope segment that selects the personal vault.
	BWPersonal = "personal"
	// BWAny is the collection/folder segment that matches every collection or folder.
	BWAny = "-"
	// BWCustomFieldPrefix forces a field segment to be read as a custom field name.
	BWCustomFieldPrefix = "field:"
)

var bwItemIDRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// BWRef is a parsed bw://<scope>/<collection>/<item>/<field> reference. All
// members are percent-decoded; names may contain spaces and slashes.
type BWRef struct {
	// Scope is BWPersonal, an organization ID or an organization name.
	Scope string
	// Collection is a collection name or ID (organization scope), a folder
	// name or ID (personal scope), or BWAny.
	Collection string
	// Item is an item ID or an item name.
	Item string
	// Field is username, password, notes, or a custom field name
	// (optionally prefixed with BWCustomFieldPrefix).
	Field string
}

// ParseBWRef parses the part of a bw:// reference after the scheme. It makes
// no external calls.
func ParseBWRef(rest string) (BWRef, error) {
	parts := strings.Split(rest, "/")
	if len(parts) != 4 {
		return BWRef{}, fmt.Errorf("bw reference must be bw://<org-or-personal>/<collection>/<item>/<field> with / inside names written as %%2F")
	}
	var dec [4]string
	for i, p := range parts {
		if p == "" {
			return BWRef{}, fmt.Errorf("bw reference has an empty segment")
		}
		if i == 1 && p == BWAny {
			dec[i] = BWAny
			continue
		}
		s, err := url.PathUnescape(p)
		if err != nil {
			return BWRef{}, fmt.Errorf("bw reference segment %q is not valid percent-encoding", p)
		}
		if s == "" || strings.IndexFunc(s, unicode.IsControl) >= 0 {
			return BWRef{}, fmt.Errorf("bw reference segment %q is empty or has control characters", p)
		}
		dec[i] = s
	}
	ref := BWRef{Scope: dec[0], Collection: dec[1], Item: dec[2], Field: dec[3]}
	if strings.EqualFold(ref.Field, "totp") {
		return BWRef{}, fmt.Errorf("bw reference: totp fields are not supported")
	}
	if ref.Field == BWCustomFieldPrefix {
		return BWRef{}, fmt.Errorf("bw reference: custom field name is empty")
	}
	return ref, nil
}

// ItemIsID reports whether Item is a Bitwarden item ID rather than a name.
func (r BWRef) ItemIsID() bool { return bwItemIDRe.MatchString(r.Item) }

// CustomFieldName returns the custom field name when Field is not one of the
// built-in login fields or carries the explicit prefix, else "".
func (r BWRef) CustomFieldName() string {
	if n, ok := strings.CutPrefix(r.Field, BWCustomFieldPrefix); ok {
		return n
	}
	switch strings.ToLower(r.Field) {
	case "username", "password", "notes":
		return ""
	}
	return r.Field
}

// String renders the reference with every segment percent-encoded.
func (r BWRef) String() string {
	enc := func(s string) string { return url.PathEscape(s) }
	coll := enc(r.Collection)
	if r.Collection == BWAny {
		coll = BWAny
	}
	return "bw://" + enc(r.Scope) + "/" + coll + "/" + enc(r.Item) + "/" + enc(r.Field)
}
