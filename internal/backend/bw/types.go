package bw

import (
	"encoding/json"
	"time"
)

// bwItem is the JSON shape returned by `bw get item <connection>`.
type bwItem struct {
	ID            string    `json:"id"`
	Name          string    `json:"name"`
	Type          int       `json:"type"` // 1=Login, 2=SecureNote, 3=Card, 4=Identity
	FolderID      *string   `json:"folderId"`
	CollectionIDs []string  `json:"collectionIds"`
	Login         *bwLogin  `json:"login,omitempty"`
	Fields        []bwField `json:"fields,omitempty"`
	RevisionDate  string    `json:"revisionDate,omitempty"`
}

// updatedTime parses RevisionDate as time.Time, returning zero on error.
func (item bwItem) updatedTime() time.Time {
	t, _ := time.Parse("2006-01-02T15:04:05.000Z", item.RevisionDate)
	if t.IsZero() {
		t, _ = time.Parse(time.RFC3339, item.RevisionDate)
	}
	return t
}

// bwField is a custom field within a bwItem.
// Type: 0=text (plain), 1=hidden (concealed), 2=boolean.
//
// Value is stored as []byte so zero() can wipe it from memory when
// the cache entry is evicted (TTL expiry or explicit invalidation).
type bwField struct {
	Name  string `json:"name"`
	Value []byte `json:"value"`
	Type  int    `json:"type"` // 0=text, 1=hidden
}

// zero overwrites Value with zeros, preventing the secret from remaining in
// memory after the cache entry is evicted.
func (f *bwField) zero() {
	for i := range f.Value {
		f.Value[i] = 0
	}
}

// MarshalJSON serialises Value as a plain JSON string (not base64) so the
// Bitwarden API wire format is preserved. encoding/json would base64-encode
// []byte by default.
func (f bwField) MarshalJSON() ([]byte, error) {
	type bwFieldPlain struct {
		Name  string `json:"name"`
		Value string `json:"value"`
		Type  int    `json:"type"`
	}
	return json.Marshal(bwFieldPlain{
		Name:  f.Name,
		Value: string(f.Value),
		Type:  f.Type,
	})
}

// UnmarshalJSON deserialises a Bitwarden API field, reading Value as a plain
// string and storing it as []byte.
func (f *bwField) UnmarshalJSON(data []byte) error {
	type bwFieldPlain struct {
		Name  string `json:"name"`
		Value string `json:"value"`
		Type  int    `json:"type"`
	}
	var plain bwFieldPlain
	if err := json.Unmarshal(data, &plain); err != nil {
		return err
	}
	f.Name = plain.Name
	f.Value = []byte(plain.Value)
	f.Type = plain.Type
	return nil
}

// bwLogin holds login-specific data for a bwItem.
type bwLogin struct {
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}

// zero overwrites Username and Password with empty strings. Strings cannot be
// zeroed in-place like byte slices, but overwriting removes the reference to
// the original backing array, allowing GC to collect it.
func (b *bwLogin) zero() {
	b.Password = ""
	b.Username = ""
}

// bwStatus is the JSON shape returned by `bw status`.
type bwStatus struct {
	ServerURL string `json:"serverUrl"`
	LastSync  string `json:"lastSync,omitempty"`
	UserEmail string `json:"userEmail,omitempty"`
	UserID    string `json:"userId,omitempty"`
	Status    string `json:"status"` // "locked" | "unlocked" | "unauthenticated"
}

// bwFolder is the JSON shape for a Bitwarden folder.
type bwFolder struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}
