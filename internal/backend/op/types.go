package op

import "time"

// opItem is the JSON shape returned by `op item get <connection> --format=json`.
type opItem struct {
	ID        string    `json:"id"`
	Title     string    `json:"title"`
	Vault     opRef     `json:"vault"`
	Category  string    `json:"category"`
	Fields    []opField `json:"fields"`
	URLs      []opURL   `json:"urls,omitempty"`
	Tags      []string  `json:"tags,omitempty"`
	UpdatedAt string    `json:"updated_at,omitempty"`
}

// updatedTime parses UpdatedAt as time.Time, returning zero on error.
func (item opItem) updatedTime() time.Time {
	t, _ := time.Parse(time.RFC3339, item.UpdatedAt)
	return t
}

// opField is a single field within an opItem.
type opField struct {
	ID    string `json:"id"`
	Label string `json:"label"`
	Type  string `json:"type"`
	Value string `json:"value,omitempty"`
}

// opRef is a vault/account reference with an ID and optional name.
type opRef struct {
	ID   string `json:"id"`
	Name string `json:"name,omitempty"`
}

// opURL is a URL entry within an opItem.
type opURL struct {
	Href    string `json:"href"`
	Primary bool   `json:"primary,omitempty"`
}
