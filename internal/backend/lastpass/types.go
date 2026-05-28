package lastpass

// lpassListItem is the JSON shape for each entry in `lpass ls --json` output.
// Only metadata fields are included — password values are never parsed into structs.
type lpassListItem struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// lpassGetResult is the JSON shape returned by `lpass show --json <name>`.
// The Password field is read inline and immediately zeroed — never stored in a persistent struct.
type lpassGetResult struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Password string `json:"password"`
}
