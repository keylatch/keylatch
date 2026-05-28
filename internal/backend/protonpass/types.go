package protonpass

// passItem is a minimal JSON shape for Proton Pass CLI list output.
// Only metadata fields are included — secret values are never parsed into structs.
type passItem struct {
	ItemID string `json:"ItemID"`
	Name   string `json:"name"`
}

// passGetResult is the JSON shape returned by `pass-cli item get ... --output json`.
// Only the fields needed to extract the stored note/value are included.
type passGetResult struct {
	Metadata passMetadata `json:"metadata"`
	Content  passContent  `json:"content"`
}

type passMetadata struct {
	Name string `json:"name"`
}

type passContent struct {
	Note string `json:"note"`
}
