package keeper

// keeperRecord is a minimal JSON shape for Keeper Commander list output.
// Only metadata fields are included — secret values are never parsed into structs.
type keeperRecord struct {
	RecordUID string `json:"record_uid"`
	Title     string `json:"title"`
}

// keeperGetResult is the JSON shape returned by `keeper get --format=json <title>`.
// Only the fields needed to extract the stored password are included.
type keeperGetResult struct {
	RecordUID string `json:"record_uid"`
	Title     string `json:"title"`
	Password  string `json:"password"`
}
