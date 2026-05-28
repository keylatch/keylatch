package cli

import (
	"encoding/json"
	"fmt"
	"io"
)

// printJSON marshals v and writes it to w.
func printJSON(w io.Writer, v interface{}) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		fmt.Fprintf(w, `{"error":%q}`, err.Error())
		return
	}
	fmt.Fprintln(w, string(data))
}
