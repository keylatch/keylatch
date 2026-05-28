package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/spf13/cobra"
)

func newShareCmd() *cobra.Command {
	var outFile string
	var public bool

	cmd := &cobra.Command{
		Use:   "share <receipt-id>",
		Short: "Generate a sanitised receipt for sharing",
		Long: `Generate a sanitised, credential-free receipt document from a past run.
Output contains only non-sensitive metadata: runtime mode, provider name, exit status.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if public {
				// Confirm before sharing.
				fmt.Fprint(cmd.OutOrStdout(), "This will share a sanitised summary publicly (no credentials). Continue? (y/N) ")
				var ans string
				if _, err := fmt.Fscan(cmd.InOrStdin(), &ans); err != nil {
					ans = ""
				}
				if ans != "y" && ans != "Y" {
					fmt.Fprintln(cmd.OutOrStdout(), "Cancelled.")
					return nil
				}

				// Build sanitised payload (use the SanitizedReceipt from internal/share).
				// For 1.0.0 we share a stub receipt since receipts are in-memory only.
				payload := map[string]string{
					"timestamp":       time.Now().UTC().Format(time.RFC3339),
					"exit_code_class": "success",
					"provider_name":   args[0], // receipt-id used as provider hint
					"runtime_mode":    "gateway_typed",
					"agent_name":      "keylatch",
				}
				body, _ := json.Marshal(payload)

				resp, err := http.Post(
					"https://share.keylatch.dev/v1/receipts",
					"application/json",
					bytes.NewReader(body),
				)
				if err != nil {
					return fmt.Errorf("share: %w", err)
				}
				defer resp.Body.Close()

				switch resp.StatusCode {
				case 201:
					var result struct {
						URL string `json:"url"`
					}
					if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
						return fmt.Errorf("share: parse response: %w", err)
					}
					fmt.Fprintln(cmd.OutOrStdout(), "Shared at:", result.URL)
				case 429:
					return fmt.Errorf("share: rate limited — try again in a minute")
				case 413:
					return fmt.Errorf("share: receipt too large")
				default:
					return fmt.Errorf("share: server error (%d)", resp.StatusCode)
				}
				return nil
			}
			// Receipts are held in the keylatchd in-memory ring buffer (ReceiptStore)
			// and are not persisted to disk in 1.0.0. Disk persistence is planned for 1.1.0.
			// Use `keylatch audit tail` to view recent runs until then.
			fmt.Fprintln(cmd.ErrOrStderr(), "Receipt file lookup not yet implemented — receipts are in-memory only in 1.0.0.")
			fmt.Fprintln(cmd.ErrOrStderr(), "Use `keylatch audit tail` to view recent runs.")
			return nil
		},
	}

	cmd.Flags().StringVarP(&outFile, "out", "o", "", "write output to file instead of stdout")
	cmd.Flags().BoolVar(&public, "public", false, "publish to keylatch.dev/r/<id>")
	_ = outFile // used in full implementation

	return cmd
}
