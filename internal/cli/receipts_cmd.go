// Package cli — receipts subcommands.
package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/paths"
	"github.com/keylatch/keylatch/internal/runner"
	"github.com/spf13/cobra"
)

// newReceiptsCmd returns the `keylatch receipts` group command.
func newReceiptsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "receipts",
		Short: "View run receipts (value-free)",
	}
	cmd.AddCommand(newReceiptsListCmd())
	cmd.AddCommand(newReceiptsShowCmd())
	cmd.AddCommand(newReceiptsTailCmd())
	return cmd
}

func newReceiptsListCmd() *cobra.Command {
	var (
		jsonOut bool
		limit   int
	)
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List run receipts",
		RunE: func(c *cobra.Command, _ []string) error {
			receipts, err := loadReceipts()
			if err != nil {
				return err
			}
			if limit > 0 && len(receipts) > limit {
				receipts = receipts[len(receipts)-limit:]
			}
			if jsonOut {
				if receipts == nil {
					receipts = []runner.Receipt{}
				}
				b, _ := json.MarshalIndent(receipts, "", "  ")
				fmt.Fprintln(c.OutOrStdout(), string(b))
				return nil
			}
			w := tabwriter.NewWriter(c.OutOrStdout(), 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "TIMESTAMP\tACTOR\tCONNECTION\tCAPABILITY\tDECISION\tEXIT")
			for _, r := range receipts {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%d\n",
					r.Timestamp.UTC().Format(time.RFC3339),
					r.Actor, r.Connection, r.Capability,
					r.PolicyDecision, r.ExitCode,
				)
			}
			return w.Flush()
		},
	}
	cmd.Flags().BoolVar(&jsonOut, "json", false, "output as JSON")
	cmd.Flags().IntVar(&limit, "limit", 50, "maximum number of receipts to show")
	return cmd
}

func newReceiptsShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show <receipt-id>",
		Short: "Show a single receipt by audit accessor",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			id := args[0]
			receipts, err := loadReceipts()
			if err != nil {
				return err
			}
			for _, r := range receipts {
				if r.AuditAccessor == id {
					b, _ := json.MarshalIndent(r, "", "  ")
					fmt.Fprintln(c.OutOrStdout(), string(b))
					return nil
				}
			}
			return fmt.Errorf("receipt %q not found", id)
		},
	}
}

// newReceiptsTailCmd returns `keylatch receipts tail [--follow]`.
//
// Without --follow: prints the latest 10 receipts from the file store and exits.
// With --follow:    connects to /v1/receipts/stream (SSE) and prints each new
//
//	receipt as a JSON line to stdout. Exits on Ctrl-C or stream close.
func newReceiptsTailCmd() *cobra.Command {
	var follow bool

	cmd := &cobra.Command{
		Use:   "tail",
		Short: "Tail run receipts; --follow streams live events via SSE",
		Long: `Without --follow, prints the latest 10 receipts from the local store and exits.

With --follow, connects to the keylatchd SSE endpoint (/v1/receipts/stream) and
prints each incoming receipt as a JSON line. Press Ctrl-C to stop.

The gateway address is read from KEYLATCH_UI_ADDR (default 127.0.0.1:7890).
Credential values are never emitted.`,
		RunE: func(c *cobra.Command, _ []string) error {
			if follow {
				return runReceiptsTailFollow(c)
			}
			// Non-follow: print latest 10 from file store.
			receipts, err := loadReceipts()
			if err != nil {
				return err
			}
			const defaultTailN = 10
			if len(receipts) > defaultTailN {
				receipts = receipts[len(receipts)-defaultTailN:]
			}
			for _, r := range receipts {
				b, _ := json.Marshal(r)
				fmt.Fprintln(c.OutOrStdout(), string(b))
			}
			return nil
		},
	}
	cmd.Flags().BoolVarP(&follow, "follow", "f", false, "follow live SSE stream from keylatchd")
	return cmd
}

// runReceiptsTailFollow connects to /v1/receipts/stream and prints each receipt
// as a JSON line to the command's output writer until interrupted.
func runReceiptsTailFollow(c *cobra.Command) error {
	addr := os.Getenv("KEYLATCH_UI_ADDR")
	if addr == "" {
		addr = "127.0.0.1:7890"
	} else if err := validateHostPort(addr); err != nil {
		return fmt.Errorf("receipts tail: KEYLATCH_UI_ADDR: %w", err)
	}
	url := "http://" + addr + "/v1/receipts/stream"

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Cancel on SIGINT / SIGTERM so the loop exits cleanly.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)
	go func() {
		select {
		case <-sigCh:
			cancel()
		case <-ctx.Done():
		}
	}()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("receipts tail: %w", err)
	}
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("Cache-Control", "no-cache")

	client := &http.Client{Timeout: 0} // no timeout — long-lived SSE connection
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("receipts tail: could not connect to %s: %w\nIs keylatchd running?", url, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("receipts tail: server returned %s", resp.Status)
	}

	out := c.OutOrStdout()
	scanner := bufio.NewScanner(resp.Body)

	var eventType string
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "event: "):
			eventType = strings.TrimPrefix(line, "event: ")
		case strings.HasPrefix(line, "data: "):
			if eventType == "receipt" {
				fmt.Fprintln(out, strings.TrimPrefix(line, "data: "))
			}
			// Do NOT reset eventType here — reset only on blank line.
		case line == "":
			// Blank line ends an event block.
			eventType = ""
		}
	}

	if err := scanner.Err(); err != nil && ctx.Err() == nil {
		return fmt.Errorf("receipts tail: stream error: %w", err)
	}
	return nil
}

// parseSSEStream is a helper used in tests to drive SSE parsing against an
// io.Reader without a real HTTP server.
func parseSSEStream(r io.Reader, out io.Writer) error {
	scanner := bufio.NewScanner(r)
	var eventType string
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "event: "):
			eventType = strings.TrimPrefix(line, "event: ")
		case strings.HasPrefix(line, "data: "):
			if eventType == "receipt" {
				fmt.Fprintln(out, strings.TrimPrefix(line, "data: "))
			}
			// Do NOT reset eventType here — reset only on blank line.
		case line == "":
			// Blank line ends an event block.
			eventType = ""
		}
	}
	return scanner.Err()
}

func loadReceipts() ([]runner.Receipt, error) {
	p := paths.Receipts(llmcontext.DefaultLookup)
	data, err := os.ReadFile(p)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var receipts []runner.Receipt
	if err := json.Unmarshal(data, &receipts); err != nil {
		return nil, err
	}
	return receipts, nil
}

// AppendReceipt appends a receipt to the receipts file (value-free).
// Called by the runner after each policy-gated execution.
func AppendReceipt(r runner.Receipt) error {
	p := paths.Receipts(llmcontext.DefaultLookup)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	receipts, err := loadReceipts()
	if err != nil {
		return err
	}
	receipts = append(receipts, r)
	b, err := json.MarshalIndent(receipts, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(p, b, 0o600); err != nil {
		return err
	}
	return os.Chmod(p, 0o600)
}
