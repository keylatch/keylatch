package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"time"

	"github.com/keylatch/keylatch/internal/runner"
)

// pushReceiptToUI sends a RuntimeReceipt to the keylatchd UI server for the
// Dashboard activity feed. This is a best-effort, fire-and-forget operation —
// keylatchd may not be running, and that is always acceptable.
func pushReceiptToUI(ctx context.Context, receipt runner.RuntimeReceipt) {
	addr := os.Getenv("KEYLATCH_UI_ADDR")
	if addr == "" {
		addr = "127.0.0.1:7890"
	} else if err := validateHostPort(addr); err != nil {
		// Best-effort push: a malformed KEYLATCH_UI_ADDR must not crash or
		// block the primary command. Silently skip, matching the existing
		// "keylatchd not running" no-op behavior below.
		return
	}
	body, err := json.Marshal(receipt)
	if err != nil {
		return // never happens for a valid receipt
	}
	pushCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()
	req, err := http.NewRequestWithContext(pushCtx, http.MethodPost,
		"http://"+addr+"/v1/receipts", bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	c := &http.Client{Timeout: 500 * time.Millisecond}
	resp, err := c.Do(req)
	if err != nil {
		return // keylatchd not running — silent no-op
	}
	_ = resp.Body.Close()
}
