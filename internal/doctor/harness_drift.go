package doctor

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"
)

// HarnessDrift records a published harness reading an installed configuration.
// It is historical evidence, not a claim about the current local installation.
type HarnessDrift struct {
	Harness   string    `json:"harness"`
	Version   string    `json:"version"`
	Result    string    `json:"result"`
	CheckedAt time.Time `json:"checked_at"`
	Scope     string    `json:"scope"`
	Commit    string    `json:"commit,omitempty"`
	RunURL    string    `json:"run_url,omitempty"`
}

// ReadHarnessDrift reads a bounded, explicitly selected drift result artifact.
func ReadHarnessDrift(path, harness string) (*HarnessDrift, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, 16385))
	if err != nil {
		return nil, err
	}
	if len(data) > 16384 {
		return nil, fmt.Errorf("harness drift result exceeds 16 KiB")
	}
	var result HarnessDrift
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("invalid harness drift result: %w", err)
	}
	if result.Harness != harness || result.Version == "" || result.CheckedAt.IsZero() || result.CheckedAt.After(time.Now().Add(5*time.Minute)) || result.Scope != "published-cli-config-reader" || (result.Result != "pass" && result.Result != "fail") {
		return nil, fmt.Errorf("incomplete or mismatched harness drift result")
	}
	return &result, nil
}
