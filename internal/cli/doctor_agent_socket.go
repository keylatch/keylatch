package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"runtime"
	"time"

	"github.com/keylatch/keylatch/internal/control"
	"github.com/keylatch/keylatch/internal/doctor"
	"github.com/keylatch/keylatch/internal/llmcontext"
)

type agentSocketReport struct {
	Source         string                   `json:"source"`
	CheckedAt      time.Time                `json:"checked_at"`
	Platform       string                   `json:"platform"`
	Harness        string                   `json:"harness"`
	Signals        []string                 `json:"signals"`
	RuntimeVersion string                   `json:"runtime_version"`
	Sandbox        string                   `json:"sandbox"`
	Socket         string                   `json:"socket,omitempty"`
	Reachable      bool                     `json:"reachable"`
	Settings       []doctor.HarnessSettings `json:"settings,omitempty"`
	Detail         string                   `json:"detail"`
}

func probeAgentSocket(lookup llmcontext.Lookup, connect func(llmcontext.Lookup) (string, error)) agentSocketReport {
	classification := llmcontext.Classify(lookup)
	report := agentSocketReport{Source: "current-process", CheckedAt: time.Now().UTC(), Platform: runtime.GOOS, Harness: classification.Harness, Signals: classification.Signals, RuntimeVersion: "unknown", Sandbox: "unknown", Detail: "Run through the harness shell tool. Harness signals identify context; they do not prove sandbox enforcement or the loaded settings."}
	if report.Harness == "" {
		report.Harness = "unknown"
	}
	if report.Harness == "claude-code" {
		_, report.Settings = doctor.ClaudeCodeSandboxSettings(lookup)
	}
	socket, err := connect(lookup)
	if err != nil {
		report.Detail += " Socket connection or peer validation failed."
		return report
	}
	report.Socket, report.Reachable = socket, true
	return report
}

func runAgentSocketProbe(w io.Writer, asJSON bool) error {
	report := probeAgentSocket(llmcontext.DefaultLookup, func(lookup llmcontext.Lookup) (string, error) {
		client, err := control.NewRawClient(lookup)
		if err != nil {
			return "", err
		}
		return client.Socket(), nil
	})
	if asJSON {
		return json.NewEncoder(w).Encode(report)
	}
	_, err := fmt.Fprintf(w, "Source: %s\nHarness: %s\nRuntime version: %s\nSandbox: %s\nSocket reachable: %t\n%s\n", report.Source, report.Harness, report.RuntimeVersion, report.Sandbox, report.Reachable, report.Detail)
	return err
}
