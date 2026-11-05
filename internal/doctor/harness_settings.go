package doctor

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"

	"github.com/keylatch/keylatch/internal/llmcontext"
)

// HarnessSettings identifies saved settings without claiming a running harness loaded them.
type HarnessSettings struct {
	Path     string `json:"path"`
	SHA256   string `json:"sha256,omitempty"`
	Enabled  *bool  `json:"enabled,omitempty"`
	Readable bool   `json:"readable"`
	Managed  bool   `json:"managed"`
}

// ClaudeCodeSandboxSettings reports configured sandbox state conservatively:
// conflicting or unreadable settings leave the effective state unknown.
func ClaudeCodeSandboxSettings(lookup llmcontext.Lookup) (string, []HarnessSettings) {
	files, _ := claudeSettingsFiles(lookup)
	var records []HarnessSettings
	var selected *bool
	unknown := false
	for _, file := range files {
		f, err := os.Open(file.path)
		if os.IsNotExist(err) {
			continue
		}
		record := HarnessSettings{Path: file.path, Managed: file.managed}
		if err != nil {
			unknown = true
			records = append(records, record)
			continue
		}
		data, err := io.ReadAll(io.LimitReader(f, 1048577))
		_ = f.Close()
		var settings struct {
			Sandbox struct {
				Enabled *bool `json:"enabled"`
			} `json:"sandbox"`
		}
		if err != nil || len(data) > 1048576 || json.Unmarshal(data, &settings) != nil {
			unknown = true
			records = append(records, record)
			continue
		}
		sum := sha256.Sum256(data)
		record.SHA256 = hex.EncodeToString(sum[:])
		record.Readable = true
		record.Enabled = settings.Sandbox.Enabled
		records = append(records, record)
		if record.Enabled != nil {
			if selected != nil && *selected != *record.Enabled {
				unknown = true
			}
			selected = record.Enabled
		}
	}
	if unknown || selected == nil {
		return "unknown", records
	}
	if *selected {
		return "on", records
	}
	return "off", records
}
