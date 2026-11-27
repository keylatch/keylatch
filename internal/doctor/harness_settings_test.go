package doctor

import (
	"os"
	"path/filepath"
	"testing"
)

func TestClaudeCodeSandboxSettings(t *testing.T) {
	defer OverrideManagedSettingsDir(t.TempDir())()
	for _, tc := range []struct{ name, user, project, want string }{
		{"missing", "", "", "unknown"},
		{"unspecified", `{}`, "", "unknown"},
		{"enabled", `{"sandbox":{"enabled":true}}`, "", "on"},
		{"disabled", `{"sandbox":{"enabled":false}}`, "", "off"},
		{"conflicting", `{"sandbox":{"enabled":true}}`, `{"sandbox":{"enabled":false}}`, "unknown"},
		{"invalid", `{`, "", "unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home, project := t.TempDir(), t.TempDir()
			for dir, data := range map[string]string{home: tc.user, project: tc.project} {
				if data == "" {
					continue
				}
				if err := os.Mkdir(filepath.Join(dir, ".claude"), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, ".claude", "settings.json"), []byte(data), 0600); err != nil {
					t.Fatal(err)
				}
			}
			state, records := ClaudeCodeSandboxSettings(func(key string) string {
				switch key {
				case "HOME":
					return home
				case "CLAUDE_PROJECT_DIR":
					return project
				}
				return ""
			})
			if state != tc.want {
				t.Fatalf("state=%s records=%+v", state, records)
			}
			if state == "on" || state == "off" {
				if len(records) != 1 || len(records[0].SHA256) != 64 || !records[0].Readable {
					t.Fatalf("records=%+v", records)
				}
			}
		})
	}
}
