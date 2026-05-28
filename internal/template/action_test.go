package template_test

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/keylatch/keylatch/internal/template"
)

// schemaFixture is a minimal YAML structure that wraps an "actions" block so we
// can round-trip test the Action types with the yaml library.
type schemaFixture struct {
	Actions map[string]template.Action `yaml:"actions"`
}

// TestActionsSchema_Parse verifies that a well-formed actions block round-trips
// correctly through YAML unmarshalling.
func TestActionsSchema_Parse(t *testing.T) {
	t.Parallel()

	raw := `
actions:
  list-models:
    method: GET
    path: /v1/models
  create-file:
    method: POST
    path: /v1/files/{file_id}
    params:
      file_id:
        type: string
        required: true
        in: path
      purpose:
        type: string
        required: false
        in: query
`
	var fixture schemaFixture
	if err := yaml.Unmarshal([]byte(raw), &fixture); err != nil {
		t.Fatalf("yaml.Unmarshal: %v", err)
	}

	if len(fixture.Actions) != 2 {
		t.Fatalf("want 2 actions, got %d", len(fixture.Actions))
	}

	lm, ok := fixture.Actions["list-models"]
	if !ok {
		t.Fatal("action list-models not found")
	}
	if lm.Method != "GET" {
		t.Errorf("list-models.Method = %q, want GET", lm.Method)
	}
	if lm.Path != "/v1/models" {
		t.Errorf("list-models.Path = %q, want /v1/models", lm.Path)
	}

	cf, ok := fixture.Actions["create-file"]
	if !ok {
		t.Fatal("action create-file not found")
	}
	if cf.Method != "POST" {
		t.Errorf("create-file.Method = %q, want POST", cf.Method)
	}
	fileIDParam, ok := cf.Params["file_id"]
	if !ok {
		t.Fatal("param file_id not found")
	}
	if !fileIDParam.Required {
		t.Error("file_id.Required = false, want true")
	}
	if fileIDParam.In != "path" {
		t.Errorf("file_id.In = %q, want path", fileIDParam.In)
	}
}

// TestActionsSchema_BackwardCompatible verifies that a template YAML without an
// "actions" key still parses correctly (Actions map will be nil).
func TestActionsSchema_BackwardCompatible(t *testing.T) {
	t.Parallel()

	raw := `
# template with no actions key at all
`
	var fixture schemaFixture
	if err := yaml.Unmarshal([]byte(raw), &fixture); err != nil {
		t.Fatalf("yaml.Unmarshal: %v", err)
	}

	if fixture.Actions != nil {
		t.Errorf("expected nil Actions for template without actions key, got %v", fixture.Actions)
	}
}

// TestActionsSchema_InvalidActionFailsParse verifies that Validate catches a
// malformed action (bad method, missing leading slash).
func TestActionsSchema_InvalidActionFailsParse(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		action  template.Action
		wantErr string
	}{
		{
			name:    "bad-method",
			action:  template.Action{Method: "CONNECT", Path: "/v1/models"},
			wantErr: "method",
		},
		{
			name:    "path-no-slash",
			action:  template.Action{Method: "GET", Path: "v1/models"},
			wantErr: "path",
		},
		{
			name: "required-param-bad-in",
			action: template.Action{
				Method: "POST",
				Path:   "/v1/items",
				Params: map[string]template.ParamSpec{
					"id": {Type: "string", Required: true, In: "cookie"},
				},
			},
			wantErr: "in",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := tc.action.Validate(tc.name)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error %q does not contain %q", err.Error(), tc.wantErr)
			}
		})
	}
}

// TestValidateActions_Happy verifies that a valid actions map passes without error.
func TestValidateActions_Happy(t *testing.T) {
	t.Parallel()

	actions := map[string]template.Action{
		"list-models": {Method: "GET", Path: "/v1/models"},
		"create":      {Method: "POST", Path: "/v1/items"},
	}
	if err := template.ValidateActions(actions); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}
