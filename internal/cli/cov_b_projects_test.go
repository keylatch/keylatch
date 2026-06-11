package cli

// cov_b_projects_test.go — Agent B coverage for projects_cmd.go.
// Tests for projects list/create/delete commands and loadProjects/saveProjects helpers.
// Hermetic: all filesystem access is redirected via KEYLATCH_CONFIG_DIR.

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func setupProjectsDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("KEYLATCH_CONFIG_DIR", dir)
	return dir
}

func TestProjectsList_Empty(t *testing.T) {
	setupProjectsDir(t)

	root := NewRootCommand()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(bytes.NewBuffer(nil))
	root.SetArgs([]string{"projects", "list"})

	if err := root.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Header should always appear.
	if !strings.Contains(out.String(), "NAME") {
		t.Errorf("expected NAME header in output, got: %s", out.String())
	}
}

func TestProjectsList_JSON_Empty(t *testing.T) {
	setupProjectsDir(t)

	root := NewRootCommand()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(bytes.NewBuffer(nil))
	root.SetArgs([]string{"projects", "list", "--json"})

	if err := root.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var arr []interface{}
	if err := json.Unmarshal([]byte(strings.TrimSpace(out.String())), &arr); err != nil {
		t.Fatalf("JSON parse error: %v — output: %s", err, out.String())
	}
}

func TestProjectsCreate_CreatesProject(t *testing.T) {
	setupProjectsDir(t)

	root := NewRootCommand()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(bytes.NewBuffer(nil))
	root.SetArgs([]string{"projects", "create", "my-project"})

	if err := root.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(out.String(), "my-project") {
		t.Errorf("expected project name in output, got: %s", out.String())
	}

	// Verify persisted.
	projects, err := loadProjects()
	if err != nil {
		t.Fatalf("loadProjects: %v", err)
	}
	if len(projects) != 1 || projects[0].Name != "my-project" {
		t.Errorf("expected 1 project named 'my-project', got: %v", projects)
	}
}

func TestProjectsCreate_WithDescription(t *testing.T) {
	setupProjectsDir(t)

	root := NewRootCommand()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(bytes.NewBuffer(nil))
	root.SetArgs([]string{"projects", "create", "proj-with-desc", "--description", "Test project"})

	if err := root.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	projects, err := loadProjects()
	if err != nil {
		t.Fatalf("loadProjects: %v", err)
	}
	if len(projects) != 1 || projects[0].Description != "Test project" {
		t.Errorf("expected description 'Test project', got: %v", projects)
	}
}

func TestProjectsCreate_Duplicate(t *testing.T) {
	setupProjectsDir(t)

	// Create once.
	for i := 0; i < 2; i++ {
		root := NewRootCommand()
		root.SetOut(bytes.NewBuffer(nil))
		root.SetErr(bytes.NewBuffer(nil))
		root.SetArgs([]string{"projects", "create", "dup-project"})
		err := root.Execute()
		if i == 0 && err != nil {
			t.Fatalf("first create: %v", err)
		}
		if i == 1 && err == nil {
			t.Fatal("expected error on duplicate create")
		}
		if i == 1 && !strings.Contains(err.Error(), "already exists") {
			t.Errorf("expected 'already exists' in error, got: %v", err)
		}
	}
}

func TestProjectsDelete_DeletesProject(t *testing.T) {
	setupProjectsDir(t)

	// Create project.
	createRoot := NewRootCommand()
	createRoot.SetOut(bytes.NewBuffer(nil))
	createRoot.SetErr(bytes.NewBuffer(nil))
	createRoot.SetArgs([]string{"projects", "create", "to-delete"})
	if err := createRoot.Execute(); err != nil {
		t.Fatalf("create: %v", err)
	}

	// Delete it.
	deleteRoot := NewRootCommand()
	var out bytes.Buffer
	deleteRoot.SetOut(&out)
	deleteRoot.SetErr(bytes.NewBuffer(nil))
	deleteRoot.SetArgs([]string{"projects", "delete", "to-delete"})
	if err := deleteRoot.Execute(); err != nil {
		t.Fatalf("delete: %v", err)
	}

	if !strings.Contains(out.String(), "to-delete") {
		t.Errorf("expected project name in output, got: %s", out.String())
	}

	// Verify gone.
	projects, err := loadProjects()
	if err != nil {
		t.Fatalf("loadProjects: %v", err)
	}
	if len(projects) != 0 {
		t.Errorf("expected 0 projects after delete, got: %d", len(projects))
	}
}

func TestProjectsDelete_NotFound(t *testing.T) {
	setupProjectsDir(t)

	root := NewRootCommand()
	root.SetOut(bytes.NewBuffer(nil))
	root.SetErr(bytes.NewBuffer(nil))
	root.SetArgs([]string{"projects", "delete", "ghost"})

	err := root.Execute()
	if err == nil {
		t.Fatal("expected error for missing project")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected 'not found' in error, got: %v", err)
	}
}

func TestProjectsList_ShowsAll(t *testing.T) {
	setupProjectsDir(t)

	for _, name := range []string{"alpha", "beta", "gamma"} {
		root := NewRootCommand()
		root.SetOut(bytes.NewBuffer(nil))
		root.SetErr(bytes.NewBuffer(nil))
		root.SetArgs([]string{"projects", "create", name})
		if err := root.Execute(); err != nil {
			t.Fatalf("create %s: %v", name, err)
		}
	}

	root := NewRootCommand()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(bytes.NewBuffer(nil))
	root.SetArgs([]string{"projects", "list"})
	if err := root.Execute(); err != nil {
		t.Fatalf("list: %v", err)
	}

	output := out.String()
	for _, name := range []string{"alpha", "beta", "gamma"} {
		if !strings.Contains(output, name) {
			t.Errorf("expected %q in output, got: %s", name, output)
		}
	}
}

func TestLoadSaveProjects_RoundTrip(t *testing.T) {
	setupProjectsDir(t)

	initial, err := loadProjects()
	if err != nil {
		t.Fatalf("loadProjects: %v", err)
	}
	if len(initial) != 0 {
		t.Errorf("expected empty initial, got: %d", len(initial))
	}

	entries := []projectEntry{
		{Name: "p1", Description: "first"},
		{Name: "p2", Description: "second"},
	}
	if err := saveProjects(entries); err != nil {
		t.Fatalf("saveProjects: %v", err)
	}

	loaded, err := loadProjects()
	if err != nil {
		t.Fatalf("loadProjects after save: %v", err)
	}
	if len(loaded) != 2 {
		t.Errorf("expected 2 projects, got: %d", len(loaded))
	}
}

func TestLoadProjects_InvalidJSON(t *testing.T) {
	dir := setupProjectsDir(t)

	// Identify the projects file path by checking what paths.Projects returns.
	// It will be in dir/projects.json or similar. Write bad JSON there.
	projPath := filepath.Join(dir, "projects.json")
	if err := os.WriteFile(projPath, []byte("{bad json"), 0o600); err != nil {
		t.Fatalf("write bad json: %v", err)
	}

	_, err := loadProjects()
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestProjectsList_JSON_ShowsAll(t *testing.T) {
	setupProjectsDir(t)

	for _, name := range []string{"x", "y"} {
		root := NewRootCommand()
		root.SetOut(bytes.NewBuffer(nil))
		root.SetErr(bytes.NewBuffer(nil))
		root.SetArgs([]string{"projects", "create", name})
		if err := root.Execute(); err != nil {
			t.Fatalf("create %s: %v", name, err)
		}
	}

	root := NewRootCommand()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(bytes.NewBuffer(nil))
	root.SetArgs([]string{"projects", "list", "--json"})
	if err := root.Execute(); err != nil {
		t.Fatalf("list --json: %v", err)
	}

	var arr []projectEntry
	if err := json.Unmarshal([]byte(strings.TrimSpace(out.String())), &arr); err != nil {
		t.Fatalf("JSON parse: %v — output: %s", err, out.String())
	}
	if len(arr) != 2 {
		t.Errorf("expected 2 projects, got: %d", len(arr))
	}
}
