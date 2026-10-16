package merge_test

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keylatch/keylatch/internal/harness/merge"
)

const userJSON = `{
  "theme": "dark",
  "hooks": {
    "BeforeTool": [
      {"matcher": "x", "hooks": [{"type": "command", "command": "user-hook"}]}
    ]
  },
  "zeta": [1, 2.50, true, null],
  "alpha": {"nested": "\u003c&>"}
}
`

func addServer(root *merge.Object) error {
	servers, err := root.Child("mcpServers")
	if err != nil {
		return err
	}
	srv := merge.NewObject()
	srv.Set("command", "keylatch")
	srv.Set("args", []any{"mcp", "--stdio"})
	servers.Set("keylatch", srv)
	return nil
}

func TestMergePreservesUnknownKeys(t *testing.T) {
	out, err := merge.EditJSON([]byte(userJSON), addServer)
	require.NoError(t, err)
	s := string(out)

	root, err := merge.ParseJSON(out)
	require.NoError(t, err)
	assert.Equal(t, []string{"theme", "hooks", "zeta", "alpha", "mcpServers"}, root.Keys(), "user keys keep their order and the new key goes last")
	assert.Contains(t, s, `"command": "user-hook"`)
	assert.Contains(t, s, "2.50", "numbers keep their literal form")
	assert.Contains(t, s, `"<&>"`, "HTML characters are not escaped on the way out")
	assert.True(t, strings.HasSuffix(s, "}\n"))
}

func TestMergeIdempotent(t *testing.T) {
	once, err := merge.EditJSON([]byte(userJSON), addServer)
	require.NoError(t, err)
	twice, err := merge.EditJSON(once, addServer)
	require.NoError(t, err)
	assert.Equal(t, string(once), string(twice))

	// A document the edit does not change is returned as it was written, even
	// when it is not in the encoder's own layout.
	odd := []byte("{\"a\":1,   \"mcpServers\":{\"keylatch\":{\"command\":\"keylatch\",\"args\":[\"mcp\",\"--stdio\"]}}}")
	same, err := merge.EditJSON(odd, addServer)
	require.NoError(t, err)
	assert.Equal(t, string(odd), string(same))
}

func TestMergeRefusesWhatItCannotRoundTrip(t *testing.T) {
	for name, doc := range map[string]string{
		"comment":        "{\n// my settings\n\"a\": 1}",
		"trailing comma": `{"a": 1,}`,
		"not an object":  `[1]`,
		"two documents":  `{"a":1} {"b":2}`,
		"duplicate key":  `{"a":1,"a":2}`,
	} {
		_, err := merge.EditJSON([]byte(doc), addServer)
		assert.Error(t, err, name)
	}
	_, err := merge.EditJSON([]byte(`{"mcpServers": "oops"}`), addServer)
	assert.ErrorContains(t, err, "not an object", "a value of the wrong type is never overwritten")

	obj := merge.NewObject()
	obj.Set("l", "x")
	_, err = obj.List("l")
	assert.Error(t, err)
	l, err := obj.List("missing")
	assert.NoError(t, err)
	assert.Nil(t, l)
}

func TestJSONObjectBasics(t *testing.T) {
	o, err := merge.ParseJSON(nil)
	require.NoError(t, err)
	assert.Empty(t, o.Keys())
	assert.Equal(t, "{}\n", string(o.Encode("  ")))
	o.Set("a", []any{})
	o.Set("b", "x")
	o.Set("a", []any{"first"})
	o.Delete("b")
	o.Delete("missing")
	assert.Equal(t, "{\n\t\"a\": [\n\t\t\"first\"\n\t]\n}\n", string(o.Encode("\t")))
	assert.Equal(t, "\t", merge.DetectIndent([]byte("{\n\t\"a\": 1\n}")))
	assert.Equal(t, "  ", merge.DetectIndent([]byte(`{"a":1}`)))
}

const userTOML = `# my codex settings
model = "gpt-5"   # keep this comment

[mcp_servers.other]
command = "other"
`

func TestMergePreservesComments(t *testing.T) {
	t.Run("toml", func(t *testing.T) {
		body := "[mcp_servers.keylatch]\ncommand = \"keylatch\"\nargs = [\"mcp\", \"--stdio\"]"
		out, err := merge.TOMLBlock([]byte(userTOML), body)
		require.NoError(t, err)
		s := string(out)
		assert.True(t, strings.HasPrefix(s, userTOML), "everything the user wrote is untouched, byte for byte")
		assert.Contains(t, s, merge.BlockBegin+"\n[mcp_servers.keylatch]")

		again, err := merge.TOMLBlock(out, body)
		require.NoError(t, err)
		assert.Equal(t, s, string(again), "idempotent")

		changed, err := merge.TOMLBlock(out, "[mcp_servers.keylatch]\ncommand = \"/opt/keylatch\"")
		require.NoError(t, err)
		assert.Contains(t, string(changed), "/opt/keylatch")
		assert.Equal(t, 1, strings.Count(string(changed), merge.BlockBegin), "the block is replaced in place")

		back, removed, err := merge.RemoveTOMLBlock(out)
		require.NoError(t, err)
		assert.True(t, removed)
		assert.Equal(t, userTOML, string(back))
		_, removed, err = merge.RemoveTOMLBlock([]byte(userTOML))
		require.NoError(t, err)
		assert.False(t, removed)
	})

	t.Run("toml conflicts and damage", func(t *testing.T) {
		_, err := merge.TOMLBlock([]byte("[mcp_servers.keylatch]\ncommand = \"mine\"\n"), "[mcp_servers.keylatch]\ncommand = \"keylatch\"")
		assert.ErrorContains(t, err, "already exist outside")
		_, err = merge.TOMLBlock([]byte("model = = 1"), "x = 1")
		assert.ErrorContains(t, err, "not valid TOML")
		_, err = merge.TOMLBlock([]byte(merge.BlockBegin+"\nx = 1\n"), "x = 1")
		assert.ErrorContains(t, err, "no closing")
		_, err = merge.TOMLBlock([]byte(merge.BlockBegin+"\n"+merge.BlockBegin+"\n"+merge.BlockEnd+"\n"), "x = 1")
		assert.ErrorContains(t, err, "more than one")
	})

	t.Run("markdown", func(t *testing.T) {
		doc := "# Project rules\n\nBe kind.\n"
		out, err := merge.MarkdownBlock([]byte(doc), "Use keylatch run.")
		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(string(out), doc))
		back, removed, err := merge.RemoveMarkdownBlock(out)
		require.NoError(t, err)
		assert.True(t, removed)
		assert.Equal(t, doc, string(back))
		fresh, err := merge.MarkdownBlock(nil, "x")
		require.NoError(t, err)
		assert.Equal(t, merge.MarkdownBegin+"\nx\n"+merge.MarkdownEnd+"\n", string(fresh))
		noNewline, err := merge.MarkdownBlock([]byte("no newline"), "x")
		require.NoError(t, err)
		assert.Contains(t, string(noNewline), "no newline\n\n"+merge.MarkdownBegin)
	})

	t.Run("yaml", func(t *testing.T) {
		doc := "# top comment\nmodel: x   # trailing\nmcp:\n  # before other\n  other:\n    command: other\n"
		value := map[string]any{"command": "keylatch", "args": []string{"mcp", "--stdio"}}
		out, err := merge.EditYAML([]byte(doc), []string{"mcp", "keylatch"}, value)
		require.NoError(t, err)
		s := string(out)
		for _, kept := range []string{"# top comment", "# trailing", "# before other", "command: other"} {
			assert.Contains(t, s, kept)
		}
		assert.Contains(t, s, "keylatch:")
		assert.Less(t, strings.Index(s, "model:"), strings.Index(s, "mcp:"), "key order is kept")

		again, err := merge.EditYAML(out, []string{"mcp", "keylatch"}, value)
		require.NoError(t, err)
		assert.Equal(t, s, string(again))

		replaced, err := merge.EditYAML(out, []string{"mcp", "keylatch"}, map[string]any{"command": "/opt/keylatch"})
		require.NoError(t, err)
		assert.Contains(t, string(replaced), "/opt/keylatch")

		deep, err := merge.EditYAML(nil, []string{"a", "b", "c"}, "v")
		require.NoError(t, err)
		assert.Equal(t, "a:\n  b:\n    c: v\n", string(deep))

		_, err = merge.EditYAML([]byte("mcp: scalar\n"), []string{"mcp", "keylatch"}, value)
		assert.Error(t, err)
		_, err = merge.EditYAML([]byte("- list\n"), []string{"a"}, value)
		assert.Error(t, err)
		_, err = merge.EditYAML([]byte("a: [unclosed"), []string{"a"}, value)
		assert.Error(t, err)
		_, err = merge.EditYAML(nil, nil, value)
		assert.Error(t, err)
	})
}

func TestApplyBacksUpAndIsAtomic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "settings.json")

	edit := func(old []byte) ([]byte, error) { return merge.EditJSON(old, addServer) }

	dry, err := merge.Apply(path, merge.Options{DryRun: true}, edit)
	require.NoError(t, err)
	assert.True(t, dry.Changed && dry.Created)
	assert.Contains(t, dry.Diff, "+")
	_, statErr := os.Stat(path)
	assert.True(t, os.IsNotExist(statErr), "a dry run writes nothing")

	created, err := merge.Apply(path, merge.Options{}, edit)
	require.NoError(t, err)
	assert.True(t, created.Created)
	assert.Empty(t, created.Backup, "a new file has nothing to back up")

	require.NoError(t, os.WriteFile(path, []byte(userJSON), 0o644))
	require.NoError(t, os.Chmod(path, 0o644))
	changed, err := merge.Apply(path, merge.Options{}, edit)
	require.NoError(t, err)
	assert.True(t, changed.Changed)
	assert.Equal(t, path+merge.BackupSuffix, changed.Backup)
	backup, err := os.ReadFile(changed.Backup)
	require.NoError(t, err)
	assert.Equal(t, userJSON, string(backup))
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o644), info.Mode().Perm(), "the file keeps its mode")
	}

	same, err := merge.Apply(path, merge.Options{}, edit)
	require.NoError(t, err)
	assert.False(t, same.Changed)

	_, err = merge.Apply(path, merge.Options{}, func([]byte) ([]byte, error) { return nil, os.ErrInvalid })
	assert.Error(t, err)

	leftovers, _ := filepath.Glob(filepath.Join(dir, "nested", ".keylatch-*"))
	assert.Empty(t, leftovers, "no temporary file remains")
}

func TestApplyFollowsSymlinks(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "dotfiles", "settings.json")
	require.NoError(t, os.MkdirAll(filepath.Dir(target), 0o700))
	require.NoError(t, os.WriteFile(target, []byte(userJSON), 0o600))
	link := filepath.Join(dir, "settings.json")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	_, err := merge.Apply(link, merge.Options{}, func(old []byte) ([]byte, error) { return merge.EditJSON(old, addServer) })
	require.NoError(t, err)
	info, err := os.Lstat(link)
	require.NoError(t, err)
	assert.NotZero(t, info.Mode()&os.ModeSymlink, "the link is still a link")
	data, err := os.ReadFile(target)
	require.NoError(t, err)
	assert.Contains(t, string(data), "mcpServers")
}
