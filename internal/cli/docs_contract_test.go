package cli_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keylatch/keylatch/internal/cli"
)

// docFiles lists the documents whose keylatch commands must exist. Release
// notes and architecture decision records describe the past and are exempt.
func docFiles(t *testing.T, root string) []string {
	t.Helper()
	files := []string{"README.md", "SECURITY.md"}
	require.NoError(t, filepath.WalkDir(filepath.Join(root, "docs"), func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if rel == "docs/release-notes" || rel == "docs/architecture/decisions" {
				return filepath.SkipDir
			}
			return nil
		}
		// docs/experimental.md documents commands built only with the experimental tag.
		if strings.HasSuffix(rel, ".md") && rel != "docs/experimental.md" {
			files = append(files, rel)
		}
		return nil
	}))
	sort.Strings(files)
	return files
}

var (
	fenceRE      = regexp.MustCompile("(?s)```[a-zA-Z0-9_-]*\n(.*?)```")
	inlineRE     = regexp.MustCompile("`([^`\n]+)`")
	continuation = regexp.MustCompile(`\\\n\s*`)
	flagRE       = regexp.MustCompile(`^--?[A-Za-z][A-Za-z0-9-]*`)
)

// commandsIn returns every "keylatch ..." invocation in markdown text: each
// line of a shell code block that starts with the binary name, and each inline
// code span that does.
func commandsIn(markdown string) []string {
	var out []string
	for _, block := range fenceRE.FindAllStringSubmatch(markdown, -1) {
		body := continuation.ReplaceAllString(block[1], " ")
		for _, line := range strings.Split(body, "\n") {
			line = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "$ "))
			if strings.HasPrefix(line, "keylatch ") {
				out = append(out, line)
			}
		}
	}
	rest := fenceRE.ReplaceAllString(markdown, "")
	for _, m := range inlineRE.FindAllStringSubmatch(rest, -1) {
		if span := strings.TrimSpace(m[1]); strings.HasPrefix(span, "keylatch ") {
			out = append(out, span)
		}
	}
	return out
}

// resolve walks the command tree along the leading words of an invocation and
// returns the deepest command found, the words after it and an error when the
// first word is not a registered command.
func resolve(root *cobra.Command, words []string) (*cobra.Command, []string, error) {
	cmd := root
	i := 0
	for i < len(words) {
		w := words[i]
		if strings.HasPrefix(w, "-") || strings.ContainsAny(w, "<[$\"'=@./") {
			break
		}
		var next *cobra.Command
		for _, c := range cmd.Commands() {
			if c.Name() == w || c.HasAlias(w) {
				next = c
				break
			}
		}
		if next == nil {
			break
		}
		cmd = next
		i++
	}
	if cmd == root && len(words) > 0 && !strings.HasPrefix(words[0], "-") && !strings.ContainsAny(words[0], "<[$\"'=@./") {
		return nil, nil, &unknownCommand{words[0]}
	}
	return cmd, words[i:], nil
}

type unknownCommand struct{ name string }

func (e *unknownCommand) Error() string { return "unknown command " + e.name }

func hasFlag(cmd *cobra.Command, token string) bool {
	name := flagRE.FindString(token)
	if name == "" || name == "--" || name == "-" {
		return true
	}
	name = strings.TrimLeft(name, "-")
	look := func(fs *pflag.FlagSet) bool {
		if fs == nil {
			return false
		}
		if len(token) > 1 && token[1] != '-' && len(name) >= 1 {
			return fs.ShorthandLookup(name[:1]) != nil
		}
		return fs.Lookup(name) != nil
	}
	if look(cmd.Flags()) || look(cmd.InheritedFlags()) || look(cmd.PersistentFlags()) {
		return true
	}
	// help is added by cobra at run time.
	return name == "help" || name == "h" || name == "version"
}

// checkCommand returns a description of what is wrong with one invocation, or
// an empty string.
func checkCommand(root *cobra.Command, invocation string) string {
	line := strings.TrimSpace(strings.TrimPrefix(invocation, "keylatch"))
	for _, cut := range []string{" | ", " > ", " >> ", " 2>", " && ", " || ", " ; ", " # "} {
		if i := strings.Index(line, cut); i >= 0 {
			line = line[:i]
		}
	}
	words := strings.Fields(line)
	if len(words) == 0 {
		return ""
	}
	cmd, rest, err := resolve(root, words)
	if err != nil {
		return err.Error()
	}
	for _, w := range rest {
		if cmd.DisableFlagParsing {
			break
		}
		if w == "--" {
			break
		}
		if strings.HasPrefix(w, "-") && !hasFlag(cmd, w) {
			return "command \"" + cmd.CommandPath() + "\" has no flag " + w
		}
	}
	return ""
}

func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	require.NoError(t, err)
	return root
}

// TestDocsContract proves every keylatch command and flag the documentation
// shows exists in the command tree.
func TestDocsContract(t *testing.T) {
	root := repoRoot(t)
	tree := cli.NewRootCommand()
	var problems []string
	for _, rel := range docFiles(t, root) {
		data, err := os.ReadFile(filepath.Join(root, rel)) //nolint:gosec // G304: repository documents
		require.NoError(t, err)
		for _, inv := range commandsIn(string(data)) {
			if msg := checkCommand(tree, inv); msg != "" {
				problems = append(problems, rel+": `"+inv+"`: "+msg)
			}
		}
	}
	assert.Empty(t, problems, "documented commands that do not exist:\n%s", strings.Join(problems, "\n"))
}

var linkRE = regexp.MustCompile(`\]\(([^)\s#]+)(?:#[^)\s]*)?\)`)

// TestDocsLinksResolve proves every relative markdown link points at a file
// or directory that exists.
func TestDocsLinksResolve(t *testing.T) {
	root := repoRoot(t)
	files := append(docFiles(t, root), "CONTRIBUTING.md")
	var broken []string
	for _, rel := range files {
		data, err := os.ReadFile(filepath.Join(root, rel)) //nolint:gosec // G304: repository documents
		require.NoError(t, err)
		text := fenceRE.ReplaceAllString(string(data), "")
		for _, m := range linkRE.FindAllStringSubmatch(text, -1) {
			target := m[1]
			if strings.Contains(target, "://") || strings.HasPrefix(target, "mailto:") {
				continue
			}
			full := filepath.Join(root, filepath.Dir(rel), target)
			if strings.HasPrefix(target, "/") {
				full = filepath.Join(root, target)
			}
			if _, err := os.Stat(full); err != nil {
				broken = append(broken, rel+" -> "+target)
			}
		}
	}
	assert.Empty(t, broken, "broken relative links:\n%s", strings.Join(broken, "\n"))
}

// TestDocsContractRejectsRemovedCommands proves the check itself fails on a
// document that mentions a removed command or flag.
func TestDocsContractRejectsRemovedCommands(t *testing.T) {
	tree := cli.NewRootCommand()
	fixture := "Run `keylatch restore backup.enc` or:\n\n```bash\nkeylatch get svc key --masked\nkeylatch doctor --json\n```\n"
	var bad []string
	for _, inv := range commandsIn(fixture) {
		if checkCommand(tree, inv) != "" {
			bad = append(bad, inv)
		}
	}
	assert.Equal(t, []string{"keylatch get svc key --masked", "keylatch restore backup.enc"}, bad)
}
