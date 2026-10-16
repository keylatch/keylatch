package targets

import (
	"bytes"
	"context"
	"regexp"
	"strings"

	keysync "github.com/keylatch/keylatch/internal/sync"
)

var envLine = regexp.MustCompile(`^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=`)

// EnvFile edits the contents of a dotenv file in memory. Lines that are not
// managed variables, comments and blanks included, are kept as they are.
// Nothing reaches disk until Flush.
type EnvFile struct {
	id      string
	lines   []string
	flush   func([]byte) error
	dirty   bool
	trailNL bool
}

// NewEnvFile wraps existing (nil for a new file). flush receives the merged
// content once, from Flush.
func NewEnvFile(id string, existing []byte, flush func([]byte) error) *EnvFile {
	text := strings.ReplaceAll(string(existing), "\r\n", "\n")
	f := &EnvFile{id: id, flush: flush, trailNL: true}
	if text != "" {
		f.trailNL = strings.HasSuffix(text, "\n")
		f.lines = strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	}
	return f
}

// ID is the identity the daemon keys its record of writes by.
func (f *EnvFile) ID() string { return f.id }

// Keys returns the names of the variables the file defines.
func Keys(content []byte) []string { return keysync.EnvKeys(content) }

// List returns the file's variable names.
func (f *EnvFile) List(context.Context) ([]keysync.Remote, error) {
	var out []keysync.Remote
	for _, name := range Keys([]byte(strings.Join(f.lines, "\n"))) {
		out = append(out, keysync.Remote{Name: name, Environments: []string{keysync.EnvFile}})
	}
	return out, nil
}

func quote(v string) string {
	if v == "" || !strings.ContainsAny(v, " \t#'\"\\$`\n\r") {
		return v
	}
	if !strings.ContainsAny(v, "'\n\r") {
		return "'" + v + "'"
	}
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`, "\r", `\r`, "$", `\$`, "`", "\\`")
	return `"` + r.Replace(v) + `"`
}

// Write sets name to value, replacing the first line that defines it or
// appending one.
func (f *EnvFile) Write(_ context.Context, name string, value []byte, _ []string, _ bool) error {
	line := name + "=" + quote(string(value))
	for i, l := range f.lines {
		if m := envLine.FindStringSubmatch(l); m != nil && m[1] == name {
			if f.lines[i] != line {
				f.lines[i], f.dirty = line, true
			}
			return nil
		}
	}
	f.lines, f.dirty = append(f.lines, line), true
	return nil
}

// Delete removes every line that defines the variable.
func (f *EnvFile) Delete(_ context.Context, r keysync.Remote) error {
	kept := f.lines[:0]
	for _, l := range f.lines {
		if m := envLine.FindStringSubmatch(l); m != nil && m[1] == r.Name {
			f.dirty = true
			continue
		}
		kept = append(kept, l)
	}
	f.lines = kept
	return nil
}

// Readback reports false: the daemon does not read the file back to compare.
func (f *EnvFile) Readback(context.Context, keysync.Remote) ([]byte, bool, error) {
	return nil, false, nil
}

// Content is the merged file.
func (f *EnvFile) Content() []byte {
	if len(f.lines) == 0 {
		return nil
	}
	var b bytes.Buffer
	b.WriteString(strings.Join(f.lines, "\n"))
	if f.trailNL {
		b.WriteByte('\n')
	}
	return b.Bytes()
}

// Flush hands the merged content to the writer when anything changed.
func (f *EnvFile) Flush(context.Context) error {
	if !f.dirty {
		return nil
	}
	f.trailNL = true
	if err := f.flush(f.Content()); err != nil {
		return err
	}
	f.dirty = false
	return nil
}
