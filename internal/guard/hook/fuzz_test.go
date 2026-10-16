package hook

import "testing"

// FuzzHookDecision asserts the guard never panics: a recovered panic still
// denies, but it means a path the guard cannot reason about.
func FuzzHookDecision(f *testing.F) {
	for _, seed := range []string{
		"env", "ls", "bash -c 'env'", "cat ~/.ssh/id_rsa", "echo $(printenv)", "env -C /tmp make", "$'\\x65nv'",
		"{env,}", "cat <<EOF\nenv\nEOF", "a | b | c", "f() { env; }", "x=$(cat ~/.ssh/id_rsa)", "find . -exec env \\;",
		"eval \"$(echo env)\"", "sudo -u root env", "case x in y) env;; esac", "echo 'unterminated",
		"declare -p", "export -p", "python3 -c 'import os; os.environ'", "cd ~ && cat .ssh/id_rsa",
	} {
		f.Add(seed, "/work")
	}
	f.Fuzz(func(t *testing.T, cmd, cwd string) {
		env := Env{Home: testHome, Lookup: func(string) string { return "" }, Binary: testBinary}
		t.Setenv("HOME", testHome)
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("guard panicked on %q: %v", cmd, r)
			}
		}()
		decide(bashPayload(cmd), env)
		decide(toolPayload("Read", map[string]any{"file_path": cmd, "path": cwd}), env)
		decide(toolPayload("Glob", map[string]any{"pattern": cmd, "path": cwd}), env)
	})
}
