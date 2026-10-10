#!/usr/bin/env bash
# Edge-case tests for the guard: environments that differ from a developer
# Linux shell (no jq, a BSD-like sed, a realpath without -m, macOS case folding,
# a HOME with a space, an unset HOME) and internal failures, which must deny.
# shellcheck disable=SC2034,SC2088
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=harness-fixtures.sh
. "$SCRIPT_DIR/harness-fixtures.sh"

PASS=0
FAIL=0
REAL_HOME="$HOME"

TMP_ROOT="$(mktemp -d)"
trap 'rm -rf "$TMP_ROOT"' EXIT

expect() {
	local label="$1" harness="$2" want="$3" payload="$4"
	run_guard "$harness" "$payload"
	if verdict_ok "$harness" "$want"; then
		PASS=$((PASS + 1))
	else
		echo "FAIL: [$harness] $label expected=$want got=$GUARD_CODE out=$GUARD_OUT err=$GUARD_ERR"
		FAIL=$((FAIL + 1))
	fi
}

# A throwaway HOME with a credential directory and a symlink into it.
FAKE_HOME="$TMP_ROOT/home"
mkdir -p "$FAKE_HOME/.ssh" "$FAKE_HOME/proj" "$FAKE_HOME/.aws"
echo secret >"$FAKE_HOME/.ssh/id_rsa"
ln -s "$FAKE_HOME/.ssh" "$FAKE_HOME/proj/link"
ln -s "$FAKE_HOME/.ssh/id_rsa" "$FAKE_HOME/proj/keylink"
echo notes >"$FAKE_HOME/proj/readme"
export HOME="$FAKE_HOME"

# --- fail closed ---------------------------------------------------------
for h in claude-code cursor antigravity windsurf gemini; do
	GUARD_ENV_OPTS="-u HOME" expect "unset HOME still denies env" "$h" deny "$(shell_payload "$h" printenv)"
	GUARD_ENV_OPTS="-u HOME" expect "unset HOME allows a plain command" "$h" allow "$(shell_payload "$h" "echo hello")"
	GUARD_ENV_OPTS="-u HOME" expect "unset HOME allows a project read" "$h" allow "$(read_payload "$h" /work/a.go)"
done

STUB="$TMP_ROOT/stub-broken"
mkdir -p "$STUB"
printf '#!/bin/sh\nexit 1\n' >"$STUB/awk"
chmod +x "$STUB/awk"
GUARD_STUB_DIR="$STUB"
for h in $HARNESSES; do
	expect "an internal error denies" "$h" deny "$(shell_payload "$h" "echo hello")"
done
GUARD_STUB_DIR=""

# --- realpath without -m, and macOS --------------------------------------
STUB="$TMP_ROOT/stub-bsd"
mkdir -p "$STUB"
REAL_REALPATH="$(command -v realpath)"
cat >"$STUB/realpath" <<EOF
#!/bin/sh
for a in "\$@"; do
	if [ "\$a" = -m ]; then echo "realpath: illegal option -- m" >&2; exit 1; fi
done
exec $REAL_REALPATH "\$@"
EOF
chmod +x "$STUB/realpath"
GUARD_STUB_DIR="$STUB"
for h in claude-code cursor antigravity; do
	expect "dot segment" "$h" deny "$(read_payload "$h" "$HOME/./.ssh/id_rsa")"
	expect "double slash" "$h" deny "$(read_payload "$h" "$HOME//.ssh/id_rsa")"
	expect "dot-dot segment" "$h" deny "$(read_payload "$h" "$HOME/proj/../.ssh/id_rsa")"
	expect "dot-dot through a missing directory" "$h" deny "$(read_payload "$h" "$HOME/missing/../.ssh/id_rsa")"
	expect "symlinked directory" "$h" deny "$(read_payload "$h" "$HOME/proj/link/id_rsa")"
	expect "symlinked file" "$h" deny "$(read_payload "$h" "$HOME/proj/keylink")"
	expect "symlinked directory itself" "$h" deny "$(read_payload "$h" "$HOME/proj/link")"
	expect "tilde with dot segment" "$h" deny "$(read_payload "$h" "~/./.ssh/id_rsa")"
	expect "tilde with dot-dot" "$h" deny "$(read_payload "$h" "~/proj/../.aws/credentials")"
	expect "project file" "$h" allow "$(read_payload "$h" "$HOME/proj/readme")"
	expect "project file with dot-dot" "$h" allow "$(read_payload "$h" "$HOME/proj/../proj/readme")"
done
GUARD_STUB_DIR=""

STUB="$TMP_ROOT/stub-darwin"
mkdir -p "$STUB"
cp "$TMP_ROOT/stub-bsd/realpath" "$STUB/realpath"
printf '#!/bin/sh\necho Darwin\n' >"$STUB/uname"
chmod +x "$STUB/uname"
GUARD_STUB_DIR="$STUB"
for h in claude-code cursor antigravity; do
	expect "darwin upper-case directory" "$h" deny "$(read_payload "$h" "$HOME/.SSH/id_rsa")"
	expect "darwin mixed-case directory" "$h" deny "$(read_payload "$h" "$HOME/.Aws")"
	expect "darwin dot segment" "$h" deny "$(read_payload "$h" "$HOME/./.ssh/id_rsa")"
	expect "darwin symlink" "$h" deny "$(read_payload "$h" "$HOME/proj/link/id_rsa")"
	expect "darwin shell reader, upper case" "$h" deny "$(shell_payload "$h" "cat ~/.SSH/id_rsa")"
	expect "darwin shell reader, upper-case variable" "$h" deny "$(shell_payload "$h" "cat \$HOME/.Aws/credentials")"
	expect "darwin project file" "$h" allow "$(read_payload "$h" "$HOME/proj/readme")"
	expect "darwin plain command" "$h" allow "$(shell_payload "$h" "ls -la")"
done
GUARD_STUB_DIR=""

# --- HOME with a space ---------------------------------------------------
SPACE_HOME="$TMP_ROOT/h o me"
mkdir -p "$SPACE_HOME/.ssh" "$SPACE_HOME/proj"
export HOME="$SPACE_HOME"
for h in claude-code cursor antigravity; do
	expect "space in HOME, read" "$h" deny "$(read_payload "$h" "$HOME/.ssh/id_rsa")"
	expect "space in HOME, tilde read" "$h" deny "$(read_payload "$h" "~/.ssh/id_rsa")"
	expect "space in HOME, quoted absolute path" "$h" deny "$(shell_payload "$h" "cat '$HOME/.ssh/id_rsa'")"
	expect "space in HOME, project read" "$h" allow "$(read_payload "$h" "$HOME/proj/readme")"
done
export HOME="$FAKE_HOME"

# --- no jq, BSD-like sed -------------------------------------------------
GUARD_PATH_DIR="$TMP_ROOT/nojq-bin"
make_tool_dir "$GUARD_PATH_DIR" nojq
for h in $HARNESSES; do
	expect "no-jq read of a credential file" "$h" deny "$(read_payload "$h" "$HOME/.ssh/id_rsa")"
	expect "no-jq read of a credential directory" "$h" deny "$(read_payload "$h" "$HOME/.aws")"
	expect "no-jq read of the home directory" "$h" deny "$(read_payload "$h" "$HOME")"
	expect "no-jq tilde read" "$h" deny "$(read_payload "$h" "~/.ssh/id_rsa")"
	expect "no-jq read of a project file" "$h" allow "$(read_payload "$h" "/work/src/main.go")"
	expect "no-jq printenv" "$h" deny "$(shell_payload "$h" printenv)"
	expect "no-jq env" "$h" deny "$(shell_payload "$h" env)"
	expect "no-jq plain command" "$h" allow "$(shell_payload "$h" "echo hello")"
	expect "no-jq reader of a credential file" "$h" deny "$(shell_payload "$h" "cat ~/.ssh/id_rsa")"
done
expect "no-jq cursor attachment" cursor deny "$(cursor_attachment_payload /work/a.go "$HOME/.aws/credentials")"
expect "no-jq clean cursor attachment" cursor allow "$(cursor_attachment_payload /work/a.go /work/b.go)"
expect "no-jq Grep path" claude-code deny '{"tool_name":"Grep","tool_input":{"pattern":".","path":"~/.ssh"}}'
expect "no-jq Glob pattern" claude-code deny "$(jq -nc --arg p "$HOME/.ssh/**" '{tool_name:"Glob",tool_input:{pattern:$p}}')"
expect "no-jq read_many_files" gemini deny "$(jq -nc --arg p "$HOME/.ssh/id_rsa" '{tool_name:"read_many_files",tool_input:{paths:["/work/a.go",$p]}}')"
expect "no-jq Copilot view" copilot deny "$(copilot_view_payload "$HOME/.ssh/id_rsa")"
expect "no-jq Copilot view of a project file" copilot allow "$(copilot_view_payload /work/a.go)"
expect "no-jq newline-separated commands" claude-code deny "$(jq -nc '{tool_name:"Bash",tool_input:{command:"echo x\nprintenv"}}')"
expect "no-jq command key before cwd" cursor deny '{"command":"printenv","cwd":"/work","sandbox":false}'
expect "no-jq command with escaped quotes" claude-code allow '{"tool_name":"Bash","tool_input":{"command":"echo \"hello\""}}'
GUARD_PATH_DIR=""

echo
echo "Guard edge cases: $PASS passed, $FAIL failed"
HOME="$REAL_HOME"
[ "$FAIL" -eq 0 ]
