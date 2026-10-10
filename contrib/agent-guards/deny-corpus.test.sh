#!/usr/bin/env bash
# Shared deny corpus: every command here is evaluated through every harness's
# real payload, so the corpus is enforced identically for all agents.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=harness-fixtures.sh
. "$SCRIPT_DIR/harness-fixtures.sh"

PASS=0
FAIL=0

DENY=(
	"env"
	"printenv"
	"bash -c 'env'"
	"keylatch get clockify api_key"
	"cat ~/.keylatch/config.yaml"
	"op read op://vault/item/field"
	"bw get item clockify"
	"direnv exec . env"
	"direnv exec /abs/project printenv"
	"direnv exec . bash -c 'env'"
	"direnv export bash"
	"direnv export json"
	"direnv -v export zsh"
	"direnv dump"
	"mise env"
	"mise env -s bash"
	"mise e"
	"mise exec -- env"
	"mise x node@22 -- printenv"
	"mise set"
	"atuin search foo"
	"atuin search --limit 50"
	"atuin history list"
	"atuin history last"
	"bash -c 'direnv export bash'"
	"sudo mise env"
	"cd /work && direnv export bash"
	"cat ~/.bash_history"
	"tail -n 200 ~/.zsh_history"
	"ls ~/.local/share/atuin"
	"sqlite3 ~/.local/share/atuin/history.db .dump"
	"cat ~/.kube/config"
	"head -n 5 \$HOME/.netrc"
	"less $HOME/.config/gh/hosts.yml"
	"cp ~/.docker/config.json /tmp/x"
	"grep -r token \${HOME}/.azure/"
	"bash -c 'tail ~/.npmrc'"
	"cat ~/.git-credentials"
	"base64 ~/.terraform.d/credentials.tfrc.json"
	"sed -n 1p ~/.pypirc"
	"mise set --json"
	"/bin/cat ~/.ssh/id_rsa"
	"/usr/bin/head -n 3 \$HOME/.aws/credentials"
	"cat ~/./.ssh/id_rsa"
	"cat ~//.ssh/id_rsa"
	"cat ~/x/../.ssh/id_rsa"
	"cat \"\$HOME\"/.ssh/id_rsa"
	"cat ~/\".ssh\"/id_rsa"
	"cat '\$HOME'/.ssh/id_rsa"
	"cat $HOME//.ssh/./id_rsa"
	"cd ~ && cat .ssh/id_rsa"
	"cd \$HOME; cat .aws/credentials"
	"cd && cat .ssh/id_rsa"
	"dd if=~/.ssh/id_rsa"
	"tar cf - ~/.ssh"
	"diff /dev/null ~/.ssh/id_rsa"
	"while read l; do echo \$l; done < ~/.ssh/id_rsa"
	"python3 -c 'print(open(\"$HOME/.ssh/id_rsa\").read())'"
	"python3 -c 'print(open(\"~/.ssh/id_rsa\").read())'"
	"xxd ~/.gnupg/secring.gpg"
	"cat <(cat ~/.ssh/id_rsa)"
)

ALLOW=(
	"kubectl config view"
	"gh auth status"
	"docker ps"
	"cat .npmrc"
	"cat ./.netrc.example"
	"ls ~/.kube"
	"git config --get user.name"
	"echo hello"
	"keylatch get --masked clockify api_key"
	"keylatch list"
	"direnv allow"
	"direnv reload"
	"direnv exec . npm test"
	"direnv exec /abs/project make build"
	"mise install"
	"mise use node@22"
	"mise exec -- node -v"
	"mise x node@22 -- npm test"
	"mise set FOO=bar"
	"mise run build"
	"atuin sync"
	"atuin status"
	"grep -n direnv README.md"
	"echo atuin search"
	"git log --oneline"
	"ls ~/.ssh"
	"stat ~/.ssh/id_rsa"
	"kubectl --kubeconfig ~/.kube/config get pods"
	"docker ps --filter name=ssh"
	"cd ~ && ls"
	"cd ~/code/project && cat .npmrc"
	"cat ~/code/project/.kubeconfig-template"
	"echo ~/code/ssh-notes"
)

check() {
	local want="$1" cmd="$2" h
	for h in $HARNESSES; do
		run_guard "$h" "$(shell_payload "$h" "$cmd")"
		want_code="$want"
		[ "$want" -eq 2 ] && want_code="$(deny_code "$h")"
		if [ "$GUARD_CODE" -eq "$want_code" ] && { [ "$want" -ne 2 ] || [ "$h" != antigravity ] || printf '%s' "$GUARD_OUT" | grep -q '"deny"'; }; then
			PASS=$((PASS + 1))
		else
			echo "FAIL: [$h] expected=$want got=$GUARD_CODE: $cmd"
			FAIL=$((FAIL + 1))
		fi
	done
}

for cmd in "${DENY[@]}"; do check 2 "$cmd"; done
for cmd in "${ALLOW[@]}"; do check 0 "$cmd"; done

for h in $HARNESSES; do
	# shellcheck disable=SC2088
	for path in "$HOME/.bash_history" "$HOME/.local/share/atuin/history.db" "$HOME/.keylatch/config.yaml" "$HOME/.ssh" "$HOME" "$HOME/.kube/config" "$HOME/.kube" "$HOME/.netrc" "$HOME/.config/gcloud/credentials.db" "$HOME/.docker" "$HOME/.git-credentials" "$HOME/.terraform.d/credentials.tfrc.json" "$HOME/./.ssh/id_rsa" "$HOME//.ssh/id_rsa" "$HOME/proj/../.ssh/id_rsa" "~/.ssh/id_rsa" "~/./.aws/credentials"; do
		run_guard "$h" "$(read_payload "$h" "$path")"
		if verdict_ok "$h" deny; then
			PASS=$((PASS + 1))
		else
			echo "FAIL: [$h] read of $path expected=$(deny_code "$h") got=$GUARD_CODE"
			FAIL=$((FAIL + 1))
		fi
	done
done

# Read-capable tools other than Read: search and glob tools, multi-file reads
# and Copilot's view.
read_tool_check() {
	local label="$1" want="$2" h="$3" payload="$4"
	run_guard "$h" "$payload"
	if verdict_ok "$h" "$want"; then
		PASS=$((PASS + 1))
	else
		echo "FAIL: [$h] $label expected=$want got=$GUARD_CODE out=$GUARD_OUT"
		FAIL=$((FAIL + 1))
	fi
}

for h in claude-code codex; do
	read_tool_check "Grep of ~/.ssh" deny "$h" "$(jq -nc --arg p "$HOME/.ssh" '{tool_name:"Grep",tool_input:{pattern:".",path:$p,output_mode:"content"}}')"
	read_tool_check "Grep with tilde path" deny "$h" '{"tool_name":"Grep","tool_input":{"pattern":"BEGIN","path":"~/.ssh"}}'
	read_tool_check "Grep glob filter under ~/.aws" deny "$h" "$(jq -nc --arg p "$HOME/.aws/*" '{tool_name:"Grep",tool_input:{pattern:"key",glob:$p}}')"
	read_tool_check "Glob of ~/.ssh" deny "$h" "$(jq -nc --arg p "$HOME/.ssh/**" '{tool_name:"Glob",tool_input:{pattern:$p}}')"
	read_tool_check "Glob wildcard in the home directory" deny "$h" "$(jq -nc --arg p "$HOME" '{tool_name:"Glob",tool_input:{pattern:".ss*/*",path:$p}}')"
	read_tool_check "Glob wildcard on a protected name" deny "$h" "$(jq -nc --arg p "$HOME/.ss*/id_*" '{tool_name:"Glob",tool_input:{pattern:$p}}')"
	read_tool_check "Grep of a project" allow "$h" '{"tool_name":"Grep","tool_input":{"pattern":"TODO","path":"/work/src"}}'
	read_tool_check "Glob of a project" allow "$h" '{"tool_name":"Glob","tool_input":{"pattern":"/work/src/**/*.go"}}'
	read_tool_check "Grep without a path" allow "$h" '{"tool_name":"Grep","tool_input":{"pattern":"TODO"}}'
done
read_tool_check "read_many_files with a protected path" deny gemini "$(jq -nc --arg p "$HOME/.ssh/id_rsa" '{tool_name:"read_many_files",tool_input:{paths:["/work/a.go",$p]}}')"
read_tool_check "read_many_files with a protected glob" deny gemini "$(jq -nc --arg p "$HOME/.aws/**" '{tool_name:"read_many_files",tool_input:{paths:[$p]}}')"
read_tool_check "read_many_files of a project" allow gemini '{"tool_name":"read_many_files","tool_input":{"paths":["/work/a.go","/work/b.go"]}}'
read_tool_check "search_file_content under ~/.kube" deny gemini "$(jq -nc --arg p "$HOME/.kube" '{tool_name:"search_file_content",tool_input:{pattern:"token",path:$p}}')"
read_tool_check "glob under ~/.ssh" deny gemini "$(jq -nc --arg p "$HOME/.ssh" '{tool_name:"glob",tool_input:{pattern:"*",path:$p}}')"
read_tool_check "grep_search under ~/.ssh" deny gemini "$(jq -nc --arg p "$HOME/.ssh" '{tool_name:"grep_search",tool_input:{pattern:"x",dir_path:$p}}')"
read_tool_check "search_file_content of a project" allow gemini '{"tool_name":"search_file_content","tool_input":{"pattern":"x","path":"/work"}}'
read_tool_check "Copilot view of a protected file" deny copilot "$(copilot_view_payload "$HOME/.ssh/id_rsa")"
read_tool_check "Copilot grep of a protected directory" deny copilot "$(jq -nc --arg p "$HOME/.aws" '{toolName:"grep",toolArgs:({pattern:"k",path:$p}|tojson)}')"
read_tool_check "Copilot view of a project file" allow copilot "$(copilot_view_payload "/work/a.go")"
read_tool_check "Copilot PascalCase Read of a protected file" deny copilot "$(jq -nc --arg p "$HOME/.ssh/id_rsa" '{hook_event_name:"PreToolUse",tool_name:"Read",tool_input:{file_path:$p}}')"

echo "Deny corpus: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
