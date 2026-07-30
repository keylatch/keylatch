#!/usr/bin/env bash
# Test harness for block-keylatch-exfiltration.sh
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
HOOK="$SCRIPT_DIR/block-keylatch-exfiltration.sh"

PASS=0
FAIL=0

run_case() {
	local label="$1"
	local tool_name="$2"
	local tool_input="$3"
	local expected_code="$4"

	actual_code=0
	CLAUDE_TOOL_NAME="$tool_name" CLAUDE_TOOL_INPUT="$tool_input" bash "$HOOK" </dev/null 2>/dev/null || actual_code=$?

	if [ "$actual_code" -eq "$expected_code" ]; then
		echo "PASS: $label"
		PASS=$((PASS + 1))
	else
		echo "FAIL: $label (expected=$expected_code, got=$actual_code)"
		FAIL=$((FAIL + 1))
	fi
}

# run_case_stdin exercises the current Claude Code contract: tool call JSON on
# stdin, no CLAUDE_TOOL_* env vars set.
run_case_stdin() {
	local label="$1"
	local json="$2"
	local expected_code="$3"

	actual_code=0
	printf '%s' "$json" | env -u CLAUDE_TOOL_NAME -u CLAUDE_TOOL_INPUT bash "$HOOK" 2>/dev/null || actual_code=$?

	if [ "$actual_code" -eq "$expected_code" ]; then
		echo "PASS: $label"
		PASS=$((PASS + 1))
	else
		echo "FAIL: $label (expected=$expected_code, got=$actual_code)"
		FAIL=$((FAIL + 1))
	fi
}

# run_case_stdin_nojq is identical to run_case_stdin but forces PATH to a
# jq-free directory, exercising the no-jq JSON fallback branch (TOOL_COMMAND
# extraction via sed) -- the first coverage that branch has ever had.
run_case_stdin_nojq() {
	local label="$1"
	local json="$2"
	local expected_code="$3"

	actual_code=0
	printf '%s' "$json" | env -u CLAUDE_TOOL_NAME -u CLAUDE_TOOL_INPUT PATH=/usr/bin:/bin bash "$HOOK" 2>/dev/null || actual_code=$?

	if [ "$actual_code" -eq "$expected_code" ]; then
		echo "PASS: $label"
		PASS=$((PASS + 1))
	else
		echo "FAIL: $label (expected=$expected_code, got=$actual_code)"
		FAIL=$((FAIL + 1))
	fi
}

# Core test cases
run_case "Plain get blocked"                    Bash  "keylatch get clockify api_key"                    2
run_case "get --masked allowed"                 Bash  "keylatch get --masked clockify api_key"           0
run_case "security find-generic-password"       Bash  "security find-generic-password -s keylatch -w"   2
run_case "security find-internet-password"      Bash  "security find-internet-password -s test -w"      2
run_case "op read blocked"                      Bash  "op read op://vault/item/field"                    2
run_case "op item get blocked"                  Bash  "op item get my-item"                              2
run_case "bw get blocked"                       Bash  "bw get item clockify"                             2
run_case "bw list blocked"                      Bash  "bw list items"                                    2
run_case ".keylatch Read blocked"               Read  "~/.keylatch/vault/imports/plaintext.env"          2
run_case "keylatch run -- env blocked"          Bash  "keylatch run openrouter -- env"                   2
run_case "keylatch run -- node allowed"         Bash  "keylatch run openrouter -- node script.js"        0
run_case "keylatch list allowed"                Bash  "keylatch list"                                    0
run_case "cat .env blocked"                     Bash  "cat ~/.keylatch/secrets.env"                      2
run_case "keylatch describe allowed"            Bash  "keylatch describe svc"                            0
run_case "keylatch validate allowed"            Bash  "keylatch validate svc"                            0

# SEC3 quoting variants — single-quote wrapper must not bypass blocks
run_case "get blocked single-quoted"            Bash  "'keylatch get clockify api_key'"                  2
run_case "get blocked double-quoted"            Bash  '"keylatch get clockify api_key"'                  2

# Additional edge cases
run_case "keylatch run -- env with args blocked" Bash "keylatch run openrouter -- env HOME"              2
run_case "keylatch get-masked allowed"          Bash  "keylatch get-masked svc key"                      0
run_case "unrelated command allowed"            Bash  "echo hello"                                       0
run_case "node script allowed"                  Bash  "node index.js"                                    0

# Quote-wrapped / subshell-wrapped bypass coverage (SEC3 extended to
# patterns 2-5, 7-9). Confirmed reproduction before the fix: bash -c '...'
# and sh -c "..." wrappers evaded these patterns because the leading
# boundary was whitespace-only, not quote-aware.

# --- pattern 1: keylatch get (already quote-aware; regression coverage) ---
run_case "p1 bash -c wrapped blocked"           Bash  "bash -c 'keylatch get clockify api_key'"          2
run_case "p1 sh -c wrapped blocked"             Bash  'sh -c "keylatch get clockify api_key"'            2
run_case "p1 prose near-miss allowed"           Bash  "echo 'keylatch getSecretValue helper'"            0

# --- pattern 2: security find-generic-password ---
run_case "p2 bash -c wrapped blocked"           Bash  "bash -c 'security find-generic-password -s x -w'" 2
run_case "p2 sh -c wrapped blocked"             Bash  'sh -c "security find-generic-password -s x -w"'   2
run_case "p2 prose near-miss allowed"           Bash  "echo 'security' word alone"                       0

# --- pattern 3: security find-internet-password ---
run_case "p3 bash -c wrapped blocked"           Bash  "bash -c 'security find-internet-password -s x -w'" 2
run_case "p3 sh -c wrapped blocked"             Bash  'sh -c "security find-internet-password -s x -w"'  2
run_case "p3 prose near-miss allowed"           Bash  "echo find-internet-password removed from docs"    0

# --- pattern 4: op read / op item get ---
run_case "p4 bash -c wrapped blocked"           Bash  "bash -c 'op read op://vault/item/field'"          2
run_case "p4 sh -c wrapped blocked"             Bash  'sh -c "op item get my-item"'                      2
run_case "p4 prose near-miss allowed"           Bash  "echo 'op' is a great cli, read the docs"          0

# --- pattern 5: bw get / bw list ---
run_case "p5 bash -c wrapped blocked"           Bash  "bash -c 'bw get item clockify'"                   2
run_case "p5 sh -c wrapped blocked"             Bash  'sh -c "bw list items"'                            2
run_case "p5 prose near-miss allowed"           Bash  "echo 'bw' tool notes"                             0

# --- pattern 7: keylatch run -- env ---
run_case "p7 bash -c wrapped blocked"           Bash  "bash -c 'keylatch run openrouter -- env'"         2
run_case "p7 sh -c wrapped blocked"             Bash  'sh -c "keylatch run openrouter -- env"'           2
run_case "p7 prose near-miss allowed"           Bash  "echo keylatch run supports -- environment flags"  0

# --- pattern 8: cat of keylatch/.env paths (the confirmed bypass repro) ---
run_case "p8 bash -c wrapped blocked (repro)"   Bash  "bash -c 'cat ~/.keylatch/secrets.env'"            2
run_case "p8 sh -c wrapped blocked (repro)"     Bash  'sh -c "cat ~/.keylatch/secrets.env"'              2
run_case "p8 prose near-miss allowed"           Bash  "grep -n keylatch README.md"                       0

# --- pattern 9: bare env / printenv structural analyzer (awk tokenizer,
# deny-by-default inside interpreter/eval payloads). Replaces three rounds
# of regex-only patching (79c5a97 -> bb07679 -> 0ff763e -> bca5deb revert)
# with real shell-word tokenization. See the comment above pattern 9 in
# block-keylatch-exfiltration.sh for the full design and accepted gaps.

# Group A — must-not-regress ALLOW. These are the false positives that
# started this whole session; every one must pass.
run_case "p9 A: grep -n 'env' settings.json allowed"        Bash  "grep -n 'env' settings.json"          0
run_case "p9 A: grep -n \"env\" settings.json allowed"      Bash  'grep -n "env" settings.json'           0
run_case "p9 A: grep -rn 'env' src/ allowed"                Bash  "grep -rn 'env' src/"                  0
run_case "p9 A: grep -n '\"env\"' settings.json allowed"    Bash  "grep -n '\"env\"' settings.json"      0
run_case "p9 A: echo mentioning env allowed"                Bash  "echo \"some text mentioning env\""    0
run_case "p9 A: cat environment-notes.md allowed"           Bash  "cat environment-notes.md"             0
run_case "p9 A: echo .env.example allowed"                  Bash  "echo .env.example is our template file" 0
run_case "p9 A: cat | grep environment allowed"             Bash  "cat package.json | grep environment"  0
run_case "p9 A: git commit -m env docs allowed"             Bash  'git commit -m "update env docs"'      0
run_case "p9 A: sed s/env/environment/ allowed"              Bash  "sed -i 's/env/environment/g' notes.md" 0
run_case "p9 A: npm run build --env allowed"                Bash  "npm run build --env production"       0
run_case "p9 A: sudo grep env allowed"                      Bash  "sudo grep env /etc/hosts"             0
run_case "p9 A: command -v env allowed (lookup)"            Bash  "command -v env"                       0
run_case "p9 A: bash -c 'echo hello' allowed"               Bash  "bash -c 'echo hello'"                 0
run_case "p9 A: bash -c 'grep -n \"env\" f' allowed"        Bash  'bash -c '"'"'grep -n "env" f'"'"''    0
run_case "p9 A: bash -c \"echo \$HOME\" allowed"            Bash  'bash -c "echo $HOME"'                 0
run_case "p9 A: echo \"a; env\" allowed"                    Bash  'echo "a; env"'                        0

# Group B — must-not-regress BLOCK, pattern 9's original purpose.
run_case "p9 B: bare env blocked"                           Bash  "env"                                 2
run_case "p9 B: bare printenv blocked"                      Bash  "printenv"                             2
run_case "p9 B: ls; env blocked"                            Bash  "ls; env"                              2
run_case "p9 B: ls && env blocked"                          Bash  "ls && env"                            2
run_case "p9 B: ls || env blocked"                          Bash  "ls || env"                            2
run_case "p9 B: find . | env blocked"                       Bash  "find . | env"                         2
run_case "p9 B: FOO=bar env blocked"                        Bash  "FOO=bar env"                          2
run_case "p9 B: FOO=bar BAZ=qux printenv blocked"           Bash  "FOO=bar BAZ=qux printenv"              2
run_case "p9 B: /usr/bin/env blocked"                       Bash  "/usr/bin/env"                         2
run_case "p9 B: env NODE_ENV=production npm start blocked"  Bash  "env NODE_ENV=production npm start"    2

# Group C — round-1 / round-2 regressions.
run_case "p9 C: bash -c 'env' blocked"                       Bash  "bash -c 'env'"                        2
run_case "p9 C: sh -c \"printenv\" blocked"                  Bash  'sh -c "printenv"'                      2
run_case "p9 C: bash -c ' env' (leading ws) blocked"         Bash  "bash -c ' env'"                        2
run_case "p9 C: bash -c '  env  ' (extra ws) blocked"        Bash  "bash -c '  env  '"                     2
run_case "p9 C: bash -c 'FOO=bar env' blocked"               Bash  "bash -c 'FOO=bar env'"                 2
run_case "p9 C: bash -c 'FOO=bar BAZ=qux printenv' blocked"  Bash  "bash -c 'FOO=bar BAZ=qux printenv'"     2
run_case "p9 C: bash -c -x 'env' (flag after -c) blocked"    Bash  "bash -c -x 'env'"                      2
run_case "p9 C: bash -x -c 'env' (flag before -c) blocked"   Bash  "bash -x -c 'env'"                      2
run_case "p9 C: bash -c<TAB>'env' (tab, not space) blocked"  Bash  $'bash -c\t\'env\''                     2
run_case "p9 C: bash -c 'true; env' compound blocked"        Bash  "bash -c 'true; env'"                   2
run_case "p9 C: bash -c 'true && env' compound blocked"      Bash  "bash -c 'true && env'"                 2
run_case "p9 C: bash -c 'true' -c 'env' (only first -c honoured) blocked" Bash "bash -c 'true' -c 'env'"   2

# Group D — round-3 bypasses 1, 2, 3, 5, 6, 7 (the core of the rewrite).
run_case "p9 D1: bash -c env (unquoted) blocked"             Bash  "bash -c env"                          2
run_case "p9 D1: sh -c env blocked"                          Bash  "sh -c env"                            2
run_case "p9 D1: zsh -c env blocked"                         Bash  "zsh -c env"                           2
run_case "p9 D1: dash -c env blocked"                        Bash  "dash -c env"                          2
run_case "p9 D1: ksh -c printenv blocked"                    Bash  "ksh -c printenv"                      2
run_case "p9 D1: bash -ec env (bundled cluster) blocked"     Bash  "bash -ec env"                         2
run_case "p9 D2: bash -c \"e\"nv (quote-spliced) blocked"    Bash  'bash -c "e"nv'                        2
run_case "p9 D2: bash -c 'e''nv' (quote-spliced) blocked"    Bash  "bash -c 'e''nv'"                      2
run_case "p9 D2: bash -c 'e'\"n\"v (mixed-spliced) blocked"  Bash  'bash -c '"'"'e'"'"'"n"v'               2
run_case "p9 D3: bash -c \$'\\x65nv' (ANSI-C escaped) blocked" Bash $'bash -c $\'\\x65nv\''                2
run_case "p9 D5: bash -c 'bash -c env' (nested) blocked"     Bash  "bash -c 'bash -c env'"                 2
run_case "p9 D5: bash -c 'bash -c \"bash -c env\"' (3 levels) blocked" Bash 'bash -c '"'"'bash -c "bash -c env"'"'"'' 2
run_case "p9 D6: eval env blocked"                           Bash  "eval env"                             2
run_case "p9 D6: eval 'env' blocked"                         Bash  "eval 'env'"                            2
run_case "p9 D6: eval \"printenv\" blocked"                  Bash  'eval "printenv"'                       2
run_case "p9 D7: exec env blocked"                           Bash  "exec env"                             2
run_case "p9 D7: command env blocked"                        Bash  "command env"                          2

# Group E — deny-by-default side effects (bypass 4 inside a payload:
# blocked by refusal, not by resolution).
run_case "p9 E: bash -c \"\$(echo env)\" blocked"            Bash  'bash -c "$(echo env)"'                 2
run_case "p9 E: bash -c \`echo env\` (backtick) blocked"     Bash  'bash -c `echo env`'                    2
run_case "p9 E: bash -c \"\$(printf env)\" blocked"          Bash  'bash -c "$(printf env)"'                2
run_case "p9 E: bash -c \"\$CMD\" blocked"                   Bash  'bash -c "$CMD"'                        2
run_case "p9 E: eval \"\$CMD\" blocked"                      Bash  'eval "$CMD"'                           2

# Group F — structural coverage the regex reached only by accident.
run_case "p9 F: bash -c 'if true; then env; fi' blocked"    Bash  "bash -c 'if true; then env; fi'"        2
run_case "p9 F: find . | xargs env blocked"                 Bash  "find . | xargs env"                     2
run_case "p9 F: sudo env blocked"                            Bash  "sudo env"                              2
run_case "p9 F: timeout 5s env blocked"                       Bash  "timeout 5s env"                        2
run_case "p9 F: nohup env blocked"                            Bash  "nohup env"                             2
run_case "p9 F: busybox sh -c env blocked"                    Bash  "busybox sh -c env"                     2
run_case "p9 F: newline separator blocked"                    Bash  $'ls\nenv'                             2

# Group G — documented accepted gaps, pinned as ALLOW so any future
# behavior change surfaces as a test diff, not a silent gap.
run_case "p9 G: KNOWN ACCEPTED GAP - top-level \$(echo env) allowed (unresolvable without execution)" Bash '$(echo env)' 0
run_case "p9 G: KNOWN ACCEPTED GAP - X=env; \$X allowed (variable indirection, unresolvable without execution)" Bash 'X=env; $X' 0
run_case "p9 G: KNOWN ACCEPTED GAP - bash dump.sh allowed (file-based payload, guard inspects tool-call text only)" Bash "bash dump.sh" 0
run_case "p9 G: KNOWN ACCEPTED GAP - bash -c 'env (unterminated quote) allowed (real shell rejects it too)" Bash "bash -c 'env" 0

# Current Claude Code contract — tool call JSON delivered on stdin
run_case_stdin "stdin: plain get blocked"        '{"tool_name":"Bash","tool_input":{"command":"keylatch get clockify api_key"}}'         2
run_case_stdin "stdin: get --masked allowed"     '{"tool_name":"Bash","tool_input":{"command":"keylatch get --masked clockify api_key"}}' 0
run_case_stdin "stdin: tilde .keylatch Read blocked"    '{"tool_name":"Read","tool_input":{"file_path":"~/.keylatch/vault/imports/plaintext.env"}}' 2
run_case_stdin "stdin: absolute .keylatch Read blocked" '{"tool_name":"Read","tool_input":{"file_path":"/Users/u/.keylatch/vault/imports/plaintext.env"}}' 2
run_case_stdin "stdin: env dump blocked"         '{"tool_name":"Bash","tool_input":{"command":"printenv"}}'                               2
run_case_stdin "stdin: unrelated command allowed" '{"tool_name":"Bash","tool_input":{"command":"echo hello"}}'                            0
run_case_stdin "stdin: unrelated Read allowed"   '{"tool_name":"Read","tool_input":{"file_path":"/tmp/notes.md"}}'                        0
run_case_stdin "stdin: empty payload allowed"    '{}'                                                                                     0

# Group H — stdin contract fixtures, including first-ever coverage of the
# no-jq fallback branch's TOOL_COMMAND extraction.
run_case_stdin "stdin p9: bash -c env blocked"        '{"tool_name":"Bash","tool_input":{"command":"bash -c env"}}'                 2
run_case_stdin "stdin p9: grep -n env allowed"        '{"tool_name":"Bash","tool_input":{"command":"grep -n '\''env'\'' settings.json"}}' 0
run_case_stdin_nojq "stdin nojq: bash -c env blocked" '{"tool_name":"Bash","tool_input":{"command":"bash -c env"}}'                 2
run_case_stdin_nojq "stdin nojq: echo hello allowed"  '{"tool_name":"Bash","tool_input":{"command":"echo hello"}}'                  0

# Group I — security-auditor round 2 (2026-07-30): two narrow implementation
# bugs found in the tokenizer/resolver, not design flaws in the tokenizer
# approach itself.
#
# Bypass A: bundled -c cluster where c is not the trailing character. Real
# bash keeps parsing short flags after -c anywhere in a bundled cluster (all
# five orderings below genuinely dump the environment in real bash,
# verified) -- the original -c-family regex only matched c at the END of
# the cluster (-xc/-ec style), missing -cx/-cv/-xce/-ecx/-cex.
run_case "p9 I: bash -cx env (c not trailing) blocked"  Bash "bash -cx env"  2
run_case "p9 I: bash -cv env (c not trailing) blocked"  Bash "bash -cv env"  2
run_case "p9 I: bash -xce env (c not trailing) blocked" Bash "bash -xce env" 2
run_case "p9 I: bash -ecx env (c not trailing) blocked" Bash "bash -ecx env" 2
run_case "p9 I: bash -cex env (c not trailing) blocked" Bash "bash -cex env" 2

# Bypass B: unquoted backslash-newline line continuation. Real bash removes
# `\<newline>` entirely (POSIX line continuation) and executes
# `bash \` + newline + `-c env` as `bash -c env` (verified -- dumps real
# environment). The tokenizer's ordinary unquoted-backslash-escape rule was
# copying the raw newline into the token instead, corrupting the following
# -c token so the payload was never inspected.
run_case "p9 I: bash \\<newline>-c env (line continuation) blocked"      Bash $'bash \\\n-c env'      2
run_case "p9 I: bash \\<newline>-c printenv (line continuation) blocked" Bash $'bash \\\n-c printenv' 2

# Group J — round 6 review (2026-07-30): same bug CLASS as Bypass B (backslash-
# newline line continuation) but in the double-quote (dq) tokenizer branch,
# which the Bypass B fix never touched. Real bash strips \<newline> inside
# double quotes too (POSIX: backslash retains escaping meaning before $, `,
# ", \, and newline) -- `"e\<newline>nv"` executes as `env` (verified).
#
# Completeness check across all three quoting contexts for backslash-newline:
#   1. Unquoted   -- fixed round 5 (Bypass B), re-confirmed still correct above.
#   2. Double-quoted -- fixed here (Bypass C).
#   3. Single-quoted -- POSIX gives backslash NO escaping meaning inside single
#      quotes, so `'e\<newline>nv'` is genuinely two literal lines of content,
#      not a continuation. Verified directly in real bash: it does NOT run
#      env, it errors "command not found" (exit 127) because the literal
#      "word" is `e\` + newline + `nv`, not `env`. No fix needed in the sq
#      branch (it never had escape processing to begin with); pinned as ALLOW
#      below so that claim is a test fixture, not just an assertion.
run_case "p9 J: bypass C bare - dq backslash-newline blocked"          Bash $'"e\\\nnv"'          2
run_case "p9 J: bypass C nested in bash -c blocked"                    Bash 'bash -c '"'"$'"e\\\nnv"'"'"                   2
run_case "p9 J: sq backslash-newline pinned allowed (no fix needed)"   Bash $'\'e\\\nnv\''        0

# Group K — round 8 review (2026-07-30): a scope/design gap, not an
# implementation slip like Bypass A/B/C. A bare top-level ANSI-C-quoted
# command word ($'...', no wrapper at all) decodes to `env` in real bash
# and dumps the environment directly -- confirmed live: was exit 0
# (allowed) when it should be exit 2 (blocked).
#
# Root cause: the D2 plan decision bundled $(...), backtick, $'...', and
# $VAR together as all "unresolvable without execution, accept as gap."
# That is correct for $(...)/backtick/$VAR (those genuinely need
# execution) but wrong for $'...' -- ANSI-C quote decoding is a pure
# deterministic string transform, the same category of operation this
# tokenizer already does for '...'/"..." quote removal, so it does not
# need execution and should never have been in the unresolvable bucket.
# $'...' now carries a distinct taint flag (A, vs the generic D flag for
# $(...)/backtick/$VAR) that resolve_segment blocks unconditionally, at
# any depth -- not just inside a -c/eval payload.
run_case "p9 K: bare top-level \$'\\x65nv' (hex, no wrapper) blocked"    Bash $'$'"'"'\x65nv'"'"''    2
run_case "p9 K: bare top-level \$'\\145nv' (octal, no wrapper) blocked" Bash $'$'"'"'\145nv'"'"''    2
run_case "p9 K: bash -c \$'\\x65nv' (depth>0, re-confirmed) blocked"    Bash $'bash -c $'"'"'\x65nv'"'"''    2
run_case "p9 K: bash -c \"\$'\\x65nv\"' (dollar-quote inside dq, depth>0, re-confirmed) blocked" Bash 'bash -c "$'"'"'\x65nv'"'"'"'    2

# Group L — round 10 review (2026-07-30): same well-scoped class as Bypass D
# (deterministic, no-execution-needed sub-cases wrongly left open), not
# implementation slips.
#
# Bypass E: brace expansion. `{env,}` expands to just `env` in real bash
# (the empty alternative vanishes on unquoted word splitting) -- purely
# lexical, no execution needed, same category that closed Bypass D. Was a
# pure blind spot (never in the accepted-gaps list at all), not a
# miscategorization.
run_case "p9 L: bare {env,} (brace expansion) blocked"        Bash "{env,}"          2
run_case "p9 L: bare {,env,} (brace expansion) blocked"       Bash "{,env,}"         2
run_case "p9 L: bare {printenv,} (brace expansion) blocked"   Bash "{printenv,}"     2
run_case "p9 L: bash -c '{env,}' (wrapped) blocked"           Bash "bash -c '{env,}'" 2
run_case "p9 L: sudo {env,} (wrapped) blocked"                Bash "sudo {env,}"     2
# Regression coverage: brace expansion must NOT over-block ordinary usage.
run_case "p9 L: {ls,env} (ls first, not env) allowed"         Bash "{ls,env}"        0
run_case "p9 L: {env} (no comma, not expansion) allowed"      Bash "{env}"           0

# Bypass F: positional-parameter default expansion at top level. With $1/$9
# always unset (Claude Code never appends positional args to the command
# string), `${1:-env}` deterministically resolves to `env` -- no execution
# needed. Already correctly blocked at depth>0 via the existing blanket
# unquoted-$-in-command-word rule; the bypass was top-level (depth 0) only,
# where D2's dynamic-taint-allowed rule fired instead.
run_case "p9 L: \${1:-env} (positional default) blocked"      Bash '${1:-env}'       2
run_case "p9 L: \${9:-printenv} (positional default) blocked" Bash '${9:-printenv}'  2
# Regression coverage: named-variable defaults stay a gap (undecidable --
# the variable could be set externally). Must NOT be over-blocked.
run_case "p9 L: \${SOME_VAR:-env} (named var default) allowed" Bash '${SOME_VAR:-env}' 0

# Copy-sync assertion: the go:embed source of truth (internal/guard/scripts)
# must stay byte-identical to this contrib copy modulo the "S0-6 " comment
# prefix, so the two can never silently drift apart again. PASS-neutral if
# the internal copy is absent (the contrib directory may be vendored
# standalone).
INTERNAL_HOOK="$SCRIPT_DIR/../../../internal/guard/scripts/block-keylatch-exfiltration.sh"
if [ -f "$INTERNAL_HOOK" ]; then
	if diff -q <(sed 's/# S0-6 pattern /# pattern /' "$INTERNAL_HOOK") "$HOOK" >/dev/null 2>&1; then
		echo "PASS: internal/contrib copy-sync (byte-identical modulo S0-6 prefix)"
		PASS=$((PASS + 1))
	else
		echo "FAIL: internal/contrib copy-sync (files have drifted apart)"
		FAIL=$((FAIL + 1))
	fi
else
	echo "SKIP: internal/contrib copy-sync (internal copy not present -- standalone contrib checkout)"
fi

echo ""
echo "Results: $PASS passed, $FAIL failed"

if [ "$FAIL" -gt 0 ]; then
	exit 1
fi
exit 0
