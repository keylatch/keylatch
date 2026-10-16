package doctor

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"slices"
	"strings"

	"github.com/keylatch/keylatch/internal/brokerapi"
	"github.com/keylatch/keylatch/internal/control"
	kexec "github.com/keylatch/keylatch/internal/exec"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/paths"
	klversion "github.com/keylatch/keylatch/internal/version"
)

// BrokerState is what doctor learns about the system broker for this user.
type BrokerState struct {
	// Installed reports that the broker's socket exists.
	Installed bool
	// Reachable reports that the daemon answered a status request.
	Reachable bool
	Error     string
	Version   string
	Policy    string
	Presence  string
	// TPM reports whether the host can bind the device root to a TPM2.
	TPM bool
	// Leftovers names in-user key files that still exist.
	Leftovers []string
	// Adopted lists the upstream keys that sat in the user's account.
	Adopted []string
}

// brokerAvailable lists the platforms on which the system broker can be
// installed.
func brokerAvailable() bool {
	return runtime.GOOS == "linux" || runtime.GOOS == "darwin" || runtime.GOOS == "windows"
}

// brokerStartHint says how to start the installed broker on this platform.
func brokerStartHint() string {
	switch runtime.GOOS {
	case "darwin":
		return "Run: sudo launchctl kickstart -k system/dev.keylatch.broker"
	case "windows":
		return "Run, as an administrator: Start-Service keylatch"
	}
	return "Run: sudo systemctl start keylatchd.socket, then: journalctl -u keylatchd"
}

// probeBroker inspects the broker without trusting it: it asks for status over
// the socket and reads local files, and changes nothing.
func probeBroker(ctx context.Context, env llmcontext.Lookup, runner kexec.CommandRunner) BrokerState {
	st := BrokerState{Leftovers: inUserKeyFiles(env)}
	if a, ok, err := brokerapi.ReadAdopted(paths.BrokerAdopted(env)); err == nil && ok {
		st.Adopted = a.UpstreamKey
	}
	if !control.BrokerInstalled(env) {
		return st
	}
	st.Installed = true
	client, err := control.NewRawClient(env)
	if err != nil {
		st.Error = err.Error()
		return st
	}
	resp, err := client.Call(brokerapi.Request{Op: "broker.status"})
	if err != nil || !resp.OK || resp.Status == nil {
		st.Error = "the daemon did not answer a status request"
		if err != nil {
			st.Error = err.Error()
		}
		return st
	}
	st.Reachable, st.Version, st.Policy, st.Presence = true, resp.Status.Version, resp.Status.Policy, resp.Status.Presence
	if runner != nil && runtime.GOOS == "linux" {
		_, _, code, err := runner.Run(ctx, "/usr/bin/systemd-creds", []string{"has-tpm2"}, nil)
		st.TPM = err == nil && code == 0
	}
	return st
}

// inUserKeyFiles names the in-user key files that exist.
func inUserKeyFiles(env llmcontext.Lookup) []string {
	var out []string
	for name, p := range map[string]string{
		"identity":     paths.KeyringIdentityPath(env),
		"keyring.json": paths.KeyringPath(env),
		"signing.key":  paths.GatewaySigningKey(env),
		"audit-salt":   paths.AuditSalt(env),
	} {
		if _, err := os.Stat(p); err == nil {
			out = append(out, name)
		}
	}
	slices.Sort(out)
	return out
}

// brokerChecks are the doctor rows for the system broker. probe is replaced in
// tests.
func brokerChecks(env llmcontext.Lookup, runner kexec.CommandRunner, probe func(context.Context, llmcontext.Lookup, kexec.CommandRunner) BrokerState) []namedCheck {
	var (
		cached BrokerState
		done   bool
	)
	state := func(ctx context.Context) BrokerState {
		if !done {
			cached, done = probe(ctx, env, runner), true
		}
		return cached
	}
	row := func(name string, fn func(BrokerState) Status) namedCheck {
		return plain("daemon", func(ctx context.Context) Status {
			st := fn(state(ctx))
			st.Name, st.Section = name, "daemon"
			st.Tags = append(st.Tags, "broker")
			return st
		})
	}
	return []namedCheck{
		plain("environment", func(ctx context.Context) Status { return modeRow(state(ctx)) }),
		row("broker.version", versionRow),
		row("broker.tpm", tpmRow),
		row("broker.leftovers", leftoversRow),
		row("broker.adopted", adoptedRow),
	}
}

// modeRow reports which mode is active. The daemon mode passes; the in-user
// mode warns wherever the broker is available, because there the keys sit in
// the user's own account and protection is defense in depth, not a boundary.
func modeRow(b BrokerState) Status {
	st := Status{Name: "mode.deployment", Section: "environment", OK: true, Tags: []string{"mode"}}
	switch {
	case b.Installed && b.Reachable:
		st.Detail = fmt.Sprintf("daemon mode: keys, store, policy and audit log are held by the keylatch system user (policy %s, presence %s)", b.Policy, b.Presence)
	case b.Installed:
		st.OK = false
		st.Detail = "daemon mode: the broker socket exists but the daemon does not answer (" + b.Error + ")"
		st.Fix = brokerStartHint()
	default:
		st.Detail = "in-user mode: keys are held by your own account, so protection depends on the agent guard and policy, not on a separate OS user"
		if brokerAvailable() {
			st.Warn = true
			st.Fix = "Run: sudo keylatch broker install, then: keylatch broker adopt"
			if runtime.GOOS == "windows" {
				st.Fix = "Run, as an administrator: keylatch broker install, then: keylatch broker adopt"
			}
		}
	}
	return st
}

func versionRow(b BrokerState) Status {
	st := Status{OK: true, Detail: "the system broker is not installed"}
	if !b.Installed || !b.Reachable {
		st.Skipped = !b.Installed
		return st
	}
	st.Detail = "daemon " + b.Version + ", client " + klversion.Version
	if b.Version != klversion.Version {
		st.Warn = true
		st.Detail += ": versions differ"
		st.Fix = "Update the keylatch package and restart the daemon: sudo systemctl restart keylatchd"
	}
	return st
}

func tpmRow(b BrokerState) Status {
	st := Status{OK: true, Detail: "the system broker is not installed"}
	if !b.Installed || !b.Reachable {
		st.Skipped = !b.Installed
		return st
	}
	if b.TPM {
		st.Detail = "a TPM2 is available to bind the device root"
		return st
	}
	st.Warn = true
	st.Detail = "no TPM binding: the device root is protected by the host key only"
	st.Fix = "Machines without a TPM2 get host-key protection; with a TPM2, reinstall the root credential: sudo systemd-creds encrypt --with-key=tpm2+host"
	return st
}

func leftoversRow(b BrokerState) Status {
	st := Status{OK: true, Detail: "no in-user key material is left"}
	if !b.Installed {
		st.Detail = "the system broker is not installed"
		st.Skipped = true
		return st
	}
	if len(b.Leftovers) > 0 {
		st.Warn = true
		st.Detail = "in-user key material remains while the broker is installed: " + strings.Join(b.Leftovers, ", ")
		st.Fix = "Run: keylatch broker adopt (it moves the secrets and shreds these files)"
	}
	return st
}

func adoptedRow(b BrokerState) Status {
	st := Status{OK: true, Detail: "no secrets were adopted from an in-user install"}
	if len(b.Adopted) > 0 {
		st.Warn = true
		st.Detail = "rotate recommended: these upstream keys were stored in your account and a process of that account could have read them: " + strings.Join(b.Adopted, ", ")
		st.Fix = "Rotate each key at its provider, then store the new value with: keylatch set <path>"
	}
	return st
}
