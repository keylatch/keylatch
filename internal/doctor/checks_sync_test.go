package doctor

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/brokerapi"
	"github.com/keylatch/keylatch/internal/llmcontext"
	keysync "github.com/keylatch/keylatch/internal/sync"
)

func runRows(t *testing.T, checks []namedCheck) map[string]Status {
	t.Helper()
	out := map[string]Status{}
	for _, c := range checks {
		st := c.fn(context.Background())
		out[st.Name] = st
	}
	return out
}

func rowsFor(t *testing.T, s SyncState) map[string]Status {
	t.Helper()
	return runRows(t, syncChecks(llmcontext.DefaultLookup, func(context.Context, llmcontext.Lookup) SyncState { return s }))
}

func TestDoctorSyncDrift(t *testing.T) {
	// A fixture repository with an extra Vercel name is reported as a failure.
	rows := rowsFor(t, SyncState{
		Manifest: "/repo/keylatch.sync.yaml",
		Drift:    []keysync.Change{{Target: "web", Environment: "production", Name: "STRAY", Kind: keysync.KindExtra, Reason: "not in the manifest"}},
	})
	d := rows["sync.drift"]
	if d.OK || d.Warn || !strings.Contains(d.Detail, "1 extra") || !strings.Contains(d.Detail, "STRAY") || !strings.Contains(d.Fix, "keylatch sync apply") {
		t.Fatalf("drift row = %+v", d)
	}
	if strings.Contains(d.Detail, "value") {
		t.Fatalf("detail must name, not show: %s", d.Detail)
	}

	rows = rowsFor(t, SyncState{Manifest: "/repo/keylatch.sync.yaml"})
	if d := rows["sync.drift"]; !d.OK || d.Warn || d.Skipped {
		t.Fatalf("clean row = %+v", d)
	}
	rows = rowsFor(t, SyncState{Manifest: "/repo/keylatch.sync.yaml", Unchecked: "drift needs the system broker"})
	if d := rows["sync.drift"]; !d.OK || !d.Warn || !strings.Contains(d.Detail, "not checked") {
		t.Fatalf("unchecked row = %+v", d)
	}
	rows = rowsFor(t, SyncState{})
	for name, st := range rows {
		if !st.Skipped || !st.OK || !strings.Contains(st.Detail, "no keylatch.sync.yaml") {
			t.Errorf("%s without a manifest = %+v", name, st)
		}
	}

	many := SyncState{Manifest: "/r/keylatch.sync.yaml"}
	for i := 0; i < 9; i++ {
		many.Drift = append(many.Drift, keysync.Change{Target: "t", Environment: "e", Name: "N" + string(rune('A'+i)), Kind: keysync.KindAdd})
	}
	if d := rowsFor(t, many)["sync.drift"]; !strings.Contains(d.Detail, "and 3 more") {
		t.Fatalf("long list: %s", d.Detail)
	}
}

func TestDoctorSyncEnvFileUnguarded(t *testing.T) {
	rows := rowsFor(t, SyncState{Manifest: "/r/keylatch.sync.yaml", Unguarded: []string{"config/secrets.local"}})
	e := rows["sync.envfiles"]
	if !e.OK || !e.Warn || !strings.Contains(e.Detail, "config/secrets.local") {
		t.Fatalf("env-file row = %+v", e)
	}
	if rows := rowsFor(t, SyncState{Manifest: "/r/keylatch.sync.yaml"}); rows["sync.envfiles"].Warn {
		t.Fatal("guarded env files warned")
	}
	c := rowsFor(t, SyncState{Manifest: "/r/keylatch.sync.yaml", LongLived: []string{"ci"}})["sync.credentials"]
	if !c.Warn || !strings.Contains(c.Detail, "ci") || !strings.Contains(c.Fix, "github-app") {
		t.Fatalf("credentials row = %+v", c)
	}
	if rowsFor(t, SyncState{Manifest: "/r/keylatch.sync.yaml"})["sync.credentials"].Warn {
		t.Fatal("no long-lived token, no warning")
	}
}

func TestProbeSyncFindsTheRepositoryManifest(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	if s := probeSync(context.Background(), llmcontext.DefaultLookup); s.Manifest != "" {
		t.Fatalf("a directory without a manifest: %+v", s)
	}
	manifest := "version: 1\ntargets:\n  local: {type: env-file, path: config/secrets.local}\nvars:\n  - {name: A, from: {connection: c}, to: {local: [file]}}\n"
	if err := os.WriteFile(filepath.Join(dir, keysync.DefaultFile), []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}
	// Not a git repository, so the env-file rules cannot be confirmed.
	s := probeSync(context.Background(), llmcontext.DefaultLookup)
	if s.Manifest == "" || s.Unchecked == "" {
		t.Fatalf("an unvalidated manifest must say why it was not checked: %+v", s)
	}
}

func TestBrokerCallWithoutBroker(t *testing.T) {
	env := func(k string) string {
		if k == "KEYLATCH_BROKER_SOCKET" {
			return filepath.Join(t.TempDir(), "none.sock")
		}
		return ""
	}
	if _, err := brokerCall(context.Background(), env, brokerapi.Request{Op: brokerapi.OpServiceList, Service: &brokerapi.ServiceRequest{}}); err == nil {
		t.Fatal("no broker, no answer")
	}
	if s := probeServices(context.Background(), env); s.Unreachable == "" {
		t.Fatal("services without a broker must say so")
	}
}

func TestDoctorChangedUnitFails(t *testing.T) {
	rows := func(s ServiceState) Status {
		return runRows(t, serviceChecks(llmcontext.DefaultLookup, func(context.Context, llmcontext.Lookup) ServiceState { return s }))["services.units"]
	}
	st := rows(ServiceState{Services: []brokerapi.ServiceInfo{
		{Connection: "app-db", Unit: "app.service", Scope: "system"},
		{Connection: "mail", Unit: "mail.service", Scope: "user", Changed: true, Detail: "the unit file changed"},
	}})
	if st.OK || !strings.Contains(st.Detail, "mail.service") || strings.Contains(st.Detail, "app.service") {
		t.Fatalf("changed unit row = %+v", st)
	}
	if !strings.Contains(st.Fix, "keylatch service enroll mail --unit mail.service --scope user") {
		t.Fatalf("the fix must be the re-enroll command: %s", st.Fix)
	}
	if st := rows(ServiceState{Services: []brokerapi.ServiceInfo{{Connection: "app-db", Unit: "app.service", Scope: "system"}}}); !st.OK || st.Skipped {
		t.Fatalf("unchanged = %+v", st)
	}
	if st := rows(ServiceState{}); !st.OK || !st.Skipped || !strings.Contains(st.Detail, "no service units") {
		t.Fatalf("none enrolled = %+v", st)
	}
	if st := rows(ServiceState{Unreachable: "the system broker is not installed"}); !st.OK || !st.Skipped {
		t.Fatalf("unreachable = %+v", st)
	}
}
