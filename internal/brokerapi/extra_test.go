package brokerapi

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

const testManifest = "version: 1\ntargets:\n  l: {type: env-file, path: .env.local}\nvars:\n  - {name: A, from: {connection: c}, to: {l: [file]}}\n"

func syncReq(op Op, mutate func(*SyncRequest)) Request {
	s := &SyncRequest{Manifest: []byte(testManifest)}
	if mutate != nil {
		mutate(s)
	}
	return Request{Op: op, Sync: s}
}

func TestSyncRequestValidation(t *testing.T) {
	good := []Request{
		syncReq(OpSyncDiff, nil), syncReq(OpSyncDrift, nil), syncReq(OpSyncApply, func(s *SyncRequest) { s.EnvFiles = []string{"l"}; s.Prune = true }),
		syncReq(OpSyncRotate, func(s *SyncRequest) { s.Name = "A"; s.KeepOldSeconds = 60 }),
	}
	for _, r := range good {
		if err := r.Validate(); err != nil {
			t.Errorf("%s: %v", r.Op, err)
		}
	}
	bad := map[string]Request{
		"no sync":          {Op: OpSyncDiff},
		"empty manifest":   syncReq(OpSyncDiff, func(s *SyncRequest) { s.Manifest = nil }),
		"huge manifest":    syncReq(OpSyncDiff, func(s *SyncRequest) { s.Manifest = bytes.Repeat([]byte("a"), maxManifest+1) }),
		"bad link":         syncReq(OpSyncDiff, func(s *SyncRequest) { s.Links = map[string]string{"x": ""} }),
		"bad env keys":     syncReq(OpSyncDiff, func(s *SyncRequest) { s.EnvKeys = map[string][]string{"bad name": nil} }),
		"bad env target":   syncReq(OpSyncApply, func(s *SyncRequest) { s.EnvFiles = []string{"bad name"} }),
		"files on diff":    syncReq(OpSyncDiff, func(s *SyncRequest) { s.EnvFiles = []string{"l"} }),
		"keep-old":         syncReq(OpSyncRotate, func(s *SyncRequest) { s.Name = "A"; s.KeepOldSeconds = maxKeepOld + 1 }),
		"negative keepold": syncReq(OpSyncRotate, func(s *SyncRequest) { s.Name = "A"; s.KeepOldSeconds = -1 }),
		"rotate no name":   syncReq(OpSyncRotate, nil),
		"long target":      syncReq(OpSyncDiff, func(s *SyncRequest) { s.Target = strings.Repeat("t", 65) }),
		"nul root":         syncReq(OpSyncDiff, func(s *SyncRequest) { s.Root = "a\x00b" }),
		"too many links": syncReq(OpSyncDiff, func(s *SyncRequest) {
			s.Links = map[string]string{}
			for i := 0; i < 65; i++ {
				s.Links[strings.Repeat("a", i+1)] = "p"
			}
		}),
	}
	for name, r := range bad {
		if err := r.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestServiceRequestValidation(t *testing.T) {
	enroll := func(m func(*ServiceRequest)) Request {
		s := &ServiceRequest{Connection: "app-db", Units: []string{"app.service"}, Scope: "system"}
		if m != nil {
			m(s)
		}
		return Request{Op: OpServiceEnroll, Service: s}
	}
	for _, r := range []Request{
		enroll(nil), enroll(func(s *ServiceRequest) { s.Scope = "user"; s.AllowTransient = true }),
		{Op: OpServiceList, Service: &ServiceRequest{}},
		{Op: OpServiceRevoke, Service: &ServiceRequest{Connection: "app-db"}},
		{Op: OpServiceRevoke, Service: &ServiceRequest{Connection: "app-db", Unit: "app.service"}},
		{Op: OpServiceRelease, Service: &ServiceRequest{Connection: "app-db", Capability: bytes.Repeat([]byte{1}, 32)}},
	} {
		if err := r.Validate(); err != nil {
			t.Errorf("%s: %v", r.Op, err)
		}
	}
	for name, r := range map[string]Request{
		"no service":    {Op: OpServiceEnroll},
		"no connection": enroll(func(s *ServiceRequest) { s.Connection = "" }),
		"no units":      enroll(func(s *ServiceRequest) { s.Units = nil }),
		"too many":      enroll(func(s *ServiceRequest) { s.Units = make([]string, 17) }),
		"not a unit":    enroll(func(s *ServiceRequest) { s.Units = []string{"app.socket"} }),
		"scope":         enroll(func(s *ServiceRequest) { s.Scope = "global" }),
		"revoke unit":   {Op: OpServiceRevoke, Service: &ServiceRequest{Connection: "c", Unit: "x"}},
		"capability":    {Op: OpServiceRelease, Service: &ServiceRequest{Connection: "c", Capability: []byte("short")}},
	} {
		if err := r.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestMachineRequestValidation(t *testing.T) {
	issue := func(m func(*MachineRequest)) Request {
		r := &MachineRequest{Name: "ci-runner", Domain: "ci", Caps: []string{"call"}, TTLSeconds: 3600, PublicKey: bytes.Repeat([]byte{2}, 32)}
		if m != nil {
			m(r)
		}
		return Request{Op: OpMachineIssue, Machine: r}
	}
	for _, r := range []Request{issue(nil), {Op: OpMachineRevoke, Machine: &MachineRequest{Name: "ci-runner"}}, {Op: OpMachineList, Machine: &MachineRequest{}}} {
		if err := r.Validate(); err != nil {
			t.Errorf("%s: %v", r.Op, err)
		}
	}
	for name, r := range map[string]Request{
		"no machine": {Op: OpMachineIssue},
		"name":       issue(func(m *MachineRequest) { m.Name = "Bad Name" }),
		"domain":     issue(func(m *MachineRequest) { m.Domain = "" }),
		"no caps":    issue(func(m *MachineRequest) { m.Caps = nil }),
		"cap name":   issue(func(m *MachineRequest) { m.Caps = []string{"Bad Cap"} }),
		"short ttl":  issue(func(m *MachineRequest) { m.TTLSeconds = 5 }),
		"long ttl":   issue(func(m *MachineRequest) { m.TTLSeconds = maxMachineT + 1 }),
		"key":        issue(func(m *MachineRequest) { m.PublicKey = []byte("x") }),
		"revoke":     {Op: OpMachineRevoke, Machine: &MachineRequest{Name: "!"}},
	} {
		if err := r.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestExtraDigestsBindTheRequest(t *testing.T) {
	apply := syncReq(OpSyncApply, nil)
	d0 := apply.Digest()
	for name, other := range map[string]Request{
		"prune":    syncReq(OpSyncApply, func(s *SyncRequest) { s.Prune = true }),
		"manifest": syncReq(OpSyncApply, func(s *SyncRequest) { s.Manifest = []byte(testManifest + "# x\n") }),
		"files":    syncReq(OpSyncApply, func(s *SyncRequest) { s.EnvFiles = []string{"l"} }),
		"op":       syncReq(OpSyncRotate, func(s *SyncRequest) { s.Name = "A" }),
	} {
		if other.Digest() == d0 {
			t.Errorf("%s does not change the digest", name)
		}
	}
	svc := Request{Op: OpServiceEnroll, Service: &ServiceRequest{Connection: "c", Units: []string{"a.service"}, Scope: "system"}}
	svc2 := Request{Op: OpServiceEnroll, Service: &ServiceRequest{Connection: "c", Units: []string{"b.service"}, Scope: "system"}}
	if svc.Digest() == svc2.Digest() {
		t.Error("units do not change the digest")
	}
	m := Request{Op: OpMachineIssue, Machine: &MachineRequest{Name: "a", Domain: "d", Caps: []string{"call"}, TTLSeconds: 60}}
	m2 := m
	m2.Machine = &MachineRequest{Name: "a", Domain: "d", Caps: []string{"call", "mint"}, TTLSeconds: 60}
	if m.Digest() == m2.Digest() {
		t.Error("caps do not change the digest")
	}
	// A request without the new fields digests as it always did.
	plain := Request{Op: OpSecretSet, Path: "a/b", Value: []byte("v")}
	if plain.Digest() != (Request{Op: OpSecretSet, Path: "a/b", Value: []byte("v")}).Digest() {
		t.Error("digest is not deterministic")
	}
}

func TestExtraDescriptionsNameCountsAndNames(t *testing.T) {
	apply := syncReq(OpSyncApply, func(s *SyncRequest) { s.Prune = true })
	action, summary := apply.Describe()
	if action != "sync.apply" || !strings.Contains(summary, "l (env-file, path .env.local): 1 name(s) A<-c") || !strings.Contains(summary, "DELETE") {
		t.Fatalf("apply: %s / %s", action, summary)
	}
	action, summary = syncReq(OpSyncRotate, func(s *SyncRequest) { s.Name = "A" }).Describe()
	if action != "sync.rotate" || !strings.Contains(summary, "Rotate A") {
		t.Fatalf("rotate: %s / %s", action, summary)
	}
	for op, want := range map[Op]string{
		OpServiceEnroll: "a.service",
		OpServiceRevoke: "every unit",
		OpMachineIssue:  "ci-runner",
		OpMachineRevoke: "ci-runner",
	} {
		r := Request{Op: op, Service: &ServiceRequest{Connection: "c", Units: []string{"a.service"}, Scope: "user"}, Machine: &MachineRequest{Name: "ci-runner", Domain: "ci", Caps: []string{"call"}, TTLSeconds: 60}}
		if _, summary := r.Describe(); !strings.Contains(summary, want) {
			t.Errorf("%s: %q lacks %q", op, summary, want)
		}
	}
	rev := Request{Op: OpServiceRevoke, Service: &ServiceRequest{Connection: "c", Unit: "a.service"}}
	if _, summary := rev.Describe(); !strings.Contains(summary, "a.service") {
		t.Errorf("revoke one unit: %q", summary)
	}
	if syncSummary(nil, "") == "" {
		t.Error("empty summary")
	}
	var round Request
	b, _ := json.Marshal(apply)
	if _, err := Decode(b); err != nil {
		t.Fatal(err)
	}
	_ = round
}

func TestPrivilegedCoversNewOps(t *testing.T) {
	for _, op := range []Op{OpSyncApply, OpSyncRotate, OpServiceEnroll, OpServiceRevoke, OpMachineIssue, OpMachineRevoke} {
		if !Privileged(op) {
			t.Errorf("%s must need presence", op)
		}
	}
	for _, op := range []Op{OpSyncDiff, OpSyncDrift, OpServiceList, OpServiceRelease, OpMachineList} {
		if Privileged(op) {
			t.Errorf("%s must not need presence", op)
		}
	}
}
