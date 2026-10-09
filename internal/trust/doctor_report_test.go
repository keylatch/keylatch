package trust_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/trust"
)

type trCapRoot struct {
	mockRoot
	caps   trust.Capability
	closed *bool
}

func (r *trCapRoot) Has(c trust.Capability) bool { return r.caps&c != 0 }
func (r *trCapRoot) Close() error                { *r.closed = true; return nil }

func trRegister(t *testing.T, rt trust.RootType, f trust.Factory) {
	t.Helper()
	trust.Register(rt, f)
	t.Cleanup(func() { trust.Unregister(rt) })
}

func TestDoctorMapsErrorsToValueFreeDescriptions(t *testing.T) {
	secretPath := "/home/u/.keylatch/pin-1234"
	cases := map[trust.RootType]struct {
		err  error
		want string
	}{
		"tr_doc_unavail": {fmt.Errorf("%w: %s", trust.ErrRootUnavailable, secretPath), "unavailable"},
		"tr_doc_unsupp":  {fmt.Errorf("x %s: %w", secretPath, trust.ErrCapabilityUnsupported), "capability unsupported"},
		"tr_doc_revoked": {trust.ErrRootRevoked, "revoked"},
		"tr_doc_expired": {trust.ErrRootExpired, "expired"},
		"tr_doc_other":   {errors.New("open " + secretPath + ": permission denied"), "probe failed"},
	}
	for rt, c := range cases {
		err := c.err
		trRegister(t, rt, func(trust.RootSpec) (trust.RootOfTrust, error) { return nil, err })
	}
	closed := false
	trRegister(t, "tr_doc_ok", func(spec trust.RootSpec) (trust.RootOfTrust, error) {
		if spec.Status != trust.RootActive {
			return nil, errors.New("doctor must probe with an active spec")
		}
		return &trCapRoot{caps: trust.CapWrap | trust.CapAttestation | trust.CapMTLSClientAuth, closed: &closed}, nil
	})
	trRegister(t, "tr_doc_nocaps", func(trust.RootSpec) (trust.RootOfTrust, error) {
		c := false
		return &trCapRoot{closed: &c}, nil
	})

	rep := trust.Doctor(context.Background())
	rows := map[trust.RootType]trust.ReportRow{}
	for _, r := range rep.Rows {
		rows[r.Type] = r
	}
	for rt, c := range cases {
		r := rows[rt]
		if r.Available || r.Error != c.want {
			t.Errorf("%s: row = %+v, want error %q", rt, r, c.want)
		}
	}
	if r := rows["tr_doc_ok"]; !r.Available || strings.Join(r.Capabilities, ",") != "wrap,attestation,mtls_client_auth" {
		t.Errorf("ok row = %+v", r)
	}
	if !closed {
		t.Error("Doctor did not close the probed root")
	}

	js := string(rep.JSON())
	text := rep.String()
	for _, out := range []string{js, text} {
		if strings.Contains(out, secretPath) || strings.Contains(out, "permission denied") {
			t.Fatalf("report leaked error detail: %s", out)
		}
	}
	var back trust.Report
	if err := json.Unmarshal([]byte(js), &back); err != nil || len(back.Rows) != len(rep.Rows) {
		t.Fatalf("JSON round-trip: %v", err)
	}
	for _, line := range []string{
		"tr_doc_ok            yes       wrap,attestation,mtls_client_auth",
		"tr_doc_nocaps        yes       (none)",
		"tr_doc_revoked       no        revoked",
	} {
		if !strings.Contains(text, line) {
			t.Errorf("String() missing %q:\n%s", line, text)
		}
	}
}

func TestReportStringDefaultsMissingError(t *testing.T) {
	s := trust.Report{Rows: []trust.ReportRow{{Type: "x"}}}.String()
	if !strings.Contains(s, "x                    no        unavailable") {
		t.Fatalf("String() = %q", s)
	}
}

func TestSecureEnclaveGatedOffDarwin(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("the check only applies off darwin")
	}
	called := false
	trRegister(t, trust.RootSecureEnclave, func(trust.RootSpec) (trust.RootOfTrust, error) {
		called = true
		return &mockRoot{}, nil
	})
	_, err := trust.New(trust.RootSpec{Type: trust.RootSecureEnclave})
	if !errors.Is(err, trust.ErrRootUnavailable) || !strings.Contains(err.Error(), "requires darwin") || called {
		t.Fatalf("err = %v called = %v", err, called)
	}
	for _, rt := range trust.Available() {
		if rt == trust.RootSecureEnclave {
			t.Fatal("Available() lists secure_enclave off darwin")
		}
	}
}

func TestVerifyPresenceProofAge(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name   string
		at     time.Time
		maxAge int
		want   error
	}{
		{"zero time", time.Time{}, 60, trust.ErrPresenceProofInvalid},
		{"no limit", now.Add(-24 * time.Hour), 0, nil},
		{"fresh", now.Add(-10 * time.Second), 60, nil},
		{"stale", now.Add(-2 * time.Minute), 60, trust.ErrPresenceProofStale},
		{"future within skew", now.Add(30 * time.Second), 60, nil},
		{"future beyond window", now.Add(10 * time.Minute), 60, trust.ErrPresenceProofStale},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := trust.VerifyPresenceProofAge(trust.PresenceProof{ConfirmedAt: tc.at}, tc.maxAge)
			if !errors.Is(err, tc.want) || (tc.want == nil && err != nil) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestChallengeReexport(t *testing.T) {
	ch := trust.NewChallenge("a", "inject", time.Minute)
	if ch.Actor != "a" || ch.Bind != trust.BindNone || len(ch.Nonce) != 32 {
		t.Fatalf("challenge = %+v", ch)
	}
}
