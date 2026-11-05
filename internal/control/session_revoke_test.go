//go:build !windows

package control

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/keylatch/keylatch/internal/callerkind"
	"github.com/keylatch/keylatch/internal/gateway/token"
	"github.com/keylatch/keylatch/internal/paths"
	"github.com/keylatch/keylatch/internal/registry"
)

// A session token issued over the socket stops working once the client
// reports the child's exit.
func TestSessionTokenRevokedWhenChildExits(t *testing.T) {
	addr, _ := fakeGateway(t)
	state := t.TempDir()
	if err := os.MkdirAll(filepath.Join(state, "gateway"), 0o700); err != nil {
		t.Fatal(err)
	}
	env := lookupOf(map[string]string{"KEYLATCH_CONFIG_DIR": state, "KEYLATCH_GATEWAY_ADDR": addr})
	if err := registry.InitFromConfig(context.Background(), env); err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{7}, 32)
	s := NewServer(Config{Env: env, SigningKey: func() ([]byte, error) { return bytes.Clone(key), nil }})
	store := paths.GatewayTokens(env)

	resp := s.decideRun(context.Background(), callerkind.Result{Kind: callerkind.Human},
		&RunRequest{Connection: "openrouter", Command: []string{"true"}, Tier: TierGateway})
	if !resp.OK || resp.Session == nil || resp.Session.RunID == "" {
		t.Fatalf("session not issued: %+v", resp)
	}
	active, err := token.List(token.ListOpts{}, store)
	if err != nil || len(active) != 1 {
		t.Fatalf("active tokens = %d, err %v", len(active), err)
	}

	if r := s.runExited(context.Background(), Request{RunID: resp.Session.RunID}); !r.OK {
		t.Fatalf("exit not accepted: %+v", r)
	}
	if active, _ = token.List(token.ListOpts{}, store); len(active) != 0 {
		t.Fatalf("%d token(s) still active after the child exited", len(active))
	}
	all, _ := token.List(token.ListOpts{IncludeRevoked: true}, store)
	if len(all) != 1 || !all[0].Revoked {
		t.Fatalf("token not marked revoked: %+v", all)
	}
}
