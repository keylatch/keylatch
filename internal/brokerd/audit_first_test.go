//go:build unix

package brokerd

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/brokerapi"
)

func TestDeleteNeedsItsAuditRecord(t *testing.T) {
	h := newHarness(t, nil)
	p, err := h.srv.partition(context.Background(), 1000)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.store.Put(context.Background(), "svc/key", []byte("v")); err != nil {
		t.Fatal(err)
	}
	del := func() brokerapi.Response {
		return h.send(t, 1000, h.proven(t, 1000, brokerapi.Request{Op: brokerapi.OpSecretDelete, Path: "svc/key"}))
	}
	h.rec.mu.Lock()
	h.rec.fail = errors.New("audit log is full")
	h.rec.mu.Unlock()
	if resp := del(); resp.OK {
		t.Fatalf("a delete that could not be audited happened: %+v", resp)
	}
	if _, _, err := p.store.Get(context.Background(), "svc/key"); err != nil {
		t.Fatalf("the secret was deleted without a record: %v", err)
	}
	h.rec.mu.Lock()
	h.rec.fail = nil
	h.rec.mu.Unlock()
	if resp := del(); !resp.OK {
		t.Fatalf("delete = %+v", resp)
	}
	if h.rec.count(audit.ActionDelete) != 1 {
		t.Fatalf("delete events = %d", h.rec.count(audit.ActionDelete))
	}
	if resp := del(); resp.OK || resp.Code != brokerapi.CodeNotFound {
		t.Fatalf("deleting a missing secret = %+v", resp)
	}
	if h.rec.count(audit.ActionDelete) != 1 {
		t.Fatal("a delete of nothing was recorded as a delete")
	}
}

func TestMachineListenNeedsItsAuditRecord(t *testing.T) {
	h := newHarness(t, nil)
	h.rec.mu.Lock()
	h.rec.fail = errors.New("audit log is full")
	h.rec.mu.Unlock()
	req := h.proven(t, 1000, brokerapi.Request{Op: brokerapi.OpMachineListen, Machine: &brokerapi.MachineRequest{Listen: "127.0.0.1:7443"}})
	if resp := h.send(t, 1000, req); resp.OK {
		t.Fatalf("an unaudited listener change was applied: %+v", resp)
	}
	if _, err := os.Stat(h.srv.listenFile()); err == nil {
		t.Fatal("the listen address was stored without a record")
	}
}
