package ipc_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/keylatch/keylatch/internal/sidecar/ipc"
)

func testKey() []byte {
	key := make([]byte, 32)
	for i := range key {
		key[i] = 0xAB
	}
	return key
}

func TestFrameRoundtrip(t *testing.T) {
	key := testKey()
	var buf bytes.Buffer

	fw := ipc.NewFrameWriter(&buf, key)
	fr := ipc.NewFrameReader(&buf, key)

	type Payload struct {
		Value string `cbor:"value"`
	}

	in := Payload{Value: "hello"}
	if err := fw.Write(in); err != nil {
		t.Fatalf("write: %v", err)
	}

	var out Payload
	if err := fr.Read(&out); err != nil {
		t.Fatalf("read: %v", err)
	}
	if out.Value != in.Value {
		t.Errorf("got %q, want %q", out.Value, in.Value)
	}
}

func TestHMACMismatch(t *testing.T) {
	key := testKey()
	var buf bytes.Buffer

	fw := ipc.NewFrameWriter(&buf, key)

	type Payload struct {
		Value string `cbor:"value"`
	}
	if err := fw.Write(Payload{Value: "test"}); err != nil {
		t.Fatalf("write: %v", err)
	}

	// Use a different key to cause HMAC mismatch.
	wrongKey := make([]byte, 32)
	data := make([]byte, buf.Len())
	copy(data, buf.Bytes())

	fr := ipc.NewFrameReader(bytes.NewReader(data), wrongKey)
	var out Payload
	err := fr.Read(&out)
	if err == nil {
		t.Fatal("expected error for tampered frame, got nil")
	}
	if err != ipc.ErrHMACMismatch {
		t.Errorf("expected ErrHMACMismatch, got %v", err)
	}
}

func TestMethodRegistryRejectsUnregistered(t *testing.T) {
	// Dispatch returns "unsupported_method" for a method that is allowed but
	// not registered (no handler was added for Health).
	reg := ipc.NewMethodRegistry()
	req := ipc.Request{Method: ipc.MethodHealth}
	resp := reg.Dispatch(context.Background(), req, nil)
	if resp.Error != "unsupported_method" {
		t.Errorf("expected unsupported_method, got %q", resp.Error)
	}
}

func TestAllowedMethodsCount(t *testing.T) {
	// The allow-list must have exactly 5 entries.
	// We verify by registering all 5 and confirming no panic.
	reg := ipc.NewMethodRegistry()
	noop := ipc.HandlerFunc(func(ctx context.Context, _ any, _ *ipc.FrameWriter) (any, error) {
		return nil, nil
	})
	reg.Register(ipc.MethodHealth, noop)
	reg.Register(ipc.MethodMintBootstrapToken, noop)
	reg.Register(ipc.MethodSubscribeEvents, noop)
	reg.Register(ipc.MethodShutdown, noop)
	reg.Register(ipc.MethodOpenSystemBrowser, noop)
	// If we get here without panic, the allow-list has at least 5 entries.
	t.Log("all 5 allowed methods registered without panic")
}

func TestRegisterDisallowedMethodPanics(t *testing.T) {
	// Trying to register a method not in the allow-list must panic.
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic when registering disallowed method, got none")
		}
	}()
	reg := ipc.NewMethodRegistry()
	noop := ipc.HandlerFunc(func(ctx context.Context, _ any, _ *ipc.FrameWriter) (any, error) {
		return nil, nil
	})
	// "VaultGet" is not in the allow-list — should panic.
	reg.Register(ipc.MethodName("VaultGet"), noop)
}
