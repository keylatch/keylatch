package cli

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/backend/childstore"
	"github.com/keylatch/keylatch/internal/brokerapi"
	"github.com/keylatch/keylatch/internal/config"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/testutil"
)

var brokerStoreCanary = "canary" + "-cli-store-" + "13ac"

func brokerStoreFixture(t *testing.T) (*dispatchedStore, *syncBroker) {
	t.Helper()
	testutil.SetupHermeticConfig(t)
	testutil.ClearLLMSessionEnv(t)
	b := &syncBroker{answer: func(brokerapi.Request) brokerapi.Response { return brokerapi.Response{OK: true} }}
	prevInst, prevDial := brokerInstalled, dialBroker
	brokerInstalled = func(llmcontext.Lookup) bool { return true }
	dialBroker = func(llmcontext.Lookup) (brokerCaller, error) { return b, nil }
	t.Cleanup(func() { brokerInstalled, dialBroker = prevInst, prevDial })
	return newDispatchedStore(config.Default(), llmcontext.DefaultLookup), b
}

func TestStoreWritesGoThroughTheBroker(t *testing.T) {
	st, b := brokerStoreFixture(t)
	ctx := context.Background()
	if err := st.Set(ctx, "default/ai/demo/api_key", []byte(brokerStoreCanary), backend.Meta{}); err != nil {
		t.Fatal(err)
	}
	if err := st.Delete(ctx, "default/ai/demo/api_key"); err != nil {
		t.Fatal(err)
	}
	var ops []brokerapi.Op
	for _, r := range b.requests {
		if r.Op != brokerapi.OpPresenceBegin {
			ops = append(ops, r.Op)
		}
	}
	if len(ops) != 2 || ops[0] != brokerapi.OpSecretSet || ops[1] != brokerapi.OpSecretDelete {
		t.Fatalf("ops = %v", ops)
	}
}

func TestStoreReadsAreRefusedAndListsAreFiltered(t *testing.T) {
	st, b := brokerStoreFixture(t)
	ctx := context.Background()
	if _, _, err := st.Get(ctx, "default/ai/demo/api_key"); !errors.Is(err, backend.ErrLocked) || !strings.Contains(err.Error(), "mint") {
		t.Fatalf("Get = %v", err)
	}
	b.answer = func(req brokerapi.Request) brokerapi.Response {
		return brokerapi.Response{OK: true, Entries: []brokerapi.Entry{{Path: "default/a", Version: 1}, {Path: "other/b", Version: 2}}}
	}
	es, err := st.List(ctx, "default/")
	if err != nil || len(es) != 1 || es[0].Path != "default/a" || es[0].Backend != "broker" {
		t.Fatalf("List = %+v %v", es, err)
	}
	b.answer = func(brokerapi.Request) brokerapi.Response {
		return brokerapi.Response{Code: brokerapi.CodeUnavailable, Error: "down"}
	}
	if _, err := st.List(ctx, ""); err == nil {
		t.Fatal("List hid a broker failure")
	}
}

func TestStoreBrokerFailuresSurface(t *testing.T) {
	st, b := brokerStoreFixture(t)
	b.refuse = true
	if err := st.Set(context.Background(), "default/a/b/c", []byte("v"), backend.Meta{}); err == nil {
		t.Fatal("Set without presence succeeded")
	}
	brokerInstalled = func(llmcontext.Lookup) bool { return true }
	dialBroker = func(llmcontext.Lookup) (brokerCaller, error) { return nil, errors.New("no socket") }
	for name, err := range map[string]error{
		"set":    st.Set(context.Background(), "default/a/b/c", []byte("v"), backend.Meta{}),
		"delete": st.Delete(context.Background(), "default/a/b/c"),
	} {
		if err == nil {
			t.Fatalf("%s hid a dial failure", name)
		}
	}
	if _, err := st.List(context.Background(), ""); err == nil {
		t.Fatal("list hid a dial failure")
	}
}

func TestBrokerChildIsNotRoutedBackToTheBroker(t *testing.T) {
	_, _ = brokerStoreFixture(t)
	if !brokerStoreActive(llmcontext.DefaultLookup) {
		t.Fatal("the broker is not used when installed")
	}
	child := func(k string) string {
		if k == childstore.EnvFD {
			return "3"
		}
		return ""
	}
	if brokerStoreActive(child) {
		t.Fatal("a daemon-run verb was routed back to the broker")
	}
	if !brokerStoreActive(nil) {
		t.Fatal("a nil lookup falls back to the process environment")
	}
}
