package broker_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/broker"
)

// flakyEmitter reports the audit log unavailable while down is set; failEmit
// makes only Emit fail, after Ready has passed.
type flakyEmitter struct {
	down     bool
	failEmit bool
	events   int
}

func (e *flakyEmitter) Ready() error {
	if e.down {
		return fmt.Errorf("%w: test", audit.ErrUnavailable)
	}
	return nil
}

func (e *flakyEmitter) Emit(context.Context, audit.Event) error {
	if e.down || e.failEmit {
		return fmt.Errorf("%w: test", audit.ErrUnavailable)
	}
	e.events++
	return nil
}

func newAuditedBroker(em audit.Emitter) *broker.BrokerImpl {
	return broker.NewBroker(context.Background(), map[string]broker.ExchangeStrategy{
		"canary-provider": &mockCanaryStrategy{provider: "canary-provider"},
	}, em, []byte("test-hmac-key-32-bytes-pad!!!!!!"))
}

func requireWithheld(t *testing.T, res broker.ExchangeResult, err error) {
	t.Helper()
	if !errors.Is(err, broker.ErrAuditFailed) || !errors.Is(err, audit.ErrUnavailable) {
		t.Fatalf("Exchange error = %v, want ErrAuditFailed wrapping audit.ErrUnavailable", err)
	}
	if bytes.Contains(res.TokenBytes(), []byte(canaryToken)) {
		t.Fatal("credential returned although the exchange was not audited")
	}
}

func TestExchangeRefusedWhileAuditUnavailable(t *testing.T) {
	em := &flakyEmitter{down: true}
	b := newAuditedBroker(em)
	ctx := context.Background()

	res, err := b.Exchange(ctx, "actor", "sess", "canary-provider", "cap", "ns")
	requireWithheld(t, res, err)

	em.down = false
	res, err = b.Exchange(ctx, "actor", "sess", "canary-provider", "cap", "ns")
	if err != nil {
		t.Fatalf("Exchange once audit is back: %v", err)
	}
	res.Zero()

	em.down = true
	res, err = b.Exchange(ctx, "actor", "sess", "canary-provider", "cap", "ns")
	requireWithheld(t, res, err)
}

func TestExchangeWithheldWhenAuditWriteFails(t *testing.T) {
	em := &flakyEmitter{failEmit: true}
	b := newAuditedBroker(em)
	ctx := context.Background()

	res, err := b.Exchange(ctx, "actor", "sess", "canary-provider", "cap", "ns")
	requireWithheld(t, res, err)
	res, err = b.Exchange(ctx, "actor", "sess", "canary-provider", "cap", "ns")
	requireWithheld(t, res, err)
}

func TestExchangeRefusedWithoutAuditEmitter(t *testing.T) {
	b := broker.NewBroker(context.Background(), map[string]broker.ExchangeStrategy{
		"canary-provider": &mockCanaryStrategy{provider: "canary-provider"},
	}, nil, []byte("test-hmac-key-32-bytes-pad!!!!!!"))
	res, err := b.Exchange(context.Background(), "actor", "sess", "canary-provider", "cap", "ns")
	requireWithheld(t, res, err)
	if !errors.Is(err, audit.ErrNotConfigured) {
		t.Fatalf("Exchange error = %v, want audit.ErrNotConfigured", err)
	}
}
