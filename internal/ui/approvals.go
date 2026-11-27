package ui

import (
	"context"

	"github.com/keylatch/keylatch/internal/brokerapi"
	"github.com/keylatch/keylatch/internal/control"
	"github.com/keylatch/keylatch/internal/llmcontext"
)

type localApprovalBroker struct {
	env llmcontext.Lookup
}

func (b *localApprovalBroker) CallContext(ctx context.Context, req brokerapi.Request) (brokerapi.Response, error) {
	if err := ctx.Err(); err != nil {
		return brokerapi.Response{}, err
	}
	client, err := control.NewClient(b.env)
	if err != nil {
		return brokerapi.Response{}, err
	}
	return client.CallContext(ctx, req)
}
