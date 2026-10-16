package control

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keylatch/keylatch/internal/brokerapi"
	"github.com/keylatch/keylatch/internal/exitcode"
	"github.com/keylatch/keylatch/internal/runner"
)

type scriptedBroker struct {
	req  brokerapi.Request
	resp brokerapi.Response
	err  error
}

func (s *scriptedBroker) Call(req brokerapi.Request) (brokerapi.Response, error) {
	s.req = req
	return s.resp, s.err
}

func TestClientReleaserPresentsTheCapability(t *testing.T) {
	cap := bytes.Repeat([]byte{4}, 32)
	b := &scriptedBroker{resp: brokerapi.Response{OK: true, Service: &brokerapi.ServiceResult{Env: []brokerapi.ServiceEnv{{Name: "A", Value: []byte("v")}}}}}
	env, err := clientReleaser{b}.Release(context.Background(), "app-db", cap)
	require.NoError(t, err)
	assert.Equal(t, brokerapi.OpServiceRelease, b.req.Op)
	assert.Equal(t, "app-db", b.req.Service.Connection)
	assert.Equal(t, cap, b.req.Service.Capability)
	assert.Equal(t, []runner.ServiceEnv{{Name: "A", Value: []byte("v")}}, env)
}

func TestClientReleaserSeparatesRefusalFromFailure(t *testing.T) {
	refused := &scriptedBroker{resp: brokerapi.Response{Code: brokerapi.CodeRefused, ExitCode: exitcode.SecurityBlock, Error: "no"}}
	_, err := clientReleaser{refused}.Release(context.Background(), "c", nil)
	assert.ErrorIs(t, err, runner.ErrReleaseRefused)

	unavailable := &scriptedBroker{resp: brokerapi.Response{Code: brokerapi.CodeUnavailable, Error: "store locked"}}
	_, err = clientReleaser{unavailable}.Release(context.Background(), "c", nil)
	require.Error(t, err)
	assert.NotErrorIs(t, err, runner.ErrReleaseRefused)

	_, err = clientReleaser{&scriptedBroker{err: errors.New("socket closed")}}.Release(context.Background(), "c", nil)
	assert.Error(t, err)

	empty := &scriptedBroker{resp: brokerapi.Response{OK: true}}
	_, err = clientReleaser{empty}.Release(context.Background(), "c", nil)
	assert.Error(t, err, "an OK reply with nothing released is not a success")
}

func TestRunArgsAcceptTheServiceRuntime(t *testing.T) {
	ra, err := parseRunArgs([]string{"--runtime", "service", "app-db", "--", "/bin/true"})
	require.NoError(t, err)
	assert.Equal(t, runner.ServiceRuntime, ra.runtime)
	assert.Equal(t, "app-db", ra.connection)
}
