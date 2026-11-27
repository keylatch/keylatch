package cli

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/keylatch/keylatch/internal/exitcode"
	"github.com/keylatch/keylatch/internal/gateway"
	"github.com/keylatch/keylatch/internal/machinecert"
	"github.com/keylatch/keylatch/internal/runner"
)

// remoteHTTP builds the client a guest uses; tests replace it to reach a
// listener bound on a loopback address.
var remoteHTTP = func(cfg *tls.Config) *http.Client {
	return &http.Client{Timeout: 90 * time.Second, Transport: &http.Transport{TLSClientConfig: cfg}}
}

// machineTLS returns the guest's mutual TLS 1.3 configuration from the file
// `machine issue` wrote. The server must chain to the CA in that file.
func machineTLS(keyFile, host string) (*tls.Config, error) {
	data, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}
	defer clear(data)
	key, _, clientDER, ca, err := machinecert.ParseBundle(data)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		RootCAs:      pool,
		ServerName:   host,
		Certificates: []tls.Certificate{{Certificate: [][]byte{clientDER}, PrivateKey: key}},
	}, nil
}

type remoteReply struct {
	gateway.MachineCallResult
	Error *struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// remoteCall asks the broker at addr to run one provider action as the machine
// whose credential is in keyFile.
func remoteCall(ctx context.Context, addr, keyFile string, call gateway.MachineCall) (gateway.MachineCallResult, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return gateway.MachineCallResult{}, NewUsageError("call --remote: %q is not host:port", addr)
	}
	cfg, err := machineTLS(keyFile, host)
	if err != nil {
		return gateway.MachineCallResult{}, withExitCode(exitcode.UserError, fmt.Errorf("call --remote: machine key: %w", err))
	}
	body, err := json.Marshal(call)
	if err != nil {
		return gateway.MachineCallResult{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+addr+"/v1/call", bytes.NewReader(body))
	if err != nil {
		return gateway.MachineCallResult{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := remoteHTTP(cfg).Do(req)
	if err != nil {
		return gateway.MachineCallResult{}, withExitCode(exitcode.OperationFailed, fmt.Errorf("call --remote: %w", err))
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return gateway.MachineCallResult{}, withExitCode(exitcode.OperationFailed, err)
	}
	var reply remoteReply
	if err := json.Unmarshal(raw, &reply); err != nil {
		return gateway.MachineCallResult{}, withExitCode(exitcode.OperationFailed, fmt.Errorf("call --remote: unreadable reply (status %d)", resp.StatusCode))
	}
	if resp.StatusCode != http.StatusOK || reply.Error != nil {
		msg := http.StatusText(resp.StatusCode)
		if reply.Error != nil {
			msg = reply.Error.Code + ": " + reply.Error.Message
		}
		code := exitcode.OperationFailed
		switch resp.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden:
			code = exitcode.SecurityBlock
		case http.StatusNotFound:
			code = exitcode.Missing
		case http.StatusBadRequest:
			code = exitcode.UserError
		}
		return gateway.MachineCallResult{}, withExitCode(code, errors.New("call --remote: "+msg))
	}
	return reply.MachineCallResult, nil
}

// runRemoteCall is `keylatch call --remote`: the broker holds the credential
// and the guest only ever sees the redacted response.
func runRemoteCall(c *cobra.Command, addr, keyFile, namespace string, args, rawParams []string, useJSON bool) error {
	if keyFile == "" {
		return NewUsageError("call --remote needs --machine-key <file>")
	}
	params, err := parseParamFlags(rawParams)
	if err != nil {
		return NewUsageError("call --remote: invalid --param: %v", err)
	}
	call := gateway.MachineCall{Connection: args[0], Action: args[1], Params: params}
	if c.Flags().Changed("namespace") {
		call.Namespace = namespace
	}
	res, err := remoteCall(c.Context(), addr, keyFile, call)
	if err != nil {
		return err
	}
	body := runner.Redact(res.Body)
	if useJSON {
		printCallResultJSON(c, res.Status, res.DurationMs, body, nil, false)
	} else {
		fmt.Fprintf(c.OutOrStdout(), "%s\n", body)
	}
	if res.Status < 200 || res.Status >= 300 {
		return withExitCode(exitcode.UserError, fmt.Errorf("call --remote: provider answered %d", res.Status))
	}
	return nil
}
