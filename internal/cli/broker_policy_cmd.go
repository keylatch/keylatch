package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/keylatch/keylatch/internal/brokerapi"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/paths"
)

// brokerPolicyImport sends a directory of connection policy documents, with the
// current policy.json, to the daemon. The daemon signs what it accepts after
// the human approves; the files in the user's own directories are not policy.
func brokerPolicyImport(c *cobra.Command, env llmcontext.Lookup, dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return NewUsageError("policy import: %v", err)
	}
	files := map[string][]byte{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return NewUsageError("policy import: %v", err)
		}
		if e.Name() == "policy.json" {
			files["policy.json"] = b
		} else {
			files["policy.d/"+e.Name()] = b
		}
	}
	if len(files) == 0 {
		return NewUsageError("policy import: no *.json files in %q", dir)
	}
	if _, ok := files["policy.json"]; !ok {
		b, err := os.ReadFile(paths.Policy(env))
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return NewUsageError("policy import: %v", err)
		}
		if err != nil {
			b = []byte(`{"default_deny":true}`)
		}
		files["policy.json"] = b
	}
	bc, err := brokerClient(env)
	if err != nil {
		return err
	}
	resp, err := brokerPrivileged(bc, "policy import", brokerapi.Request{Op: brokerapi.OpPolicyAccept, Files: files})
	if err != nil {
		return err
	}
	state := "unknown"
	if resp.Policy != nil {
		state = resp.Policy.State
	}
	fmt.Fprintf(c.OutOrStdout(), "policy import: %d file(s) accepted by the broker (policy %s)\n", len(files), state)
	return nil
}

// brokerPolicyExport writes the broker's signed policy documents to dir.
func brokerPolicyExport(c *cobra.Command, env llmcontext.Lookup, dir string, force bool) error {
	bc, err := brokerClient(env)
	if err != nil {
		return err
	}
	resp, err := bc.Call(brokerapi.Request{Op: brokerapi.OpPolicyExport})
	if err != nil {
		return withExitCodeOperation("policy export", err)
	}
	if !resp.OK {
		return brokerFailure("policy export", resp)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("policy export: %w", err)
	}
	n := 0
	if resp.Bundle == nil {
		return withExitCodeOperation("policy export", errors.New("the broker returned no policy"))
	}
	for name, body := range resp.Bundle.Files {
		dst := filepath.Join(dir, filepath.Base(name))
		if _, err := os.Stat(dst); err == nil && !force {
			return NewUsageError("policy export: %s exists; use --force to overwrite", dst)
		}
		if err := os.WriteFile(dst, body, 0o600); err != nil {
			return fmt.Errorf("policy export: %w", err)
		}
		n++
	}
	fmt.Fprintf(c.OutOrStdout(), "policy export: %d file(s) written to %s\n", n, dir)
	return nil
}

// brokerAuditHead prints the head of the daemon's audit chain.
func brokerAuditHead(c *cobra.Command, env llmcontext.Lookup) error {
	bc, err := brokerClient(env)
	if err != nil {
		return err
	}
	resp, err := bc.Call(brokerapi.Request{Op: brokerapi.OpAuditHead})
	if err != nil {
		return withExitCodeOperation("audit head", err)
	}
	if !resp.OK {
		return brokerFailure("audit head", resp)
	}
	if resp.Head == nil {
		return withExitCodeOperation("audit head", errors.New("the broker returned no head"))
	}
	if asJSON, _ := c.Flags().GetBool("json"); asJSON {
		return json.NewEncoder(c.OutOrStdout()).Encode(resp.Head)
	}
	fmt.Fprintf(c.OutOrStdout(), "seq: %d\nhash: %s\n", resp.Head.Events, resp.Head.Hash)
	return nil
}
