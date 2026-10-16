package control

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/keylatch/keylatch/internal/exitcode"
	"github.com/keylatch/keylatch/internal/keyops"
)

// KeyVerb is the CLI verb for key operations.
const KeyVerb = "key"

const keyUsage = "usage: keylatch key sign|verify|encrypt|decrypt|jwt-sign <connection> [--field <name>] [--alg <alg>] [--in <file|->] [--out <file>] [--sig <file>] [--aad <text>] [--kid <id>] [--encoding raw|hex|base64]"

var keyActions = map[string]keyops.Operation{
	"sign":     keyops.OpSign,
	"verify":   keyops.OpVerify,
	"encrypt":  keyops.OpEncrypt,
	"decrypt":  keyops.OpDecrypt,
	"jwt-sign": keyops.OpJWTSign,
}

type keyArgs struct {
	req      KeyRequest
	in       string
	out      string
	sig      string
	aad      string
	encoding string
}

func parseKeyArgs(args []string) (keyArgs, error) {
	var ka keyArgs
	if len(args) == 0 {
		return ka, errors.New(keyUsage)
	}
	op, ok := keyActions[args[0]]
	if !ok {
		return ka, fmt.Errorf("unknown key operation %q\n%s", args[0], keyUsage)
	}
	ka.req.Action = string(op)
	ka.in, ka.encoding = "-", "raw"

	rest := args[1:]
	for i := 0; i < len(rest); i++ {
		a := rest[i]
		name, inline, hasInline := strings.Cut(a, "=")
		if !strings.HasPrefix(a, "--") {
			if ka.req.Connection != "" {
				return ka, errors.New(keyUsage)
			}
			ka.req.Connection = a
			continue
		}
		var dst *string
		switch name {
		case "--field":
			dst = &ka.req.Field
		case "--alg":
			dst = &ka.req.Alg
		case "--in":
			dst = &ka.in
		case "--out":
			dst = &ka.out
		case "--sig":
			dst = &ka.sig
		case "--aad":
			dst = &ka.aad
		case "--kid":
			dst = &ka.req.KeyID
		case "--encoding":
			dst = &ka.encoding
		default:
			return ka, fmt.Errorf("%s is not a key option\n%s", name, keyUsage)
		}
		if hasInline {
			*dst = inline
			continue
		}
		if i+1 >= len(rest) {
			return ka, fmt.Errorf("%s needs a value", name)
		}
		i++
		*dst = rest[i]
	}
	if ka.req.Connection == "" {
		return ka, errors.New(keyUsage)
	}
	ka.req.AAD = []byte(ka.aad)
	if ka.encoding != "raw" && ka.encoding != "hex" && ka.encoding != "base64" {
		return ka, errors.New("--encoding is raw, hex or base64")
	}
	if op == keyops.OpVerify && ka.sig == "" {
		return ka, errors.New("verify needs --sig <file>")
	}
	return ka, nil
}

func readLimited(path string, stdin io.Reader) ([]byte, error) {
	r := stdin
	if path != "-" {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer func() { _ = f.Close() }()
		r = f
	}
	b, err := io.ReadAll(io.LimitReader(r, keyops.MaxInput+1))
	if err != nil {
		return nil, err
	}
	if len(b) > keyops.MaxInput {
		return nil, fmt.Errorf("input is larger than %d bytes", keyops.MaxInput)
	}
	return b, nil
}

func decodeText(b []byte, encoding string) ([]byte, error) {
	text := strings.TrimSpace(string(b))
	switch encoding {
	case "hex":
		return hex.DecodeString(text)
	case "base64":
		return base64.StdEncoding.DecodeString(text)
	}
	return b, nil
}

func encodeText(b []byte, encoding string) []byte {
	switch encoding {
	case "hex":
		return []byte(hex.EncodeToString(b) + "\n")
	case "base64":
		return []byte(base64.StdEncoding.EncodeToString(b) + "\n")
	}
	return b
}

const keyPolicyUsage = "usage: keylatch key allow <connection> --field <name> [--secret <backend path>] [--op <ops>] [--alg <algs>] [--agent-decrypt] [--ssh-agent] [--host-key <SHA256:...>]\n       keylatch key revoke <connection> [--field <name>] [--op <ops>] [--alg <algs>] [--agent-decrypt] [--ssh-agent]\n       keylatch key list [<connection>]"

func parseKeyPolicyArgs(args []string) (KeyPolicyRequest, error) {
	kp := KeyPolicyRequest{Action: args[0]}
	split := func(v string) []string {
		var out []string
		for _, p := range strings.Split(v, ",") {
			if p = strings.TrimSpace(p); p != "" {
				out = append(out, p)
			}
		}
		return out
	}
	rest := args[1:]
	for i := 0; i < len(rest); i++ {
		a := rest[i]
		name, inline, hasInline := strings.Cut(a, "=")
		if !strings.HasPrefix(a, "--") {
			if kp.Connection != "" {
				return kp, errors.New(keyPolicyUsage)
			}
			kp.Connection = a
			continue
		}
		switch name {
		case "--agent-decrypt":
			kp.AgentDecrypt = true
			continue
		case "--ssh-agent":
			kp.SSHAgent = true
			continue
		case "--field", "--secret", "--op", "--alg", "--host-key":
		default:
			return kp, fmt.Errorf("%s is not a key option\n%s", name, keyPolicyUsage)
		}
		v := inline
		if !hasInline {
			if i+1 >= len(rest) {
				return kp, fmt.Errorf("%s needs a value", name)
			}
			i++
			v = rest[i]
		}
		switch name {
		case "--field":
			kp.Field = v
		case "--secret":
			kp.Secret = v
		case "--op":
			kp.Operations = append(kp.Operations, split(strings.ReplaceAll(v, "-", "_"))...)
		case "--alg":
			kp.Algorithms = append(kp.Algorithms, split(v)...)
		case "--host-key":
			kp.HostKeys = append(kp.HostKeys, split(v)...)
		}
	}
	if kp.Action != "list" && kp.Connection == "" {
		return kp, errors.New(keyPolicyUsage)
	}
	return kp, nil
}

func runKeyPolicy(c *Client, args []string, streams IO) int {
	kp, err := parseKeyPolicyArgs(args)
	if err != nil {
		fmt.Fprintf(streams.ErrOut, "keylatch key: %v\n", err)
		return exitcode.UserError
	}
	if kp.Action == "allow" {
		proof, err := requireAllowPresence(c, kp)
		if err != nil {
			fmt.Fprintf(streams.ErrOut, "keylatch key: %v\n", err)
			return exitcode.SecurityBlock
		}
		kp.PresenceDigest = proof.Digest
	}
	resp, err := c.KeyPolicy(kp)
	if err != nil {
		fmt.Fprintf(streams.ErrOut, "keylatch key: daemon: %v\n", err)
		return exitcode.OperationFailed
	}
	return report(resp, streams)
}

func runKey(c *Client, args []string, streams IO) int {
	if len(args) > 0 && (args[0] == "allow" || args[0] == "revoke" || args[0] == "list") {
		return runKeyPolicy(c, args, streams)
	}
	fail := func(err error) int {
		fmt.Fprintf(streams.ErrOut, "keylatch key: %v\n", err)
		return exitcode.UserError
	}
	ka, err := parseKeyArgs(args)
	if err != nil {
		return fail(err)
	}
	op := keyops.Operation(ka.req.Action)

	if ka.req.Input, err = readLimited(ka.in, streams.In); err != nil {
		return fail(err)
	}
	if op == keyops.OpDecrypt {
		if ka.req.Input, err = decodeText(ka.req.Input, ka.encoding); err != nil {
			return fail(fmt.Errorf("--encoding: %w", err))
		}
	}
	if ka.sig != "" {
		raw, err := readLimited(ka.sig, streams.In)
		if err != nil {
			return fail(err)
		}
		if ka.req.Signature, err = decodeText(raw, ka.encoding); err != nil {
			return fail(fmt.Errorf("--encoding: %w", err))
		}
	}

	resp, err := c.Key(ka.req)
	if err != nil {
		fmt.Fprintf(streams.ErrOut, "keylatch key: daemon: %v\n", err)
		return exitcode.OperationFailed
	}
	if resp.OK {
		switch op {
		case keyops.OpSign, keyops.OpEncrypt:
			resp.Stdout = encodeText(resp.Stdout, ka.encoding)
		case keyops.OpJWTSign:
			resp.Stdout = append(resp.Stdout, '\n')
		}
		if ka.out != "" {
			if err := os.WriteFile(ka.out, resp.Stdout, 0o600); err != nil {
				return fail(err)
			}
			resp.Stdout = nil
		}
	}
	return report(resp, streams)
}
