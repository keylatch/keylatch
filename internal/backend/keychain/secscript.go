//go:build darwin

package keychain

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// scriptPart is one word of a `security -i` command line.
type scriptPart struct {
	text string
	// quoted words are wrapped in double quotes; flags and hex payloads are
	// emitted as they are.
	quoted bool
}

func sflag(s string) scriptPart { return scriptPart{text: s} }

func sval(s string) scriptPart { return scriptPart{text: s, quoted: true} }

// shex encodes data as the hex string `security -X` takes, so a secret of any
// byte content needs no quoting.
func shex(data []byte) scriptPart { return scriptPart{text: hex.EncodeToString(data)} }

// scriptLine builds one command line for `security -i`. Words that carry
// names or passwords are double-quoted with backslash and quote escaped; a
// line break or NUL cannot be quoted safely and is refused.
func scriptLine(command string, parts ...scriptPart) ([]byte, error) {
	var b bytes.Buffer
	b.WriteString(command)
	for _, p := range parts {
		b.WriteByte(' ')
		if !p.quoted {
			b.WriteString(p.text)
			continue
		}
		if strings.ContainsAny(p.text, "\r\n\x00") {
			return nil, errors.New("keychain: value contains a line break or NUL")
		}
		b.WriteByte('"')
		b.WriteString(strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(p.text))
		b.WriteByte('"')
	}
	b.WriteByte('\n')
	return b.Bytes(), nil
}

// script runs one command through `security -i`, which reads its command
// line from stdin: passwords and secret values never appear in the argument
// list of a process any local user can list. `security -i` can exit 0 when
// the inner command fails, so anything it writes to stderr counts as failure.
// The script is zeroed afterwards.
func (k *KeychainBackend) script(ctx context.Context, command string, parts ...scriptPart) error {
	line, err := scriptLine(command, parts...)
	if err != nil {
		return err
	}
	defer clear(line)
	_, stderr, exitCode, runErr := k.opts.Runner.Run(ctx, k.opts.SecurityBin, []string{"-i"}, line)
	if runErr != nil {
		return runErr
	}
	if exitCode != 0 {
		return fmt.Errorf("security exited %d: %s", exitCode, strings.TrimSpace(string(stderr)))
	}
	if msg := strings.TrimSpace(string(stderr)); msg != "" {
		return fmt.Errorf("security: %s", msg)
	}
	return nil
}
