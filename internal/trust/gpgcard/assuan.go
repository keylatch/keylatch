// Package gpgcard implements a trust.RootOfTrust adapter backed by a GnuPG smartcard
// via the scdaemon Assuan protocol.
package gpgcard

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"
)

// AssuanDial opens a Unix socket connection to the Assuan-speaking scdaemon.
// Exported for testing with mock servers.
func AssuanDial(socketPath string) (net.Conn, error) {
	return assuanDial(socketPath)
}

// AssuanSign is the exported variant of assuanSign for testing.
func AssuanSign(conn net.Conn, keygrip string, data []byte) ([]byte, error) {
	return assuanSign(conn, keygrip, data)
}

// assuanDial opens a Unix socket connection to the Assuan-speaking scdaemon.
func assuanDial(socketPath string) (net.Conn, error) {
	conn, err := net.DialTimeout("unix", socketPath, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("assuan: dial %q: %w", socketPath, err)
	}
	// Read and discard the initial OK greeting.
	r := bufio.NewReader(conn)
	line, err := r.ReadString('\n')
	if err != nil {
		_ = conn.Close() // best-effort cleanup in error path
		return nil, fmt.Errorf("assuan: read greeting: %w", err)
	}
	if !strings.HasPrefix(line, "OK") {
		_ = conn.Close() // best-effort cleanup in error path
		return nil, fmt.Errorf("assuan: unexpected greeting %q", strings.TrimSpace(line))
	}
	return conn, nil
}

// assuanSend sends a command over conn and collects the response lines until
// an OK or ERR line is received.
//
// Returns the concatenated D-line data (decoded from percent-encoding) and
// the final OK/ERR status line.
func assuanSend(conn net.Conn, command string) (response string, err error) {
	// Write the command.
	if _, err := fmt.Fprintf(conn, "%s\n", command); err != nil {
		return "", fmt.Errorf("assuan: send %q: %w", command, err)
	}

	var dataBuf bytes.Buffer
	r := bufio.NewReader(conn)
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return "", fmt.Errorf("assuan: read response: %w", err)
		}
		line = strings.TrimRight(line, "\r\n")

		switch {
		case strings.HasPrefix(line, "D "):
			// D-line carries binary data percent-encoded.
			decoded, err := assuanDecodeD(line[2:])
			if err != nil {
				return "", fmt.Errorf("assuan: decode D-line: %w", err)
			}
			dataBuf.Write(decoded)

		case strings.HasPrefix(line, "S ") || strings.HasPrefix(line, "# "):
			// Status or comment — skip.
			continue

		case strings.HasPrefix(line, "OK"):
			return dataBuf.String(), nil

		case strings.HasPrefix(line, "ERR"):
			return "", fmt.Errorf("assuan: error response: %s", line)

		default:
			// Unknown line type — skip.
		}
	}
}

// assuanSign signs data using the key identified by keygrip via scdaemon.
//
// Protocol:
//  1. SETKEY <keygrip>
//  2. SIGKEY <keygrip>
//  3. SETHASH --hash=sha256 <hexhash>
//  4. PKSIGN
func assuanSign(conn net.Conn, keygrip string, data []byte) ([]byte, error) {
	// Step 1: SETKEY.
	if _, err := assuanSend(conn, "SETKEY "+keygrip); err != nil {
		return nil, fmt.Errorf("assuan: SETKEY: %w", err)
	}

	// Step 2: SIGKEY.
	if _, err := assuanSend(conn, "SIGKEY "+keygrip); err != nil {
		return nil, fmt.Errorf("assuan: SIGKEY: %w", err)
	}

	// Step 3: SETHASH.
	hexHash := hex.EncodeToString(data)
	if _, err := assuanSend(conn, "SETHASH --hash=sha256 "+hexHash); err != nil {
		return nil, fmt.Errorf("assuan: SETHASH: %w", err)
	}

	// Step 4: PKSIGN.
	resp, err := assuanSend(conn, "PKSIGN")
	if err != nil {
		return nil, fmt.Errorf("assuan: PKSIGN: %w", err)
	}

	return []byte(resp), nil
}

// assuanDecodeD decodes an Assuan D-line payload (percent-encoded binary data).
// Special chars: %XX hex-encoded, \n is literal newline within data.
func assuanDecodeD(encoded string) ([]byte, error) {
	var out bytes.Buffer
	for i := 0; i < len(encoded); i++ {
		if encoded[i] == '%' && i+2 < len(encoded) {
			b, err := hex.DecodeString(encoded[i+1 : i+3])
			if err != nil {
				return nil, fmt.Errorf("assuan: bad percent-escape at %d", i)
			}
			out.Write(b)
			i += 2
		} else {
			out.WriteByte(encoded[i])
		}
	}
	return out.Bytes(), nil
}
