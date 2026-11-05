package brokerd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"

	"github.com/keylatch/keylatch/internal/brokerapi"
)

// maxEnvFile bounds the env file the daemon reads from a descriptor.
const maxEnvFile = 8 << 20

// receiveEnvFiles asks the client for the descriptors of the env-file targets
// of a request: for each, the existing file opened read-only and a new empty
// file opened for writing in the same directory. The daemon fills the second;
// the client renames it over the first, so the value is never in the client.
func (a *admin) receiveEnvFiles(ctx context.Context, sr *brokerapi.SyncRequest) (map[string]*envFile, func(), error) {
	out := map[string]*envFile{}
	if len(sr.EnvFiles) == 0 {
		return out, func() {}, nil
	}
	conn, ok := ctx.Value(connCtxKey{}).(*net.UnixConn)
	if !ok {
		return nil, func() {}, errors.New("file descriptors can only arrive over the socket")
	}
	b, _ := json.Marshal(brokerapi.Response{OK: true, Code: brokerapi.CodeSendFiles})
	if _, err := conn.Write(append(b, '\n')); err != nil {
		return nil, func() {}, err
	}
	files, err := receiveFiles(conn, 2*len(sr.EnvFiles))
	if err != nil {
		return nil, func() {}, err
	}
	cleanup := func() {
		for _, f := range files {
			_ = f.Close()
		}
	}
	for i, target := range sr.EnvFiles {
		existing, temp := files[2*i], files[2*i+1]
		if err := checkTemp(temp); err != nil {
			cleanup()
			return nil, func() {}, fmt.Errorf("%s: %w", target, err)
		}
		content, err := io.ReadAll(io.LimitReader(existing, maxEnvFile+1))
		if err != nil || len(content) > maxEnvFile {
			cleanup()
			return nil, func() {}, fmt.Errorf("%s: the env file cannot be read or is too large", target)
		}
		out[target] = &envFile{existing: content, temp: temp}
	}
	return out, cleanup, nil
}

func checkTemp(f *os.File) error {
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() != 0 {
		return errors.New("the output descriptor must be an empty regular file")
	}
	return nil
}
