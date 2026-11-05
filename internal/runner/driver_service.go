package runner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"

	"github.com/keylatch/keylatch/internal/exitcode"
	"github.com/keylatch/keylatch/internal/redactor"
)

// ServiceRuntime is the --runtime value of a command that runs inside an
// enrolled systemd unit and receives its connection from the broker.
const ServiceRuntime = "service"

// ErrReleaseRefused means the broker would not release the connection to this
// process: it is not the enrolled unit, or the unit changed since enrollment.
var ErrReleaseRefused = errors.New("service: the broker refused to release the credential")

// ErrNoServiceCredential means the unit's credential file is missing.
var ErrNoServiceCredential = errors.New("service: the unit has no credential file for this connection")

var serviceConnection = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// ServiceCredentialName is the name a unit loads the connection's credential
// under (LoadCredentialEncrypted=<name>:<path>).
func ServiceCredentialName(connection string) string { return "keylatch-" + connection }

// ServiceEnv is one environment variable the broker released.
type ServiceEnv struct {
	Name  string
	Value []byte
}

// ServiceReleaser presents a unit's capability to the broker and returns what
// the connection's runtime contract injects.
type ServiceReleaser interface {
	Release(ctx context.Context, connection string, capability []byte) ([]ServiceEnv, error)
}

// ServiceRun describes one command run inside a service unit.
type ServiceRun struct {
	Connection string
	Command    []string
	// CredentialsDir is $CREDENTIALS_DIRECTORY, where systemd put the unit's credentials.
	CredentialsDir string
	Releaser       ServiceReleaser
	// Env is the environment the child starts from.
	Env    []string
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
}

// RunService reads the unit's capability, presents it to the broker, and runs
// the command with the released values in its environment. The capability is
// the content of the credential file: it proves the process is the enrolled
// unit and is worth nothing anywhere else. Output is redacted for the values.
// The returned code is the command's exit status, or a Keylatch exit code when
// the command did not start.
func RunService(ctx context.Context, r ServiceRun) (int, error) {
	if !serviceConnection.MatchString(r.Connection) {
		return exitcode.UserError, fmt.Errorf("service: %q is not a connection name a unit credential can carry", r.Connection)
	}
	if len(r.Command) == 0 {
		return exitcode.UserError, errors.New("service: a command is required")
	}
	if r.CredentialsDir == "" {
		return exitcode.UserError, errors.New("service: CREDENTIALS_DIRECTORY is not set; this command must run inside a unit that loads the credential with LoadCredentialEncrypted")
	}
	capability, err := os.ReadFile(filepath.Join(r.CredentialsDir, ServiceCredentialName(r.Connection))) //nolint:gosec // G304: the credentials directory is systemd's
	if err != nil {
		return exitcode.UserError, fmt.Errorf("%w: %v", ErrNoServiceCredential, err)
	}
	defer clear(capability)
	if len(capability) != 32 {
		return exitcode.UserError, fmt.Errorf("%w: the file is not a Keylatch capability", ErrNoServiceCredential)
	}
	env, err := r.Releaser.Release(ctx, r.Connection, capability)
	if err != nil {
		code := exitcode.OperationFailed
		if errors.Is(err, ErrReleaseRefused) {
			code = exitcode.SecurityBlock
		}
		return code, err
	}
	var secrets [][]byte
	childEnv := ScrubChildEnv(r.Env)
	for _, e := range env {
		secrets = append(secrets, e.Value)
		childEnv = appendOrReplace(childEnv, e.Name, string(e.Value))
	}
	defer func() {
		for _, e := range env {
			clear(e.Value)
		}
	}()
	childEnv = appendOrReplace(childEnv, "KEYLATCH_RUNTIME", ServiceRuntime)

	stdout, stderr := r.Stdout, r.Stderr
	if stdout == nil {
		stdout = os.Stdout
	}
	if stderr == nil {
		stderr = os.Stderr
	}
	guard := newOutputGuard(stdout, stderr, "", redactor.ScanReport, secrets...)
	cmd := exec.CommandContext(ctx, r.Command[0], r.Command[1:]...) //nolint:gosec // G204: the command is the unit's own
	cmd.Env = childEnv
	cmd.Stdin = r.Stdin
	cmd.Stdout, cmd.Stderr = guard.Stdout(), guard.Stderr()
	runErr := cmd.Run()
	guard.Finish()
	var exitErr *exec.ExitError
	switch {
	case runErr == nil:
		return 0, nil
	case errors.As(runErr, &exitErr) && exitErr.ExitCode() >= 0:
		return exitErr.ExitCode(), nil
	}
	return 127, runErr
}
