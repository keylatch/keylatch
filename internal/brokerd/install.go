package brokerd

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// ErrNotRoot means the installer was not run with root privileges.
var ErrNotRoot = errors.New("broker install changes system files and needs root: run 'sudo keylatch broker install'")

// Runner runs a host command with optional standard input.
type Runner interface {
	Run(ctx context.Context, stdin []byte, name string, args ...string) ([]byte, error)
}

// ExecRunner runs commands on the host.
type ExecRunner struct{}

// Run implements Runner.
func (ExecRunner) Run(ctx context.Context, stdin []byte, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...) //nolint:gosec // G204: the installer's own fixed command names
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("%s: %w: %s", name, err, strings.TrimSpace(string(out)))
	}
	return out, nil
}

// unit and file locations, relative to the host root.
const (
	sysusersDest = "usr/lib/sysusers.d/keylatch.conf"
	polkitDest   = "usr/share/polkit-1/actions/dev.keylatch.policy"
	credDest     = "etc/keylatch/root.cred"
	unitDir      = "etc/systemd/system"
	packagedDir  = "usr/lib/systemd/system"
	rootCredLen  = 32
)

// Installer puts the broker on a host: the system user, the units, the polkit
// policy and the sealed device root, then starts the socket. It never replaces
// an existing root credential, which would orphan every key wrapped under it.
type Installer struct {
	// Root is the filesystem root; "/" on a real host.
	Root string
	// Files holds the packaged files (linuxpkg.Files).
	Files fs.FS
	Run   Runner
	// Euid is the effective user id; os.Geteuid in production.
	Euid func() int
	// Rand supplies the device root; crypto/rand in production.
	Rand io.Reader
	Out  io.Writer
}

// InstallResult lists what Install did.
type InstallResult struct {
	Written     []string `json:"written"`
	Kept        []string `json:"kept"`
	RootCreated bool     `json:"root_credential_created"`
	Commands    []string `json:"commands"`
}

func (in *Installer) path(rel string) string { return filepath.Join(in.Root, rel) }

// Install runs the installation. It is safe to run again.
func (in *Installer) Install(ctx context.Context) (InstallResult, error) {
	var res InstallResult
	if in.Euid() != 0 {
		return res, ErrNotRoot
	}
	rd := in.Rand
	if rd == nil {
		rd = rand.Reader
	}
	run := func(stdin []byte, name string, args ...string) error {
		res.Commands = append(res.Commands, strings.Join(append([]string{name}, args...), " "))
		_, err := in.Run.Run(ctx, stdin, name, args...)
		return err
	}
	put := func(src, dest string) error {
		body, err := fs.ReadFile(in.Files, src)
		if err != nil {
			return err
		}
		return in.write(&res, dest, body, 0o644)
	}

	if err := put("sysusers.d/keylatch.conf", sysusersDest); err != nil {
		return res, err
	}
	for _, unit := range []string{"keylatchd.service", "keylatchd.socket"} {
		// A package owns its units; the installer only supplies them for a
		// tarball install.
		if _, err := os.Stat(in.path(filepath.Join(packagedDir, unit))); err == nil {
			res.Kept = append(res.Kept, filepath.Join(packagedDir, unit))
			continue
		}
		if err := put("systemd/"+unit, filepath.Join(unitDir, unit)); err != nil {
			return res, err
		}
	}
	if err := put("polkit/dev.keylatch.policy", polkitDest); err != nil {
		return res, err
	}
	if err := run(nil, "systemd-sysusers", in.path(sysusersDest)); err != nil {
		return res, fmt.Errorf("create the keylatch system user: %w", err)
	}
	if err := in.sealRoot(&res, rd, run); err != nil {
		return res, err
	}
	for _, c := range [][]string{{"systemctl", "daemon-reload"}, {"systemctl", "enable", "--now", "keylatchd.socket"}} {
		if err := run(nil, c[0], c[1:]...); err != nil {
			return res, fmt.Errorf("start the broker socket: %w", err)
		}
	}
	return res, nil
}

// sealRoot creates the device root credential unless one exists. The root is
// 32 random bytes sealed by systemd-creds with --with-key=auto: the TPM2 and
// the host key when a TPM exists, the host key alone otherwise.
func (in *Installer) sealRoot(res *InstallResult, rd io.Reader, run func([]byte, string, ...string) error) error {
	dest := in.path(credDest)
	if _, err := os.Stat(dest); err == nil {
		res.Kept = append(res.Kept, credDest)
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil { //nolint:gosec // G301: /etc/keylatch holds only the sealed credential
		return err
	}
	secret := make([]byte, rootCredLen)
	defer clear(secret)
	if _, err := io.ReadFull(rd, secret); err != nil {
		return fmt.Errorf("generate the device root: %w", err)
	}
	if err := run(secret, "systemd-creds", "encrypt", "--with-key=auto", "--name=keylatch-root", "-", dest); err != nil {
		_ = os.Remove(dest)
		return fmt.Errorf("seal the device root with systemd-creds: %w", err)
	}
	if err := os.Chmod(dest, 0o600); err != nil {
		return err
	}
	res.Written = append(res.Written, credDest)
	res.RootCreated = true
	return nil
}

// write installs body at dest under the root unless identical content is there.
func (in *Installer) write(res *InstallResult, dest string, body []byte, mode os.FileMode) error {
	full := in.path(dest)
	if cur, err := os.ReadFile(full); err == nil && bytes.Equal(cur, body) { //nolint:gosec // G304: a path under the installer's root
		res.Kept = append(res.Kept, dest)
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil { //nolint:gosec // G301: system directories
		return err
	}
	if err := os.WriteFile(full, body, mode); err != nil { //nolint:gosec // G306: unit and policy files are world-readable by design
		return err
	}
	res.Written = append(res.Written, dest)
	return nil
}
