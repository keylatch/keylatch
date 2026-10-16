package control

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"slices"
	"strings"
	"syscall"

	"github.com/keylatch/keylatch/internal/exitcode"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/runner"
)

// IO carries the streams of a thin-client invocation.
type IO struct {
	In     io.Reader
	Out    io.Writer
	ErrOut io.Writer
}

// globalValueFlags take a separate value argument ahead of the verb.
var globalValueFlags = []string{"--log-level"}

// Handle serves a keylatch invocation through the daemon when one is reachable
// and the verb is one it serves. It reports false when the caller should act
// on local state instead.
func Handle(ctx context.Context, lookup llmcontext.Lookup, args []string, streams IO) (exitCode int, handled bool) {
	if lookup(LocalEnv) == "1" || slices.ContainsFunc(args, func(a string) bool { return a == "-h" || a == "--help" }) {
		return 0, false
	}
	global, verb, rest, ok := splitVerb(args)
	if !ok {
		return 0, false
	}
	if verb == gitCredentialVerb {
		return runGitCredential(lookup, rest, streams), true
	}
	if verb == dockerCredentialVerb {
		return RunDockerCredential(lookup, rest, streams), true
	}
	if !IsServedVerb(verb) && verb != KeyVerb {
		return 0, false
	}
	client, err := NewClient(lookup)
	if err != nil {
		return 0, false
	}

	if verb == KeyVerb {
		return runKey(client, rest, streams), true
	}
	if verb == "run" && !slices.Contains(rest, "--dry-run") {
		return runThroughDaemon(ctx, client, lookup, rest, streams), true
	}

	resp, err := client.ExecStream(global, verb, rest, streams)
	if err != nil {
		if errors.Is(err, ErrNoDaemon) {
			return 0, false
		}
		fmt.Fprintf(streams.ErrOut, "keylatch: daemon: %v\n", err)
		return exitcode.OperationFailed, true
	}
	if resp.Code == CodeRunLocally {
		return 0, false
	}
	return report(resp, streams), true
}

// report writes a daemon reply to the caller's streams and returns the exit code.
func report(resp Response, streams IO) int {
	_, _ = streams.Out.Write(resp.Stdout)
	_, _ = streams.ErrOut.Write(resp.Stderr)
	if resp.Error != "" {
		fmt.Fprintf(streams.ErrOut, "keylatch: %s\n", resp.Error)
	}
	if !resp.OK && resp.ExitCode == 0 {
		return exitcode.OperationFailed
	}
	return resp.ExitCode
}

// splitVerb separates the global flags that lead the command line from the
// verb and the arguments after it.
func splitVerb(args []string) (global []string, verb string, rest []string, ok bool) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--":
			return nil, "", nil, false
		case strings.HasPrefix(a, "-"):
			global = append(global, a)
			if slices.Contains(globalValueFlags, a) && i+1 < len(args) {
				i++
				global = append(global, args[i])
			}
		default:
			return global, a, args[i+1:], true
		}
	}
	return nil, "", nil, false
}

type runArgs struct {
	connection string
	command    []string
	runtime    string
	tier       Tier
	clean      bool
	extra      []string
	repository string
	perms      []string
	target     string
	dbUser     string
	database   string
}

var errRunUsage = errors.New("usage: keylatch run [--runtime <mode>] [--tier <tier>] [--repo <owner/name>] [--permission <name>=<level>]... <connection> -- <command> [args...]")

func parseRunArgs(args []string) (runArgs, error) {
	var ra runArgs
	valueOf := func(i *int, name, a string) (string, error) {
		if v, ok := strings.CutPrefix(a, name+"="); ok {
			return v, nil
		}
		if *i+1 >= len(args) {
			return "", fmt.Errorf("%s needs a value", name)
		}
		*i++
		return args[*i], nil
	}
	for i := 0; i < len(args); i++ {
		a := args[i]
		name, _, _ := strings.Cut(a, "=")
		switch {
		case a == "--":
			ra.command = args[i+1:]
			if ra.connection == "" || len(ra.command) == 0 {
				return ra, errRunUsage
			}
			return ra, nil
		case name == "--runtime":
			v, err := valueOf(&i, name, a)
			if err != nil {
				return ra, err
			}
			ra.runtime = v
		case name == "--tier":
			v, err := valueOf(&i, name, a)
			if err != nil {
				return ra, err
			}
			ra.tier = Tier(strings.ToUpper(v))
		case name == "--repo":
			v, err := valueOf(&i, name, a)
			if err != nil {
				return ra, err
			}
			ra.repository = v
		case name == "--target" || name == "--db-user" || name == "--database":
			v, err := valueOf(&i, name, a)
			if err != nil {
				return ra, err
			}
			switch name {
			case "--target":
				ra.target = v
			case "--db-user":
				ra.dbUser = v
			default:
				ra.database = v
			}
		case name == "--permission":
			v, err := valueOf(&i, name, a)
			if err != nil {
				return ra, err
			}
			ra.perms = append(ra.perms, v)
		case name == "--extra":
			v, err := valueOf(&i, name, a)
			if err != nil {
				return ra, err
			}
			for _, n := range strings.Split(v, ",") {
				n = strings.TrimSpace(n)
				if strings.HasPrefix(n, "KEYLATCH_") {
					return ra, errors.New("--extra cannot forward Keylatch configuration")
				}
				if n != "" {
					ra.extra = append(ra.extra, n)
				}
			}
		case a == "--clean-env":
			ra.clean = true
		case a == "--no-daemon-start":
		case strings.HasPrefix(a, "-"):
			return ra, fmt.Errorf("%s is not supported when running through the daemon", name)
		case ra.connection == "":
			ra.connection = a
		default:
			return ra, errRunUsage
		}
	}
	return ra, errRunUsage
}

// callerProxy is the proxy the caller's own environment names for HTTPS.
func callerProxy(lookup llmcontext.Lookup) string {
	for _, name := range []string{"HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"} {
		if v := lookup(name); v != "" {
			return v
		}
	}
	return ""
}

func runThroughDaemon(ctx context.Context, c *Client, lookup llmcontext.Lookup, args []string, streams IO) (code int) {
	ra, err := parseRunArgs(args)
	if err != nil {
		fmt.Fprintf(streams.ErrOut, "keylatch run: %v\n", err)
		return exitcode.UserError
	}
	if ra.tier == TierContained {
		return runContained(ctx, c, lookup, ra, streams)
	}
	cwd, _ := os.Getwd()
	resp, err := c.RunSession(RunRequest{
		Connection:    ra.connection,
		Runtime:       ra.runtime,
		Tier:          ra.tier,
		Command:       ra.command,
		CWD:           cwd,
		UpstreamProxy: callerProxy(lookup),
		Repository:    ra.repository,
		Permissions:   ra.perms,
		Target:        ra.target,
		DBUser:        ra.dbUser,
		Database:      ra.database,
	})
	if err != nil {
		fmt.Fprintf(streams.ErrOut, "keylatch run: daemon: %v\n", err)
		return exitcode.OperationFailed
	}
	if !resp.OK || resp.Session == nil {
		fmt.Fprintf(streams.ErrOut, "keylatch run: %s\n", resp.Error)
		if resp.ExitCode == 0 {
			return exitcode.OperationFailed
		}
		return resp.ExitCode
	}

	sess := resp.Session
	c.SetRun(sess.RunID)
	defer func() { _ = c.ReportExit(code) }()
	placeholder := sess.Tier == TierPlaceholder
	var addr string
	var stop func()
	if placeholder || sess.Tier == TierAdapter {
		defer func() { _ = c.EndSession(sess.ProxyID) }()
		addr, stop, err = c.ForwardProxy(sess.ProxyID)
	} else {
		addr, stop, err = c.Forward()
	}
	if err != nil {
		fmt.Fprintf(streams.ErrOut, "keylatch run: %v\n", err)
		return exitcode.OperationFailed
	}
	defer stop()

	session := sess.Env
	if helper := self(); helper != "" {
		usesHelper := false
		for i := range session.Set {
			if strings.Contains(session.Set[i].Value, runner.BinaryPlaceholder) {
				session.Set[i].Value = strings.ReplaceAll(session.Set[i].Value, runner.BinaryPlaceholder, shellQuote(helper))
				usesHelper = true
			}
		}
		if usesHelper {
			session.Set = append(session.Set, runner.EnvAssign{Name: "KEYLATCH_SOCKET", Value: c.Socket()})
		}
	}
	dockerBin, cleanDocker, err := withDockerConfig(&session, self())
	if err != nil {
		fmt.Fprintf(streams.ErrOut, "keylatch run: %v\n", err)
		return exitcode.OperationFailed
	}
	defer cleanDocker()
	if dockerBin != "" && !slices.ContainsFunc(session.Set, func(e runner.EnvAssign) bool { return e.Name == "KEYLATCH_SOCKET" }) {
		session.Set = append(session.Set, runner.EnvAssign{Name: "KEYLATCH_SOCKET", Value: c.Socket()})
	}
	_, port, _ := net.SplitHostPort(addr)
	for i := range session.Set {
		session.Set[i].Value = strings.ReplaceAll(session.Set[i].Value, runner.GatewayAddrPlaceholder, addr)
		session.Set[i].Value = strings.ReplaceAll(session.Set[i].Value, runner.AdapterPortPlaceholder, port)
	}
	if placeholder {
		bundle, cleanup, warn, err := writeCABundle(lookup, sess.CAPEM)
		if err != nil {
			fmt.Fprintf(streams.ErrOut, "keylatch run: %v\n", err)
			return exitcode.OperationFailed
		}
		defer cleanup()
		if warn != nil {
			fmt.Fprintf(streams.ErrOut, "keylatch run: %v; only the session CA is trusted\n", warn)
		}
		for _, name := range sess.CAVars {
			session.Set = append(session.Set, runner.EnvAssign{Name: name, Value: bundle})
		}
	}

	ctx, cancel := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer cancel()
	cmd := exec.CommandContext(ctx, ra.command[0], ra.command[1:]...) //nolint:gosec // G204: the child is the command the caller asked for, started inside the caller's own sandbox
	cmd.Env = session.Apply(os.Environ(), ra.clean, ra.extra)
	if dockerBin != "" {
		cmd.Env = prependPath(cmd.Env, dockerBin)
	}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = streams.In, streams.Out, streams.ErrOut
	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			if code := exitErr.ExitCode(); code >= 0 {
				return code
			}
			return 128 + int(syscall.SIGINT)
		}
		fmt.Fprintf(streams.ErrOut, "keylatch run: %v\n", err)
		return 127
	}
	return 0
}

// self is the path of the running keylatch executable.
func self() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	return exe
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
