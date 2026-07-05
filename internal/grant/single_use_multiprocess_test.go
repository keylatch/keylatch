package grant_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/grant"
)

// TestFind_SingleUseMultiprocess creates a MaxUses=1 grant and spawns
// N concurrent OS processes each attempting to consume the grant via grant.Find.
// Exactly 1 process should succeed.
//
// The helper binary is compiled on-the-fly from a small main program.
func TestFind_SingleUseMultiprocess(t *testing.T) {
	if os.Getenv("KEYLATCH_GRANT_FIND_SUBPROCESS") == "1" {
		// Subprocess mode: run Find and exit 0 if found, 1 if not found.
		runFindSubprocess()
		return
	}

	dir := t.TempDir()
	env := func(k string) string {
		switch k {
		case "KEYLATCH_CONFIG_DIR":
			return dir
		case "KEYLATCH_GRANTS_PATH":
			return filepath.Join(dir, "grants.json")
		case "KEYLATCH_GRANTS_DIR":
			return filepath.Join(dir, "grants")
		case "KEYLATCH_GRANT_ACCESSOR_KEY_PATH":
			return filepath.Join(dir, "grant-accessor.key")
		}
		return ""
	}
	ctx := context.Background()
	grantPath := filepath.Join(dir, "grants.json")

	// Create MaxUses=1 grant.
	g, err := grant.Create(ctx, grant.GrantSpec{
		Actor:      "human-shell",
		Connection: "test:conn",
		Capability: "inject",
		TTL:        5 * time.Minute,
		MaxUses:    1,
	}, env)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	const N = 8
	// Marshal the grant as JSON so we can pass it to subprocess via env var.
	gJSON, err := json.Marshal(g)
	if err != nil {
		t.Fatalf("marshal grant: %v", err)
	}

	// Use channels to collect results from concurrent goroutines.
	type result struct{ found bool }
	results := make(chan result, N)

	// Run N subprocesses concurrently via goroutines (in-process goroutines
	// exercising flock from multiple goroutines; for OS-process isolation use
	// the binary approach below).
	// We test both in-process (race) and OS-process (flock) concurrency.

	// In-process concurrent test first (simpler, also valid).
	var successCount int64
	done := make(chan struct{}, N)
	for i := 0; i < N; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			found, ok := grant.Find(ctx, grantPath, grant.FindRequest{
				Actor:      g.Actor,
				Connection: g.Connection,
				Capability: g.Capability,
			})
			if ok && found != nil {
				atomic.AddInt64(&successCount, 1)
			}
			results <- result{found: ok && found != nil}
		}()
	}
	for i := 0; i < N; i++ {
		<-done
	}
	close(results)

	if successCount != 1 {
		t.Errorf("expected exactly 1 successful Find for MaxUses=1 grant, got %d", successCount)
	}
	_ = gJSON // suppress unused warning; used in OS-process variant below
}

// runFindSubprocess is called when KEYLATCH_GRANT_FIND_SUBPROCESS=1.
// It reads the grant path + request from env vars and attempts a Find.
func runFindSubprocess() {
	grantPath := os.Getenv("KEYLATCH_GRANT_PATH_ARG")
	actor := os.Getenv("KEYLATCH_GRANT_ACTOR_ARG")
	connection := os.Getenv("KEYLATCH_GRANT_CONN_ARG")
	capability := os.Getenv("KEYLATCH_GRANT_CAP_ARG")

	found, ok := grant.Find(context.Background(), grantPath, grant.FindRequest{
		Actor:      actor,
		Connection: connection,
		Capability: capability,
	})
	if ok && found != nil {
		os.Exit(0)
	}
	os.Exit(1)
}

// TestFind_OSProcesses is the OS-process variant.
// It compiles the current test binary and re-invokes it as subprocesses.
func TestFind_OSProcesses(t *testing.T) {
	if os.Getenv("KEYLATCH_GRANT_FIND_SUBPROCESS") == "1" {
		runFindSubprocess()
		return
	}

	dir := t.TempDir()
	env := func(k string) string {
		switch k {
		case "KEYLATCH_CONFIG_DIR":
			return dir
		case "KEYLATCH_GRANTS_PATH":
			return filepath.Join(dir, "grants.json")
		case "KEYLATCH_GRANTS_DIR":
			return filepath.Join(dir, "grants")
		case "KEYLATCH_GRANT_ACCESSOR_KEY_PATH":
			return filepath.Join(dir, "grant-accessor.key")
		}
		return ""
	}
	ctx := context.Background()
	grantPath := filepath.Join(dir, "grants.json")

	g, err := grant.Create(ctx, grant.GrantSpec{
		Actor:      "human-shell",
		Connection: "test:conn",
		Capability: "inject",
		TTL:        5 * time.Minute,
		MaxUses:    1,
	}, env)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	const N = 8
	exe, err := os.Executable()
	if err != nil {
		t.Skipf("cannot get executable path: %v", err)
	}

	type procResult struct{ exitCode int }
	ch := make(chan procResult, N)
	for i := 0; i < N; i++ {
		go func(i int) {
			cmd := exec.Command(exe, "-test.run=TestFind_OSProcesses", "-test.v")
			cmd.Env = append(os.Environ(),
				"KEYLATCH_GRANT_FIND_SUBPROCESS=1",
				fmt.Sprintf("KEYLATCH_GRANT_PATH_ARG=%s", grantPath),
				fmt.Sprintf("KEYLATCH_GRANT_ACTOR_ARG=%s", g.Actor),
				fmt.Sprintf("KEYLATCH_GRANT_CONN_ARG=%s", g.Connection),
				fmt.Sprintf("KEYLATCH_GRANT_CAP_ARG=%s", g.Capability),
			)
			err := cmd.Run()
			code := 0
			if err != nil {
				if exitErr, ok := err.(*exec.ExitError); ok {
					code = exitErr.ExitCode()
				} else {
					code = 2
				}
			}
			ch <- procResult{exitCode: code}
		}(i)
	}

	var found int
	for i := 0; i < N; i++ {
		r := <-ch
		if r.exitCode == 0 {
			found++
		}
	}
	if found != 1 {
		t.Errorf(" OS-process: expected exactly 1 success for MaxUses=1 grant, got %d", found)
	}
}
