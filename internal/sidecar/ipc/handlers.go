package ipc

import (
	"context"
	"fmt"
	"net/url"
	"os/exec"
	"runtime"
	"time"

	"github.com/keylatch/keylatch/internal/sidecar/events"
)

// BuildVersion is injected at link time and returned by the Health handler.
var BuildVersion = "dev"

// BootstrapTokenMinter is the interface the MintBootstrapToken handler
// uses to obtain a single-use bootstrap token from the Phase 10 UI server.
type BootstrapTokenMinter interface {
	MintBootstrapToken() (token string, expiresAt time.Time, err error)
}

// ShutdownFunc is called by the Shutdown handler to initiate a graceful
// shutdown of the sidecar process.
type ShutdownFunc func()

// RegisterHandlers registers all 5 allowed IPC handlers in reg (S14-8).
// The CI lint verifies this function registers exactly 5 handlers.
func RegisterHandlers(reg *MethodRegistry, mux *events.Mux, minter BootstrapTokenMinter, shutdown ShutdownFunc) {
	reg.Register(MethodHealth, healthHandler())
	reg.Register(MethodMintBootstrapToken, mintBootstrapTokenHandler(minter))
	reg.Register(MethodSubscribeEvents, subscribeEventsHandler(mux))
	reg.Register(MethodShutdown, shutdownHandler(shutdown))
	reg.Register(MethodOpenSystemBrowser, openSystemBrowserHandler())
}

// healthHandler returns {"ok":true,"build":"<version>"}.
func healthHandler() HandlerFunc {
	return func(_ context.Context, _ any, _ *FrameWriter) (any, error) {
		return map[string]any{
			"ok":    true,
			"build": BuildVersion,
		}, nil
	}
}

// mintBootstrapTokenHandler calls the Phase 10 bootstrap API and returns a
// single-use token. The token is NEVER a long-lived session token and NEVER
// contains vault values (S14-8).
func mintBootstrapTokenHandler(minter BootstrapTokenMinter) HandlerFunc {
	return func(_ context.Context, _ any, _ *FrameWriter) (any, error) {
		if minter == nil {
			return nil, fmt.Errorf("bootstrap token minter not configured")
		}
		token, expiresAt, err := minter.MintBootstrapToken()
		if err != nil {
			return nil, err
		}
		return map[string]any{
			"token":      token,
			"expires_at": expiresAt.Unix(),
		}, nil
	}
}

// subscribeEventsHandler upgrades the connection to an event stream, reading
// events from the mux and writing them as CBOR frames until the context is
// cancelled or the connection closes.
// The handler returns nil so the server writes a final empty response frame,
// signalling the stream is starting.
func subscribeEventsHandler(mux *events.Mux) HandlerFunc {
	return func(ctx context.Context, _ any, fw *FrameWriter) (any, error) {
		ch := mux.Subscribe()
		defer mux.Unsubscribe(ch)

		for {
			select {
			case <-ctx.Done():
				return nil, nil
			case ev, ok := <-ch:
				if !ok {
					return nil, nil
				}
				if err := fw.Write(ev); err != nil {
					// Connection closed — clean exit.
					return nil, nil
				}
			}
		}
	}
}

// shutdownHandler calls the provided ShutdownFunc and returns {"ok":true}.
func shutdownHandler(shutdown ShutdownFunc) HandlerFunc {
	return func(_ context.Context, _ any, _ *FrameWriter) (any, error) {
		if shutdown != nil {
			go shutdown()
		}
		return map[string]any{"ok": true}, nil
	}
}

// openSystemBrowserHandler opens a URL in the system browser.
// Only https:// and keylatch:// URLs are accepted (S14-2).
// M8: uses full URL parsing for scheme validation — not prefix matching.
func openSystemBrowserHandler() HandlerFunc {
	return func(_ context.Context, params any, _ *FrameWriter) (any, error) {
		rawURL, ok := extractURLParam(params)
		if !ok || rawURL == "" {
			return nil, fmt.Errorf("OpenSystemBrowser: missing url param")
		}

		// M8: validate scheme via full URL parsing, not prefix matching.
		// Reject file://, unc://, ftp://, and any other non-allowed scheme.
		parsed, err := url.Parse(rawURL)
		if err != nil || (parsed.Scheme != "https" && parsed.Scheme != "keylatch") {
			return nil, fmt.Errorf("OpenSystemBrowser: rejected URL scheme (only https:// and keylatch:// allowed): %q", rawURL)
		}

		// Audit hook placeholder — wired to Phase 5 audit in production.
		if err := openBrowser(parsed); err != nil {
			return nil, fmt.Errorf("OpenSystemBrowser: %w", err)
		}
		return map[string]any{"ok": true}, nil
	}
}

// extractURLParam pulls the "url" string from a params map.
func extractURLParam(params any) (string, bool) {
	m, ok := params.(map[string]any)
	if !ok {
		return "", false
	}
	u, ok := m["url"].(string)
	return u, ok
}

// openBrowser opens the validated URL in the system browser.
// M8: on Windows, use "cmd /c start" rather than explorer.exe to avoid UNC path risks.
// The parsed URL is used to ensure only the validated string is passed to the OS.
func openBrowser(parsed *url.URL) error {
	safeURL := parsed.String()
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", safeURL) //nolint:gosec // G204: "open" is the macOS system binary; not user input
	case "linux":
		cmd = exec.Command("xdg-open", safeURL) //nolint:gosec // G204: "xdg-open" is the standard Linux browser launcher; not user input
	case "windows":
		// M8: use "cmd /c start" — avoids explorer.exe UNC path injection risk.
		cmd = exec.Command("cmd", "/c", "start", "", safeURL) //nolint:gosec // G204: "cmd" is the Windows shell; args validated by URL parser above
	default:
		return fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
	return cmd.Start()
}
