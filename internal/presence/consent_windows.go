//go:build windows

package presence

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// consentScript drives the WinRT UserConsentVerifier from PowerShell, which
// has no direct binding. The message is the only interpolated value; quote
// characters and control characters are removed before it is placed in a
// single-quoted literal.
const consentScript = `
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Runtime.WindowsRuntime
[void][Windows.Security.Credentials.UI.UserConsentVerifier, Windows.Security.Credentials.UI, ContentType = WindowsRuntime]
$asTask = ([System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object {
  $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation` + "`" + `1'
})[0]
$op = [Windows.Security.Credentials.UI.UserConsentVerifier]::RequestVerificationAsync('%s')
$task = $asTask.MakeGenericMethod([Windows.Security.Credentials.UI.UserConsentVerificationResult]).Invoke($null, @($op))
[void]$task.Wait(-1)
Write-Output $task.Result
`

type consent struct{}

// platformMethod asks Windows Hello (or the account PIN or password) through
// UserConsentVerifier.
func platformMethod() Method { return consent{} }

func (consent) Name() string { return "windows-hello" }

func (consent) Confirm(ctx context.Context, action Action, summary string) error {
	msg := strings.Map(func(r rune) rune {
		switch {
		case r < ' ', r == '\'', r == '‘', r == '’', r == '‚', r == '‛':
			return ' '
		}
		return r
	}, fmt.Sprintf("Approve %s: %s", action, summary))
	cmd := exec.CommandContext(ctx, `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, "-NoProfile", "-NonInteractive", "-Command", "-") //nolint:gosec // fixed binary path
	cmd.Stdin = strings.NewReader(fmt.Sprintf(consentScript, msg))
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	switch result := strings.TrimSpace(out.String()); result {
	case "Verified":
		return nil
	case "DeviceNotPresent", "NotConfiguredForUser", "DisabledByPolicy":
		return fmt.Errorf("%w: %s", ErrUnavailable, result)
	default:
		return errors.New(result)
	}
}
