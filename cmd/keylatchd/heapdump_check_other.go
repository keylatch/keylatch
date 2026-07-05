//go:build !linux

package main

// heapdump_check_other.go — heap-dump protection status for non-Linux.
//
// On macOS and Windows, heap dump protection is OS-managed:
// - macOS: the kernel prevents /proc-style memory access; Task for PID
// access requires code signing entitlements or SIP bypass.
// - Windows: VirtualProtect / NtQueryVirtualMemory require elevated access.
//
// We log an informational message that the OS is handling protection and
// there is no runtime scan to perform.

import "log/slog"

// logHeapDumpProtectionStatus logs a notice that heap dump protection is
// OS-managed on this platform (macOS / Windows).
func logHeapDumpProtectionStatus() {
	slog.Debug("heap dump protection: OS-managed on this platform (no /proc/self/mem scan)")
}
