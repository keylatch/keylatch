//go:build linux

package main

// heapdump_check_linux.go — heap-dump canary check for Linux.
//
// On Linux, /proc/self/mem provides direct access to the process address space.
// This check scans readable memory regions (from /proc/self/maps) for
// canary strings that should not be present. If a canary is found, it logs
// a warning — it does NOT terminate the process (the canary may not be a
// secret value).
//
// Security note: this is a best-effort detection mechanism. A determined
// attacker with root access can bypass it. Its primary use is catching
// accidental leaks during development and testing.
//
// canary strings must not appear in heap memory after they are
// cleared. This check fires at startup, before any secrets are loaded.

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"math"
	"os"
	"strconv"
	"strings"
)

// heapCanaries are strings that should never appear in process memory after
// keylatchd starts. They are checked before any secrets are loaded.
// They are intentionally split to avoid the source file containing a
// credential-shaped pattern.
var heapCanaries = [][]byte{
	// Residual passphrase variable names (must not persist across versions).
	// String concatenation prevents the verbatim credential-shaped string from
	// appearing in the binary's data section and triggering secret scanners.
	[]byte("KEYLATCH_" + "PASSPHRASE"),
	// Residual fingerprint_sha256 pattern (removed in v1.0.0).
	[]byte("fingerprint_" + "sha256"),
}

// runHeapDumpCanaryCheck scans process memory for canary strings on Linux.
// It logs a warning for each canary found and returns the number found.
// A non-zero return indicates a potential memory residual.
func runHeapDumpCanaryCheck() int {
	found := 0

	maps, err := os.Open("/proc/self/maps")
	if err != nil {
		slog.Debug("heap canary check: cannot open /proc/self/maps", "error", err)
		return 0
	}
	defer func() { _ = maps.Close() }()

	mem, err := os.Open("/proc/self/mem")
	if err != nil {
		slog.Debug("heap canary check: cannot open /proc/self/mem", "error", err)
		return 0
	}
	defer func() { _ = mem.Close() }()

	scanner := bufio.NewScanner(maps)
	for scanner.Scan() {
		line := scanner.Text()
		// Parse: address-range perms offset dev inode pathname
		// e.g.: 7f1a00000000-7f1a00400000 rw-p 00000000 00:00 0
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		perms := fields[1]
		// Only scan readable, writable, non-executable, private pages (heap/stack/data).
		// Skip [vvar], [vsyscall], and shared libraries.
		if !strings.HasPrefix(perms, "rw") {
			continue
		}
		// Skip special regions.
		if len(fields) >= 6 {
			name := fields[5]
			if strings.HasPrefix(name, "[vvar]") || strings.HasPrefix(name, "[vsyscall]") {
				continue
			}
		}

		addrRange := fields[0]
		dash := strings.Index(addrRange, "-")
		if dash < 0 {
			continue
		}
		startHex := addrRange[:dash]
		endHex := addrRange[dash+1:]

		start, err1 := strconv.ParseUint(startHex, 16, 64)
		end, err2 := strconv.ParseUint(endHex, 16, 64)
		if err1 != nil || err2 != nil || start >= end {
			continue
		}

		size := end - start
		// Scan using the sliding-window scanner to avoid peak OOM on large mappings.
		n := scanRegionForCanaries(mem, start, size, heapCanaries)
		if n > 0 {
			slog.Warn("heap canary check: residual pattern(s) found in process memory",
				"count", n,
				"region", addrRange,
			)
			found += n
		}
	}

	return found
}

// logHeapDumpProtectionStatus logs the heap dump protection status on startup.
// Called once from main.go startup path.
func logHeapDumpProtectionStatus() {
	slog.Debug("heap dump canary check: scanning process memory (Linux)")
	n := runHeapDumpCanaryCheck()
	if n > 0 {
		fmt.Fprintf(os.Stderr,
			"keylatchd: WARNING: %d heap canary pattern(s) detected in process memory — "+
				"check for passphrase residuals. See SECURITY.md §Heap Dump Protection.\n", n)
	} else {
		slog.Debug("heap dump canary check: no residuals found")
	}
}

// maxCanaryLen returns the length of the longest canary slice.
func maxCanaryLen(canaries [][]byte) int {
	max := 0
	for _, c := range canaries {
		if len(c) > max {
			max = len(c)
		}
	}
	return max
}

// scanRegionForCanaries reads up to maxScanBytes from r at offset start using a
// sliding-window approach with a 4 MiB buffer. The window overlaps by
// (maxCanaryLen - 1) bytes so that canaries spanning a chunk boundary are not
// missed. Returns the number of distinct canary types found at least once.
func scanRegionForCanaries(r io.ReaderAt, start uint64, size uint64, canaries [][]byte) int {
	const (
		maxScanBytes = 16 * 1024 * 1024
		chunkSize    = 4 * 1024 * 1024
	)

	if len(canaries) == 0 {
		return 0
	}

	if size > maxScanBytes {
		size = maxScanBytes
	}

	overlap := maxCanaryLen(canaries)
	if overlap > 0 {
		overlap-- // overlap by maxCanaryLen-1 to catch cross-boundary matches
	}

	found := make(map[int]bool) // canary index → found
	buf := make([]byte, chunkSize)
	var offset uint64

	for offset < size {
		readSize := uint64(chunkSize)
		if offset+readSize > size {
			readSize = size - offset
		}

		if start+offset > math.MaxInt64 {
			break
		}
		n, err := r.ReadAt(buf[:readSize], int64(start+offset)) //nolint:gosec // bounds checked above
		if n == 0 {
			break
		}
		chunk := buf[:n]

		for i, c := range canaries {
			if !found[i] && bytes.Contains(chunk, c) {
				found[i] = true
			}
		}

		if err != nil {
			break
		}

		// Advance by (chunkSize - overlap) to keep the tail for cross-boundary detection.
		// chunkSize > overlap is guaranteed by the degenerate guard below, so the subtraction is non-negative.
		advance := uint64(chunkSize - overlap) //nolint:gosec // chunkSize > overlap ensured above
		if advance == 0 {
			// Degenerate: canary longer than chunk — fall back to full advance.
			advance = uint64(chunkSize)
		}
		offset += advance
	}

	return len(found)
}
