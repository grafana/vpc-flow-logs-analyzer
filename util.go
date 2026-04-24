package main

import (
	"fmt"
	"io"
	"net"
	"os"
)

// Logger provides simple logging functionality.
type Logger struct {
	w io.Writer
}

// NewStderrLogger creates a new StderrLogger instance.
func NewStderrLogger() Logger {
	return Logger{w: os.Stderr}
}

// LogInfo prints an informational message to stderr with a newline.
func (l Logger) LogInfo(format string, args ...any) {
	fmt.Fprintf(l.w, format+"\n", args...)
}

// LogError prints an error message to stderr with a newline.
func (l Logger) LogError(format string, args ...any) {
	fmt.Fprintf(l.w, "Error: "+format+"\n", args...)
}

// GetWriter returns the writer used by the logger (stderr).
func (l Logger) GetWriter() io.Writer {
	return l.w
}

// NewNoopLogger creates a new NoopLogger instance.
func NewNoopLogger() Logger {
	return Logger{w: io.Discard}
}

// isPrivateIP checks if the given IP address is a private or loopback IP.
func isPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	if ip.To4() == nil {
		return false
	}

	return ip.IsPrivate() || ip.IsLoopback()
}

// mbAndPct turns the size to MiB and how much of the total it
// represents.
func mbAndPct(b, total int64) (float64, float64) {
	mb := float64(b) / (1024 * 1024)
	pct := float64(b) * 100.0 / float64(total)
	return mb, pct
}

// lenLongestName returns the length of the longest name among
// all elements of s.
func lenLongestName[E NameGetter](s []E, limitFirstN int) int {
	var maxLen int

	for count, e := range s {
		if count >= limitFirstN {
			break
		}

		maxLen = max(maxLen, len(e.GetName()))
	}

	return maxLen
}

// getOthersBytes calculate others bytes for elements beyond the
// limit.
func getOthersBytes[E BytesGetter](s []E, count int) int64 {
	var total int64
	for _, e := range s[count:] {
		total += e.GetBytes()
	}
	return total
}

// getDisplayCount calculate total and display count.
func getDisplayCount[S ~[]E, E any](s S, maxDisplayCount int) int {
	count := len(s)
	if maxDisplayCount > 0 {
		return min(count, maxDisplayCount)
	}
	return count
}
