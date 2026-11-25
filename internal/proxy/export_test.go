package proxy

import (
	"bytes"
	"time"
)

// NewBufferedResponseWriterForTest exposes newBufferedResponseWriter for white-box tests.
func NewBufferedResponseWriterForTest() *bufferedResponseWriter {
	return newBufferedResponseWriter()
}

// WriteResponseToForTest exposes writeResponseTo for white-box tests.
func (b *bufferedResponseWriter) WriteResponseToForTest(w *bytes.Buffer) error {
	return b.writeResponseTo(w)
}

// SetClockForTest replaces the injector's clock and re-mint gap.
func (g *GitHubInjector) SetClockForTest(now func() time.Time) { g.now = now }
