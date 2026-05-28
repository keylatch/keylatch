package proxy

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
)

// bufferedResponseWriter captures an HTTP response in memory so it can be
// replayed over a hijacked TLS connection in handleCONNECT.
type bufferedResponseWriter struct {
	header http.Header
	buf    bytes.Buffer
	status int
}

func newBufferedResponseWriter() *bufferedResponseWriter {
	return &bufferedResponseWriter{
		header: make(http.Header),
		status: http.StatusOK,
	}
}

func (b *bufferedResponseWriter) Header() http.Header {
	return b.header
}

func (b *bufferedResponseWriter) WriteHeader(code int) {
	b.status = code
}

func (b *bufferedResponseWriter) Write(p []byte) (int, error) {
	return b.buf.Write(p)
}

// writeResponseTo writes the captured response to w as a proper HTTP/1.1 response.
func (b *bufferedResponseWriter) writeResponseTo(w io.Writer) error {
	statusText := http.StatusText(b.status)
	if statusText == "" {
		statusText = "Unknown"
	}
	if _, err := fmt.Fprintf(w, "HTTP/1.1 %d %s\r\n", b.status, statusText); err != nil {
		return err
	}
	for k, vv := range b.header {
		for _, v := range vv {
			if _, err := fmt.Fprintf(w, "%s: %s\r\n", k, v); err != nil {
				return err
			}
		}
	}
	if _, err := fmt.Fprintf(w, "Content-Length: %d\r\n\r\n", b.buf.Len()); err != nil {
		return err
	}
	_, err := w.Write(b.buf.Bytes())
	return err
}
