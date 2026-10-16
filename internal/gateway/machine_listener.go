package gateway

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// ErrWildcardBind means a listen address names every interface, or none.
var ErrWildcardBind = errors.New("gateway: the machine listener must bind a specific address; pass --allow-wildcard to bind every interface")

// ValidateMachineAddr checks a host:port the machine listener may bind. An empty
// host and the unspecified addresses (0.0.0.0, ::) are refused unless
// allowWildcard is set, because they expose the listener on every interface.
func ValidateMachineAddr(addr string, allowWildcard bool) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("gateway: %q is not host:port: %w", addr, err)
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("gateway: %q is not a port", port)
	}
	if allowWildcard {
		return nil
	}
	// "0", "0.0", "0x0" and the like are spellings resolvers read as 0.0.0.0.
	if host == "" || strings.Trim(host, "0.:xX") == "" {
		return ErrWildcardBind
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsUnspecified() {
		return ErrWildcardBind
	}
	return nil
}

// MachinePrincipal is who a verified certificate stands for.
type MachinePrincipal struct {
	Name   string
	Domain string
	Caps   []string
	Serial string
}

// MachineCall is one remote `call`.
type MachineCall struct {
	Connection string            `json:"connection"`
	Action     string            `json:"action"`
	Params     map[string]string `json:"params,omitempty"`
	// Namespace, when set, must equal the certificate's domain. The domain is
	// forced; naming another one is refused and audited.
	Namespace string `json:"namespace,omitempty"`
}

// MachineCallResult is the provider's answer, already redacted.
type MachineCallResult struct {
	Status     int    `json:"status_code"`
	DurationMs int64  `json:"duration_ms"`
	Body       []byte `json:"body"`
}

// MachineBackend is what the listener asks of the broker.
type MachineBackend interface {
	// Authenticate maps a certificate whose chain TLS verified to a principal,
	// checking revocation and expiry. It runs on every request.
	Authenticate(cert *x509.Certificate) (MachinePrincipal, error)
	// Call performs the action inside the principal's domain and audits it.
	Call(ctx context.Context, p MachinePrincipal, c MachineCall) (MachineCallResult, error)
	// Refused records a refused request.
	Refused(ctx context.Context, p *MachinePrincipal, reason string)
}

// Errors a MachineBackend can return to select the status code.
var (
	ErrMachineNotFound = errors.New("gateway: no such connection or action in the machine's domain")
	ErrMachineRevoked  = errors.New("gateway: the machine certificate is revoked or expired")
)

// MachineListenerConfig configures a MachineListener.
type MachineListenerConfig struct {
	Addr          string
	AllowWildcard bool
	// ClientCAs holds the machine CA and nothing else.
	ClientCAs *x509.CertPool
	// ServerCert is the listener's certificate. GetCertificate, when set,
	// replaces it and is asked on every handshake, so a certificate can be
	// renewed while the listener runs.
	ServerCert     tls.Certificate
	GetCertificate func() (*tls.Certificate, error)
	Backend        MachineBackend
	// Listen binds the address; nil uses net.Listen.
	Listen func(network, addr string) (net.Listener, error)
}

// MachineListener serves remote machines over mutual TLS 1.3. A client
// certificate must chain to the machine CA, and is checked against the
// revocation list on every request, not only at the handshake.
type MachineListener struct {
	cfg MachineListenerConfig
}

// NewMachineListener validates cfg.
func NewMachineListener(cfg MachineListenerConfig) (*MachineListener, error) {
	if err := ValidateMachineAddr(cfg.Addr, cfg.AllowWildcard); err != nil {
		return nil, err
	}
	if cfg.ClientCAs == nil || cfg.Backend == nil || (len(cfg.ServerCert.Certificate) == 0 && cfg.GetCertificate == nil) {
		return nil, errors.New("gateway: the machine listener needs a CA, a server certificate and a backend")
	}
	return &MachineListener{cfg: cfg}, nil
}

// TLSConfig is the listener's TLS configuration: version 1.3 only, a client
// certificate from the machine CA required.
func (l *MachineListener) TLSConfig() *tls.Config {
	c := &tls.Config{
		MinVersion: tls.VersionTLS13,
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  l.cfg.ClientCAs,
	}
	if get := l.cfg.GetCertificate; get != nil {
		c.GetCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return get() }
	} else {
		c.Certificates = []tls.Certificate{l.cfg.ServerCert}
	}
	return c
}

var nameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

const maxMachineBody = 1 << 20

// Handler serves POST /v1/call.
func (l *MachineListener) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/call", l.call)
	return mux
}

func writeMachine(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func machineError(w http.ResponseWriter, status int, code, msg string) {
	writeMachine(w, status, map[string]any{"error": map[string]string{"code": code, "message": msg}})
}

func (l *MachineListener) call(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if r.Method != http.MethodPost {
		machineError(w, http.StatusMethodNotAllowed, "method_not_allowed", "POST only")
		return
	}
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		machineError(w, http.StatusUnauthorized, "no_certificate", "a client certificate is required")
		return
	}
	p, err := l.cfg.Backend.Authenticate(r.TLS.PeerCertificates[0])
	if err != nil {
		l.cfg.Backend.Refused(ctx, nil, err.Error())
		machineError(w, http.StatusUnauthorized, "unauthenticated", "the certificate is not accepted")
		return
	}
	var c MachineCall
	dec := json.NewDecoder(io.LimitReader(r.Body, maxMachineBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil || !nameRe.MatchString(c.Connection) || !nameRe.MatchString(c.Action) {
		machineError(w, http.StatusBadRequest, "bad_request", "a connection and an action are required")
		return
	}
	if !slices.Contains(p.Caps, "call") {
		l.cfg.Backend.Refused(ctx, &p, "the certificate has no call capability")
		machineError(w, http.StatusForbidden, "capability", "the certificate does not hold the call capability")
		return
	}
	if c.Namespace != "" && c.Namespace != p.Domain {
		l.cfg.Backend.Refused(ctx, &p, "cross-domain call: "+c.Namespace)
		machineError(w, http.StatusForbidden, "cross_domain", "the certificate is limited to its own domain")
		return
	}
	res, err := l.cfg.Backend.Call(ctx, p, c)
	switch {
	case errors.Is(err, ErrMachineRevoked):
		machineError(w, http.StatusUnauthorized, "unauthenticated", "the certificate is not accepted")
	case errors.Is(err, ErrMachineNotFound):
		machineError(w, http.StatusNotFound, "not_found", "no such connection or action in this domain")
	case err != nil:
		machineError(w, http.StatusBadGateway, "call_failed", "the call could not be made")
	default:
		writeMachine(w, http.StatusOK, res)
	}
}

// Serve binds the address and serves until ctx is done.
func (l *MachineListener) Serve(ctx context.Context) error {
	listen := l.cfg.Listen
	if listen == nil {
		listen = net.Listen
	}
	ln, err := listen("tcp", l.cfg.Addr)
	if err != nil {
		return fmt.Errorf("gateway: machine listener: %w", err)
	}
	srv := &http.Server{
		Handler:           l.Handler(),
		TLSConfig:         l.TLSConfig(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      90 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	if err := srv.ServeTLS(ln, "", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
