package tcp

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"time"

	accesslog "github.com/traefik/traefik/v3/pkg/middlewares/accesslog"
	"github.com/traefik/traefik/v3/pkg/tcp"
)

// AccessLogConfig holds the logger and config for TCP access logging.
type AccessLogConfig struct {
	Logger  *accesslog.TCPAccessLogger
	Router  string
	Service string
}

// AccessLogMiddleware returns a TCP middleware that logs connection info.
func AccessLogMiddleware(cfg *AccessLogConfig) tcp.Constructor {
	return func(next tcp.Handler) (tcp.Handler, error) {
		return &accessLogHandler{next: next, cfg: cfg}, nil
	}
}

type accessLogHandler struct {
	next tcp.Handler
	cfg  *AccessLogConfig
}

func (h *accessLogHandler) ServeTCP(conn tcp.WriteCloser) {
	start := time.Now()
	clientAddr, clientPort := accesslog.SplitHostPort(conn.RemoteAddr().String())
	serverAddr, serverPort := accesslog.SplitHostPort(conn.LocalAddr().String())

	var tlsState *tls.ConnectionState
	if tlsConn, ok := conn.(*tls.Conn); ok {
		state := tlsConn.ConnectionState()
		tlsState = &state
	}

	// Log connection start
	startEntry := &accesslog.TCPAccessLogEntry{
		Timestamp:         start,
		ClientAddr:        clientAddr,
		ClientPort:        clientPort,
		ServerAddr:        serverAddr,
		ServerPort:        serverPort,
		RouterName:        h.cfg.Router,
		ServiceName:       h.cfg.Service,
		BytesRead:         0,
		BytesWritten:      0,
		Duration:          0,
	}
	if tlsState != nil {
		startEntry.TLSVersion = tlsVersionString(tlsState.Version)
		startEntry.TLSCipher = tlsCipherString(tlsState.CipherSuite)
		subj, serial, issuer := accesslog.ExtractMTLSInfo(tlsState)
		startEntry.MTLSClientSubject = subj
		startEntry.MTLSClientSerial = serial
		startEntry.MTLSClientIssuer = issuer
	}
	_ = h.cfg.Logger.Log(startEntry)

	// Wrap connection to count bytes
	monConn := &monitoredConn{Conn: conn}

	h.next.ServeTCP(monConn)
	duration := time.Since(start)

	// Log connection end
	endEntry := &accesslog.TCPAccessLogEntry{
		Timestamp:         time.Now(),
		ClientAddr:        clientAddr,
		ClientPort:        clientPort,
		ServerAddr:        serverAddr,
		ServerPort:        serverPort,
		RouterName:        h.cfg.Router,
		ServiceName:       h.cfg.Service,
		BytesRead:         monConn.bytesRead,
		BytesWritten:      monConn.bytesWritten,
		Duration:          duration.Milliseconds(),
	}
	if tlsState != nil {
		endEntry.TLSVersion = tlsVersionString(tlsState.Version)
		endEntry.TLSCipher = tlsCipherString(tlsState.CipherSuite)
		subj, serial, issuer := accesslog.ExtractMTLSInfo(tlsState)
		endEntry.MTLSClientSubject = subj
		endEntry.MTLSClientSerial = serial
		endEntry.MTLSClientIssuer = issuer
	}
	_ = h.cfg.Logger.Log(endEntry)
}

// monitoredConn wraps a net.Conn to count bytes read/written.
type monitoredConn struct {
	tcp.WriteCloser
	bytesRead    int64
	bytesWritten int64
}

func (m *monitoredConn) Read(p []byte) (int, error) {
	n, err := m.WriteCloser.Read(p)
	m.bytesRead += int64(n)
	return n, err
}

func (m *monitoredConn) Write(p []byte) (int, error) {
	n, err := m.WriteCloser.Write(p)
	m.bytesWritten += int64(n)
	return n, err
}

// Helper to get TLS version as string
func tlsVersionString(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "1.0"
	case tls.VersionTLS11:
		return "1.1"
	case tls.VersionTLS12:
		return "1.2"
	case tls.VersionTLS13:
		return "1.3"
	default:
		return "unknown"
	}
}

// Helper to get TLS cipher as string
func tlsCipherString(cs uint16) string {
	// Could use a map for more detail, but simple for now
	return io.CipherSuiteName(cs)
}
