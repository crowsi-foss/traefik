package accesslog

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"time"
)

// TCPAccessLogEntry represents a single TCP connection log entry.
type TCPAccessLogEntry struct {
	Timestamp         time.Time `json:"timestamp"`
	ClientAddr        string    `json:"clientAddr"`
	ClientPort        string    `json:"clientPort"`
	ServerAddr        string    `json:"serverAddr"`
	ServerPort        string    `json:"serverPort"`
	RouterName        string    `json:"routerName,omitempty"`
	ServiceName       string    `json:"serviceName,omitempty"`
	BytesRead         int64     `json:"bytesRead"`
	BytesWritten      int64     `json:"bytesWritten"`
	Duration          int64     `json:"durationMs"`
	TLSVersion        string    `json:"tlsVersion,omitempty"`
	TLSCipher         string    `json:"tlsCipher,omitempty"`
	MTLSClientSubject string    `json:"mtlsClientSubject,omitempty"`
	MTLSClientSerial  string    `json:"mtlsClientSerial,omitempty"`
	MTLSClientIssuer  string    `json:"mtlsClientIssuer,omitempty"`
}

// TCPAccessLogger handles writing TCP access logs.
type TCPAccessLogger struct {
	file   *os.File
	format string // "json" or "clf" (future)
}

// NewTCPAccessLogger creates a new logger writing to the given file path.
func NewTCPAccessLogger(filePath, format string) (*TCPAccessLogger, error) {
	file, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, fmt.Errorf("failed to open TCP access log file: %w", err)
	}
	return &TCPAccessLogger{file: file, format: format}, nil
}

// Log writes a TCP access log entry.
func (l *TCPAccessLogger) Log(entry *TCPAccessLogEntry) error {
	var line string
	if l.format == "json" {
		b, err := json.Marshal(entry)
		if err != nil {
			return err
		}
		line = string(b)
	} else {
		// Simple text format for now
		line = fmt.Sprintf("%s %s:%s -> %s:%s %dB/%dB %dms", entry.Timestamp.Format(time.RFC3339), entry.ClientAddr, entry.ClientPort, entry.ServerAddr, entry.ServerPort, entry.BytesRead, entry.BytesWritten, entry.Duration)
	}
	_, err := l.file.WriteString(line + "\n")
	return err
}

// Close closes the log file.
func (l *TCPAccessLogger) Close() error {
	return l.file.Close()
}

// ExtractMTLSInfo extracts mTLS client info from a TLS connection state.
func ExtractMTLSInfo(state *tls.ConnectionState) (subject, serial, issuer string) {
	if state == nil || len(state.PeerCertificates) == 0 {
		return
	}
	cert := state.PeerCertificates[0]
	return cert.Subject.String(), cert.SerialNumber.String(), cert.Issuer.String()
}

// Utility to split host:port
func splitHostPort(addr string) (host, port string) {
	host, port, _ = net.SplitHostPort(addr)
	return
}
