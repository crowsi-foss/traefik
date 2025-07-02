package tcpaccesslog

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/traefik/traefik/v3/pkg/tcp"
	"github.com/traefik/traefik/v3/pkg/types"
)

// mockTCPHandler is a simple tcp.Handler for testing.
type mockTCPHandler struct {
	ServeTCPFunc func(conn tcp.WriteCloser)
	wg           sync.WaitGroup
}

func (m *mockTCPHandler) ServeTCP(conn tcp.WriteCloser) {
	if m.ServeTCPFunc != nil {
		m.ServeTCPFunc(conn)
	}
	m.wg.Done()
}

func (m *mockTCPHandler) AddDone() {
	m.wg.Add(1)
}

func (m *mockTCPHandler) Wait() {
	m.wg.Wait()
}

// mockWriteCloser is a mock for tcp.WriteCloser.
// It embeds a net.Conn for basic functionalities.
type mockWriteCloser struct {
	net.Conn // Underlying connection, can be *net.TCPConn, *tls.Conn, or another mock
	closed   bool
	writeBuf bytes.Buffer // To capture writes if needed
}

func (m *mockWriteCloser) CloseWrite() error {
	// For many net.Conn types, CloseWrite is not directly available.
	// If the embedded net.Conn is a *net.TCPConn, we could call its CloseWrite.
	if tcpConn, ok := m.Conn.(*net.TCPConn); ok {
		return tcpConn.CloseWrite()
	}
	// Fallback or error if not a TCPConn, depending on test needs
	return m.Close() // Simple close as fallback
}

func (m *mockWriteCloser) Close() error {
	m.closed = true
	if m.Conn != nil {
		return m.Conn.Close()
	}
	return nil
}

func (m *mockWriteCloser) Write(b []byte) (int, error) {
	if m.Conn != nil {
		return m.Conn.Write(b)
	}
	return m.writeBuf.Write(b)
}

func (m *mockWriteCloser) Read(b []byte) (int, error) {
	if m.Conn != nil {
		return m.Conn.Read(b)
	}
	return 0, os.ErrClosed // Or some other mock behavior
}

// Implement other net.Conn methods if needed for specific tests
func (m *mockWriteCloser) LocalAddr() net.Addr {
	if m.Conn != nil {
		return m.Conn.LocalAddr()
	}
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8080}
}
func (m *mockWriteCloser) RemoteAddr() net.Addr {
	if m.Conn != nil {
		return m.Conn.RemoteAddr()
	}
	return &net.TCPAddr{IP: net.ParseIP("1.2.3.4"), Port: 12345}
}
func (m *mockWriteCloser) SetDeadline(t time.Time) error      { return nil }
func (m *mockWriteCloser) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockWriteCloser) SetWriteDeadline(t time.Time) error { return nil }

// For TLS unwrapping test
func (m *mockWriteCloser) Unwrap() net.Conn { return m.Conn }


func TestTCPAccessLog_ServeTCP_Basic(t *testing.T) {
	nextHandler := &mockTCPHandler{}
	nextHandler.AddDone()

	// Using a buffer to capture log output
	logOutput := new(strings.Builder)
	handler, err := New(context.Background(), nextHandler, &types.TCPAccessLog{}, "test-ep")
	require.NoError(t, err)
	handler.logger = newJSONLogger(logOutput) // Override logger to use buffer

	// Create a real TCP client and server to get a net.Conn
	serverListener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer serverListener.Close()

	go func() {
		serverConn, acceptErr := serverListener.Accept()
		require.NoError(t, acceptErr)
		// Simulate server just closing the connection after a bit
		time.Sleep(10 * time.Millisecond)
		serverConn.Close()
	}()

	clientConn, err := net.Dial("tcp", serverListener.Addr().String())
	require.NoError(t, err)

	mockConn := &mockWriteCloser{Conn: clientConn}

	handler.ServeTCP(mockConn)
	nextHandler.Wait() // Ensure next handler's ServeTCP was called and finished

	// Assertions
	assert.True(t, mockConn.closed, "Connection should be closed by the mock or next handler")

	logLine := logOutput.String()
	require.NotEmpty(t, logLine, "Log output should not be empty")

	var loggedData map[string]interface{}
	err = json.Unmarshal([]byte(logLine), &loggedData)
	require.NoError(t, err, "Failed to unmarshal log output: %s", logLine)

	assert.Equal(t, "test-ep", loggedData[EntryPointName])
	assert.Contains(t, loggedData, ClientHost)
	assert.Contains(t, loggedData, ClientPort)
	assert.Contains(t, loggedData, Duration)
	assert.Equal(t, "TCP", loggedData[TransportProtocol])
	assert.NotNil(t, loggedData[ConnectionID])

	valBefore := connectionCounter
	handler.ServeTCP(mockConn) // Call again to check counter
	nextHandler.AddDone()      // Need to re-arm wg for the next call
	nextHandler.Wait()
	assert.Equal(t, valBefore+1, loggedData[ConnectionID].(float64)+1) // JSON unmarshals numbers to float64
}


func TestTCPAccessLog_ServeTCP_WithTLS(t *testing.T) {
	nextHandler := &mockTCPHandler{}
	nextHandler.AddDone()

	logOutput := new(strings.Builder)
	handler, err := New(context.Background(), nextHandler, &types.TCPAccessLog{}, "tls-ep")
	require.NoError(t, err)
	handler.logger = newJSONLogger(logOutput)

	// Setup a simple TLS server to get a *tls.Conn
	cert, err := tls.LoadX509KeyPair("testdata/server.crt", "testdata/server.key")
	require.NoError(t, err, "Failed to load server cert/key. Ensure testdata/server.crt and .key exist.")

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.NoClientCert, // Change if testing mTLS client certs
	}
	serverListener, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	require.NoError(t, err)
	defer serverListener.Close()

	go func() {
		serverConn, acceptErr := serverListener.Accept()
		require.NoError(t, acceptErr)
		// Simulate server just closing the connection
		time.Sleep(10 * time.Millisecond)
		serverConn.Close()
	}()

	// Client dials the TLS server
	// For testing, skip client verification of server cert if it's self-signed
	dialer := &net.Dialer{Timeout: 2 * time.Second}
	clientTLSConn, err := tls.DialWithDialer(dialer, "tcp", serverListener.Addr().String(), &tls.Config{InsecureSkipVerify: true})
	require.NoError(t, err)

	// Wrap the *tls.Conn in our mockWriteCloser
	// The tcpaccesslog handler should attempt to unwrap to get to the *tls.Conn
	// To make unwrap work, mockWriteCloser's Conn field must be the tls.Conn
	mockTLSWriteCloser := &mockWriteCloser{Conn: clientTLSConn}

	handler.ServeTCP(mockTLSWriteCloser)
	nextHandler.Wait()

	logLine := logOutput.String()
	require.NotEmpty(t, logLine)

	var loggedData map[string]interface{}
	err = json.Unmarshal([]byte(logLine), &loggedData)
	require.NoError(t, err, "Failed to unmarshal log output: %s", logLine)

	assert.Equal(t, "tls-ep", loggedData[EntryPointName])
	assert.Equal(t, "TLS", loggedData[TransportProtocol])
	assert.Contains(t, loggedData, TLSVersion)
	assert.Contains(t, loggedData, TLSCipherSuite)
	// ServerName (SNI) might not be sent by basic tls.Dial, depends on client config
	// assert.Contains(t, loggedData, TLSServerName)
}

// TestMain is used to create dummy cert files for TLS tests
func TestMain(m *testing.M) {
	// Create a temporary directory for test certificates
	_ = os.Mkdir("testdata", 0755)
	// Generate a self-signed certificate and key for testing TLS connections
	// This is a simplified version; for robust cert generation, use crypto/x509 functions
	// For simplicity, these files are expected to be pre-generated for tests.
	// If they don't exist, the TLS test will fail with a clear message.
	// Example command to generate:
	// openssl req -x509 -newkey rsa:2048 -keyout testdata/server.key -out testdata/server.crt -days 365 -nodes -subj "/CN=localhost"

	// Check if certs exist, if not, skip TLS tests or instruct user.
	// For now, assume they are present or LoadX509KeyPair will fail informatively.

	exitVal := m.Run()
	// _ = os.RemoveAll("testdata") // Clean up
	os.Exit(exitVal)
}

// TODO:
// - Test with actual client certificate data for mTLS.
// - Test different log formats (e.g., a "common" TCP format) once implemented.
// - Test filtering logic once implemented.
// - Test field selection logic once implemented.
// - Test file output and buffering once implemented.
// - Test OTLP integration once implemented.
// - Test Close() method of the handler (e.g., for closing log files).

[end of pkg/middlewares/tcp/tcpaccesslog/tcpaccesslog_test.go]
