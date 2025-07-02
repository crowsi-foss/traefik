package tcpaccesslog

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewTCPLogData(t *testing.T) {
	logData := NewTCPLogData()
	assert.NotNil(t, logData)
	assert.NotNil(t, logData.Core)
	assert.Empty(t, logData.Core)
}

type mockConn struct {
	net.Conn
	remoteAddr net.Addr
	localAddr  net.Addr
}

func (m *mockConn) RemoteAddr() net.Addr { return m.remoteAddr }
func (m *mockConn) LocalAddr() net.Addr  { return m.localAddr }
func (m *mockConn) Close() error         { return nil }

func TestPopulateBasic(t *testing.T) {
	logData := NewTCPLogData()
	now := time.Now()

	conn := &mockConn{
		remoteAddr: &net.TCPAddr{IP: net.ParseIP("192.168.1.100"), Port: 12345},
	}

	logData.PopulateBasic(conn, "test-entrypoint", "test-router", "test-service", 42)

	assert.WithinDuration(t, now, logData.Core[StartUTC].(time.Time), time.Second, "StartUTC should be recent")
	assert.WithinDuration(t, now, logData.Core[StartLocal].(time.Time), time.Second, "StartLocal should be recent")
	assert.Equal(t, uint64(42), logData.Core[ConnectionID])
	assert.Equal(t, "test-entrypoint", logData.Core[EntryPointName])
	assert.Equal(t, "test-router", logData.Core[RouterName])
	assert.Equal(t, "test-service", logData.Core[ServiceName])
	assert.Equal(t, "192.168.1.100:12345", logData.Core[ClientAddr])
	assert.Equal(t, "192.168.1.100", logData.Core[ClientHost])
	assert.Equal(t, "12345", logData.Core[ClientPort])
	assert.Equal(t, "TCP", logData.Core[TransportProtocol])

	// Test with nil conn
	logDataNilConn := NewTCPLogData()
	logDataNilConn.PopulateBasic(nil, "ep", "", "", 1)
	assert.Equal(t, "-", logDataNilConn.Core[ClientAddr])
	assert.Equal(t, "-", logDataNilConn.Core[ClientHost])
	assert.Equal(t, "-", logDataNilConn.Core[ClientPort])

	// Test with non-TCPAddr (e.g. unix domain socket)
	logDataUnixConn := NewTCPLogData()
	unixConn := &mockConn{
		remoteAddr: &net.UnixAddr{Name: "/tmp/socket.sock", Net: "unix"},
	}
	logDataUnixConn.PopulateBasic(unixConn, "ep", "", "", 2)
	assert.Equal(t, "/tmp/socket.sock", logDataUnixConn.Core[ClientAddr])
	assert.Equal(t, "/tmp/socket.sock", logDataUnixConn.Core[ClientHost])
	assert.Equal(t, "-", logDataUnixConn.Core[ClientPort])
}

func TestPopulateTLS(t *testing.T) {
	logData := NewTCPLogData()

	// Nil ConnectionState
	logData.PopulateTLS(nil)
	_, ok := logData.Core[TLSVersion]
	assert.False(t, ok, "TLS fields should not be populated for nil ConnectionState")

	// Create a dummy client certificate for testing
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "test.client.com",
			Organization: []string{"Test Org"},
		},
		Issuer: pkix.Name{
			CommonName:   "Test CA",
			Organization: []string{"Test CA Org"},
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(time.Hour * 24 * 30),
		KeyUsage:  x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,

		DNSNames:       []string{"client.example.com", "alt.client.example.org"},
		EmailAddresses: []string{"test@example.com"},
		IPAddresses:    []net.IP{net.ParseIP("10.0.0.1"), net.ParseIP("::1")},
		URIs:           []*net.URL{{Scheme: "spiffe", Host: "example.com", Path: "/workload/client"}},
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privKey.PublicKey, privKey)
	require.NoError(t, err)
	clientCert, err := x509.ParseCertificate(certBytes)
	require.NoError(t, err)

	connState := &tls.ConnectionState{
		Version:           tls.VersionTLS13,
		CipherSuite:       tls.TLS_AES_128_GCM_SHA256,
		ServerName:        "server.example.com",
		PeerCertificates:  []*x509.Certificate{clientCert},
		NegotiatedProtocol: "h2",
	}

	logData.PopulateTLS(connState)

	assert.Equal(t, "TLS", logData.Core[TransportProtocol])
	assert.Equal(t, "TLS1.3", logData.Core[TLSVersion])
	assert.Equal(t, "TLS_AES_128_GCM_SHA256", logData.Core[TLSCipherSuite])
	assert.Equal(t, "server.example.com", logData.Core[TLSServerName])

	assert.Equal(t, "CN=test.client.com,O=Test Org", logData.Core[TLSClientSubject])
	assert.Equal(t, "CN=Test CA,O=Test CA Org", logData.Core[TLSClientIssuer])
	assert.Equal(t, template.NotBefore.Format(time.RFC3339), logData.Core[TLSClientNotBefore])
	assert.Equal(t, template.NotAfter.Format(time.RFC3339), logData.Core[TLSClientNotAfter])
	assert.Equal(t, "1", logData.Core[TLSClientSerialNumber]) // SerialNumber.String()

	_, ok = logData.Core[TLSClientFingerprintSHA1].(string)
	assert.True(t, ok)
	_, ok = logData.Core[TLSClientFingerprintSHA256].(string)
	assert.True(t, ok)

	assert.Equal(t, "client.example.com,alt.client.example.org", logData.Core[TLSClientDNSNames])
	assert.Equal(t, "test@example.com", logData.Core[TLSClientEmailAddresses])
	assert.True(t, strings.Contains(logData.Core[TLSClientIPAddresses].(string), "10.0.0.1"))
	assert.True(t, strings.Contains(logData.Core[TLSClientIPAddresses].(string), "::1"))
	assert.Equal(t, "spiffe://example.com/workload/client", logData.Core[TLSClientURIs])

	// Test with no client certificates
	logDataNoClientCert := NewTCPLogData()
	connStateNoClientCert := &tls.ConnectionState{
		Version:     tls.VersionTLS12,
		CipherSuite: tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		ServerName:  "another.server.com",
	}
	logDataNoClientCert.PopulateTLS(connStateNoClientCert)
	assert.Equal(t, "TLS", logDataNoClientCert.Core[TransportProtocol])
	assert.Equal(t, "TLS1.2", logDataNoClientCert.Core[TLSVersion])
	_, clientSubjectOk := logDataNoClientCert.Core[TLSClientSubject]
	assert.False(t, clientSubjectOk, "TLSClientSubject should not be present if no peer certs")
}

func TestFinalize(t *testing.T) {
	logData := NewTCPLogData()
	startTime := time.Now().Add(-500 * time.Millisecond)
	logData.Core[StartUTC] = startTime

	logData.Finalize()

	duration, ok := logData.Core[Duration].(time.Duration)
	require.True(t, ok)
	assert.GreaterOrEqual(t, duration.Milliseconds(), int64(500))
	assert.Less(t, duration.Milliseconds(), int64(600), "Duration should be around 500ms")

	// Test with StartUTC not set (should not happen in normal flow)
	logDataNoStart := NewTCPLogData()
	logDataNoStart.Finalize()
	assert.Equal(t, time.Duration(0), logDataNoStart.Core[Duration])
}

func TestTlsVersionString(t *testing.T) {
	tests := []struct {
		version uint16
		want    string
	}{
		{tls.VersionTLS10, "TLS1.0"},
		{tls.VersionTLS11, "TLS1.1"},
		{tls.VersionTLS12, "TLS1.2"},
		{tls.VersionTLS13, "TLS1.3"},
		{0x0300, "unknown(0x0300)"}, // SSLv3, though not a const in crypto/tls
		{0, "unknown(0x0000)"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			assert.Equalf(t, tt.want, tlsVersionString(tt.version), "tlsVersionString(%v)", tt.version)
		})
	}
}

[end of pkg/middlewares/tcp/tcpaccesslog/logdata_test.go]
