package accesslog

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/traefik/traefik/v3/pkg/tcp"
	"github.com/traefik/traefik/v3/pkg/types"
)

func TestHandler(t *testing.T) {
	logFile, err := os.CreateTemp(t.TempDir(), "access.log")
	require.NoError(t, err)

	defer os.Remove(logFile.Name())

	config := &types.TCPAccessLog{
		FilePath: logFile.Name(),
		Format:   "json",
	}

	next := tcp.HandlerFunc(func(conn tcp.WriteCloser) {
		_, err := conn.Write([]byte("test"))
		require.NoError(t, err)
	})

	handler, err := NewHandler(context.Background(), next, config, "accesslog")
	require.NoError(t, err)

	server, client := net.Pipe()

	go func() {
		handler.ServeTCP(newConn(server))
	}()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		var buf [4]byte
		_, err = client.Read(buf[:])
		require.NoError(t, err)
		assert.Equal(t, "test", string(buf[:]))
		server.Close()
		client.Close()
	}()

	wg.Wait()
	handler.Close()

	logContent, err := os.ReadFile(logFile.Name())
	require.NoError(t, err)

	assert.Contains(t, string(logContent), `"level":"info"`)
	assert.Contains(t, string(logContent), `"msg":"TCP connection"`)
}

func TestHandlerTLS(t *testing.T) {
	logFile, err := os.CreateTemp(t.TempDir(), "access.log")
	require.NoError(t, err)

	defer os.Remove(logFile.Name())

	config := &types.TCPAccessLog{
		FilePath: logFile.Name(),
		Format:   "json",
	}

	next := tcp.HandlerFunc(func(conn tcp.WriteCloser) {
		_, err := conn.Write([]byte("test"))
		require.NoError(t, err)
	})

	handler, err := NewHandler(context.Background(), next, config, "accesslog")
	require.NoError(t, err)

	server, client := net.Pipe()

	// Create a self-signed certificate for the server
	certTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "localhost"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	certBytes, err := x509.CreateCertificate(rand.Reader, certTmpl, certTmpl, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})

	serverCert, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)

	// Create a self-signed certificate for the client
	clientCertTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "client"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	clientPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	clientCertBytes, err := x509.CreateCertificate(rand.Reader, clientCertTmpl, clientCertTmpl, &clientPrivateKey.PublicKey, clientPrivateKey)
	require.NoError(t, err)

	clientCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientCertBytes})
	clientKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(clientPrivateKey)})

	clientCert, err := tls.X509KeyPair(clientCertPEM, clientKeyPEM)
	require.NoError(t, err)

	clientCAPool := x509.NewCertPool()
	clientCAPool.AppendCertsFromPEM(clientCertPEM)

	tlsServerConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAPool,
	}

	go func() {
		tlsServer := tls.Server(newConn(server), tlsServerConfig)
		handler.ServeTCP(tlsServer)
	}()

	tlsClientConfig := &tls.Config{
		Certificates:       []tls.Certificate{clientCert},
		InsecureSkipVerify: true,
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		tlsClient := tls.Client(client, tlsClientConfig)
		var buf [4]byte
		_, err = tlsClient.Read(buf[:])
		require.NoError(t, err)
		assert.Equal(t, "test", string(buf[:]))
		tlsClient.Close()
		server.Close()
		client.Close()
	}()

	wg.Wait()
	handler.Close()

	logContent, err := os.ReadFile(logFile.Name())
	require.NoError(t, err)

	assert.Contains(t, string(logContent), `"level":"info"`)
	assert.Contains(t, string(logContent), `"msg":"TCP connection"`)
	assert.Contains(t, string(logContent), `"TLSClientSubject":"CN=client"`)
}

// newConn is a helper function to create a tcp.WriteCloser from a net.Conn
func newConn(conn net.Conn) tcp.WriteCloser {
	return &conncloser{conn}
}

type conncloser struct {
	net.Conn
}

func (c *conncloser) CloseWrite() error {
	return nil
}
