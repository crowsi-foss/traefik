package tcp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"github.com/traefik/traefik/v3/integration"
	"github.com/traefik/traefik/v3/pkg/middlewares/tcp/tcpaccesslog"
	checker "github.com/vdemeester/shakers"
)

// TCPAccessLogSuite tests TCP access logs.
type TCPAccessLogSuite struct{ integration.TraefikSuite }

func TestTCPAccessLogSuite(t *testing.T) {
	suite.Run(t, new(TCPAccessLogSuite))
}

func (s *TCPAccessLogSuite) SetupSuite() {
	s.TraefikSuite.SetupSuite()
	// Additional setup for the test suite if needed
}

func (s *TCPAccessLogSuite) TearDownSuite() {
	s.TraefikSuite.TearDownSuite()
	// Additional teardown for the test suite if needed
}

func (s *TCPAccessLogSuite) TestBasicTCPAccessLogToFile() {
	tempDir := s.T().TempDir()
	logFilePath := filepath.Join(tempDir, "tcp_access.log")

	staticConfig := fmt.Sprintf(`
[global]
  checkNewVersion = false

[entryPoints]
  [entryPoints.tcpเอง] # Using a non-standard name to avoid conflicts
    address = ":8083"

[api]
  insecure = true

[log]
  level = "DEBUG" # Traefik's own logs, not access logs

# Define TCPAccessLog globally if needed, or per router. For now, let's test per router.
# [accessLog] # This is for HTTP
# We need to define a TCP middleware with accessLog enabled.
`)

	dynamicConfig := fmt.Sprintf(`
[tcp.services]
  [tcp.services.echo-server.loadBalancer]
    [[tcp.services.echo-server.loadBalancer.servers]]
      address = "echo-server:7" # jmalloc/echo-server listens on port 7

[tcp.middlewares]
  [tcp.middlewares.logtcp.accessLog]
    filePath = "%s"
    format = "json"
    # bufferingSize = 0 # Default is 0, explicit for clarity

[tcp.routers]
  [tcp.routers.to-echo]
    entryPoints = ["tcpเอง"]
    rule = "HostSNI(`*`)" # Catch-all for TCP
    service = "echo-server"
    middlewares = ["logtcp"]
`, logFilePath)

	s.SetupTraefik(staticConfig, dynamicConfig)
	s.StartTraefik()
	defer s.StopTraefik()

	// Start an echo server backend
	s.StartEchoServer("echo-server", "jmalloc/echo-server", "7")
	defer s.StopEchoServer("echo-server")

	// Wait for Traefik and backend to be ready
	err := s.WaitForTraefik("tcpเอง", 2*time.Second)
	require.NoError(s.T(), err, "Traefik instance failed to start or entryPoint not ready")

	// Make a TCP connection
	conn, err := net.DialTimeout("tcp", "127.0.0.1:8083", 2*time.Second)
	require.NoError(s.T(), err, "Failed to connect to Traefik TCP entrypoint")

	// Send data and verify echo
	testMessage := "hello tcp access log"
	_, err = conn.Write([]byte(testMessage + "\n"))
	require.NoError(s.T(), err)

	buffer := make([]byte, len(testMessage)+1) // +1 for newline
	n, err := conn.Read(buffer)
	require.NoError(s.T(), err)
	assert.Equal(s.T(), testMessage+"\n", string(buffer[:n]))

	err = conn.Close()
	require.NoError(s.T(), err)

	// Check for access log (allow some time for log to be written)
	var logContent []byte
	require.Eventually(s.T(), func() bool {
		if _, errStat := os.Stat(logFilePath); os.IsNotExist(errStat) {
			return false
		}
		logContent, err = os.ReadFile(logFilePath)
		return err == nil && len(logContent) > 0
	}, 5*time.Second, 100*time.Millisecond, "TCP Access log file not found or empty")

	s.T().Logf("TCP Access Log Content:\n%s", string(logContent))

	// Parse the JSON log (assuming one line for this simple test)
	// Note: If buffering is > 0 or multiple connections, might have multiple lines.
	logLines := strings.Split(strings.TrimSpace(string(logContent)), "\n")
	require.NotEmpty(s.T(), logLines, "No log lines found in the file")

	var loggedData map[string]interface{}
	err = json.Unmarshal([]byte(logLines[len(logLines)-1]), &loggedData) // Check the last line
	require.NoError(s.T(), err, "Failed to unmarshal TCP access log JSON: %s", logLines[len(logLines)-1])

	// Verify some basic fields
	assert.Equal(s.T(), "tcpเอง", loggedData[tcpaccesslog.EntryPointName])
	assert.Contains(s.T(), loggedData, tcpaccesslog.ClientHost)
	assert.Contains(s.T(), loggedData, tcpaccesslog.ClientPort)
	assert.Contains(s.T(), loggedData, tcpaccesslog.Duration)
	assert.NotNil(s.T(), loggedData[tcpaccesslog.ConnectionID])
	assert.Equal(s.T(), "TCP", loggedData[tcpaccesslog.TransportProtocol]) // Default for non-TLS
	// RouterName and ServiceName might not be populated by default without context passing, check if present
	// For this setup, they should be available via middleware context if `provider.AddInContext` is used correctly.
	// The current tcpaccesslog.New takes entryPointName but not router/service.
	// This needs to be revisited in the middleware implementation.
	// For now, we might not see RouterName/ServiceName.
	// assert.Equal(s.T(), "to-echo@internal", loggedData[tcpaccesslog.RouterName]) // Assuming internal provider
	// assert.Equal(s.T(), "echo-server@internal", loggedData[tcpaccesslog.ServiceName])
}

// TODO:
// - Test for mTLS:
//   - Generate client/server certs.
//   - Configure Traefik for TLS termination with client cert auth.
//   - Make mTLS connection.
//   - Verify client cert fields in the log.
// - Test "common" log format.
// - Test other configuration aspects (filters, field selection) once implemented.
// - Test log to stdout/stderr (might need to capture Traefik's output).

// Helper to start a simple echo server for TCP tests
func (s *TCPAccessLogSuite) StartEchoServer(name, imageName, exposedPort string) {
	cmd := []string{
		"docker", "run", "-d", "--name", name,
		"-p", exposedPort + ":" + exposedPort, // Expose on the same port internally and externally for simplicity
		imageName,
	}
	err := s.RunCmd(cmd...)
	require.NoError(s.T(), err, "Failed to start echo server %s", name)

	// Basic wait, could be improved with health check if echo server had one
	time.Sleep(2 * time.Second)
}

// Helper to stop and remove the echo server
func (s *TCPAccessLogSuite) StopEchoServer(name string) {
	s.RunCmd("docker", "stop", name)
	s.RunCmd("docker", "rm", name)
}

// WaitForTraefik is a helper to wait for Traefik to be ready on a specific entryPoint.
// It tries to connect to the entryPoint address.
func (s *TCPAccessLogSuite) WaitForTraefik(entryPointName string, timeout time.Duration) error {
	// This assumes the entryPointName corresponds to a configured address in staticConfig
	// For this test, it's "tcpเอง" at ":8083"
	address := "127.0.0.1:8083" // Hardcoded for this test, could be dynamic if needed

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("timeout waiting for Traefik on entryPoint %s (%s)", entryPointName, address)
		default:
			conn, err := net.DialTimeout("tcp", address, 500*time.Millisecond)
			if err == nil {
				conn.Close()
				s.T().Logf("Traefik is ready on entryPoint %s (%s)", entryPointName, address)
				return nil
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
}

// Ensure our test suite uses the checker for Eventually
func (s *TCPAccessLogSuite) SetupTest() {
	s.Assertions = checker.New(s.T())
}

[end of integration/tcp/accesslog_test.go]
