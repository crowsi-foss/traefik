package server

import (
	"bufio"
	"crypto/tls"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	accesslog "github.com/traefik/traefik/v3/pkg/middlewares/accesslog"
	"github.com/traefik/traefik/v3/pkg/config/static"
)

func TestTCPAccessLogIntegration(t *testing.T) {
	logFile := "test_tcp_access.log"
	defer os.Remove(logFile)

	entryPoint := &static.EntryPoint{
		Address:   "127.0.0.1:0",
		Transport: &static.EntryPointsTransport{},
		AccessLog: &static.AccessLog{
			FilePath: logFile,
			Format:   "json",
		},
	}
	entryPoint.Transport.SetDefaults()

	ep, err := NewTCPEntryPoint(nil, "test", entryPoint, nil, nil)
	require.NoError(t, err)

	ln := ep.listener
	go ep.Start(nil)
	time.Sleep(100 * time.Millisecond)

	conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{InsecureSkipVerify: true})
	require.NoError(t, err)
	_, _ = conn.Write([]byte("hello"))
	_ = conn.Close()

	time.Sleep(200 * time.Millisecond)

	f, err := os.Open(logFile)
	require.NoError(t, err)
	defer f.Close()
	lines := 0
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lines++
		line := scanner.Text()
		require.True(t, strings.Contains(line, "clientAddr"), "log line should contain clientAddr")
	}
	require.GreaterOrEqual(t, lines, 1, "should log at least one entry")
}
