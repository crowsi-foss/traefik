package tcpaccesslog

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/traefik/traefik/v3/pkg/config/dynamic"
	"github.com/traefik/traefik/v3/pkg/tcp"
)

var connectionCounter uint64

// Handler is a TCP middleware that logs TCP connections.
type Handler struct {
	next           tcp.Handler
	config         *dynamic.TCPAccessLog
	logger         logger
	entryPointName string
	routerName     string
}

// logger defines the interface for logging access log data.
type logger interface {
	Log(data *TCPLogData)
	io.Closer
}

// jsonLogger logs data in JSON format.
type jsonLogger struct {
	writer io.WriteCloser
}

func newJSONLogger(writer io.WriteCloser) *jsonLogger {
	return &jsonLogger{writer: writer}
}

func (l *jsonLogger) Log(data *TCPLogData) {
	jsonData, err := json.Marshal(data.Core)
	if err != nil {
		log.Error().Err(err).Msg("Failed to marshal TCP access log data to JSON")
		return
	}
	fmt.Fprintln(l.writer, string(jsonData))
}

func (l *jsonLogger) Close() error {
	if l.writer != nil && l.writer != os.Stdout && l.writer != os.Stderr {
		return l.writer.Close()
	}
	return nil
}

// New creates a new TCP access log handler.
func New(ctx context.Context, next tcp.Handler, config *dynamic.TCPAccessLog, entryPointName, routerName string) (*Handler, error) {
	var logWriter io.WriteCloser = os.Stdout
	if config.FilePath != "" {
		dir := filepath.Dir(config.FilePath)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("failed to create log path %s: %w", dir, err)
		}

		file, err := os.OpenFile(config.FilePath, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o664)
		if err != nil {
			return nil, fmt.Errorf("error opening file %s: %w", config.FilePath, err)
		}
		logWriter = file
	}

	var currentLogger logger
	switch config.Format {
	case "json":
		currentLogger = newJSONLogger(logWriter)
	case "common":
		// TODO: Implement Common Log Format for TCP
		// For now, defaulting to JSON.
		log.Warn().Msgf("Common format for TCP access log is not yet implemented, defaulting to JSON.")
		currentLogger = newJSONLogger(logWriter)
	default:
		// Default to JSON if format is not specified or unknown
		currentLogger = newJSONLogger(logWriter)
	}

	return &Handler{
		next:           next,
		config:         config,
		logger:         currentLogger,
		entryPointName: entryPointName,
		routerName:     routerName,
	}, nil
}

// ServeTCP implements the tcp.Handler interface.
func (h *Handler) ServeTCP(conn tcp.WriteCloser) {
	connID := atomic.AddUint64(&connectionCounter, 1)
	logData := NewTCPLogData()
	logData.PopulateBasic(conn, h.entryPointName, h.routerName, connID)

	// Defer the logging until the connection handling is finished.
	defer func() {
		logData.Finalize() // Calculate duration
		h.logger.Log(logData)
	}()

	// Use the ConnectionStater interface to reliably get TLS connection state.
	if cs, ok := conn.(tcp.ConnectionStater); ok {
		state := cs.ConnectionState()
		if state != nil {
			logData.PopulateTLS(state)
		}
	}

	h.next.ServeTCP(conn)
}

// Close is called when the middleware is being stopped.
func (h *Handler) Close() error {
	return h.logger.Close()
}
