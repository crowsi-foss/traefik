package accesslog

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/sirupsen/logrus"
	"github.com/traefik/traefik/v3/pkg/tcp"
	traefiktls "github.com/traefik/traefik/v3/pkg/tls"
	"github.com/traefik/traefik/v3/pkg/types"
)

const (
	// DataTableKey is the key within the request context used to store the Log Data Table.
	DataTableKey = "LogDataTable"
)

type noopCloser struct {
	*os.File
}

func (n noopCloser) Write(p []byte) (int, error) {
	return n.File.Write(p)
}

func (n noopCloser) Close() error {
	// noop
	return nil
}

// Handler will write each request and its response to the access log.
type Handler struct {
	config *types.TCPAccessLog
	logger *logrus.Logger
	file   io.WriteCloser
	mu     sync.Mutex
	next   tcp.Handler
	wg     sync.WaitGroup
}

// NewHandler creates a new Handler.
func NewHandler(ctx context.Context, next tcp.Handler, config *types.TCPAccessLog, name string) (*Handler, error) {
	var file io.WriteCloser = noopCloser{os.Stdout}
	if len(config.FilePath) > 0 {
		f, err := openAccessLogFile(config.FilePath)
		if err != nil {
			return nil, fmt.Errorf("error opening access log file: %w", err)
		}
		file = f
	}

	formatter, err := NewLogFormatter(config.Format)
	if err != nil {
		return nil, fmt.Errorf("error creating new log formatter: %w", err)
	}

	logger := &logrus.Logger{
		Out:       file,
		Formatter: formatter,
		Hooks:     make(logrus.LevelHooks),
		Level:     logrus.InfoLevel,
	}

	logHandler := &Handler{
		config: config,
		logger: logger,
		file:   file,
		next:   next,
	}

	return logHandler, nil
}

func openAccessLogFile(filePath string) (*os.File, error) {
	dir := filepath.Dir(filePath)

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("failed to create log path %s: %w", dir, err)
	}

	file, err := os.OpenFile(filePath, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o664)
	if err != nil {
		return nil, fmt.Errorf("error opening file %s: %w", filePath, err)
	}

	return file, nil
}

func (h *Handler) ServeTCP(conn tcp.WriteCloser) {
	h.wg.Add(1)
	defer h.wg.Done()

	now := time.Now().UTC()

	core := CoreLogData{
		StartUTC:   now,
		StartLocal: now.Local(),
	}

	logDataTable := &LogData{
		Core: core,
	}

	ctx := context.WithValue(context.Background(), DataTableKey, logDataTable)

	core[ClientAddr] = conn.RemoteAddr().String()
	core[ClientHost], core[ClientPort], _ = net.SplitHostPort(conn.RemoteAddr().String())

	if tlsConn, ok := conn.(*tls.Conn); ok {
		if err := tlsConn.Handshake(); err != nil {
			log.Debug().Err(err).Msg("TLS handshake error")
		}
		state := tlsConn.ConnectionState()
		core[TLSVersion] = traefiktls.GetVersion(&state)
		core[TLSCipher] = traefiktls.GetCipherName(&state)
		if len(state.PeerCertificates) > 0 && state.PeerCertificates[0] != nil {
			core[TLSClientSubject] = state.PeerCertificates[0].Subject.String()
		}
	}

	defer func() {
		totalDuration := time.Now().UTC().Sub(core[StartUTC].(time.Time))
		core[Duration] = totalDuration
		h.logTheRoundTrip(ctx, logDataTable)
	}()

	h.next.ServeTCP(conn)
}

// Close closes the Logger (i.e. the file, drain logHandlerChan, etc).
func (h *Handler) Close() error {
	h.wg.Wait()
	return h.file.Close()
}

// Rotate closes and reopens the log file to allow for rotation by an external source.
func (h *Handler) Rotate() error {
	if h.config.FilePath == "" {
		return nil
	}

	if h.file != nil {
		defer func(f io.Closer) { _ = f.Close() }(h.file)
	}

	var err error
	h.file, err = os.OpenFile(h.config.FilePath, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o664)
	if err != nil {
		return err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.logger.Out = h.file
	return nil
}

func (h *Handler) logTheRoundTrip(ctx context.Context, logDataTable *LogData) {
	fields := logrus.Fields{}

	for k, v := range logDataTable.Core {
		fields[k] = v
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	h.logger.WithContext(ctx).WithFields(fields).Println("TCP connection")
}
