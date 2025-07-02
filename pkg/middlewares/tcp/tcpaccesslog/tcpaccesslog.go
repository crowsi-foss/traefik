package tcpaccesslog

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/traefik/traefik/v3/pkg/tcp"
	"github.com/traefik/traefik/v3/pkg/types"
)

var connectionCounter uint64

// Handler is a TCP middleware that logs TCP connections.
type Handler struct {
	next           tcp.Handler
	config         *types.TCPAccessLog // TODO: Define this struct in pkg/types
	logger         logger
	entryPointName string
	// Potentially add routerName and serviceName if they can be passed down
}

// logger defines the interface for logging access log data.
// This allows for different log formats (e.g., JSON, Common Log Format).
type logger interface {
	Log(data *TCPLogData)
}

// jsonLogger logs data in JSON format.
type jsonLogger struct {
	writer io.Writer
}

func newJSONLogger(writer io.Writer) *jsonLogger {
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

// New creates a new TCP access log handler.
// TODO: The config parameter will be of a specific type from pkg/types.
// For now, using a placeholder and assuming stdout logging.
func New(ctx context.Context, next tcp.Handler, config *types.TCPAccessLog, entryPointName string) (*Handler, error) {
	// For now, hardcode to JSON logger writing to stdout
	// This will be configurable later.
	logWriter := os.Stdout
	currentLogger := newJSONLogger(logWriter)

	// TODO: Initialize config properly once types.TCPAccessLog is defined.
	// Example:
	// if config == nil {
	// 	config = &types.TCPAccessLog{}
	// }
	// if config.Format == "" {
	//    config.Format = "common" // or "json"
	// }
	// etc.

	return &Handler{
		next:           next,
		config:         config, // This will be the actual config struct
		logger:         currentLogger,
		entryPointName: entryPointName,
	}, nil
}

// ServeTCP implements the tcp.Handler interface.
func (h *Handler) ServeTCP(conn tcp.WriteCloser) {
	connID := atomic.AddUint64(&connectionCounter, 1)
	logData := NewTCPLogData()
	logData.PopulateBasic(conn, h.entryPointName, "", "", connID) // Router/Service name can be added if available

	// Check if the connection is a TLS connection to extract client certificate data
	// This requires the actual net.Conn. We need to see if tcp.WriteCloser can give us that,
	// or if we need to operate on a net.Conn before it's wrapped into a tcp.WriteCloser.
	// Assuming conn can be unwrapped or is already a net.Conn that might be a *tls.Conn.
	// This part is crucial and might need adjustment based on how middlewares handle connections.

	// Attempt to get underlying tls.Conn
	// This is a common pattern but might need to be adapted based on Traefik's specific connection wrapping.
	var tlsConn *tls.Conn
	realConn := conn
	// Unwrap if it's a known wrapper type, e.g. Traefik's trackedConnection
	// For now, we'll assume `conn` itself might be a `*tls.Conn` or can be asserted.
	// This might involve inspecting `conn`'s concrete type or using an interface method if available.

	// Example of how one might try to get to the *tls.Conn:
	type unwrapper interface {
		Unwrap() net.Conn
	}
	currentConn := net.Conn(conn) // Assuming tcp.WriteCloser is also a net.Conn
	for {
		if c, ok := currentConn.(*tls.Conn); ok {
			tlsConn = c
			break
		}
		if u, ok := currentConn.(unwrapper); ok {
			currentConn = u.Unwrap()
		} else {
			break
		}
	}

	if tlsConn != nil {
		// Ensure handshake is complete to access PeerCertificates.
		// If the handshake is not yet complete, calling ConnectionState() might block or return incomplete data.
		// For a server-side middleware, the handshake should typically be complete by the time data flows.
		// If Traefik handles TLS termination itself before this middleware, then this is the place.
		// If it's TLS passthrough, this middleware won't see decrypted data or client certs unless it IS the terminator.
		if err := tlsConn.Handshake(); err != nil {
			// Handshake failed, could log this as a specific event, but for basic access log,
			// we might just not get TLS info. Or the connection will close shortly.
			log.Debug().Err(err).Msg("TLS handshake error during access log processing")
		}
		connState := tlsConn.ConnectionState()
		logData.PopulateTLS(&connState)
	}

	// Defer the logging until the connection handling is finished.
	defer func() {
		logData.Finalize() // Calculate duration
		h.logger.Log(logData)
	}()

	// Call the next handler in the chain.
	// This blocks until the connection is closed or the handler returns.
	h.next.ServeTCP(conn)
}

// Close is called when the middleware is being stopped.
// It can be used to close any open resources, like log files.
func (h *Handler) Close() error {
	// If the logger has a Close method (e.g., for a file), call it here.
	// For stdout, there's nothing to close.
	// Example:
	// if c, ok := h.logger.(io.Closer); ok {
	//    return c.Close()
	// }
	return nil
}

// TODO:
// 1. Define `types.TCPAccessLog` struct in `pkg/types/accesslog.go` or a new file.
//    This struct will hold configuration like Format (json, common), FilePath, Filters, Fields.
// 2. Implement different logger types (e.g., Common Log Format for TCP).
// 3. Implement filtering based on configuration (e.g., log only TLS, log only specific IPs).
// 4. Implement field selection for the log output.
// 5. Integrate with the middleware builder in `pkg/server/middleware/tcp/middlewares.go`.
// 6. Handle log rotation if FilePath is used.
// 7. Address how to get the underlying `*tls.Conn` reliably from `tcp.WriteCloser`.
//    This might involve changes to `tcp.WriteCloser` or how connections are passed.
//    A common approach is that `tcp.WriteCloser` itself implements `ConnectionStater` interface:
//    type ConnectionStater interface { ConnectionState() tls.ConnectionState }
//    Then we can type assert: if cs, ok := conn.(ConnectionStater); ok { logData.PopulateTLS(cs.ConnectionState()) }
//    Alternatively, the `net.Conn` passed to `ServeTCP` might need to be the one that can be asserted to `*tls.Conn`.

[end of pkg/middlewares/tcp/tcpaccesslog/tcpaccesslog.go]
