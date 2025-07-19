package accesslog

const (
	// StartUTC is the map key used for the time at which request processing started.
	StartUTC = "StartUTC"
	// StartLocal is the map key used for the local time at which request processing started.
	StartLocal = "StartLocal"
	// Duration is the map key used for the total time taken by processing the response, including the origin server's time but
	// not the log writing time.
	Duration = "Duration"

	// RouterName is the map key used for the name of the Traefik router.
	RouterName = "RouterName"
	// ServiceName is the map key used for the name of the Traefik backend.
	ServiceName = "ServiceName"
	// ServiceAddr is the map key used for the IP:port of the Traefik backend (extracted from BackendURL).
	ServiceAddr = "ServiceAddr"

	// ClientAddr is the map key used for the remote address in its original form (usually IP:port).
	ClientAddr = "ClientAddr"
	// ClientHost is the map key used for the remote IP address from which the client request was received.
	ClientHost = "ClientHost"
	// ClientPort is the map key used for the remote TCP port from which the client request was received.
	ClientPort = "ClientPort"

	// TLSVersion is the version of TLS used in the request.
	TLSVersion = "TLSVersion"
	// TLSCipher is the cipher used in the request.
	TLSCipher = "TLSCipher"
	// TLSClientSubject is the string representation of the TLS client certificate's Subject.
	TLSClientSubject = "TLSClientSubject"
)

// CoreLogData holds the fields computed from the request/response.
type CoreLogData map[string]interface{}

// LogData is the data captured by the middleware so that it can be logged.
type LogData struct {
	Core CoreLogData
}
