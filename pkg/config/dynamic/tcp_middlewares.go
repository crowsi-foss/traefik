package dynamic

import "github.com/traefik/paerser/types"

// +k8s:deepcopy-gen=true

// TCPMiddleware holds the TCPMiddleware configuration.
type TCPMiddleware struct {
	InFlightConn *TCPInFlightConn `json:"inFlightConn,omitempty" toml:"inFlightConn,omitempty" yaml:"inFlightConn,omitempty" export:"true"`
	// Deprecated: please use IPAllowList instead.
	IPWhiteList *TCPIPWhiteList `json:"ipWhiteList,omitempty" toml:"ipWhiteList,omitempty" yaml:"ipWhiteList,omitempty" export:"true"`
	IPAllowList *TCPIPAllowList `json:"ipAllowList,omitempty" toml:"ipAllowList,omitempty" yaml:"ipAllowList,omitempty" export:"true"`

	AccessLog *TCPAccessLog `json:"accessLog,omitempty" toml:"accessLog,omitempty" yaml:"accessLog,omitempty" export:"true"`
}

// +k8s:deepcopy-gen=true

// TCPAccessLog holds the configuration settings for the TCP access logger.
// +k8s:deepcopy-gen=true
type TCPAccessLog struct {
	FilePath      string                 `description:"TCP access log file path. Stdout is used when omitted or empty." json:"filePath,omitempty" toml:"filePath,omitempty" yaml:"filePath,omitempty"`
	Format        string                 `description:"TCP access log format: json | common" json:"format,omitempty" toml:"format,omitempty" yaml:"format,omitempty" export:"true"`
	Filters       *TCPAccessLogFilters   `description:"TCP access log filters, used to keep only specific access logs." json:"filters,omitempty" toml:"filters,omitempty" yaml:"filters,omitempty" export:"true"`
	Fields        *TCPAccessLogFields    `description:"TCP AccessLogFields." json:"fields,omitempty" toml:"fields,omitempty" yaml:"fields,omitempty" export:"true"`
	BufferingSize int64                  `description:"Number of TCP access log lines to process in a buffered way." json:"bufferingSize,omitempty" toml:"bufferingSize,omitempty" yaml:"bufferingSize,omitempty" export:"true"`
}

// +k8s:deepcopy-gen=true

// TCPAccessLogFilters holds filters configuration for TCP access logs.
type TCPAccessLogFilters struct {
	MinDuration types.Duration `description:"Keep access logs when connection took longer than the specified duration." json:"minDuration,omitempty" toml:"minDuration,omitempty" yaml:"minDuration,omitempty" export:"true"`
	RequireTLS  bool           `description:"Keep access logs only for TLS connections." json:"requireTLS,omitempty" toml:"requireTLS,omitempty" yaml:"requireTLS,omitempty" export:"true"`
}

// +k8s:deepcopy-gen=true

// TCPAccessLogFields holds configuration for TCP access log fields.
type TCPAccessLogFields struct {
	DefaultMode string            `description:"Default mode for fields: keep | drop" json:"defaultMode,omitempty" toml:"defaultMode,omitempty" yaml:"defaultMode,omitempty"  export:"true"`
	Names       map[string]string `description:"Override mode for fields" json:"names,omitempty" toml:"names,omitempty" yaml:"names,omitempty" export:"true"`
}

// TCPInFlightConn holds the TCP InFlightConn middleware configuration.
// This middleware prevents services from being overwhelmed with high load,
// by limiting the number of allowed simultaneous connections for one IP.
// More info: https://doc.traefik.io/traefik/v3.5/middlewares/tcp/inflightconn/
type TCPInFlightConn struct {
	// Amount defines the maximum amount of allowed simultaneous connections.
	// The middleware closes the connection if there are already amount connections opened.
	// +kubebuilder:validation:Minimum=0
	Amount int64 `json:"amount,omitempty" toml:"amount,omitempty" yaml:"amount,omitempty" export:"true"`
}

// +k8s:deepcopy-gen=true

// TCPIPWhiteList holds the TCP IPWhiteList middleware configuration.
// Deprecated: please use IPAllowList instead.
type TCPIPWhiteList struct {
	// SourceRange defines the allowed IPs (or ranges of allowed IPs by using CIDR notation).
	SourceRange []string `json:"sourceRange,omitempty" toml:"sourceRange,omitempty" yaml:"sourceRange,omitempty"`
}

// +k8s:deepcopy-gen=true

// TCPIPAllowList holds the TCP IPAllowList middleware configuration.
// This middleware limits allowed requests based on the client IP.
// More info: https://doc.traefik.io/traefik/v3.5/middlewares/tcp/ipallowlist/
type TCPIPAllowList struct {
	// SourceRange defines the allowed IPs (or ranges of allowed IPs by using CIDR notation).
	SourceRange []string `json:"sourceRange,omitempty" toml:"sourceRange,omitempty" yaml:"sourceRange,omitempty"`
}
