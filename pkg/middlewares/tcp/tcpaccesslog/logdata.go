package tcpaccesslog

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
)

const (
	// Core Fields
	StartUTC     = "StartUTC"
	StartLocal   = "StartLocal"
	Duration     = "Duration"
	ConnectionID = "ConnectionID"

	// Connection Information
	ClientAddr        = "ClientAddr"
	ClientHost        = "ClientHost"
	ClientPort        = "ClientPort"
	EntryPointName    = "EntryPointName"
	RouterName        = "RouterName"
	ServiceName       = "ServiceName"
	TransportProtocol = "TransportProtocol"

	// TLS Information
	TLSVersion                 = "TLSVersion"
	TLSCipherSuite             = "TLSCipherSuite"
	TLSServerName              = "TLSServerName"
	TLSClientSubject           = "TLSClientSubject"
	TLSClientIssuer            = "TLSClientIssuer"
	TLSClientNotBefore         = "TLSClientNotBefore"
	TLSClientNotAfter          = "TLSClientNotAfter"
	TLSClientSerialNumber      = "TLSClientSerialNumber"
	TLSClientFingerprintSHA1   = "TLSClientFingerprintSHA1"
	TLSClientFingerprintSHA256 = "TLSClientFingerprintSHA256"
	TLSClientDNSNames          = "TLSClientDNSNames"
	TLSClientEmailAddresses    = "TLSClientEmailAddresses"
	TLSClientIPAddresses       = "TLSClientIPAddresses"
	TLSClientURIs              = "TLSClientURIs"
)

// TCPCoreLogData holds the core fields computed for the TCP connection.
type TCPCoreLogData map[string]interface{}

// TCPLogData is the data captured by the middleware for TCP access logging.
type TCPLogData struct {
	Core TCPCoreLogData
}

// NewTCPLogData creates and initializes a new TCPLogData.
func NewTCPLogData() *TCPLogData {
	return &TCPLogData{
		Core: make(TCPCoreLogData),
	}
}

// PopulateBasic extracts basic information from the connection and configuration.
func (tld *TCPLogData) PopulateBasic(conn net.Conn, entryPointName, routerName string, connID uint64) {
	now := time.Now()
	tld.Core[StartUTC] = now.UTC()
	tld.Core[StartLocal] = now
	tld.Core[ConnectionID] = connID

	if entryPointName != "" {
		tld.Core[EntryPointName] = entryPointName
	}
	if routerName != "" {
		tld.Core[RouterName] = routerName
	}

	if conn != nil && conn.RemoteAddr() != nil {
		clientAddr := conn.RemoteAddr().String()
		clientHost, clientPort, err := net.SplitHostPort(clientAddr)
		if err == nil {
			tld.Core[ClientAddr] = clientAddr
			tld.Core[ClientHost] = clientHost
			tld.Core[ClientPort] = clientPort
		} else {
			tld.Core[ClientAddr] = clientAddr
			tld.Core[ClientHost] = clientAddr
			tld.Core[ClientPort] = "-"
		}
	} else {
		tld.Core[ClientAddr] = "-"
		tld.Core[ClientHost] = "-"
		tld.Core[ClientPort] = "-"
	}
	tld.Core[TransportProtocol] = "TCP"
}

// PopulateTLS extracts TLS information from a tls.ConnectionState.
func (tld *TCPLogData) PopulateTLS(connState *tls.ConnectionState) {
	if connState == nil {
		return
	}

	tld.Core[TransportProtocol] = "TLS"
	tld.Core[TLSVersion] = tlsVersionString(connState.Version)
	tld.Core[TLSCipherSuite] = tls.CipherSuiteName(connState.CipherSuite)
	if connState.ServerName != "" {
		tld.Core[TLSServerName] = connState.ServerName
	}

	if len(connState.PeerCertificates) > 0 {
		clientCert := connState.PeerCertificates[0]
		tld.Core[TLSClientSubject] = clientCert.Subject.String()
		tld.Core[TLSClientIssuer] = clientCert.Issuer.String()
		tld.Core[TLSClientNotBefore] = clientCert.NotBefore.Format(time.RFC3339)
		tld.Core[TLSClientNotAfter] = clientCert.NotAfter.Format(time.RFC3339)
		if clientCert.SerialNumber != nil {
			tld.Core[TLSClientSerialNumber] = clientCert.SerialNumber.String()
		}

		rawCert := clientCert.Raw
		sha1Hash := sha1.Sum(rawCert)
		tld.Core[TLSClientFingerprintSHA1] = hex.EncodeToString(sha1Hash[:])
		sha256Hash := sha256.Sum256(rawCert)
		tld.Core[TLSClientFingerprintSHA256] = hex.EncodeToString(sha256Hash[:])

		if len(clientCert.DNSNames) > 0 {
			tld.Core[TLSClientDNSNames] = strings.Join(clientCert.DNSNames, ",")
		}
		if len(clientCert.EmailAddresses) > 0 {
			tld.Core[TLSClientEmailAddresses] = strings.Join(clientCert.EmailAddresses, ",")
		}
		if len(clientCert.IPAddresses) > 0 {
			var ips []string
			for _, ip := range clientCert.IPAddresses {
				ips = append(ips, ip.String())
			}
			tld.Core[TLSClientIPAddresses] = strings.Join(ips, ",")
		}
		if len(clientCert.URIs) > 0 {
			var uris []string
			for _, uri := range clientCert.URIs {
				uris = append(uris, uri.String())
			}
			tld.Core[TLSClientURIs] = strings.Join(uris, ",")
		}
	}
}

// Finalize sets the duration of the connection.
func (tld *TCPLogData) Finalize() {
	startTimeUTC, ok := tld.Core[StartUTC].(time.Time)
	if !ok {
		tld.Core[Duration] = 0
		return
	}
	tld.Core[Duration] = time.Since(startTimeUTC)
}

func tlsVersionString(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS1.0"
	case tls.VersionTLS11:
		return "TLS1.1"
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS13:
		return "TLS1.3"
	default:
		return fmt.Sprintf("unknown(0x%04x)", version)
	}
}
