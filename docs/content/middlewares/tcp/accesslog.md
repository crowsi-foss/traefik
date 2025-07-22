# TCP Access Logging

Traefik now supports access logging for TCP connections, including mTLS (mutual TLS) client certificate details. This feature is enabled automatically when the global access log is configured—no additional configuration is required for TCP access logs beyond enabling access logging in your static configuration.

## How It Works
- When access logging is enabled (via the `accessLog` section in your static configuration), Traefik will log all incoming TCP connections on all TCP entrypoints.
- The TCP access log includes connection metadata such as source/destination IPs, bytes sent/received, connection duration, and (if mTLS is used) client certificate subject, serial number, and issuer.
- The log format and file path are inherited from the global access log configuration.

## Example Configuration

```yaml
entryPoints:
  mytcp:
    address: ":9000"
    # No need to add anything here for access logging

accessLog:
  filePath: "/var/log/traefik/access.log"
  format: json
```

## Log Fields
Each TCP access log entry contains:
- `timestamp`: Connection start time
- `entryPoint`: Name of the entrypoint
- `remoteAddr`: Client IP and port
- `localAddr`: Traefik IP and port
- `bytesReceived`: Total bytes received from client
- `bytesSent`: Total bytes sent to client
- `duration`: Connection duration in milliseconds
- `mtlsSubject`: (if mTLS) Subject of client certificate
- `mtlsSerialNumber`: (if mTLS) Serial number of client certificate
- `mtlsIssuer`: (if mTLS) Issuer of client certificate

## mTLS Details
If the client presents a certificate (mTLS), the following fields are included:
- `mtlsSubject`: Distinguished Name (DN) of the client certificate subject
- `mtlsSerialNumber`: Serial number of the client certificate
- `mtlsIssuer`: Distinguished Name (DN) of the certificate issuer

## Notes
- TCP access logging is always enabled for all TCP entrypoints when access logging is enabled globally.
- No additional configuration is required for TCP access logs.
- The log format (JSON, CLF, etc.) and file path are shared with HTTP access logs.

## Example Log Entry (JSON)
```json
{
  "timestamp": "2025-07-20T12:34:56Z",
  "entryPoint": "mytcp",
  "remoteAddr": "203.0.113.42:54321",
  "localAddr": "192.0.2.10:9000",
  "bytesReceived": 1024,
  "bytesSent": 2048,
  "duration": 1500,
  "mtlsSubject": "CN=client,O=Example Corp",
  "mtlsSerialNumber": "01A2B3C4D5E6F7",
  "mtlsIssuer": "CN=Example CA,O=Example Corp"
}
```

## See Also
- [Access Log documentation](../../access-log/overview.md)
- [TCP Middleware Overview](./overview.md)
