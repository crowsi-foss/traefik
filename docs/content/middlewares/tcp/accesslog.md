---
title: "TCP Access Log Middleware"
description: "Reference for the Traefik TCP Access Log middleware."
---

# TCP Access Log

Keeping Access Logs for TCP services.
{: .subtitle }

The TCP Access Log middleware enables Traefik to generate and write detailed logs for incoming TCP connections.
These logs provide valuable insights into the traffic passing through Traefik's TCP routers, including connection details, timing, and comprehensive client certificate information for mTLS setups.

## Configuration Examples

```yaml tab="YAML"
# Enable TCP Access Log for a middleware instance
tcp:
  middlewares:
    my-tcp-accesslog:
      accessLog:
        filePath: "/path/to/tcp-access.log"
        format: "json" # or "common"
        bufferingSize: 100
        filters:
          minDuration: "10ms" # Example filter
          requireTLS: true    # Example filter
        fields:
          defaultMode: "keep"
          names:
            TLSClientSubject: "keep"
            Duration: "drop" # Example to drop a specific field
```

```toml tab="TOML"
# Enable TCP Access Log for a middleware instance
[tcp.middlewares]
  [tcp.middlewares.my-tcp-accesslog.accessLog]
    filePath = "/path/to/tcp-access.log"
    format = "json" # or "common"
    bufferingSize = 100
    [tcp.middlewares.my-tcp-accesslog.accessLog.filters]
      minDuration = "10ms" # Example filter
      requireTLS = true    # Example filter
    [tcp.middlewares.my-tcp-accesslog.accessLog.fields]
      defaultMode = "keep"
      [tcp.middlewares.my-tcp-accesslog.accessLog.fields.names]
        TLSClientSubject = "keep"
        Duration = "drop" # Example to drop a specific field
```

## Configuration Options

### General

#### `filePath`

Set the path to the access log file. Defaults to stdout if not specified.

```yaml tab="YAML"
tcp:
  middlewares:
    my-tcp-accesslog:
      accessLog:
        filePath: "/var/log/traefik_tcp_access.log"
```

```toml tab="TOML"
[tcp.middlewares]
  [tcp.middlewares.my-tcp-accesslog.accessLog]
    filePath = "/var/log/traefik_tcp_access.log"
```

#### `format`

Set the access log format.
Two formats are available: `json` and `common`.
The default value is `json`.

The `common` format for TCP logs is similar to the CLF (Common Log Format) but adapted for TCP connections:

`ClientHost - <ClientUsername (not typically available for raw TCP)> - [Timestamp] "TCP Connected/TLS Handshake" <EntryPointName> <RouterName (if available)> <ServiceName (if available)> <Duration_ms>ms`

Actual username is rarely available in raw TCP unless a higher-level protocol parsed by another middleware provides it. It will default to "-".
RouterName and ServiceName depend on context propagation and might default to "-" if not available to the middleware.

```yaml tab="YAML"
tcp:
  middlewares:
    my-tcp-accesslog:
      accessLog:
        format: "common"
```

```toml tab="TOML"
[tcp.middlewares]
  [tcp.middlewares.my-tcp-accesslog.accessLog]
    format = "common"
```

#### `bufferingSize`

The `bufferingSize` option refers to the number of access log lines that are processed in a buffered way.
By default (`0`), the access log is not buffered.

```yaml tab="YAML"
tcp:
  middlewares:
    my-tcp-accesslog:
      accessLog:
        bufferingSize: 100
```

```toml tab="TOML"
[tcp.middlewares]
  [tcp.middlewares.my-tcp-accesslog.accessLog]
    bufferingSize = 100
```

### `filters`

Enable access log filters.

!!! todo
    The specific filter options like `minDuration` and `requireTLS` need to be implemented in the handler.
    The examples below are illustrative of potential filters.

#### `minDuration`

Keep access logs when the connection duration is longer than the specified duration.
The duration is provided in a format compatible with `time.ParseDuration`.

```yaml tab="YAML"
tcp:
  middlewares:
    my-tcp-accesslog:
      accessLog:
        filters:
          minDuration: "10ms"
```

```toml tab="TOML"
[tcp.middlewares]
  [tcp.middlewares.my-tcp-accesslog.accessLog.filters]
    minDuration = "10ms"
```

#### `requireTLS`

Keep access logs only for connections that were successfully negotiated over TLS.

```yaml tab="YAML"
tcp:
  middlewares:
    my-tcp-accesslog:
      accessLog:
        filters:
          requireTLS: true
```

```toml tab="TOML"
[tcp.middlewares]
  [tcp.middlewares.my-tcp-accesslog.accessLog.filters]
    requireTLS = true
```

### `fields`

Configure the fields to be included in the access log.

#### `fields.defaultMode`

The `defaultMode` option sets the default behavior for all fields: `keep` or `drop`.
Default: `keep`.

#### `fields.names`

The `names` option overrides the default behavior for specific fields.
Valid modes are `keep` or `drop`.

```yaml tab="YAML"
# Keep all fields by default, but drop the Duration field
tcp:
  middlewares:
    my-tcp-accesslog:
      accessLog:
        fields:
          defaultMode: keep
          names:
            Duration: drop
            TLSClientSerialNumber: keep # Explicitly keep, even if default is keep
```

```toml tab="TOML"
# Keep all fields by default, but drop the Duration field
[tcp.middlewares]
  [tcp.middlewares.my-tcp-accesslog.accessLog.fields]
    defaultMode = "keep"
    [tcp.middlewares.my-tcp-accesslog.accessLog.fields.names]
      Duration = "drop"
      TLSClientSerialNumber = "keep" # Explicitly keep, even if default is keep
```

### Available Log Fields

The following fields are available for TCP access logs.
Client certificate fields are only populated if mTLS is enabled and a client certificate is presented.

| Field Name                 | Description                                                                 | Example                                     |
|----------------------------|-----------------------------------------------------------------------------|---------------------------------------------|
| `StartUTC`                 | Connection start time in UTC                                                | `2023-10-27T10:20:30.123Z`                  |
| `StartLocal`               | Connection start time in local timezone                                     | `2023-10-27T12:20:30.123+02:00`             |
| `Duration`                 | Total connection duration                                                   | `15.203ms`                                  |
| `ConnectionID`             | Unique ID for the TCP connection within the Traefik instance                | `12345`                                     |
| `ClientAddr`               | Client's remote address (IP:Port)                                           | `192.168.1.100:54321`                       |
| `ClientHost`               | Client's remote IP address                                                  | `192.168.1.100`                             |
| `ClientPort`               | Client's remote port                                                        | `54321`                                     |
| `EntryPointName`           | Traefik entrypoint that handled the connection                              | `tcpin`                                     |
| `RouterName`               | Traefik TCP router name (if available)                                      | `my-tcp-router@file`                        |
| `ServiceName`              | Traefik TCP service name (if available)                                     | `my-tcp-service@file`                       |
| `TransportProtocol`        | Protocol used ("TCP" or "TLS")                                              | `TLS`                                       |
| `TLSVersion`               | TLS version used (if TLS)                                                   | `TLS1.3`                                    |
| `TLSCipherSuite`           | TLS cipher suite used (if TLS)                                              | `TLS_AES_128_GCM_SHA256`                    |
| `TLSServerName`            | Server Name Indication (SNI) from client (if TLS)                           | `myservice.example.com`                     |
| `TLSClientSubject`         | Client certificate: Subject (if mTLS)                                       | `CN=client1,O=MyOrg,C=US`                   |
| `TLSClientIssuer`          | Client certificate: Issuer (if mTLS)                                        | `CN=MyInternalCA,O=MyOrg,C=US`              |
| `TLSClientNotBefore`       | Client certificate: Validity start time (if mTLS)                           | `2023-01-01T00:00:00Z`                      |
| `TLSClientNotAfter`        | Client certificate: Validity end time (if mTLS)                             | `2024-01-01T00:00:00Z`                      |
| `TLSClientSerialNumber`    | Client certificate: Serial number (if mTLS)                                 | `1A2B3C4D5E6F`                              |
| `TLSClientFingerprintSHA1` | Client certificate: SHA1 fingerprint (if mTLS)                              | `a1b2c3d4...`                               |
| `TLSClientFingerprintSHA256`| Client certificate: SHA256 fingerprint (if mTLS)                             | `e1f2g3h4...`                               |
| `TLSClientDNSNames`        | Client certificate: Subject Alternative Names (DNS) (if mTLS), comma-separated | `alt1.example.com,alt2.example.com`         |
| `TLSClientEmailAddresses`  | Client certificate: Subject Alternative Names (Email) (if mTLS), comma-separated | `user1@example.com,user2@example.org`       |
| `TLSClientIPAddresses`     | Client certificate: Subject Alternative Names (IP) (if mTLS), comma-separated    | `10.0.0.1,10.0.0.2`                         |
| `TLSClientURIs`            | Client certificate: Subject Alternative Names (URI) (if mTLS), comma-separated   | `spiffe://trust.org/workload/client`      |

!!! note
    `RouterName` and `ServiceName` availability in logs depends on context propagation mechanisms within Traefik. They might not always be present or may default to a generic value if the specific router/service context isn't available at the point of logging for raw TCP connections.

[end of docs/content/middlewares/tcp/accesslog.md]
