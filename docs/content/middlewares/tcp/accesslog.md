---
title: "TCP Access Log Middleware"
description: "For routing and load balancing in Traefik Proxy, the TCP Access Log middleware enables and configures access logs for TCP connections. Read the technical documentation."
---

# TCP Access Log

The TCP Access Log middleware enables and configures access logs for TCP connections.

## Configuration

To enable the TCP access logs, you can configure it on the entrypoint:

```yaml tab="File (YAML)"
entryPoints:
  web:
    address: :80
    tcpAccessLog:
      filePath: "/path/to/tcp-access.log"
      format: "json"
```

```toml tab="File (TOML)"
[entryPoints]
  [entryPoints.web]
    address = ":80"
    [entryPoints.web.tcpAccessLog]
      filePath = "/path/to/tcp-access.log"
      format = "json"
```

```bash tab="CLI"
--entrypoints.web.address=:80
--entrypoints.web.tcpaccesslog.filepath=/path/to/tcp-access.log
--entrypoints.web.tcpaccesslog.format=json
```

### `filePath`

By default, TCP access logs are written to the standard output.
To write the logs into a log file, use the `filePath` option.

### `format`

_Optional, Default="common"_

By default, logs are written using the Common Log Format (CLF).
To write logs in JSON, use `json` in the `format` option.
If the given format is unsupported, the default (CLF) is used instead.

### `bufferingSize`

To write the logs in an asynchronous fashion, specify a `bufferingSize` option.
This option represents the number of log lines Traefik will keep in memory before writing them to the selected output.
In some cases, this option can greatly help performances.

## Available Fields

| Field                   | Description                                                                                                                                                         |
|-------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `StartUTC`              | The time at which request processing started.                                                                                                                       |
| `StartLocal`            | The local time at which request processing started.                                                                                                                 |
| `Duration`              | The total time taken (in nanoseconds) by processing the response, including the origin server's time but not the log writing time.                                  |
| `RouterName`            | The name of the Traefik router.                                                                                                                                     |
| `ServiceName`           | The name of the Traefik backend.                                                                                                                                    |
| `ServiceAddr`           | The IP:port of the Traefik backend (extracted from `ServiceURL`)                                                                                                    |
| `ClientAddr`            | The remote address in its original form (usually IP:port).                                                                                                          |
| `ClientHost`            | The remote IP address from which the client request was received.                                                                                                   |
| `ClientPort`            | The remote TCP port from which the client request was received.                                                                                                     |
| `TLSVersion`            | The TLS version used by the connection (e.g. `1.2`) (if connection is TLS).                                                                                         |
| `TLSCipher`             | The TLS cipher used by the connection (e.g. `TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA`) (if connection is TLS)                                                           |
| `TLSClientSubject`      | The string representation of the TLS client certificate's Subject (e.g. `CN=username,O=organization`)                                                               |
