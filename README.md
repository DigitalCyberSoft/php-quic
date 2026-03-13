# php-quic

A PHP extension for QUIC transport as defined in [RFC 9000](https://www.rfc-editor.org/rfc/rfc9000). QUIC is the multiplexed UDP-based transport protocol used by HTTP/3.

This extension uses the [OpenSSL 3.2+](https://www.openssl.org/) native QUIC client API to provide QUIC connections and stream multiplexing with zero additional dependencies beyond OpenSSL.

## Features

- **QUIC client connections** with full TLS 1.3 handshake, ALPN negotiation, and peer certificate verification
- **Bidirectional and unidirectional streams** with independent read/write state tracking (RFC 9000 Section 2)
- **Stream multiplexing** with proper flow control and concurrent stream support
- **Configurable TLS** - ciphersuites, peer name verification, self-signed certificate handling, client certificates
- **Connection statistics** - bytes sent/received, streams opened
- **GC-safe reference counting** - streams hold references to their parent connection, preventing use-after-free

## Requirements

- PHP 8.4+
- OpenSSL 3.2+ with QUIC support (`openssl-devel` on Fedora/RHEL, `libssl-dev` on Debian/Ubuntu)

## Installation

### From COPR (Fedora/RHEL)

```bash
sudo dnf copr enable reversejames/php-quic
sudo dnf install php-quic
```

### From Source

```bash
phpize
./configure --enable-quic
make
make test
sudo make install
```

Add to your PHP configuration:

```ini
extension=quic.so
```

## Quick Start

```php
$conn = quic_connect('quic.aiortc.org', 443, ['alpn' => ['hq-interop']]);

$stream = $conn->openStream();
$stream->write("GET /\r\n");
$stream->conclude();

$response = $stream->read(8192, 5.0);
echo $response;

$conn->close();
```

## API

### QuicConnection Class

```php
$conn = new QuicConnection(string $host, int $port, array $options = []);
```

#### Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `alpn` | `string[]` | `[]` | ALPN protocol list (e.g., `['h3', 'hq-interop']`) |
| `verify_peer` | `bool` | `true` | Verify server certificate |
| `verify_peer_name` | `bool` | `true` | Verify hostname matches certificate |
| `peer_name` | `string` | (host) | Override hostname for SNI and verification |
| `allow_self_signed` | `bool` | `false` | Accept self-signed certificates |
| `cafile` | `string` | - | Path to CA certificate file |
| `capath` | `string` | - | Path to directory of CA certificates |
| `local_cert` | `string` | - | Path to client certificate (PEM) |
| `local_pk` | `string` | - | Path to client private key (PEM) |
| `ciphersuites` | `string` | - | TLS 1.3 ciphersuite string |

#### `connect(): bool`

Performs the QUIC handshake. The constructor configures the context; `connect()` initiates the connection.

```php
$conn = new QuicConnection('example.com', 443, ['alpn' => ['h3']]);
$conn->connect();
```

#### `openStream(int $type = QUIC_STREAM_BIDI): QuicStream`

Opens a new stream on the connection.

```php
$bidi = $conn->openStream();                    // bidirectional
$uni  = $conn->openStream(QUIC_STREAM_UNI);     // unidirectional
```

#### `acceptStream(float $timeout = 0.0): ?QuicStream`

Accepts an incoming server-initiated stream. Returns `null` if none available.

#### `close(int $errorCode = 0, string $reason = ''): bool`

Closes the connection with an optional application error code and reason.

#### `isConnected(): bool`

Returns whether the connection is currently active.

#### `getAlpn(): ?string`

Returns the negotiated ALPN protocol, or `null` if not yet connected.

#### `getPeerCertificate(): ?string`

Returns the peer's certificate in PEM format, or `null`.

#### `getStats(): array`

Returns connection statistics.

```php
$stats = $conn->getStats();
// ['bytes_sent' => 1234, 'bytes_received' => 5678, 'streams_opened' => 3]
```

### QuicStream Class

Streams are created via `QuicConnection::openStream()` and cannot be instantiated directly.

#### `write(string $data, int $flags = 0): int`

Writes data to the stream. Returns number of bytes written. Use `QUIC_WRITE_FLAG_CONCLUDE` to send data and FIN atomically.

```php
$stream->write("GET /\r\n");
$stream->write("final data", QUIC_WRITE_FLAG_CONCLUDE);  // write + FIN
```

#### `read(int $length = 8192, float $timeout = -1.0): ?string`

Reads up to `$length` bytes. Returns `null` on stream end or timeout. Negative timeout uses blocking mode; zero or positive uses non-blocking with deadline.

#### `conclude(): bool`

Sends FIN to signal the end of the write side (half-close).

#### `reset(int $errorCode = 0): bool`

Abruptly terminates the stream with an error code.

#### `getId(): int`

Returns the QUIC stream ID (client bidi: 0, 4, 8, ...; client uni: 2, 6, 10, ...).

#### `getType(): int`

Returns the stream type.

#### `getReadState(): int` / `getWriteState(): int`

Returns the current read/write state as a `QUIC_STREAM_STATE_*` constant.

#### `isReadable(): bool` / `isWritable(): bool`

Returns whether the stream can currently be read from or written to.

### Convenience Function

```php
$conn = quic_connect(string $host, int $port, array $options = []): QuicConnection;
```

Constructs and connects in one call. Equivalent to `new QuicConnection(...)` followed by `connect()`.

### Constants

```php
QUIC_STREAM_BIDI                // Bidirectional stream type
QUIC_STREAM_UNI                 // Unidirectional stream type

QUIC_STREAM_STATE_NONE          // Stream not yet active
QUIC_STREAM_STATE_OK            // Stream active and operational
QUIC_STREAM_STATE_FINISHED      // FIN received/sent
QUIC_STREAM_STATE_RESET_LOCAL   // Reset by local side
QUIC_STREAM_STATE_RESET_REMOTE  // Reset by remote side
QUIC_STREAM_STATE_CONN_CLOSED   // Parent connection closed

QUIC_WRITE_FLAG_CONCLUDE        // Send FIN with write (atomic write+FIN)
```

## Usage with php-qpack (HTTP/3)

This extension provides the transport layer. Combined with [php-qpack](https://github.com/DigitalCyberSoft/php-qpack) for header compression, you can build HTTP/3 clients:

```php
$conn = quic_connect('example.com', 443, ['alpn' => ['h3']]);
$stream = $conn->openStream();

$qpack = new QPackContext();
$headers = $qpack->encode([
    [':method', 'GET'],
    [':path', '/'],
    [':scheme', 'https'],
    [':authority', 'example.com'],
]);

// HTTP/3 HEADERS frame (type=0x01)
$stream->write(pack('CnC', 0x01, strlen($headers)) . $headers);
$stream->conclude();

$response = $stream->read(65536, 10.0);
$conn->close();
```

## Error Handling

- `ValueError` is thrown for invalid parameters (bad port, empty host, invalid stream type, invalid ALPN)
- `RuntimeException` is thrown for connection failures, stream errors, and operations on closed objects

## Tests

```bash
make test
```

55 tests covering core functionality, protocol compliance (RFC 9000), and security regression tests derived from bugs found in msquic, quic-go, quiche, ngtcp2, OpenSSL, and .NET QUIC implementations.

## Known Limitations

- **Client-only** - OpenSSL 3.2 supports QUIC client connections only. Server-side QUIC requires OpenSSL 3.5+ or an alternative backend.
- **No 0-RTT** - Early data / 0-RTT resumption is not yet exposed.
- **No session resumption** - TLS session tickets are not cached between connections.

## License

MIT
