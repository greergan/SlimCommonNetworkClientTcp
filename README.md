<a href="https://codeberg.org/greergan/SlimTS">
  <img src="https://raw.githubusercontent.com/greergan/SlimTS/master/assets/slimts_logo.png" width="75" alt="SlimTS Logo">
</a>

# SlimCommonNetworkClientTcp

A lightweight, non-blocking TCP client with optional TLS support in modern C++.  
Part of the [SlimCommon](https://codeberg.org/greergan/SlimCommon) library.  
Built using [SlimLibraryPackager](https://codeberg.org/greergan/SlimLibraryPackager).  
CI/CD supplied by unified workflows provided by [SlimLibraryPackager](https://codeberg.org/greergan/SlimLibraryPackager).

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Core API](#core-api)
  - [ErrorStatus enum](#errorstatus-enum)
  - [NetworkException](#networkexception)
  - [Connection class](#connection-class)
  - [Constructors and object lifetime](#constructors-and-object-lifetime)
  - [Methods](#methods)
- [Building](#building)
- [Dependencies](#dependencies)
  - [required_packages](#required_packages)
  - [external_dependencies](#external_dependencies)
  - [slim_flags](#slim_flags)
- [Examples](#examples)

## Overview

This library provides a non-blocking TCP client with poll-based timeout handling and optional TLS via OpenSSL. It is designed for use in environments where predictable timeout behaviour, explicit error reporting, and minimal overhead are required.

TLS support is conditionally compiled via the `SLIM_TLS_ENABLED` preprocessor flag. When disabled, attempting to construct a TLS connection throws immediately with `ErrorStatus::TlsNotSupported`.

[↑ Top](#table-of-contents)

## Features

| Feature | Description |
|---------|-------------|
| Non-blocking I/O | Socket set to `O_NONBLOCK`; all blocking points use `poll` with explicit timeouts |
| Per-call timeouts | `read` and `write` accept a `timeout_ms` override independent of the connection timeout |
| TLS support | Optional OpenSSL TLS via `SLIM_TLS_ENABLED`; shared or owned `SSL_CTX` |
| Thread-safe TLS init | OpenSSL global initialisation guarded by `std::once_flag` |
| Dual write interface | Accepts both `std::string_view` and `std::span<uint8_t>` payloads |
| `noexcept` I/O | `read` and `write` never throw; all errors returned as `ErrorStatus` |
| Out-of-memory safety | `read` catches `std::bad_alloc` on buffer growth and returns `ErrorStatus::OutOfMemory` |
| Identifying error messages | All exceptions include `host:port` and the underlying system or OpenSSL error string |
| Error model | Strong enum-based status reporting via `ErrorStatus` (from [SlimCommonNetwork](https://codeberg.org/greergan/SlimCommonNetwork)) |

[↑ Top](#table-of-contents)

## Core API

### ErrorStatus enum

`ErrorStatus` is the scoped enum provided by [SlimCommonNetwork](https://codeberg.org/greergan/SlimCommonNetwork).

Values are grouped by concern:

| Group | Values | Meaning |
|-------|--------|---------|
| Socket setup | `SocketAddressResolutionFailed`, `SocketAddressConversionFailed`, `SocketCreationFailed`, `SocketFlagGetFailed`, `SocketFlagSetFailed` | Host resolution or socket initialisation failed |
| Connection | `SocketConnectionTimedOut`, `SocketPollFailed`, `SocketConnectionFailed` | Connection attempt failed or timed out |
| TLS | `TlsNotSupported`, `TlsHandleCreationFailed`, `TlsSocketBindFailed`, `TlsHandshakeTimedOut`, `TlsHandshakePollFailed`, `TlsHandshakeFailed` | TLS initialisation or handshake failed |
| Read | `ReadPollFailed`, `ReadTlsFailed`, `ReadFailed` | Error during a read operation |
| Write | `WriteTimedOut`, `WritePollFailed`, `WriteTlsFailed`, `WriteFailed` | Error during a write operation |
| Memory | `OutOfMemory` | Buffer growth failed during read |
| `OK` | — | No error; the operation succeeded |

[↑ Top](#table-of-contents)

### NetworkException

`NetworkException` is the exception class provided by [SlimCommonNetwork](https://codeberg.org/greergan/SlimCommonNetwork).

Thrown by constructors on connection failure. Always includes a detail string of the form `host:port` or `host:port => reason`.

[↑ Top](#table-of-contents)

### Connection class

```cpp
slim::common::network::client::tcp::Connection conn("example.com", 443, true);
```

### Constructors and object lifetime

| Form | Condition | Description |
|------|-----------|-------------|
| `Connection()` | — | Deleted — no default construction |
| `Connection(std::string_view host, uint16_t port, bool is_tls = false, int timeout_ms = 5000)` | Always available | Plain TCP or TLS with auto-managed `SSL_CTX` |
| `Connection(std::string_view host, uint16_t port, SSL_CTX* ssl_ctx, int timeout_ms = 5000)` | `SLIM_TLS_ENABLED` only | TLS with a caller-supplied `SSL_CTX`; context is not freed on destruction |
| `Connection(const Connection&)` | — | Deleted — copies are not allowed |
| `Connection(Connection&&)` | — | Not supported |

Constructors throw `NetworkException` on any failure. The connection is fully established (including TLS handshake if applicable) by the time the constructor returns.

[↑ Top](#table-of-contents)

### Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `read(std::vector<uint8_t>& buf, int timeout_ms = 5000) noexcept` | `ErrorStatus` | Reads available data into `buf`, appending to any existing content. Returns `OK` on timeout (no data) or clean close. |
| `write(std::string_view payload, int timeout_ms = 5000) noexcept` | `ErrorStatus` | Sends a string payload, retrying until fully sent or an error occurs. |
| `write(std::span<uint8_t> payload, int timeout_ms = 5000) noexcept` | `ErrorStatus` | Sends a binary payload. `string_view` overload delegates to this. |

- Both `read` and `write` are `noexcept` — errors are always returned as `ErrorStatus`, never thrown.
- `read` uses an internal `BUFFER_SIZE` of `8192` bytes per read call and grows `buf` incrementally.
- `write` loops until the entire payload is sent, handling `EAGAIN`/`EWOULDBLOCK` and TLS `WANT_READ`/`WANT_WRITE` internally.

[↑ Top](#table-of-contents)

## Building

This library is built using [SlimLibraryPackager](https://codeberg.org/greergan/SlimLibraryPackager). See that repository for build instructions.

To enable TLS support, define `SLIM_TLS_ENABLED` during compilation and ensure OpenSSL is available.

[↑ Top](#table-of-contents)

## Dependencies

### required_packages

External package dependencies for this library are declared in the [`required_packages`](required_packages) file at the repository root. This file is read by [SlimLibraryPackager](https://codeberg.org/greergan/SlimLibraryPackager) during the build process to resolve dependencies and install them if not present.

```
SlimCommonNetwork
```

- [SlimCommonNetwork](https://codeberg.org/greergan/SlimCommonNetwork)

[↑ Top](#table-of-contents)

### external_dependencies

External (non-SlimCommon) dependencies are declared in the [`external_dependencies`](external_dependencies) file at the repository root. This file is read by [SlimLibraryPackager](https://codeberg.org/greergan/SlimLibraryPackager) during the build process to resolve and install them if not present.

```
boringssl
```

- [BoringSSL](https://boringssl.googlesource.com/boringssl) — used when `SLIM_TLS_ENABLED` is set

[↑ Top](#table-of-contents)

### slim_flags

Compiler and linker flags are declared in the [`slim_flags`](slim_flags) file at the repository root. This file is read by [SlimLibraryPackager](https://codeberg.org/greergan/SlimLibraryPackager) during the build process to apply the necessary flags.

```
CPP_FLAGS -DSLIM_TLS_ENABLED
LD_FLAGS -lssl -lcrypto
```

[↑ Top](#table-of-contents)

## Examples

```cpp
// Plain TCP request
try {
    slim::common::network::client::tcp::Connection conn("example.com", 80);

    auto status = conn.write("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n");
    if(status != ErrorStatus::OK) return status;

    std::vector<uint8_t> buf;
    status = conn.read(buf);
    if(status != ErrorStatus::OK) return status;
}
catch(const slim::common::network::NetworkException& e) {
    std::cerr << "Connection failed: " << e.what() << '\n';
}
```

```cpp
// TLS request with auto-managed context
try {
    slim::common::network::client::tcp::Connection conn("example.com", 443, true);

    auto status = conn.write("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n");
    if(status != ErrorStatus::OK) return status;

    std::vector<uint8_t> buf;
    status = conn.read(buf);
    if(status != ErrorStatus::OK) return status;
}
catch(const slim::common::network::NetworkException& e) {
    std::cerr << "Connection failed: " << e.what() << '\n';
}
```

```cpp
// TLS with shared SSL_CTX across multiple connections
SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());

try {
    {
        slim::common::network::client::tcp::Connection conn("example.com", 443, ctx);
        std::vector<uint8_t> buf;
        conn.write("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n");
        conn.read(buf);
    }
    {
        slim::common::network::client::tcp::Connection conn("example.com", 443, ctx);
        std::vector<uint8_t> buf;
        conn.write("GET /other HTTP/1.1\r\nHost: example.com\r\n\r\n");
        conn.read(buf);
    }
}
catch(const slim::common::network::NetworkException& e) {
    std::cerr << "Connection failed: " << e.what() << '\n';
}

SSL_CTX_free(ctx);
```

```cpp
// Binary write via span
std::vector<uint8_t> payload = { 0x01, 0x02, 0x03 };

try {
    slim::common::network::client::tcp::Connection conn("192.168.1.1", 9000);
    auto status = conn.write(std::span<uint8_t>(payload));
    if(status != ErrorStatus::OK) return status;
}
catch(const slim::common::network::NetworkException& e) {
    std::cerr << "Connection failed: " << e.what() << '\n';
}
```

```cpp
// Custom timeout per operation
try {
    slim::common::network::client::tcp::Connection conn("example.com", 80, false, 2000);

    auto status = conn.write("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n", 1000);
    if(status != ErrorStatus::OK) return status;

    std::vector<uint8_t> buf;
    status = conn.read(buf, 1000);
    if(status != ErrorStatus::OK) return status;
}
catch(const slim::common::network::NetworkException& e) {
    std::cerr << "Connection failed: " << e.what() << '\n';
}
```

[↑ Top](#table-of-contents)
