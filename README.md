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
  - [Factories and object lifetime](#factories-and-object-lifetime)
  - [Methods](#methods)
- [Building](#building)
- [Dependencies](#dependencies)
  - [required_packages](#required_packages)
  - [external_dependencies](#external_dependencies)
  - [slim_flags](#slim_flags)
- [Examples](#examples)

## Overview

This library provides a non-blocking TCP client with io_uring-based async I/O and optional TLS via OpenSSL. It is designed for use in environments where predictable timeout behaviour, explicit error reporting, and minimal overhead are required.

TLS support requires OpenSSL and a caller-supplied `SSL_CTX`.

[↑ Top](#table-of-contents)

## Features

| Feature | Description |
|---------|-------------|
| Async I/O | Built on `io_uring` via `slim::common::io::Scheduler` |
| Async factories | `Connection::create` is a coroutine — construction never blocks the caller's thread |
| Per-call timeouts | `read` and `write` accept a `std::chrono::milliseconds` timeout |
| TLS support | Optional OpenSSL TLS via caller-supplied `SSL_CTX`; kTLS used when available, with automatic fallback to userspace TLS |
| Dual write interface | Accepts both `std::string_view` and `std::span<uint8_t>` payloads |
| `noexcept` I/O | `read` and `write` never throw; all errors returned as `ErrorStatus` |
| Out-of-memory safety | `read` catches `std::bad_alloc` on buffer growth and returns `ErrorStatus::OutOfMemory` |
| Identifying error messages | All exceptions include `host:port` and the underlying system or OpenSSL error string |
| Error model | Strong enum-based status reporting via `ErrorStatus` (from [SlimCommonNetwork](https://codeberg.org/greergan/SlimCommonNetwork)) |
| Value semantics | `Connection` is movable; factories return by value via `co_return` |
| Server-side accepted connections | fd-based factory accepts an already-connected socket from a TCP server, with optional server-side TLS handshake |

[↑ Top](#table-of-contents)

## Core API

### ErrorStatus enum

`ErrorStatus` is the scoped enum provided by [SlimCommonNetwork](https://codeberg.org/greergan/SlimCommonNetwork).

Values are grouped by concern:

| Group | Values | Meaning |
|-------|--------|---------|
| Socket setup | `SocketAddressResolutionFailed`, `SocketAddressConversionFailed`, `SocketCreationFailed`, `SocketFlagGetFailed`, `SocketFlagSetFailed` | Host resolution or socket initialisation failed |
| Connection | `SocketConnectionTimedOut`, `SocketPollFailed`, `SocketConnectionFailed` | Connection attempt failed or timed out |
| TLS | `TlsHandleCreationFailed`, `TlsSocketBindFailed`, `TlsHandshakeTimedOut`, `TlsHandshakePollFailed`, `TlsHandshakeFailed`, `KtlsUnavailable` | TLS initialisation or handshake failed |
| Read | `ReadPollFailed`, `ReadTlsFailed`, `ReadFailed` | Error during a read operation |
| Write | `WriteTimedOut`, `WriteTlsFailed`, `WriteFailed` | Error during a write operation |
| Memory | `OutOfMemory` | Buffer growth failed during read |
| `OK` | — | No error; the operation succeeded |

[↑ Top](#table-of-contents)

### NetworkException

`NetworkException` is the exception class provided by [SlimCommonNetwork](https://codeberg.org/greergan/SlimCommonNetwork).

Thrown by `Connection::create` on connection failure. Always includes a detail string of the form `host:port` or `host:port => reason`.

[↑ Top](#table-of-contents)

### Connection class

```cpp
slim::common::IO io;
slim::common::io::Scheduler scheduler{io};

auto conn = co_await slim::common::network::client::tcp::Connection::create(scheduler, "example.com", 80);
```

### Factories and object lifetime

Construction is asynchronous. Use the static `create` factory inside a coroutine, or drive it via `Scheduler::spawn` + `Scheduler::shutdown` for synchronous use.

| Form | Description |
|------|-------------|
| `Task<Connection> create(Scheduler&, string_view host, uint16_t port, milliseconds timeout = 5s)` | Plain TCP |
| `Task<Connection> create(Scheduler&, string_view host, uint16_t port, SSL_CTX*, milliseconds timeout = 5s)` | TLS with caller-supplied `SSL_CTX`; kTLS used when available, falling back to userspace TLS if unavailable (`KtlsUnavailable` is not an error in this path); context is not freed on destruction |
| `Task<Connection> create(Scheduler&, int fd, SSL_CTX* ssl_ctx = nullptr, milliseconds timeout = 5s)` | Accepted socket from a TCP server. Takes ownership of `fd`. If `ssl_ctx != nullptr`, performs a server-side TLS handshake. No host resolution is performed; `host` is empty for this form. |
| `Connection(const Connection&)` | Deleted |
| `Connection(Connection&&) noexcept` | Supported — returned by value from factories |
| `Connection& operator=(Connection&&)` | Deleted — move-assign is suppressed to enforce single-owner transfer via the factory return path only |

Factories throw `NetworkException` (via the coroutine exception mechanism) on any failure. The connection is fully established, including TLS handshake if applicable, before `create` completes.

[↑ Top](#table-of-contents)

### Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `read(std::vector<uint8_t>& buf, milliseconds timeout = 5s) noexcept` | `ErrorStatus` | Reads available data into `buf`, appending to any existing content. Returns `OK` on clean close. **Returns `OK` with no data appended on timeout** — callers must check buffer growth to distinguish timeout from data. |
| `write(std::string_view payload, milliseconds timeout = 5s) noexcept` | `ErrorStatus` | Sends a string payload, retrying until fully sent or an error occurs. Delegates to the `span` overload. |
| `write(std::span<uint8_t> payload, milliseconds timeout = 5s) noexcept` | `ErrorStatus` | Sends a binary payload, looping until fully sent. Handles `EAGAIN`/`EWOULDBLOCK` and TLS `WANT_READ`/`WANT_WRITE` internally. |

- Both `read` and `write` are `noexcept` — errors are always returned as `ErrorStatus`, never thrown.
- `read` uses an internal `BUFFER_SIZE` of `8192` bytes per read call and grows `buf` incrementally.
- `write` loops until the entire payload is sent, handling partial sends transparently.

[↑ Top](#table-of-contents)

## Building

This library is built using [SlimLibraryPackager](https://codeberg.org/greergan/SlimLibraryPackager). See that repository for build instructions.

[↑ Top](#table-of-contents)

## Dependencies

### required_packages

External package dependencies for this library are declared in the [`required_packages`](required_packages) file at the repository root. This file is read by [SlimLibraryPackager](https://codeberg.org/greergan/SlimLibraryPackager) during the build process to resolve dependencies and install them if not present.

```
SlimCommonNetwork
SlimCommonIo
SlimCommonTls
```

- [SlimCommonNetwork](https://codeberg.org/greergan/SlimCommonNetwork)
- [SlimCommonIo](https://codeberg.org/greergan/SlimCommonIo)
- [SlimCommonTls](https://codeberg.org/greergan/SlimCommonTls)

[↑ Top](#table-of-contents)

### external_dependencies

External (non-SlimCommon) dependencies are declared in the [`external_dependencies`](external_dependencies) file at the repository root.

```
boringssl
```

- [BoringSSL](https://boringssl.googlesource.com/boringssl) — required for TLS support

[↑ Top](#table-of-contents)

### slim_flags

Compiler and linker flags are declared in the [`slim_flags`](slim_flags) file at the repository root.

```
LD_FLAGS -lssl -lcrypto
```

[↑ Top](#table-of-contents)

## Examples

```cpp
// Plain TCP request
slim::common::IO io;
slim::common::io::Scheduler scheduler{io};

scheduler.spawn([&]() -> slim::common::io::Task<void> {
    try {
        auto conn = co_await Connection::create(scheduler, "example.com", 80);

        auto status = conn.write("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n");
        if (status != ErrorStatus::OK) co_return;

        std::vector<uint8_t> buf;
        conn.read(buf);
    }
    catch (const slim::common::network::NetworkException& e) {
        std::cerr << "Connection failed: " << e.what() << '\n';
    }
}());
scheduler.shutdown();
```

```cpp
// TLS request with caller-supplied SSL_CTX
SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());

scheduler.spawn([&]() -> slim::common::io::Task<void> {
    try {
        auto conn = co_await Connection::create(scheduler, "example.com", 443, ctx);

        auto status = conn.write("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n");
        if (status != ErrorStatus::OK) co_return;

        std::vector<uint8_t> buf;
        conn.read(buf);
    }
    catch (const slim::common::network::NetworkException& e) {
        std::cerr << "Connection failed: " << e.what() << '\n';
    }
}());
scheduler.shutdown();
SSL_CTX_free(ctx);
```

```cpp
// Shared SSL_CTX across multiple connections
SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());

for (const auto& path : { "/", "/other" }) {
    scheduler.spawn([&, path]() -> slim::common::io::Task<void> {
        auto conn = co_await Connection::create(scheduler, "example.com", 443, ctx);
        std::string req = std::string("GET ") + path + " HTTP/1.1\r\nHost: example.com\r\n\r\n";
        conn.write(req);
        std::vector<uint8_t> buf;
        conn.read(buf);
    }());
    scheduler.shutdown();
}

SSL_CTX_free(ctx);
```

```cpp
// Binary write via span
std::vector<uint8_t> payload = { 0x01, 0x02, 0x03 };

scheduler.spawn([&]() -> slim::common::io::Task<void> {
    auto conn = co_await Connection::create(scheduler, "192.168.1.1", 9000);
    auto status = conn.write(std::span<uint8_t>(payload));
    if (status != ErrorStatus::OK) co_return;
}());
scheduler.shutdown();
```

```cpp
// Custom timeout per operation
using ms = std::chrono::milliseconds;

scheduler.spawn([&]() -> slim::common::io::Task<void> {
    auto conn = co_await Connection::create(scheduler, "example.com", 80, ms(2000));

    auto status = conn.write("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n", ms(1000));
    if (status != ErrorStatus::OK) co_return;

    std::vector<uint8_t> buf;
    conn.read(buf, ms(1000));
}());
scheduler.shutdown();
```

```cpp
// Accepted fd from a TCP server (plain)
scheduler.spawn([&]() -> slim::common::io::Task<void> {
    try {
        auto conn = co_await Connection::create(scheduler, accepted_fd);
        std::vector<uint8_t> buf;
        conn.read(buf);
        conn.write(std::span<uint8_t>(buf));  // echo
    }
    catch (const slim::common::network::NetworkException& e) {
        std::cerr << "Accepted connection failed: " << e.what() << '\n';
    }
}());
scheduler.shutdown();
```

```cpp
// Accepted fd from a TCP server (server-side TLS)
SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());
// ... configure ctx with certificate and key ...

scheduler.spawn([&]() -> slim::common::io::Task<void> {
    try {
        auto conn = co_await Connection::create(scheduler, accepted_fd, ctx);
        std::vector<uint8_t> buf;
        conn.read(buf);
    }
    catch (const slim::common::network::NetworkException& e) {
        std::cerr << "TLS handshake failed: " << e.what() << '\n';
    }
}());
scheduler.shutdown();
// SSL_CTX_free(ctx) — caller retains ownership
```

[↑ Top](#table-of-contents)
