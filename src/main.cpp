#include <arpa/inet.h>
#include <cstring>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
#include <format>
#include <span>
#include <slim/common/io/operations.h>
#include <slim/common/tls/client_handshake.h>
#include <slim/common/tls/key_material.h>
#include <slim/common/tls/ktls.h>
#include <slim/common/network/client/tcp.h>

namespace slim::common::network::client::tcp {

using namespace slim::common::io;

// ── Private constructor ───────────────────────────────────────────────────────

Connection::Connection(Scheduler& scheduler, std::string_view host, uint16_t port)
    : scheduler_(scheduler), host_(host), port_(port) {}

// ── Destructor ────────────────────────────────────────────────────────────────

Connection::~Connection() {
    if (ssl_ != nullptr)     { SSL_shutdown(ssl_); SSL_free(ssl_); }
    if (socket_fd_ >= 0)     ::close(socket_fd_);
    if (addrinfo_ != nullptr) ::freeaddrinfo(addrinfo_);
}

// ── Move constructor ──────────────────────────────────────────────────────────

Connection::Connection(Connection&& o) noexcept
    : scheduler_(o.scheduler_)
    , socket_fd_(std::exchange(o.socket_fd_, -1))
    , addrinfo_(std::exchange(o.addrinfo_, nullptr))
    , server_addr_(o.server_addr_)
    , host_(std::move(o.host_))
    , port_(o.port_)
    , is_tls_(o.is_tls_)
    , ssl_(std::exchange(o.ssl_, nullptr))
{}

// ── DNS resolution + socket creation ─────────────────────────────────────────

void Connection::resolve_and_create_socket() {
    memset(&server_addr_, 0, sizeof(server_addr_));
    server_addr_.sin_family = AF_INET;
    server_addr_.sin_port   = htons(port_);

    struct in_addr ip_addr;
    switch (::inet_pton(AF_INET, host_.data(), &ip_addr)) {
        case 1:
            server_addr_.sin_addr = ip_addr;
            break;
        case 0: {
            addrinfo hints{};
            hints.ai_family   = AF_INET;
            hints.ai_socktype = SOCK_STREAM;
            int rc = ::getaddrinfo(host_.data(), nullptr, &hints, &addrinfo_);
            if (rc != 0)
                throw network::NetworkException(network::ErrorStatus::SocketAddressResolutionFailed,
                    std::format("{}:{} => {}", host_, port_, ::gai_strerror(rc)));
            memcpy(&server_addr_, addrinfo_->ai_addr, sizeof(struct sockaddr_in));
            server_addr_.sin_port = htons(port_);
            break;
        }
        default:
            throw network::NetworkException(network::ErrorStatus::SocketAddressConversionFailed,
                std::format("{}:{} => {}", host_, port_, ::strerror(errno)));
    }

    socket_fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
    if (socket_fd_ < 0)
        throw network::NetworkException(network::ErrorStatus::SocketCreationFailed,
            std::format("{}:{} => {}", host_, port_, ::strerror(errno)));

    int flags = ::fcntl(socket_fd_, F_GETFL, 0);
    if (flags == -1)
        throw network::NetworkException(network::ErrorStatus::SocketFlagGetFailed,
            std::format("{}:{} => {}", host_, port_, ::strerror(errno)));

    if (::fcntl(socket_fd_, F_SETFL, flags | O_NONBLOCK) == -1)
        throw network::NetworkException(network::ErrorStatus::SocketFlagSetFailed,
            std::format("{}:{} => {}", host_, port_, ::strerror(errno)));
}

// ── Async connect ─────────────────────────────────────────────────────────────

Task<void> Connection::connect_async(std::chrono::milliseconds timeout) {
    Connect op{scheduler_, socket_fd_, reinterpret_cast<const sockaddr*>(&server_addr_), sizeof(server_addr_)};
    op.with_timeout(timeout);
    int rc = co_await op;
    if (rc < 0)
        throw network::NetworkException(
            rc == -ETIMEDOUT ? network::ErrorStatus::SocketConnectionTimedOut : network::ErrorStatus::SocketConnectionFailed,
            std::format("{}:{} => {}", host_, port_, ::strerror(-rc)));
}

// ── Async TLS handshake + kTLS setup ─────────────────────────────────────────

// ── Async TLS handshake + kTLS setup ─────────────────────────────────────────

Task<void> Connection::tls_async(SSL_CTX* ssl_ctx, std::chrono::milliseconds timeout) {
    SSL* ssl = nullptr;
    // Name the Task so its frame lifetime is tied to this local variable,
    // not to the temporary expression — temporary Task lifetimes across
    // co_await suspension points are not guaranteed by the standard.
    auto handshake_task = tls::do_client_handshake(scheduler_, socket_fd_, ssl_ctx, ssl, host_.data(), timeout);
    network::ErrorStatus hs = co_await handshake_task;

    if (hs == network::ErrorStatus::KtlsUnavailable) {
        // ktls unavailable — ssl holds the userspace TLS handle, keep it
        ssl_ = ssl;
    } else if (hs != network::ErrorStatus::OK) {
        if (ssl) SSL_free(ssl);
        throw network::NetworkException(hs, std::format("{}:{}", host_, port_));
    } else {
        // hs == OK: ktls is active at the kernel level; the SSL* was set
        // by do_client_handshake but is no longer needed — free it here.
        // (do_client_handshake does NOT free ssl on OK — it sets ssl_out.)
        SSL_free(ssl);
    }
    is_tls_ = true;
}

// ── Factories ─────────────────────────────────────────────────────────────────

Task<Connection> Connection::create(Scheduler& scheduler, std::string_view host, uint16_t port,
                                    std::chrono::milliseconds timeout) {
    Connection c(scheduler, host, port);
    c.resolve_and_create_socket();
    co_await c.connect_async(timeout);
    co_return std::move(c);
}

Task<Connection> Connection::create(Scheduler& scheduler, std::string_view host, uint16_t port,
                                    SSL_CTX* ssl_ctx, std::chrono::milliseconds timeout) {
    Connection c(scheduler, host, port);
    c.resolve_and_create_socket();
    co_await c.connect_async(timeout);
    co_await c.tls_async(ssl_ctx, timeout);
    co_return std::move(c);
}

Task<Connection> Connection::create(Scheduler& scheduler, int fd, SSL_CTX* ssl_ctx,
                                    std::chrono::milliseconds timeout) {
    Connection c(scheduler, {}, 0);
    c.socket_fd_ = fd;
    if (ssl_ctx != nullptr) co_await c.tls_async(ssl_ctx, timeout);
    co_return std::move(c);
}

// ── read ──────────────────────────────────────────────────────────────────────

Task<void> Connection::read(std::vector<uint8_t>& buf, std::chrono::milliseconds timeout) {
    while (true) {
        Poll poll_op{scheduler_, socket_fd_, POLLIN};
        poll_op.with_timeout(timeout);
        int poll_rc = co_await poll_op;

        if (poll_rc == 0)          break;
        if (poll_rc == -ECANCELED) break;  // linked timeout fired — no more data
        if (poll_rc < 0)  throw network::NetworkException(network::ErrorStatus::ReadPollFailed);

        auto offset = buf.size();
        try        { buf.resize(offset + BUFFER_SIZE); }
        catch(...) { throw network::NetworkException(network::ErrorStatus::OutOfMemory); }

        int bytes_read = 0;
        if (ssl_ != nullptr) {
            // userspace TLS fallback (kTLS unavailable)
            bytes_read = SSL_read(ssl_, buf.data() + offset, static_cast<int>(BUFFER_SIZE));
            if (bytes_read <= 0) {
                buf.resize(offset);
                int ssl_err = SSL_get_error(ssl_, bytes_read);
                if (ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE) break;
                throw network::NetworkException(network::ErrorStatus::ReadTlsFailed);
            }
            try        { buf.resize(offset + static_cast<size_t>(bytes_read)); }
            catch(...) { throw network::NetworkException(network::ErrorStatus::OutOfMemory); }
            if (bytes_read < static_cast<int>(BUFFER_SIZE)) break;
        } else {
            // plain or kTLS — kernel decrypts transparently
            Recv recv_op{scheduler_, socket_fd_, buf.data() + offset, BUFFER_SIZE};
            recv_op.with_timeout(timeout);
            bytes_read = co_await recv_op;
            if (bytes_read == 0) { buf.resize(offset); break; }
            if (bytes_read < 0) {
                buf.resize(offset);
                if (bytes_read == -EAGAIN || bytes_read == -EWOULDBLOCK) break;
                throw network::NetworkException(network::ErrorStatus::ReadFailed);
            }
            try        { buf.resize(offset + static_cast<size_t>(bytes_read)); }
            catch(...) { throw network::NetworkException(network::ErrorStatus::OutOfMemory); }
            if (bytes_read < static_cast<int>(BUFFER_SIZE)) break;
        }
    }
}

// ── write ─────────────────────────────────────────────────────────────────────

Task<void> Connection::write(std::string_view payload, std::chrono::milliseconds timeout) {
    co_await write(std::span<uint8_t>(
        reinterpret_cast<uint8_t*>(const_cast<char*>(payload.data())), payload.size()), timeout);
}

Task<void> Connection::write(std::span<uint8_t> payload, std::chrono::milliseconds timeout) {
    size_t total_sent = 0;
    while (total_sent < payload.size()) {
        if (ssl_ != nullptr) {
            // userspace TLS fallback
            int sent = SSL_write(ssl_, payload.data() + total_sent,
                static_cast<int>(payload.size() - total_sent));
            if (sent <= 0) {
                int ssl_err = SSL_get_error(ssl_, sent);
                if (ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE) continue;
                throw network::NetworkException(network::ErrorStatus::WriteTlsFailed);
            }
            total_sent += static_cast<size_t>(sent);
            continue;
        }

        // plain or kTLS path
        Send send_op{scheduler_, socket_fd_, payload.data() + total_sent, payload.size() - total_sent};
        send_op.with_timeout(timeout);
        int send_rc = co_await send_op;

        if (send_rc < 0) {
            if (send_rc == -EAGAIN || send_rc == -EWOULDBLOCK) continue;
            if (send_rc == -ETIMEDOUT) throw network::NetworkException(network::ErrorStatus::WriteTimedOut);
            throw network::NetworkException(network::ErrorStatus::WriteFailed);
        }
        total_sent += static_cast<size_t>(send_rc);
    }
}

} // namespace slim::common::network::client::tcp
