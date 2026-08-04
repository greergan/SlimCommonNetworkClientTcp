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
#ifdef ENABLE_LOGGING
#include <slim/common/log.h>
#endif

namespace slim::common::network::client::tcp {

using namespace slim::common::io;

// ── Private constructor ───────────────────────────────────────────────────────

Connection::Connection(Scheduler& scheduler, std::string_view host, uint16_t port)
    : scheduler_(scheduler), host_(host), port_(port) {
#ifdef ENABLE_LOGGING
    log::trace({__func__, "begins", __FILE__, __LINE__});
    log::debug({__func__, std::format("host='{}' port={}", host_, port_), __FILE__, __LINE__});
    log::trace({__func__, "ends", __FILE__, __LINE__});
#endif
}

// ── Destructor ────────────────────────────────────────────────────────────────

Connection::~Connection() {
#ifdef ENABLE_LOGGING
    log::trace({__func__, "begins", __FILE__, __LINE__});
#endif
    if (ssl_ != nullptr)     {
#ifdef ENABLE_LOGGING
        log::debug({__func__, std::format("shutting down and freeing ssl={}", (void*)ssl_), __FILE__, __LINE__});
#endif
        SSL_shutdown(ssl_); SSL_free(ssl_);
    }
    if (socket_fd_ >= 0) {
#ifdef ENABLE_LOGGING
        log::debug({__func__, std::format("closing socket_fd={}", socket_fd_), __FILE__, __LINE__});
#endif
        ::close(socket_fd_);
    }
    if (addrinfo_ != nullptr) {
#ifdef ENABLE_LOGGING
        log::debug({__func__, "freeing addrinfo", __FILE__, __LINE__});
#endif
        ::freeaddrinfo(addrinfo_);
    }
#ifdef ENABLE_LOGGING
    log::trace({__func__, "ends", __FILE__, __LINE__});
#endif
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
{
#ifdef ENABLE_LOGGING
    log::trace({__func__, "begins", __FILE__, __LINE__});
    log::debug({__func__, std::format("moved socket_fd={} host='{}' port={}", socket_fd_, host_, port_), __FILE__, __LINE__});
    log::trace({__func__, "ends", __FILE__, __LINE__});
#endif
}

// ── DNS resolution + socket creation ─────────────────────────────────────────

void Connection::resolve_and_create_socket() {
#ifdef ENABLE_LOGGING
    log::trace({__func__, "begins", __FILE__, __LINE__});
#endif
    memset(&server_addr_, 0, sizeof(server_addr_));
    server_addr_.sin_family = AF_INET;
    server_addr_.sin_port   = htons(port_);

    struct in_addr ip_addr;
    switch (::inet_pton(AF_INET, host_.data(), &ip_addr)) {
        case 1:
#ifdef ENABLE_LOGGING
            log::debug({__func__, std::format("host='{}' resolved as literal IPv4", host_), __FILE__, __LINE__});
#endif
            server_addr_.sin_addr = ip_addr;
            break;
        case 0: {
#ifdef ENABLE_LOGGING
            log::debug({__func__, std::format("host='{}' not a literal IP, attempting DNS", host_), __FILE__, __LINE__});
#endif
            addrinfo hints{};
            hints.ai_family   = AF_INET;
            hints.ai_socktype = SOCK_STREAM;
            int rc = ::getaddrinfo(host_.data(), nullptr, &hints, &addrinfo_);
            if (rc != 0) {
#ifdef ENABLE_LOGGING
                log::debug({__func__, std::format("getaddrinfo failed rc={} err='{}'", rc, ::gai_strerror(rc)), __FILE__, __LINE__});
                log::trace({__func__, "ends (throw SocketAddressResolutionFailed)", __FILE__, __LINE__});
#endif
                throw network::NetworkException(network::ErrorStatus::SocketAddressResolutionFailed,
                    std::format("{}:{} => {}", host_, port_, ::gai_strerror(rc)));
            }
#ifdef ENABLE_LOGGING
            log::debug({__func__, std::format("getaddrinfo succeeded addrinfo_={}", (void*)addrinfo_), __FILE__, __LINE__});
#endif
            memcpy(&server_addr_, addrinfo_->ai_addr, sizeof(struct sockaddr_in));
            server_addr_.sin_port = htons(port_);
            break;
        }
        default:
#ifdef ENABLE_LOGGING
            log::debug({__func__, std::format("inet_pton error errno={} err='{}'", errno, ::strerror(errno)), __FILE__, __LINE__});
            log::trace({__func__, "ends (throw SocketAddressConversionFailed)", __FILE__, __LINE__});
#endif
            throw network::NetworkException(network::ErrorStatus::SocketAddressConversionFailed,
                std::format("{}:{} => {}", host_, port_, ::strerror(errno)));
    }

    socket_fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
    if (socket_fd_ < 0) {
#ifdef ENABLE_LOGGING
        log::debug({__func__, std::format("socket() failed errno={} err='{}'", errno, ::strerror(errno)), __FILE__, __LINE__});
        log::trace({__func__, "ends (throw SocketCreationFailed)", __FILE__, __LINE__});
#endif
        throw network::NetworkException(network::ErrorStatus::SocketCreationFailed,
            std::format("{}:{} => {}", host_, port_, ::strerror(errno)));
    }
#ifdef ENABLE_LOGGING
    log::debug({__func__, std::format("socket created socket_fd_={}", socket_fd_), __FILE__, __LINE__});
#endif

    int flags = ::fcntl(socket_fd_, F_GETFL, 0);
    if (flags == -1) {
#ifdef ENABLE_LOGGING
        log::debug({__func__, std::format("F_GETFL failed errno={} err='{}'", errno, ::strerror(errno)), __FILE__, __LINE__});
        log::trace({__func__, "ends (throw SocketFlagGetFailed)", __FILE__, __LINE__});
#endif
        throw network::NetworkException(network::ErrorStatus::SocketFlagGetFailed,
            std::format("{}:{} => {}", host_, port_, ::strerror(errno)));
    }
#ifdef ENABLE_LOGGING
    log::debug({__func__, std::format("F_GETFL flags={:#x}", flags), __FILE__, __LINE__});
#endif

    if (::fcntl(socket_fd_, F_SETFL, flags | O_NONBLOCK) == -1) {
#ifdef ENABLE_LOGGING
        log::debug({__func__, std::format("F_SETFL O_NONBLOCK failed errno={} err='{}'", errno, ::strerror(errno)), __FILE__, __LINE__});
        log::trace({__func__, "ends (throw SocketFlagSetFailed)", __FILE__, __LINE__});
#endif
        throw network::NetworkException(network::ErrorStatus::SocketFlagSetFailed,
            std::format("{}:{} => {}", host_, port_, ::strerror(errno)));
    }
#ifdef ENABLE_LOGGING
    log::debug({__func__, std::format("socket set non-blocking socket_fd_={}", socket_fd_), __FILE__, __LINE__});
    log::trace({__func__, "ends", __FILE__, __LINE__});
#endif
}

// ── Async connect ─────────────────────────────────────────────────────────────

Task<void> Connection::connect_async(std::chrono::milliseconds timeout) {
#ifdef ENABLE_LOGGING
    log::trace({__func__, "begins", __FILE__, __LINE__});
    log::debug({__func__, std::format("socket_fd_={} timeout={}ms", socket_fd_, timeout.count()), __FILE__, __LINE__});
#endif
    Connect op{scheduler_, socket_fd_, reinterpret_cast<const sockaddr*>(&server_addr_), sizeof(server_addr_)};
    op.with_timeout(timeout);
    int rc = co_await op;
#ifdef ENABLE_LOGGING
    log::debug({__func__, std::format("connect rc={}", rc), __FILE__, __LINE__});
#endif
    if (rc < 0) {
#ifdef ENABLE_LOGGING
        log::debug({__func__, std::format("connect failed rc={} timed_out={}", rc, rc == -ETIMEDOUT), __FILE__, __LINE__});
        log::trace({__func__, "ends (throw)", __FILE__, __LINE__});
#endif
        throw network::NetworkException(
            rc == -ETIMEDOUT ? network::ErrorStatus::SocketConnectionTimedOut : network::ErrorStatus::SocketConnectionFailed,
            std::format("{}:{} => {}", host_, port_, ::strerror(-rc)));
    }
#ifdef ENABLE_LOGGING
    log::trace({__func__, "ends", __FILE__, __LINE__});
#endif
}

// ── Async TLS handshake + kTLS setup ─────────────────────────────────────────

// ── Async TLS handshake + kTLS setup ─────────────────────────────────────────

Task<void> Connection::tls_async(SSL_CTX* ssl_ctx, std::chrono::milliseconds timeout) {
#ifdef ENABLE_LOGGING
    log::trace({__func__, "begins", __FILE__, __LINE__});
    log::debug({__func__, std::format("ssl_ctx={} timeout={}ms", (void*)ssl_ctx, timeout.count()), __FILE__, __LINE__});
#endif
    SSL* ssl = nullptr;
    // Name the Task so its frame lifetime is tied to this local variable,
    // not to the temporary expression — temporary Task lifetimes across
    // co_await suspension points are not guaranteed by the standard.
    auto handshake_task = tls::do_client_handshake(scheduler_, socket_fd_, ssl_ctx, ssl, host_.data(), timeout);
    network::ErrorStatus hs = co_await handshake_task;
#ifdef ENABLE_LOGGING
    log::debug({__func__, std::format("handshake result hs={} ssl={}", static_cast<int>(hs), (void*)ssl), __FILE__, __LINE__});
#endif

    if (hs == network::ErrorStatus::KtlsUnavailable) {
        // ktls unavailable — ssl holds the userspace TLS handle, keep it
#ifdef ENABLE_LOGGING
        log::debug({__func__, std::format("kTLS unavailable, keeping userspace ssl={}", (void*)ssl), __FILE__, __LINE__});
#endif
        ssl_ = ssl;
    } else if (hs != network::ErrorStatus::OK) {
        if (ssl) SSL_free(ssl);
#ifdef ENABLE_LOGGING
        log::debug({__func__, std::format("handshake error hs={} ssl freed", static_cast<int>(hs)), __FILE__, __LINE__});
        log::trace({__func__, "ends (throw)", __FILE__, __LINE__});
#endif
        throw network::NetworkException(hs, std::format("{}:{}", host_, port_));
    } else {
        // hs == OK: ktls is active at the kernel level; the SSL* was set
        // by do_client_handshake but is no longer needed — free it here.
        // (do_client_handshake does NOT free ssl on OK — it sets ssl_out.)
#ifdef ENABLE_LOGGING
        log::debug({__func__, std::format("kTLS active, freeing userspace ssl={}", (void*)ssl), __FILE__, __LINE__});
#endif
        SSL_free(ssl);
    }
    is_tls_ = true;
#ifdef ENABLE_LOGGING
    log::debug({__func__, "is_tls_=true", __FILE__, __LINE__});
    log::trace({__func__, "ends", __FILE__, __LINE__});
#endif
}

// ── Factories ─────────────────────────────────────────────────────────────────

Task<Connection> Connection::create(Scheduler& scheduler, std::string_view host, uint16_t port,
                                    std::chrono::milliseconds timeout) {
#ifdef ENABLE_LOGGING
    log::trace({__func__, "begins", __FILE__, __LINE__});
    log::debug({__func__, std::format("host='{}' port={} timeout={}ms", host, port, timeout.count()), __FILE__, __LINE__});
#endif
    Connection c(scheduler, host, port);
    c.resolve_and_create_socket();
    co_await c.connect_async(timeout);
#ifdef ENABLE_LOGGING
    log::trace({__func__, "ends (co_return plain Connection)", __FILE__, __LINE__});
#endif
    co_return std::move(c);
}

Task<Connection> Connection::create(Scheduler& scheduler, std::string_view host, uint16_t port,
                                    SSL_CTX* ssl_ctx, std::chrono::milliseconds timeout) {
#ifdef ENABLE_LOGGING
    log::trace({__func__, "begins", __FILE__, __LINE__});
    log::debug({__func__, std::format("host='{}' port={} ssl_ctx={} timeout={}ms", host, port, (void*)ssl_ctx, timeout.count()), __FILE__, __LINE__});
#endif
    Connection c(scheduler, host, port);
    c.resolve_and_create_socket();
    co_await c.connect_async(timeout);
    co_await c.tls_async(ssl_ctx, timeout);
#ifdef ENABLE_LOGGING
    log::trace({__func__, "ends (co_return TLS Connection)", __FILE__, __LINE__});
#endif
    co_return std::move(c);
}

Task<Connection> Connection::create(Scheduler& scheduler, int fd, SSL_CTX* ssl_ctx,
                                    std::chrono::milliseconds timeout) {
#ifdef ENABLE_LOGGING
    log::trace({__func__, "begins", __FILE__, __LINE__});
    log::debug({__func__, std::format("fd={} ssl_ctx={} timeout={}ms", fd, (void*)ssl_ctx, timeout.count()), __FILE__, __LINE__});
#endif
    Connection c(scheduler, {}, 0);
    c.socket_fd_ = fd;
    if (ssl_ctx != nullptr) {
#ifdef ENABLE_LOGGING
        log::debug({__func__, std::format("ssl_ctx provided, initiating tls_async fd={}", fd), __FILE__, __LINE__});
#endif
        co_await c.tls_async(ssl_ctx, timeout);
    }
#ifdef ENABLE_LOGGING
    log::trace({__func__, "ends (co_return adopted-fd Connection)", __FILE__, __LINE__});
#endif
    co_return std::move(c);
}

// ── read ──────────────────────────────────────────────────────────────────────

Task<void> Connection::read(std::vector<uint8_t>& buf, std::chrono::milliseconds timeout) {
#ifdef ENABLE_LOGGING
    log::trace({__func__, "begins", __FILE__, __LINE__});
    log::debug({__func__, std::format("socket_fd_={} timeout={}ms ssl_={}", socket_fd_, timeout.count(), (void*)ssl_), __FILE__, __LINE__});
#endif
    while (true) {
        Poll poll_op{scheduler_, socket_fd_, POLLIN};
        poll_op.with_timeout(timeout);
        int poll_rc = co_await poll_op;
#ifdef ENABLE_LOGGING
        log::debug({__func__, std::format("poll_rc={}", poll_rc), __FILE__, __LINE__});
#endif

        if (poll_rc == 0) {
#ifdef ENABLE_LOGGING
            log::debug({__func__, "poll_rc==0, no more data, breaking", __FILE__, __LINE__});
#endif
            break;
        }
        if (poll_rc == -ECANCELED) {
#ifdef ENABLE_LOGGING
            log::debug({__func__, "poll_rc==-ECANCELED, linked timeout fired, breaking", __FILE__, __LINE__});
#endif
            break;  // linked timeout fired — no more data
        }
        if (poll_rc < 0) {
#ifdef ENABLE_LOGGING
            log::debug({__func__, std::format("poll error poll_rc={}", poll_rc), __FILE__, __LINE__});
            log::trace({__func__, "ends (throw ReadPollFailed)", __FILE__, __LINE__});
#endif
            throw network::NetworkException(network::ErrorStatus::ReadPollFailed);
        }

        auto offset = buf.size();
        try        { buf.resize(offset + BUFFER_SIZE); }
        catch(...) {
#ifdef ENABLE_LOGGING
            log::debug({__func__, "resize failed OOM", __FILE__, __LINE__});
            log::trace({__func__, "ends (throw OutOfMemory)", __FILE__, __LINE__});
#endif
            throw network::NetworkException(network::ErrorStatus::OutOfMemory);
        }

        int bytes_read = 0;
        if (ssl_ != nullptr) {
            // userspace TLS fallback (kTLS unavailable)
#ifdef ENABLE_LOGGING
            log::debug({__func__, std::format("SSL_read path ssl_={} offset={}", (void*)ssl_, offset), __FILE__, __LINE__});
#endif
            bytes_read = SSL_read(ssl_, buf.data() + offset, static_cast<int>(BUFFER_SIZE));
            if (bytes_read <= 0) {
                buf.resize(offset);
                int ssl_err = SSL_get_error(ssl_, bytes_read);
#ifdef ENABLE_LOGGING
                log::debug({__func__, std::format("SSL_read returned {} ssl_err={}", bytes_read, ssl_err), __FILE__, __LINE__});
#endif
                if (ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE) {
#ifdef ENABLE_LOGGING
                    log::debug({__func__, "SSL_ERROR_WANT_READ/WRITE, breaking", __FILE__, __LINE__});
#endif
                    break;
                }
#ifdef ENABLE_LOGGING
                log::trace({__func__, "ends (throw ReadTlsFailed)", __FILE__, __LINE__});
#endif
                throw network::NetworkException(network::ErrorStatus::ReadTlsFailed);
            }
            try        { buf.resize(offset + static_cast<size_t>(bytes_read)); }
            catch(...) {
#ifdef ENABLE_LOGGING
                log::debug({__func__, "resize after SSL_read failed OOM", __FILE__, __LINE__});
                log::trace({__func__, "ends (throw OutOfMemory)", __FILE__, __LINE__});
#endif
                throw network::NetworkException(network::ErrorStatus::OutOfMemory);
            }
#ifdef ENABLE_LOGGING
            log::debug({__func__, std::format("SSL_read bytes_read={} buf.size()={}", bytes_read, buf.size()), __FILE__, __LINE__});
#endif
            if (bytes_read < static_cast<int>(BUFFER_SIZE)) {
#ifdef ENABLE_LOGGING
                log::debug({__func__, "SSL_read partial read, breaking", __FILE__, __LINE__});
#endif
                break;
            }
        } else {
            // plain or kTLS — kernel decrypts transparently
#ifdef ENABLE_LOGGING
            log::debug({__func__, std::format("plain/kTLS recv path socket_fd_={} offset={}", socket_fd_, offset), __FILE__, __LINE__});
#endif
            Recv recv_op{scheduler_, socket_fd_, buf.data() + offset, BUFFER_SIZE};
            recv_op.with_timeout(timeout);
            bytes_read = co_await recv_op;
#ifdef ENABLE_LOGGING
            log::debug({__func__, std::format("recv bytes_read={}", bytes_read), __FILE__, __LINE__});
#endif
            if (bytes_read == 0) {
#ifdef ENABLE_LOGGING
                log::debug({__func__, "recv EOF, breaking", __FILE__, __LINE__});
#endif
                buf.resize(offset); break;
            }
            if (bytes_read < 0) {
                buf.resize(offset);
#ifdef ENABLE_LOGGING
                log::debug({__func__, std::format("recv error bytes_read={}", bytes_read), __FILE__, __LINE__});
#endif
                if (bytes_read == -EAGAIN || bytes_read == -EWOULDBLOCK) {
#ifdef ENABLE_LOGGING
                    log::debug({__func__, "EAGAIN/EWOULDBLOCK, breaking", __FILE__, __LINE__});
#endif
                    break;
                }
#ifdef ENABLE_LOGGING
                log::trace({__func__, "ends (throw ReadFailed)", __FILE__, __LINE__});
#endif
                throw network::NetworkException(network::ErrorStatus::ReadFailed);
            }
            try        { buf.resize(offset + static_cast<size_t>(bytes_read)); }
            catch(...) {
#ifdef ENABLE_LOGGING
                log::debug({__func__, "resize after recv failed OOM", __FILE__, __LINE__});
                log::trace({__func__, "ends (throw OutOfMemory)", __FILE__, __LINE__});
#endif
                throw network::NetworkException(network::ErrorStatus::OutOfMemory);
            }
#ifdef ENABLE_LOGGING
            log::debug({__func__, std::format("recv buf.size()={}", buf.size()), __FILE__, __LINE__});
#endif
            if (bytes_read < static_cast<int>(BUFFER_SIZE)) {
#ifdef ENABLE_LOGGING
                log::debug({__func__, "recv partial read, breaking", __FILE__, __LINE__});
#endif
                break;
            }
        }
    }
#ifdef ENABLE_LOGGING
    log::trace({__func__, "ends", __FILE__, __LINE__});
#endif
}

// ── write ─────────────────────────────────────────────────────────────────────

Task<void> Connection::write(std::string_view payload, std::chrono::milliseconds timeout) {
#ifdef ENABLE_LOGGING
    log::trace({__func__, "begins", __FILE__, __LINE__});
    log::debug({__func__, std::format("payload.size()={} timeout={}ms", payload.size(), timeout.count()), __FILE__, __LINE__});
    log::trace({__func__, "ends (delegating to write(span))", __FILE__, __LINE__});
#endif
    co_await write(std::span<uint8_t>(
        reinterpret_cast<uint8_t*>(const_cast<char*>(payload.data())), payload.size()), timeout);
}

Task<void> Connection::write(std::span<uint8_t> payload, std::chrono::milliseconds timeout) {
#ifdef ENABLE_LOGGING
    log::trace({__func__, "begins", __FILE__, __LINE__});
    log::debug({__func__, std::format("payload.size()={} timeout={}ms ssl_={}", payload.size(), timeout.count(), (void*)ssl_), __FILE__, __LINE__});
#endif
    size_t total_sent = 0;
    while (total_sent < payload.size()) {
        if (ssl_ != nullptr) {
            // userspace TLS fallback
#ifdef ENABLE_LOGGING
            log::debug({__func__, std::format("SSL_write path total_sent={}", total_sent), __FILE__, __LINE__});
#endif
            int sent = SSL_write(ssl_, payload.data() + total_sent,
                static_cast<int>(payload.size() - total_sent));
            if (sent <= 0) {
                int ssl_err = SSL_get_error(ssl_, sent);
#ifdef ENABLE_LOGGING
                log::debug({__func__, std::format("SSL_write returned {} ssl_err={}", sent, ssl_err), __FILE__, __LINE__});
#endif
                if (ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE) {
#ifdef ENABLE_LOGGING
                    log::debug({__func__, "SSL_ERROR_WANT_READ/WRITE, continuing", __FILE__, __LINE__});
#endif
                    continue;
                }
#ifdef ENABLE_LOGGING
                log::trace({__func__, "ends (throw WriteTlsFailed)", __FILE__, __LINE__});
#endif
                throw network::NetworkException(network::ErrorStatus::WriteTlsFailed);
            }
#ifdef ENABLE_LOGGING
            log::debug({__func__, std::format("SSL_write sent={} total_sent={}", sent, total_sent + static_cast<size_t>(sent)), __FILE__, __LINE__});
#endif
            total_sent += static_cast<size_t>(sent);
            continue;
        }

        // plain or kTLS path
#ifdef ENABLE_LOGGING
        log::debug({__func__, std::format("plain/kTLS send path total_sent={}", total_sent), __FILE__, __LINE__});
#endif
        Send send_op{scheduler_, socket_fd_, payload.data() + total_sent, payload.size() - total_sent};
        send_op.with_timeout(timeout);
        int send_rc = co_await send_op;
#ifdef ENABLE_LOGGING
        log::debug({__func__, std::format("send_rc={}", send_rc), __FILE__, __LINE__});
#endif

        if (send_rc < 0) {
            if (send_rc == -EAGAIN || send_rc == -EWOULDBLOCK) {
#ifdef ENABLE_LOGGING
                log::debug({__func__, "EAGAIN/EWOULDBLOCK, continuing", __FILE__, __LINE__});
#endif
                continue;
            }
            if (send_rc == -ETIMEDOUT) {
#ifdef ENABLE_LOGGING
                log::trace({__func__, "ends (throw WriteTimedOut)", __FILE__, __LINE__});
#endif
                throw network::NetworkException(network::ErrorStatus::WriteTimedOut);
            }
#ifdef ENABLE_LOGGING
            log::trace({__func__, "ends (throw WriteFailed)", __FILE__, __LINE__});
#endif
            throw network::NetworkException(network::ErrorStatus::WriteFailed);
        }
#ifdef ENABLE_LOGGING
        log::debug({__func__, std::format("sent send_rc={} total_sent={}", send_rc, total_sent + static_cast<size_t>(send_rc)), __FILE__, __LINE__});
#endif
        total_sent += static_cast<size_t>(send_rc);
    }
#ifdef ENABLE_LOGGING
    log::trace({__func__, "ends", __FILE__, __LINE__});
#endif
}

} // namespace slim::common::network::client::tcp
