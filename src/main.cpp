#include <arpa/inet.h>
#include <cstring>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
#include <format>
#include <slim/common/network/client/tcp.h>

namespace slim::common::network::client::tcp {

#ifdef SLIM_TLS_ENABLED
std::once_flag Connection::ssl_init_flag_;
#endif

Connection::Connection(std::string_view host, const uint16_t port, const bool is_tls, const int timeout_ms)
    : host_(host), port_(port), is_tls_(is_tls), timeout_ms_(timeout_ms) {
#ifndef SLIM_TLS_ENABLED
    if(is_tls_) throw network::NetworkException(network::ErrorStatus::TlsNotSupported);
#endif
    init_socket();
#ifdef SLIM_TLS_ENABLED
    if(is_tls_) {
        owns_ssl_ctx_ = true;
        ssl_ctx_ = SSL_CTX_new(TLS_client_method());
        init_tls();
    }
#endif
}

#ifdef SLIM_TLS_ENABLED
Connection::Connection(std::string_view host, const uint16_t port, SSL_CTX* ssl_ctx, const int timeout_ms)
    : host_(host), port_(port), is_tls_(true), timeout_ms_(timeout_ms), ssl_ctx_(ssl_ctx) {
    owns_ssl_ctx_ = false;
    init_socket();
    init_tls();
}
#endif

Connection::~Connection() {
#ifdef SLIM_TLS_ENABLED
    if(ssl_ != nullptr) {
        SSL_shutdown(ssl_);
        SSL_free(ssl_);
    }
    if(ssl_ctx_ != nullptr && owns_ssl_ctx_) {
        SSL_CTX_free(ssl_ctx_);
    }
#endif
    close(socket_handle_);
    if(addrinfo_ != nullptr) freeaddrinfo(addrinfo_);
}

void Connection::init_socket() {
    memset(&server_address_, 0, sizeof(server_address_));
    server_address_.sin_family = AF_INET;
    server_address_.sin_port = htons(port_);

    bool valid_host = false;
    struct in_addr ip_addr;
    auto ip_info_errno = inet_pton(AF_INET, host_.data(), &ip_addr);
    switch(ip_info_errno) {
        case 0: {
            struct addrinfo hints;
            memset(&hints, 0, sizeof(hints));
            hints.ai_family = AF_INET;
            hints.ai_socktype = SOCK_STREAM;
            auto address_info_errno = getaddrinfo(host_.data(), NULL, &hints, &addrinfo_);
            if(address_info_errno == 0) {
                valid_host = true;
                memcpy(&server_address_, addrinfo_->ai_addr, sizeof(struct sockaddr_in));
                server_address_.sin_port = htons(port_);
            }
            else {
                throw network::NetworkException(network::ErrorStatus::SocketAddressResolutionFailed, gai_strerror(address_info_errno));
            }
        }
        break;
        case 1:
            valid_host = true;
            server_address_.sin_addr = ip_addr;
            break;
        default:
            throw network::NetworkException(network::ErrorStatus::SocketAddressConversionFailed, strerror(errno));
    }

    if(valid_host) {
        socket_handle_ = socket(AF_INET, SOCK_STREAM, 0);
        if(socket_handle_ < 0) throw network::NetworkException(network::ErrorStatus::SocketCreationFailed, strerror(errno));

        auto flags = fcntl(socket_handle_, F_GETFL, 0);
        if(flags == -1) throw network::NetworkException(network::ErrorStatus::SocketFlagGetFailed, strerror(errno));

        if(fcntl(socket_handle_, F_SETFL, flags | O_NONBLOCK) == -1)
            throw network::NetworkException(network::ErrorStatus::SocketFlagSetFailed, strerror(errno));

        connect(socket_handle_, (struct sockaddr*)&server_address_, sizeof(server_address_));
        struct pollfd pfd = { socket_handle_, POLLOUT, 0 };
        auto poll_result = poll(&pfd, 1, timeout_ms_);

        if(poll_result == 0)
            throw network::NetworkException(network::ErrorStatus::SocketConnectionTimedOut, std::format("{}:{}", host_, port_));
        else if(poll_result < 0)
            throw network::NetworkException(network::ErrorStatus::SocketPollFailed, strerror(errno));

        int so_error = 0;
        socklen_t len = sizeof(so_error);
        getsockopt(socket_handle_, SOL_SOCKET, SO_ERROR, &so_error, &len);
        if(so_error != 0)
            throw network::NetworkException(network::ErrorStatus::SocketConnectionFailed, std::format("{}:{} => {}", host_, port_, strerror(so_error)));
    }
}

#ifdef SLIM_TLS_ENABLED
void Connection::init_tls() {
    std::call_once(ssl_init_flag_, []{ OPENSSL_init_ssl(0, nullptr); });
    ssl_ = SSL_new(ssl_ctx_);
    if(ssl_ == nullptr)
        throw network::NetworkException(network::ErrorStatus::TlsHandleCreationFailed,
            std::format("{}:{} => {}", host_, port_, ERR_reason_error_string(ERR_get_error())));

    if(SSL_set_fd(ssl_, socket_handle_) == 0)
        throw network::NetworkException(network::ErrorStatus::TlsSocketBindFailed,
            std::format("{}:{} => {}", host_, port_, ERR_reason_error_string(ERR_get_error())));

    SSL_set_tlsext_host_name(ssl_, host_.data());
    while(true) {
        auto ssl_result = SSL_connect(ssl_);
        if(ssl_result == 1) break;

        auto ssl_error = SSL_get_error(ssl_, ssl_result);
        if(ssl_error == SSL_ERROR_WANT_READ) {
            struct pollfd pfd = { socket_handle_, POLLIN, 0 };
            auto poll_result = poll(&pfd, 1, timeout_ms_);
            if(poll_result == 0)
                throw network::NetworkException(network::ErrorStatus::TlsHandshakeTimedOut,
                    std::format("{}:{}", host_, port_));
            else if(poll_result < 0)
                throw network::NetworkException(network::ErrorStatus::TlsHandshakePollFailed,
                    std::format("{}:{} => {}", host_, port_, strerror(errno)));
        }
        else if(ssl_error == SSL_ERROR_WANT_WRITE) {
            struct pollfd pfd = { socket_handle_, POLLOUT, 0 };
            auto poll_result = poll(&pfd, 1, timeout_ms_);
            if(poll_result == 0)
                throw network::NetworkException(network::ErrorStatus::TlsHandshakeTimedOut,
                    std::format("{}:{}", host_, port_));
            else if(poll_result < 0)
                throw network::NetworkException(network::ErrorStatus::TlsHandshakePollFailed,
                    std::format("{}:{} => {}", host_, port_, strerror(errno)));
        }
        else {
            throw network::NetworkException(network::ErrorStatus::TlsHandshakeFailed,
                std::format("{}:{} => {}", host_, port_, ERR_reason_error_string(ERR_get_error())));
        }
    }
}
#endif

network::ErrorStatus Connection::read(std::vector<uint8_t>& buf, const int timeout_ms) {
    while(true) {
        struct pollfd pfd = { socket_handle_, POLLIN, 0 };
        auto poll_result = poll(&pfd, 1, timeout_ms);
        if(poll_result == 0)     break;
        else if(poll_result < 0) return network::ErrorStatus::ReadPollFailed;

        auto offset = buf.size();
        buf.resize(offset + BUFFER_SIZE);
#ifdef SLIM_TLS_ENABLED
        int bytes_read = is_tls_ ? SSL_read(ssl_, buf.data() + offset, BUFFER_SIZE)
                                 : static_cast<int>(::read(socket_handle_, buf.data() + offset, BUFFER_SIZE));
#else
        auto bytes_read = ::read(socket_handle_, buf.data() + offset, BUFFER_SIZE);
#endif
        if(bytes_read > 0) {
            buf.resize(offset + static_cast<size_t>(bytes_read));
        }
        else if(bytes_read == 0) {
            buf.resize(offset);
            break;
        }
        else {
            buf.resize(offset);
#ifdef SLIM_TLS_ENABLED
            if(is_tls_) {
                auto ssl_error = SSL_get_error(ssl_, bytes_read);
                if(ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE) break;
                return network::ErrorStatus::ReadTlsFailed;
            }
#endif
            if(errno == EAGAIN || errno == EWOULDBLOCK) break;
            return network::ErrorStatus::ReadFailed;
        }
    }
    return network::ErrorStatus::OK;
}

network::ErrorStatus Connection::write(std::string_view payload, const int timeout_ms) {
    size_t total_sent = 0;
    while(total_sent < payload.size()) {
        struct pollfd pfd = { socket_handle_, POLLOUT, 0 };
        auto poll_result = poll(&pfd, 1, timeout_ms);
        if(poll_result == 0)     return network::ErrorStatus::WriteTimedOut;
        else if(poll_result < 0) return network::ErrorStatus::WritePollFailed;

#ifdef SLIM_TLS_ENABLED
        int bytes_sent = is_tls_ ? SSL_write(ssl_, payload.data() + total_sent, static_cast<int>(payload.size() - total_sent))
                                 : static_cast<int>(send(socket_handle_, payload.data() + total_sent, payload.size() - total_sent, 0));
#else
        auto bytes_sent = send(socket_handle_, payload.data() + total_sent, payload.size() - total_sent, 0);
#endif
        if(bytes_sent < 0) {
#ifdef SLIM_TLS_ENABLED
            if(is_tls_) {
                auto ssl_error = SSL_get_error(ssl_, bytes_sent);
                if(ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE) continue;
                return network::ErrorStatus::WriteTlsFailed;
            }
#endif
            if(errno == EAGAIN || errno == EWOULDBLOCK) continue;
            return network::ErrorStatus::WriteFailed;
        }
        total_sent += static_cast<size_t>(bytes_sent);
    }
    return network::ErrorStatus::OK;
}

} // namespace slim::common::network::client::tcp
