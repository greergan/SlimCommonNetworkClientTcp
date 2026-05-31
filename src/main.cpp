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

#ifdef SLIM_TLS_ENABLED
std::once_flag slim::common::network::client::tcp::Connection::__ssl_init_flag;
#endif

slim::common::network::client::tcp::Connection::Connection(std::string_view _host, const uint16_t _port, const bool _is_tls, const int _timeout_ms) {
	__is_tls = _is_tls;
	__init_socket(_host, _port, _timeout_ms);
#ifdef SLIM_TLS_ENABLED
	if(!has_error() && __is_tls) {
		__ssl_ctx = SSL_CTX_new(TLS_client_method());
		__owns_ssl_ctx = true;
		__init_tls(_host, _timeout_ms);
	}
#else
	if(!has_error() && __is_tls) {
		__error_info = slim::ErrorInfo(ENOTSUP, std::format("{} => TLS requested but SLIM_TLS_ENABLED not set at compile time", __func__));
	}
#endif
}

#ifdef SLIM_TLS_ENABLED
slim::common::network::client::tcp::Connection::Connection(std::string_view _host, const uint16_t _port, SSL_CTX* _ssl_ctx, const int _timeout_ms) {
	__is_tls = true;
	__ssl_ctx = _ssl_ctx;
	__owns_ssl_ctx = false;
	__init_socket(_host, _port, _timeout_ms);
	if(!has_error()) {
		__init_tls(_host, _timeout_ms);
	}
}

slim::common::network::client::tcp::Connection::~Connection() {
#ifdef SLIM_TLS_ENABLED
	if(__ssl != nullptr) {
		SSL_shutdown(__ssl);
		SSL_free(__ssl);
	}
	if(__ssl_ctx != nullptr && __owns_ssl_ctx) {
		SSL_CTX_free(__ssl_ctx);
	}
#endif
	close(__socket_handle);
	if(__addrinfo != nullptr) {
		freeaddrinfo(__addrinfo);
	}
}

void slim::common::network::client::tcp::Connection::__init_socket(std::string_view _host, const uint16_t _port, const int _timeout_ms) {
	memset(&__server_address, 0, sizeof(__server_address));
	__server_address.sin_family = AF_INET;
	__server_address.sin_port = htons(_port);

	bool valid_host = false;
	struct in_addr ip_addr;
	auto ip_info_errno = inet_pton(AF_INET, _host.data(), &ip_addr);
	switch(ip_info_errno) {
		case 0: {
			struct addrinfo hints;
			memset(&hints, 0, sizeof(hints));
			hints.ai_family = AF_INET;
			hints.ai_socktype = SOCK_STREAM;
			auto address_info_errno = getaddrinfo(_host.data(), NULL, &hints, &__addrinfo);
			if(address_info_errno == 0) {
				valid_host = true;
				memcpy(&__server_address, __addrinfo->ai_addr, sizeof(struct sockaddr_in));
				__server_address.sin_port = htons(_port);
			}
			else {
				__error_info = slim::ErrorInfo(address_info_errno, std::format("{} => unable to resolve host => {}", __func__, gai_strerror(address_info_errno)));
			}
		}
		break;
		case 1:
			valid_host = true;
			__server_address.sin_addr = ip_addr;
			break;
		default:
			__error_info = slim::ErrorInfo(errno, std::format("{} => unable to convert IP address => {} => {}", __func__, _host, strerror(errno)));
			break;
	}

	if(valid_host) {
		__socket_handle = socket(AF_INET, SOCK_STREAM, 0);
		if(__socket_handle < 0) {
			__error_info = slim::ErrorInfo(errno, std::format("{} => unable to secure socket => {}", __func__, strerror(errno)));
		}
		else {
			auto flags = fcntl(__socket_handle, F_GETFL, 0);
			if(flags == -1) {
				__error_info = slim::ErrorInfo(errno, std::format("{} => unable to secure socket flags => {}", __func__, strerror(errno)));
			}
			else {
				if(fcntl(__socket_handle, F_SETFL, flags | O_NONBLOCK) == -1) {
					__error_info = slim::ErrorInfo(errno, std::format("{} => unable to set socket flags => {}", __func__, strerror(errno)));
				}
				else {
					connect(__socket_handle, (struct sockaddr*)&__server_address, sizeof(__server_address));
					struct pollfd pfd = { __socket_handle, POLLOUT, 0 };
					auto poll_result = poll(&pfd, 1, _timeout_ms);
					if(poll_result == 0) {
						__error_info = slim::ErrorInfo(ETIMEDOUT, std::format("{} => connection timed out => {}:{}", __func__, _host, _port));
					}
					else if(poll_result < 0) {
						__error_info = slim::ErrorInfo(errno, std::format("{} => poll failed => {}", __func__, strerror(errno)));
					}
					else {
						int so_error = 0;
						socklen_t len = sizeof(so_error);
						getsockopt(__socket_handle, SOL_SOCKET, SO_ERROR, &so_error, &len);
						if(so_error != 0) {
							__error_info = slim::ErrorInfo(so_error, std::format("{} => connection to server failed for => {}:{} => {}", __func__, _host, _port, strerror(so_error)));
						}
					}
				}
			}
		}
	}
}

void slim::common::network::client::tcp::Connection::__init_tls(std::string_view _host, const int _timeout_ms) {
	std::call_once(__ssl_init_flag, []{ OPENSSL_init_ssl(0, nullptr); });
	__ssl = SSL_new(__ssl_ctx);
	if(__ssl == nullptr) {
		__error_info = slim::ErrorInfo(errno, std::format("{} => unable to create SSL handle => {}", __func__, ERR_reason_error_string(ERR_get_error())));
		return;
	}
	if(SSL_set_fd(__ssl, __socket_handle) == 0) {
		__error_info = slim::ErrorInfo(errno, std::format("{} => unable to bind SSL to socket => {}", __func__, ERR_reason_error_string(ERR_get_error())));
		return;
	}
	SSL_set_tlsext_host_name(__ssl, _host.data());
	while(true) {
		auto ssl_result = SSL_connect(__ssl);
		if(ssl_result == 1) {
			break;
		}
		auto ssl_error = SSL_get_error(__ssl, ssl_result);
		if(ssl_error == SSL_ERROR_WANT_READ) {
			struct pollfd pfd = { __socket_handle, POLLIN, 0 };
			auto poll_result = poll(&pfd, 1, _timeout_ms);
			if(poll_result == 0) {
				__error_info = slim::ErrorInfo(ETIMEDOUT, std::format("{} => SSL handshake timed out", __func__));
				return;
			}
			else if(poll_result < 0) {
				__error_info = slim::ErrorInfo(errno, std::format("{} => SSL handshake poll failed => {}", __func__, strerror(errno)));
				return;
			}
		}
		else if(ssl_error == SSL_ERROR_WANT_WRITE) {
			struct pollfd pfd = { __socket_handle, POLLOUT, 0 };
			auto poll_result = poll(&pfd, 1, 5000);
			if(poll_result == 0) {
				__error_info = slim::ErrorInfo(ETIMEDOUT, std::format("{} => SSL handshake timed out", __func__));
				return;
			}
			else if(poll_result < 0) {
				__error_info = slim::ErrorInfo(errno, std::format("{} => SSL handshake poll failed => {}", __func__, strerror(errno)));
				return;
			}
		}
		else {
			__error_info = slim::ErrorInfo(ssl_error, std::format("{} => SSL handshake failed => {}", __func__, ERR_reason_error_string(ERR_get_error())));
			return;
		}
	}
}
#endif

slim::ErrorInfo slim::common::network::client::tcp::Connection::get_error() const {
	return __error_info;
}

bool slim::common::network::client::tcp::Connection::has_error() const {
	return __error_info.has_error();
}

slim::SlimValue slim::common::network::client::tcp::Connection::read(const int _timeout_ms) {
	slim::SlimValue result = slim_storage_container{};
	auto& container = result.get<slim_storage_container>();
	while(true) {
		struct pollfd pfd = { __socket_handle, POLLIN, 0 };
		auto poll_result = poll(&pfd, 1, _timeout_ms);
		if(poll_result == 0) {
			break;
		}
		else if(poll_result < 0) {
			result.set_error(slim::ErrorInfo(errno, std::format("{} => poll failed => {}", __func__, strerror(errno))));
			break;
		}
		auto offset = container.size();
		container.resize(offset + BUFFER_SIZE);
#ifdef SLIM_TLS_ENABLED
		int bytes_read = __is_tls ? SSL_read(__ssl, container.data() + offset, BUFFER_SIZE)
		                          : static_cast<int>(::read(__socket_handle, container.data() + offset, BUFFER_SIZE));
#else
		auto bytes_read = ::read(__socket_handle, container.data() + offset, BUFFER_SIZE);
#endif
		if(bytes_read > 0) {
			container.resize(offset + static_cast<size_t>(bytes_read));
		}
		else if(bytes_read == 0) {
			container.resize(offset);
			break;
		}
		else {
			container.resize(offset);
#ifdef SLIM_TLS_ENABLED
			if(__is_tls) {
				auto ssl_error = SSL_get_error(__ssl, bytes_read);
				if(ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE) {
					break;
				}
				result.set_error(slim::ErrorInfo(ssl_error, std::format("{} => SSL read failed => {}", __func__, ERR_reason_error_string(ERR_get_error()))));
				break;
			}
#endif
			if(errno == EAGAIN || errno == EWOULDBLOCK) {
				break;
			}
			result.set_error(slim::ErrorInfo(errno, std::format("{} => read failed => {}", __func__, strerror(errno))));
			break;
		}
	}
	return result;
}

slim::SlimValue slim::common::network::client::tcp::Connection::write(std::string_view _payload, const int _timeout_ms) {
	slim::SlimValue result = true;
	size_t total_sent = 0;
	while(total_sent < _payload.size()) {
		struct pollfd pfd = { __socket_handle, POLLOUT, 0 };
		auto poll_result = poll(&pfd, 1, _timeout_ms);
		if(poll_result == 0) {
			result = false;
			result.set_error(slim::ErrorInfo(ETIMEDOUT, std::format("{} => write timed out", __func__)));
			break;
		}
		else if(poll_result < 0) {
			result = false;
			result.set_error(slim::ErrorInfo(errno, std::format("{} => poll failed => {}", __func__, strerror(errno))));
			break;
		}
#ifdef SLIM_TLS_ENABLED
		int bytes_sent = __is_tls ? SSL_write(__ssl, _payload.data() + total_sent, static_cast<int>(_payload.size() - total_sent))
		                          : static_cast<int>(send(__socket_handle, _payload.data() + total_sent, _payload.size() - total_sent, 0));
#else
		auto bytes_sent = send(__socket_handle, _payload.data() + total_sent, _payload.size() - total_sent, 0);
#endif
		if(bytes_sent < 0) {
#ifdef SLIM_TLS_ENABLED
			if(__is_tls) {
				auto ssl_error = SSL_get_error(__ssl, bytes_sent);
				if(ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE) {
					continue;
				}
				result = false;
				result.set_error(slim::ErrorInfo(ssl_error, std::format("{} => SSL write failed => {}", __func__, ERR_reason_error_string(ERR_get_error()))));
				break;
			}
#endif
			if(errno == EAGAIN || errno == EWOULDBLOCK) {
				continue;
			}
			result = false;
			result.set_error(slim::ErrorInfo(errno, std::format("{} => socket write failed => {}", __func__, strerror(errno))));
			break;
		}
		total_sent += static_cast<size_t>(bytes_sent);
	}
	return result;
}