#include <arpa/inet.h>
#include <cstring>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <format>
//#include <memory>
//#include <openssl/ssl.h>
//#include <openssl/err.h>
#include <slim/common/network/client/tcp.h>

slim::common::network::client::tcp::Connection::Connection(std::string_view _host, const uint16_t _port, const bool _is_tls, const int _timeout_ms) {
	__is_tls = _is_tls;
	bool valid_host = false;

	memset(&__server_address, 0, sizeof(__server_address));
	__server_address.sin_family = AF_INET;
	__server_address.sin_port = htons(_port);

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

slim::common::network::client::tcp::Connection::~Connection() {
	close(__socket_handle);
	if(__addrinfo != nullptr) {
		freeaddrinfo(__addrinfo);
	}
}

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
		auto bytes_read = ::read(__socket_handle, container.data() + offset, BUFFER_SIZE);
		if(bytes_read > 0) {
			container.resize(offset + static_cast<size_t>(bytes_read));
		}
		else if(bytes_read == 0) {
			container.resize(offset);
			break;
		}
		else {
			container.resize(offset);
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
		auto bytes_sent = send(__socket_handle, _payload.data() + total_sent, _payload.size() - total_sent, 0);
		if(bytes_sent < 0) {
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