#ifndef __SLIM__COMMON__NETWORK__CLIENT__TCP__H
#define __SLIM__COMMON__NETWORK__CLIENT__TCP__H

#include <string_view>
#include <slim/SlimValue.hpp>

#define SLIMCOMMONNETWORKCLIENTTCP_VERSION "@SLIMCOMMONNETWORKCLIENTTCP_VERSION@"
#define SLIMCOMMONNETWORKCLIENTTCP_GIT_HASH "@SLIMCOMMONNETWORKCLIENTTCP_GIT_HASH@"

namespace slim::common::network::client::tcp {
	constexpr int BUFFER_SIZE = 1024;
	struct Connection {
		Connection(std::string_view _host, const int _port, const bool _is_tls = false);
		~Connection();
		slim::SlimValue read();
		slim::SlimValue write(std::string_view _payload);

		private:
			int __socket_handle = 0;
			struct sockaddr_in __server_address;
			struct addrinfo __hints;
			struct addrinfo *__addrinfo_pointer;
			bool __is_tls = false;
	};
}

#endif