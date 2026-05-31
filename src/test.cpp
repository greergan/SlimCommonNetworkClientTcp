#include <string>
#include <slim/SlimValue.hpp>
#include <slim/common/network/client/tcp.h>
#include <slim/common/log.h>

using namespace slim::common;

int main() {
	std::string request = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
	auto connection = network::client::tcp::Connection("example.com", 80);
	if(connection.has_error()) {
		log::info(std::to_string(connection.get_error().code()));
		log::info(connection.get_error().message());
	}
	else {
		auto result = connection.write(request);
		if(result) {
			auto response = connection.read();
			log::info(response.to_string());
		}
	}
	auto bad_connection = network::client::tcp::Connection("example.com", 8, false, 500);
	if(bad_connection.has_error()) {
		log::info(std::to_string(bad_connection.get_error().code()));
		log::info(bad_connection.get_error().message());
	}

#ifdef SLIM_TLS_ENABLED
	auto ssl_connection = network::client::tcp::Connection("example.com", 443, true);
	if(ssl_connection.has_error()) {
		log::info(std::to_string(ssl_connection.get_error().code()));
		log::info(ssl_connection.get_error().message());
	}
	else {
		auto result = connection.write(request);
		if(result) {
			auto response = connection.read();
			log::info(response.to_string());
		}
	}
#else
	SKIP("SLIM_TLS_ENABLED not set");
#endif
	return 0;
}
