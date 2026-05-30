#include <slim/SlimValue.hpp>
#include <slim/common/network/client/tcp.h>
#include <slim/common/log.h>

using namespace slim::common;

int main() {
	auto connection = network::client::tcp::Connection("example.com", 80);
	if(connection.has_error()) {
		log::info(std::to_string(connection.get_error().code()));
		log::info(connection.get_error().message());
	}
	return 0;
}
