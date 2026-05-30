#include <catch2/catch_test_macros.hpp>

#include <slim/common/network/client/tcp.h>
#include <slim/SlimValue.hpp>

using namespace slim::common::network::client::tcp;

TEST_CASE("valid ip address port 80 [tcp]") {
	auto connection = Connection("172.66.147.243", 80);
	CHECK_FALSE(connection.has_error());
}

TEST_CASE("valid host port 80 [tcp]") {
	auto connection = Connection("example.com", 80);
	CHECK_FALSE(connection.has_error());
}

TEST_CASE("invalid host[tcp]") {
	auto connection = Connection("abc.example.com", 80);
	CHECK(connection.has_error());
}