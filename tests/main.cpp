#include <catch2/catch_test_macros.hpp>
#include <slim/common/network/client/tcp.h>
#include <slim/SlimValue.hpp>

using namespace slim::common::network::client::tcp;
std::string request = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
std::string bad_request = "GET /badrequest HTTP/1.1\r\nHost: example.com\r\n\r\n";

TEST_CASE("valid ip address port 80 [tcp]") {
	auto connection = Connection("172.66.147.243", 80);
	REQUIRE_FALSE(connection.has_error());
	auto result = connection.write(request);
	REQUIRE(result);
	auto response = connection.read();
	REQUIRE(response.to_string().starts_with("HTTP/1.1 200 OK"));
}

TEST_CASE("valid host port 80 [tcp]") {
	auto connection = Connection("example.com", 80);
	REQUIRE_FALSE(connection.has_error());
}

TEST_CASE("valid host write and read port 80 [tcp]") {
	auto connection = Connection("example.com", 80);
	REQUIRE_FALSE(connection.has_error());
	auto result = connection.write(request);
	REQUIRE(result);
	auto response = connection.read();
	REQUIRE(response.to_string().starts_with("HTTP/1.1 200 OK"));
}

TEST_CASE("invalid host [tcp]") {
	auto connection = Connection("abc.example.com", 80);
	REQUIRE(connection.has_error());
}

TEST_CASE("invalid port [tcp]") {
	auto connection = Connection("example.com", 1234, false, 1000);
	REQUIRE(connection.has_error());
	CHECK(connection.get_error().code() == 110);
}

TEST_CASE("empty write [tcp]") {
	auto connection = Connection("example.com", 80);
	REQUIRE_FALSE(connection.has_error());
	auto result = connection.write("");
	REQUIRE(result);
}

TEST_CASE("bad request [tcp]") {
	auto connection = Connection("example.com", 80);
	REQUIRE_FALSE(connection.has_error());
	auto result = connection.write(bad_request);
	REQUIRE(result);
	auto response = connection.read();
	REQUIRE(response.to_string().starts_with("HTTP/1.1 404"));
}

TEST_CASE("read without write [tcp]") {
	auto connection = Connection("example.com", 80);
	REQUIRE_FALSE(connection.has_error());
	auto response = connection.read();
	REQUIRE_FALSE(response.has_error());
	REQUIRE(response.get_storage_container().empty());
}