#include <catch2/catch_test_macros.hpp>
#include <chrono>
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
	const int timeout_ms = 500;

	auto connect_start = std::chrono::steady_clock::now();
	auto connection = Connection("example.com", 80, false, timeout_ms);
	auto connect_elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - connect_start).count();
	REQUIRE_FALSE(connection.has_error());
	CHECK(connect_elapsed < timeout_ms + 50);

	auto write_start = std::chrono::steady_clock::now();
	auto result = connection.write(request, timeout_ms);
	auto write_elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - write_start).count();
	REQUIRE(result);
	CHECK(write_elapsed < timeout_ms + 50);

	auto read_start = std::chrono::steady_clock::now();
	auto response = connection.read(timeout_ms);
	auto read_elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - read_start).count();
	REQUIRE(response.to_string().starts_with("HTTP/1.1 200 OK"));
	CHECK(read_elapsed < timeout_ms + 50);
}

TEST_CASE("invalid host [tcp]") {
	auto connection = Connection("abc.example.com", 80);
	REQUIRE(connection.has_error());
}

TEST_CASE("invalid port [tcp]") {
	const int timeout_ms = 750;
	auto start = std::chrono::steady_clock::now();
	auto connection = Connection("example.com", 1234, false, timeout_ms);
	auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count();
	REQUIRE(connection.has_error());
	CHECK(connection.get_error().code() == 110);
	CHECK(elapsed < timeout_ms + 50);
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

TEST_CASE("valid host write and read port 443 tls [tcp]") {
#ifdef SLIM_TLS_ENABLED
	auto connection = Connection("example.com", 443, true);
	REQUIRE_FALSE(connection.has_error());
	auto result = connection.write(request);
	REQUIRE(result);
	auto response = connection.read();
	REQUIRE(response.to_string().starts_with("HTTP/1.1 200 OK"));
#else
	SKIP("SLIM_TLS_ENABLED not set");
#endif
}

TEST_CASE("shared ssl context port 443 tls [tcp]") {
#ifdef SLIM_TLS_ENABLED
	SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
	REQUIRE(ctx != nullptr);
	auto connection1 = Connection("example.com", 443, ctx);
	REQUIRE_FALSE(connection1.has_error());
	auto result1 = connection1.write(request);
	REQUIRE(result1);
	REQUIRE(connection1.read().to_string().starts_with("HTTP/1.1 200 OK"));
	auto connection2 = Connection("example.com", 443, ctx);
	REQUIRE_FALSE(connection2.has_error());
	auto result2 = connection2.write(request);
	REQUIRE(result2);
	REQUIRE(connection2.read().to_string().starts_with("HTTP/1.1 200 OK"));
	SSL_CTX_free(ctx);
#else
	SKIP("SLIM_TLS_ENABLED not set");
#endif
}