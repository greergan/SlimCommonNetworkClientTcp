#include <catch2/catch_test_macros.hpp>
#include <chrono>
#include <slim/common/network/client/tcp.h>
#include <slim/common/network/error_codes.h>

using namespace slim::common::network::client::tcp;
using namespace slim::common::network;

const std::string request     = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
const std::string bad_request = "GET /badrequest HTTP/1.1\r\nHost: example.com\r\n\r\n";

TEST_CASE("tcp connection", "[tcp]") {
    SECTION("valid ip address port 80") {
        std::vector<uint8_t> buf;
        auto connection = Connection("172.66.147.243", 80);
        REQUIRE_NOTHROW(connection.write(request));
        REQUIRE(connection.write(request) == ErrorStatus::OK);
        REQUIRE(connection.read(buf) == ErrorStatus::OK);
        REQUIRE(std::string(buf.begin(), buf.end()).starts_with("HTTP/1.1 200 OK"));
    }

    SECTION("valid host port 80") {
        REQUIRE_NOTHROW(Connection("example.com", 80));
    }

    SECTION("invalid host") {
        REQUIRE_THROWS_AS(Connection("abc.example.com", 80), NetworkException);
    }

    SECTION("invalid port times out") {
        const int timeout_ms = 750;
        auto start = std::chrono::steady_clock::now();
        REQUIRE_THROWS_AS(Connection("example.com", 1234, false, timeout_ms), NetworkException);
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start).count();
        CHECK(elapsed < timeout_ms + 50);
    }
}

TEST_CASE("tcp write", "[tcp]") {
    SECTION("empty write") {
        auto connection = Connection("example.com", 80);
        REQUIRE(connection.write("") == ErrorStatus::OK);
    }

    SECTION("bad request returns 404") {
        std::vector<uint8_t> buf;
        auto connection = Connection("example.com", 80);
        REQUIRE(connection.write(bad_request) == ErrorStatus::OK);
        REQUIRE(connection.read(buf) == ErrorStatus::OK);
        REQUIRE(std::string(buf.begin(), buf.end()).starts_with("HTTP/1.1 404"));
    }
}

TEST_CASE("tcp read", "[tcp]") {
    SECTION("read without write returns empty") {
        std::vector<uint8_t> buf;
        auto connection = Connection("example.com", 80);
        REQUIRE(connection.read(buf) == ErrorStatus::OK);
        REQUIRE(buf.empty());
    }
}

TEST_CASE("tcp timeout", "[tcp]") {
    const int timeout_ms = 500;

    SECTION("connection within timeout") {
        auto start = std::chrono::steady_clock::now();
        auto connection = Connection("example.com", 80, false, timeout_ms);
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start).count();
        CHECK(elapsed < timeout_ms + 50);
    }

    SECTION("write within timeout") {
        auto connection = Connection("example.com", 80, false, timeout_ms);
        auto start = std::chrono::steady_clock::now();
        REQUIRE(connection.write(request, timeout_ms) == ErrorStatus::OK);
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start).count();
        CHECK(elapsed < timeout_ms + 50);
    }

    SECTION("read within timeout") {
        std::vector<uint8_t> buf;
        auto connection = Connection("example.com", 80, false, timeout_ms);
        connection.write(request, timeout_ms);
        auto start = std::chrono::steady_clock::now();
        REQUIRE(connection.read(buf, timeout_ms) == ErrorStatus::OK);
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start).count();
        REQUIRE(std::string(buf.begin(), buf.end()).starts_with("HTTP/1.1 200 OK"));
        CHECK(elapsed < timeout_ms + 50);
    }
}

TEST_CASE("tcp tls", "[tcp][tls]") {
#ifdef SLIM_TLS_ENABLED
    SECTION("valid host port 443") {
        std::vector<uint8_t> buf;
        auto connection = Connection("example.com", 443, true);
        REQUIRE(connection.write(request) == ErrorStatus::OK);
        REQUIRE(connection.read(buf) == ErrorStatus::OK);
        REQUIRE(std::string(buf.begin(), buf.end()).starts_with("HTTP/1.1 200 OK"));
    }

    SECTION("shared ssl context") {
        SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
        REQUIRE(ctx != nullptr);

        {
            std::vector<uint8_t> buf;
            auto connection = Connection("example.com", 443, ctx);
            REQUIRE(connection.write(request) == ErrorStatus::OK);
            REQUIRE(connection.read(buf) == ErrorStatus::OK);
            REQUIRE(std::string(buf.begin(), buf.end()).starts_with("HTTP/1.1 200 OK"));
        }
        {
            std::vector<uint8_t> buf;
            auto connection = Connection("example.com", 443, ctx);
            REQUIRE(connection.write(request) == ErrorStatus::OK);
            REQUIRE(connection.read(buf) == ErrorStatus::OK);
            REQUIRE(std::string(buf.begin(), buf.end()).starts_with("HTTP/1.1 200 OK"));
        }

        SSL_CTX_free(ctx);
    }
#else
    SKIP("SLIM_TLS_ENABLED not set");
#endif
}
