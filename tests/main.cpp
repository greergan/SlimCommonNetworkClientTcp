#include <catch2/catch_test_macros.hpp>
#include <chrono>
#include <slim/common/io.h>
#include <slim/common/io/scheduler.h>
#include <slim/common/network/client/tcp.h>
#include <slim/common/network/error_codes.h>

using namespace slim::common::network::client::tcp;
using namespace slim::common::network;
using ms = std::chrono::milliseconds;

const std::string request     = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
const std::string bad_request = "GET /badrequest HTTP/1.1\r\nHost: example.com\r\n\r\n";

// ─── SchedCtx ────────────────────────────────────────────────────────────────

struct SchedCtx {
    slim::common::IO              io;
    slim::common::io::Scheduler   sched{io};
};

// ─── Helpers ─────────────────────────────────────────────────────────────────

static Connection make_plain(
        SchedCtx& ctx,
        std::string_view host,
        uint16_t port,
        ms timeout = std::chrono::seconds(5)) {
    Connection* conn = nullptr;
    ctx.sched.spawn([&]() -> slim::common::io::Task<void> {
        auto c = co_await Connection::create(ctx.sched, host, port, timeout);
        conn = &c;
    }());
    ctx.sched.shutdown();
    return std::move(*conn);
}

static Connection make_tls(
        SchedCtx& ctx,
        std::string_view host,
        uint16_t port,
        SSL_CTX* ssl_ctx,
        ms timeout = std::chrono::seconds(5)) {
    Connection* conn = nullptr;
    ctx.sched.spawn([&]() -> slim::common::io::Task<void> {
        auto c = co_await Connection::create(ctx.sched, host, port, ssl_ctx, timeout);
        conn = &c;
    }());
    ctx.sched.shutdown();
    return std::move(*conn);
}

// ─── Tests ───────────────────────────────────────────────────────────────────

TEST_CASE("tcp connection", "[tcp]") {
    SECTION("valid ip address port 80") {
        SchedCtx ctx;
        auto connection = make_plain(ctx, "172.66.147.243", 80);
        std::vector<uint8_t> buf;
        REQUIRE_NOTHROW(connection.write(request));
        REQUIRE(connection.write(request) == ErrorStatus::OK);
        REQUIRE(connection.read(buf) == ErrorStatus::OK);
        REQUIRE(std::string(buf.begin(), buf.end()).starts_with("HTTP/1.1 200 OK"));
    }

    SECTION("valid host port 80") {
        SchedCtx ctx;
        REQUIRE_NOTHROW(make_plain(ctx, "example.com", 80));
    }

    SECTION("invalid host") {
        SchedCtx ctx;
        REQUIRE_THROWS_AS(make_plain(ctx, "abc.example.com", 80), NetworkException);
    }

    SECTION("invalid port times out") {
        const int timeout_ms = 750;
        SchedCtx ctx;
        auto start = std::chrono::steady_clock::now();
        REQUIRE_THROWS_AS(make_plain(ctx, "example.com", 1234, ms(timeout_ms)), NetworkException);
        auto elapsed = std::chrono::duration_cast<ms>(
            std::chrono::steady_clock::now() - start).count();
        CHECK(elapsed < timeout_ms + 50);
    }
}

TEST_CASE("tcp write", "[tcp]") {
    SECTION("empty write") {
        SchedCtx ctx;
        auto connection = make_plain(ctx, "example.com", 80);
        REQUIRE(connection.write("") == ErrorStatus::OK);
    }

    SECTION("bad request returns 404") {
        SchedCtx ctx;
        auto connection = make_plain(ctx, "example.com", 80);
        std::vector<uint8_t> buf;
        REQUIRE(connection.write(bad_request) == ErrorStatus::OK);
        REQUIRE(connection.read(buf) == ErrorStatus::OK);
        REQUIRE(std::string(buf.begin(), buf.end()).starts_with("HTTP/1.1 404"));
    }
}

TEST_CASE("tcp read", "[tcp]") {
    SECTION("read without write returns empty") {
        SchedCtx ctx;
        auto connection = make_plain(ctx, "example.com", 80);
        std::vector<uint8_t> buf;
        REQUIRE(connection.read(buf) == ErrorStatus::OK);
        REQUIRE(buf.empty());
    }
}

TEST_CASE("tcp timeout", "[tcp]") {
    const int timeout_ms = 500;

    SECTION("connection within timeout") {
        SchedCtx ctx;
        auto start = std::chrono::steady_clock::now();
        auto connection = make_plain(ctx, "example.com", 80, ms(timeout_ms));
        auto elapsed = std::chrono::duration_cast<ms>(
            std::chrono::steady_clock::now() - start).count();
        CHECK(elapsed < timeout_ms + 50);
    }

    SECTION("write within timeout") {
        SchedCtx ctx;
        auto connection = make_plain(ctx, "example.com", 80, ms(timeout_ms));
        auto start = std::chrono::steady_clock::now();
        REQUIRE(connection.write(request, ms(timeout_ms)) == ErrorStatus::OK);
        auto elapsed = std::chrono::duration_cast<ms>(
            std::chrono::steady_clock::now() - start).count();
        CHECK(elapsed < timeout_ms + 50);
    }

    SECTION("read within timeout") {
        SchedCtx ctx;
        auto connection = make_plain(ctx, "example.com", 80, ms(timeout_ms));
        std::vector<uint8_t> buf;
        connection.write(request, ms(timeout_ms));
        auto start = std::chrono::steady_clock::now();
        REQUIRE(connection.read(buf, ms(timeout_ms)) == ErrorStatus::OK);
        auto elapsed = std::chrono::duration_cast<ms>(
            std::chrono::steady_clock::now() - start).count();
        REQUIRE(std::string(buf.begin(), buf.end()).starts_with("HTTP/1.1 200 OK"));
        CHECK(elapsed < timeout_ms + 50);
    }
}

TEST_CASE("tcp tls", "[tcp][tls]") {
    SECTION("valid host port 443") {
        SchedCtx ctx;
        SSL_CTX* ssl_ctx = SSL_CTX_new(TLS_client_method());
        REQUIRE(ssl_ctx != nullptr);
        auto connection = make_tls(ctx, "example.com", 443, ssl_ctx);
        std::vector<uint8_t> buf;
        REQUIRE(connection.write(request) == ErrorStatus::OK);
        REQUIRE(connection.read(buf) == ErrorStatus::OK);
        REQUIRE(std::string(buf.begin(), buf.end()).starts_with("HTTP/1.1 200 OK"));
        SSL_CTX_free(ssl_ctx);
    }

    SECTION("shared ssl context") {
        SSL_CTX* ssl_ctx = SSL_CTX_new(TLS_client_method());
        REQUIRE(ssl_ctx != nullptr);

        {
            SchedCtx ctx;
            auto connection = make_tls(ctx, "example.com", 443, ssl_ctx);
            std::vector<uint8_t> buf;
            REQUIRE(connection.write(request) == ErrorStatus::OK);
            REQUIRE(connection.read(buf) == ErrorStatus::OK);
            REQUIRE(std::string(buf.begin(), buf.end()).starts_with("HTTP/1.1 200 OK"));
        }
        {
            SchedCtx ctx;
            auto connection = make_tls(ctx, "example.com", 443, ssl_ctx);
            std::vector<uint8_t> buf;
            REQUIRE(connection.write(request) == ErrorStatus::OK);
            REQUIRE(connection.read(buf) == ErrorStatus::OK);
            REQUIRE(std::string(buf.begin(), buf.end()).starts_with("HTTP/1.1 200 OK"));
        }

        SSL_CTX_free(ssl_ctx);
    }
}
