#include <catch2/catch_test_macros.hpp>
#include <chrono>
#include <optional>
#include <sys/socket.h>
#include <slim/common/io.h>
#include <slim/common/io/scheduler.h>
#include <slim/common/network/client/tcp.h>
#include <slim/common/network/error_codes.h>

using namespace slim::common::network::client::tcp;
using namespace slim::common::network;
using ms = std::chrono::milliseconds;

const std::string request     = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
const std::string bad_request = "GET /badrequest HTTP/1.1\r\nHost: example.com\r\n\r\n";

// ── SchedCtx ──────────────────────────────────────────────────────────────────

struct SchedCtx {
    slim::common::IO            io;
    slim::common::io::Scheduler sched{io};
};

// ── Helpers ───────────────────────────────────────────────────────────────────

template<typename F>
static void run(SchedCtx& ctx, F&& f) {
    ctx.sched.spawn([f = std::forward<F>(f)]() -> slim::common::io::Task<void> {
        co_await f();
    }());
    ctx.sched.shutdown();
}

static std::optional<Connection> make_plain(SchedCtx& ctx, std::string_view host, uint16_t port,
                                            ms timeout = std::chrono::seconds(5)) {
    std::optional<Connection> conn;
    run(ctx, [&]() -> slim::common::io::Task<void> {
        conn.emplace(co_await Connection::create(ctx.sched, host, port, timeout));
    });
    return conn;
}

static std::optional<Connection> make_tls(SchedCtx& ctx, std::string_view host, uint16_t port,
                                          SSL_CTX* ssl_ctx, ms timeout = std::chrono::seconds(5)) {
    std::optional<Connection> conn;
    run(ctx, [&]() -> slim::common::io::Task<void> {
        conn.emplace(co_await Connection::create(ctx.sched, host, port, ssl_ctx, timeout));
    });
    return conn;
}

// ── Tests ─────────────────────────────────────────────────────────────────────

TEST_CASE("tcp connection", "[tcp]") {
    SECTION("valid ip address port 80") {
        SchedCtx ctx;
        auto conn = make_plain(ctx, "172.66.147.243", 80);
        REQUIRE(conn.has_value());
        std::vector<uint8_t> buf;
        run(ctx, [&]() -> slim::common::io::Task<void> {
            co_await conn->write(request);
            co_await conn->read(buf);
        });
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
        auto conn = make_plain(ctx, "example.com", 80);
        REQUIRE(conn.has_value());
        REQUIRE_NOTHROW(run(ctx, [&]() -> slim::common::io::Task<void> {
            co_await conn->write("");
        }));
    }

    SECTION("bad request returns 404") {
        SchedCtx ctx;
        auto conn = make_plain(ctx, "example.com", 80);
        REQUIRE(conn.has_value());
        std::vector<uint8_t> buf;
        run(ctx, [&]() -> slim::common::io::Task<void> {
            co_await conn->write(bad_request);
            co_await conn->read(buf);
        });
        REQUIRE(std::string(buf.begin(), buf.end()).starts_with("HTTP/1.1 404"));
    }
}

TEST_CASE("tcp read", "[tcp]") {
    SECTION("read without write returns empty") {
        SchedCtx ctx;
        auto conn = make_plain(ctx, "example.com", 80);
        REQUIRE(conn.has_value());
        std::vector<uint8_t> buf;
        run(ctx, [&]() -> slim::common::io::Task<void> {
            co_await conn->read(buf);
        });
        REQUIRE(buf.empty());
    }
}

TEST_CASE("tcp timeout", "[tcp]") {
    const int timeout_ms = 500;

    SECTION("connection within timeout") {
        SchedCtx ctx;
        auto start = std::chrono::steady_clock::now();
        REQUIRE_NOTHROW(make_plain(ctx, "example.com", 80, ms(timeout_ms)));
        auto elapsed = std::chrono::duration_cast<ms>(
            std::chrono::steady_clock::now() - start).count();
        CHECK(elapsed < timeout_ms + 50);
    }

    SECTION("write within timeout") {
        SchedCtx ctx;
        auto conn = make_plain(ctx, "example.com", 80, ms(timeout_ms));
        REQUIRE(conn.has_value());
        auto start = std::chrono::steady_clock::now();
        REQUIRE_NOTHROW(run(ctx, [&]() -> slim::common::io::Task<void> {
            co_await conn->write(request, ms(timeout_ms));
        }));
        auto elapsed = std::chrono::duration_cast<ms>(
            std::chrono::steady_clock::now() - start).count();
        CHECK(elapsed < timeout_ms + 50);
    }

    SECTION("read within timeout") {
        SchedCtx ctx;
        auto conn = make_plain(ctx, "example.com", 80, ms(timeout_ms));
        REQUIRE(conn.has_value());
        std::vector<uint8_t> buf;
        auto start = std::chrono::steady_clock::now();
        run(ctx, [&]() -> slim::common::io::Task<void> {
            co_await conn->write(request, ms(timeout_ms));
            co_await conn->read(buf, ms(timeout_ms));
        });
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
        auto conn = make_tls(ctx, "example.com", 443, ssl_ctx);
        REQUIRE(conn.has_value());
        std::vector<uint8_t> buf;
        run(ctx, [&]() -> slim::common::io::Task<void> {
            co_await conn->write(request);
            co_await conn->read(buf);
        });
        REQUIRE(std::string(buf.begin(), buf.end()).starts_with("HTTP/1.1 200 OK"));
        SSL_CTX_free(ssl_ctx);
    }

    SECTION("shared ssl context") {
        SSL_CTX* ssl_ctx = SSL_CTX_new(TLS_client_method());
        REQUIRE(ssl_ctx != nullptr);
        {
            SchedCtx ctx;
            auto conn = make_tls(ctx, "example.com", 443, ssl_ctx);
            REQUIRE(conn.has_value());
            std::vector<uint8_t> buf;
            run(ctx, [&]() -> slim::common::io::Task<void> {
                co_await conn->write(request);
                co_await conn->read(buf);
            });
            REQUIRE(std::string(buf.begin(), buf.end()).starts_with("HTTP/1.1 200 OK"));
        }
        {
            SchedCtx ctx;
            auto conn = make_tls(ctx, "example.com", 443, ssl_ctx);
            REQUIRE(conn.has_value());
            std::vector<uint8_t> buf;
            run(ctx, [&]() -> slim::common::io::Task<void> {
                co_await conn->write(request);
                co_await conn->read(buf);
            });
            REQUIRE(std::string(buf.begin(), buf.end()).starts_with("HTTP/1.1 200 OK"));
        }
        SSL_CTX_free(ssl_ctx);
    }
    SECTION("handshake fails on plain port — exception thrown") {
        SchedCtx ctx;
        SSL_CTX* ssl_ctx = SSL_CTX_new(TLS_client_method());
        REQUIRE(ssl_ctx != nullptr);
        SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, nullptr);
        SSL_CTX_set_default_verify_paths(ssl_ctx);
        REQUIRE_THROWS_AS(make_tls(ctx, "example.com", 80, ssl_ctx), NetworkException);
        SSL_CTX_free(ssl_ctx);
    }
}

TEST_CASE("tcp server handoff", "[tcp]") {
    SECTION("plain accepted fd — read and write") {
        int sv[2];
        REQUIRE(::socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
        ::send(sv[1], request.data(), request.size(), 0);

        SchedCtx ctx;
        std::optional<Connection> conn;
        run(ctx, [&]() -> slim::common::io::Task<void> {
            conn.emplace(co_await Connection::create(ctx.sched, sv[0]));
        });
        REQUIRE(conn.has_value());

        std::vector<uint8_t> buf;
        run(ctx, [&]() -> slim::common::io::Task<void> {
            co_await conn->read(buf);
            co_await conn->write(request);
        });
        REQUIRE(std::string(buf.begin(), buf.end()) == request);

        char peer_buf[4096]{};
        ssize_t n = ::recv(sv[1], peer_buf, sizeof(peer_buf), 0);
        REQUIRE(n == static_cast<ssize_t>(request.size()));
        REQUIRE(std::string(peer_buf, static_cast<size_t>(n)) == request);
        ::close(sv[1]);
    }

    SECTION("partial read — exits without blocking") {
        int sv[2];
        REQUIRE(::socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
        ::send(sv[1], request.data(), request.size(), 0);
        ::shutdown(sv[1], SHUT_WR);

        SchedCtx ctx;
        std::optional<Connection> conn;
        run(ctx, [&]() -> slim::common::io::Task<void> {
            conn.emplace(co_await Connection::create(ctx.sched, sv[0]));
        });
        REQUIRE(conn.has_value());

        std::vector<uint8_t> buf;
        auto start = std::chrono::steady_clock::now();
        run(ctx, [&]() -> slim::common::io::Task<void> {
            co_await conn->read(buf);
        });
        auto elapsed = std::chrono::duration_cast<ms>(
            std::chrono::steady_clock::now() - start).count();

        REQUIRE(std::string(buf.begin(), buf.end()) == request);
        CHECK(elapsed < 100);
        ::close(sv[1]);
    }
}
