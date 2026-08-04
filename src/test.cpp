#include <arpa/inet.h>
#include <chrono>
#include <optional>
#include <resolv.h>
#include <sys/socket.h>
#include <slim/common/io.h>
#include <slim/common/io/scheduler.h>
#include <slim/common/network/client/tcp.h>
#include <slim/common/network/error_codes.h>
#include <slim/common/log.h>

using namespace slim::common::network::client::tcp;
using namespace slim::common::network;
using ms = std::chrono::milliseconds;

const std::string request     = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
const std::string bad_request = "GET /badrequest HTTP/1.1\r\nHost: example.com\r\n\r\n";

// ── Helpers ───────────────────────────────────────────────────────────────────

void pass(std::string_view name, int& passed) {
    slim::common::log::debug({__func__, std::format("PASS => {}", name), __FILE__, __LINE__});
    ++passed;
}

void fail(std::string_view name, int& failed, std::string_view detail = "") {
    slim::common::log::error({__func__, std::format("FAIL => {} => {}", name, detail), __FILE__, __LINE__});
    ++failed;
}

// ── SchedCtx ──────────────────────────────────────────────────────────────────

struct SchedCtx {
    slim::common::IO            io;
    slim::common::io::Scheduler sched{io};
};

template<typename F>
static void run(SchedCtx& ctx, F&& f) {
    try {
        ctx.sched.spawn([f = std::forward<F>(f)]() -> slim::common::io::Task<void> {
            co_await f();
        }());
    } catch (...) {
        ctx.sched.shutdown();
        throw;
    }
    ctx.sched.shutdown();
}

// ── Tests ─────────────────────────────────────────────────────────────────────

static void run_tests(int& passed, int& failed) {

    // ─── tcp connection ───────────────────────────────────────────────────────

    {
        std::string_view name = "tcp connection valid ip address port 80";
        SchedCtx ctx;
        std::optional<Connection> conn;
        bool threw = false;
        try {
            run(ctx, [&]() -> slim::common::io::Task<void> {
                conn.emplace(co_await Connection::create(ctx.sched, "172.66.147.243", 80));
            });
        } catch (...) { threw = true; }
        if (threw || !conn.has_value()) {
            fail(name, failed, "expected connection, got exception or no value");
        } else {
            std::vector<uint8_t> buf;
            try {
                run(ctx, [&]() -> slim::common::io::Task<void> {
                    co_await conn->write(request);
                    co_await conn->read(buf);
                });
            } catch (...) { threw = true; }
            if (threw)
                fail(name, failed, "write/read threw");
            else if (!std::string(buf.begin(), buf.end()).starts_with("HTTP/1.1 200 OK"))
                fail(name, failed, "response did not start with HTTP/1.1 200 OK");
            else
                pass(name, passed);
        }
    }

    {
        std::string_view name = "tcp connection valid host port 80";
        SchedCtx ctx;
        bool threw = false;
        try {
            run(ctx, [&]() -> slim::common::io::Task<void> {
                std::optional<Connection> conn;
                conn.emplace(co_await Connection::create(ctx.sched, "example.com", 80));
            });
        } catch (...) { threw = true; }
        if (threw) fail(name, failed, "unexpected exception");
        else        pass(name, passed);
    }

    {
        std::string_view name = "tcp connection invalid host";
        SchedCtx ctx;
        bool caught_network = false;
        try {
            run(ctx, [&]() -> slim::common::io::Task<void> {
                std::optional<Connection> conn;
                conn.emplace(co_await Connection::create(ctx.sched, "abc.example.com", 80));
            });
        } catch (const NetworkException&) { caught_network = true; }
          catch (...) {}
        if (caught_network) pass(name, passed);
        else                fail(name, failed, "expected NetworkException");
    }

    {
        std::string_view name = "tcp connection invalid port times out";
        const int timeout_ms = 750;
        SchedCtx ctx;
        bool caught_network = false;
        auto start = std::chrono::steady_clock::now();
        try {
            run(ctx, [&]() -> slim::common::io::Task<void> {
                std::optional<Connection> conn;
                conn.emplace(co_await Connection::create(ctx.sched, "example.com", 1234, ms(timeout_ms)));
            });
        } catch (const NetworkException&) { caught_network = true; }
          catch (...) {}
        auto elapsed = std::chrono::duration_cast<ms>(
            std::chrono::steady_clock::now() - start).count();
        if (!caught_network)
            fail(name, failed, "expected NetworkException");
        else if (elapsed >= timeout_ms + 50)
            fail(name, failed, std::format("elapsed={}ms exceeded timeout+50", elapsed));
        else
            pass(name, passed);
    }

    // ─── tcp write ────────────────────────────────────────────────────────────

    {
        std::string_view name = "tcp write empty write";
        SchedCtx ctx;
        std::optional<Connection> conn;
        bool threw = false;
        try {
            run(ctx, [&]() -> slim::common::io::Task<void> {
                conn.emplace(co_await Connection::create(ctx.sched, "example.com", 80));
            });
        } catch (...) { threw = true; }
        if (threw || !conn.has_value()) {
            fail(name, failed, "connection failed");
        } else {
            try {
                run(ctx, [&]() -> slim::common::io::Task<void> {
                    co_await conn->write("");
                });
            } catch (...) { threw = true; }
            if (threw) fail(name, failed, "unexpected exception on empty write");
            else        pass(name, passed);
        }
    }

    {
        std::string_view name = "tcp write bad request returns 404";
        SchedCtx ctx;
        std::optional<Connection> conn;
        bool threw = false;
        try {
            run(ctx, [&]() -> slim::common::io::Task<void> {
                conn.emplace(co_await Connection::create(ctx.sched, "example.com", 80));
            });
        } catch (...) { threw = true; }
        if (threw || !conn.has_value()) {
            fail(name, failed, "connection failed");
        } else {
            std::vector<uint8_t> buf;
            try {
                run(ctx, [&]() -> slim::common::io::Task<void> {
                    co_await conn->write(bad_request);
                    co_await conn->read(buf);
                });
            } catch (...) { threw = true; }
            if (threw)
                fail(name, failed, "unexpected exception");
            else if (!std::string(buf.begin(), buf.end()).starts_with("HTTP/1.1 404"))
                fail(name, failed, "response did not start with HTTP/1.1 404");
            else
                pass(name, passed);
        }
    }

    // ─── tcp read ─────────────────────────────────────────────────────────────

    {
        std::string_view name = "tcp read without write returns empty";
        SchedCtx ctx;
        std::optional<Connection> conn;
        bool threw = false;
        try {
            run(ctx, [&]() -> slim::common::io::Task<void> {
                conn.emplace(co_await Connection::create(ctx.sched, "example.com", 80));
            });
        } catch (...) { threw = true; }
        if (threw || !conn.has_value()) {
            fail(name, failed, "connection failed");
        } else {
            std::vector<uint8_t> buf;
            try {
                run(ctx, [&]() -> slim::common::io::Task<void> {
                    co_await conn->read(buf);
                });
            } catch (...) { threw = true; }
            if (threw)            fail(name, failed, "unexpected exception");
            else if (!buf.empty()) fail(name, failed, "expected empty buf");
            else                   pass(name, passed);
        }
    }

    // ─── tcp timeout ─────────────────────────────────────────────────────────

    {
        std::string_view name = "tcp timeout connection within timeout";
        const int timeout_ms = 500;
        SchedCtx ctx;
        bool threw = false;
        auto start = std::chrono::steady_clock::now();
        try {
            run(ctx, [&]() -> slim::common::io::Task<void> {
                std::optional<Connection> conn;
                conn.emplace(co_await Connection::create(ctx.sched, "example.com", 80, ms(timeout_ms)));
            });
        } catch (...) { threw = true; }
        auto elapsed = std::chrono::duration_cast<ms>(
            std::chrono::steady_clock::now() - start).count();
        if (threw)
            fail(name, failed, "unexpected exception");
        else if (elapsed >= timeout_ms + 50)
            fail(name, failed, std::format("elapsed={}ms exceeded timeout+50", elapsed));
        else
            pass(name, passed);
    }

    {
        std::string_view name = "tcp timeout write within timeout";
        const int timeout_ms = 500;
        SchedCtx ctx;
        std::optional<Connection> conn;
        bool threw = false;
        try {
            run(ctx, [&]() -> slim::common::io::Task<void> {
                conn.emplace(co_await Connection::create(ctx.sched, "example.com", 80, ms(timeout_ms)));
            });
        } catch (...) { threw = true; }
        if (threw || !conn.has_value()) {
            fail(name, failed, "connection failed");
        } else {
            auto start = std::chrono::steady_clock::now();
            try {
                run(ctx, [&]() -> slim::common::io::Task<void> {
                    co_await conn->write(request, ms(timeout_ms));
                });
            } catch (...) { threw = true; }
            auto elapsed = std::chrono::duration_cast<ms>(
                std::chrono::steady_clock::now() - start).count();
            if (threw)
                fail(name, failed, "unexpected exception");
            else if (elapsed >= timeout_ms + 50)
                fail(name, failed, std::format("elapsed={}ms exceeded timeout+50", elapsed));
            else
                pass(name, passed);
        }
    }

    {
        std::string_view name = "tcp timeout read within timeout";
        const int timeout_ms = 500;
        SchedCtx ctx;
        std::optional<Connection> conn;
        bool threw = false;
        try {
            run(ctx, [&]() -> slim::common::io::Task<void> {
                conn.emplace(co_await Connection::create(ctx.sched, "example.com", 80, ms(timeout_ms)));
            });
        } catch (...) { threw = true; }
        if (threw || !conn.has_value()) {
            fail(name, failed, "connection failed");
        } else {
            std::vector<uint8_t> buf;
            auto start = std::chrono::steady_clock::now();
            try {
                run(ctx, [&]() -> slim::common::io::Task<void> {
                    co_await conn->write(request, ms(timeout_ms));
                    co_await conn->read(buf, ms(timeout_ms));
                });
            } catch (...) { threw = true; }
            auto elapsed = std::chrono::duration_cast<ms>(
                std::chrono::steady_clock::now() - start).count();
            if (threw)
                fail(name, failed, "unexpected exception");
            else if (!std::string(buf.begin(), buf.end()).starts_with("HTTP/1.1 200 OK"))
                fail(name, failed, "response did not start with HTTP/1.1 200 OK");
            else if (elapsed >= timeout_ms + 50)
                fail(name, failed, std::format("elapsed={}ms exceeded timeout+50", elapsed));
            else
                pass(name, passed);
        }
    }

    // ─── tcp tls ─────────────────────────────────────────────────────────────

    {
        std::string_view name = "tcp tls valid host port 443";
        SchedCtx ctx;
        SSL_CTX* ssl_ctx = SSL_CTX_new(TLS_client_method());
        if (!ssl_ctx) {
            fail(name, failed, "SSL_CTX_new failed");
        } else {
            std::optional<Connection> conn;
            bool threw = false;
            try {
                run(ctx, [&]() -> slim::common::io::Task<void> {
                    conn.emplace(co_await Connection::create(ctx.sched, "example.com", 443, ssl_ctx));
                });
            } catch (...) { threw = true; }
            if (threw || !conn.has_value()) {
                fail(name, failed, "expected TLS connection");
            } else {
                std::vector<uint8_t> buf;
                try {
                    run(ctx, [&]() -> slim::common::io::Task<void> {
                        co_await conn->write(request);
                        co_await conn->read(buf);
                    });
                } catch (...) { threw = true; }
                if (threw)
                    fail(name, failed, "write/read threw");
                else if (!std::string(buf.begin(), buf.end()).starts_with("HTTP/1.1 200 OK"))
                    fail(name, failed, "response did not start with HTTP/1.1 200 OK");
                else
                    pass(name, passed);
            }
            SSL_CTX_free(ssl_ctx);
        }
    }

    {
        std::string_view name = "tcp tls shared ssl context";
        SSL_CTX* ssl_ctx = SSL_CTX_new(TLS_client_method());
        if (!ssl_ctx) {
            fail(name, failed, "SSL_CTX_new failed");
        } else {
            bool all_ok = true;
            for (int i = 0; i < 2 && all_ok; ++i) {
                SchedCtx ctx;
                std::optional<Connection> conn;
                bool threw = false;
                try {
                    run(ctx, [&]() -> slim::common::io::Task<void> {
                        conn.emplace(co_await Connection::create(ctx.sched, "example.com", 443, ssl_ctx));
                    });
                } catch (...) { threw = true; }
                if (threw || !conn.has_value()) {
                    fail(name, failed, std::format("iteration {} connection failed", i));
                    all_ok = false;
                } else {
                    std::vector<uint8_t> buf;
                    try {
                        run(ctx, [&]() -> slim::common::io::Task<void> {
                            co_await conn->write(request);
                            co_await conn->read(buf);
                        });
                    } catch (...) { threw = true; }
                    if (threw) {
                        fail(name, failed, std::format("iteration {} write/read threw", i));
                        all_ok = false;
                    } else if (!std::string(buf.begin(), buf.end()).starts_with("HTTP/1.1 200 OK")) {
                        fail(name, failed, std::format("iteration {} bad response", i));
                        all_ok = false;
                    }
                }
            }
            if (all_ok) pass(name, passed);
            SSL_CTX_free(ssl_ctx);
        }
    }

    {
        std::string_view name = "tcp tls handshake fails on plain port exception thrown";
        SchedCtx ctx;
        SSL_CTX* ssl_ctx = SSL_CTX_new(TLS_client_method());
        if (!ssl_ctx) {
            fail(name, failed, "SSL_CTX_new failed");
        } else {
            SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, nullptr);
            SSL_CTX_set_default_verify_paths(ssl_ctx);
            bool caught_network = false;
            try {
                run(ctx, [&]() -> slim::common::io::Task<void> {
                    std::optional<Connection> conn;
                    conn.emplace(co_await Connection::create(ctx.sched, "example.com", 80, ssl_ctx));
                });
            } catch (const NetworkException&) { caught_network = true; }
              catch (...) {}
            if (caught_network) pass(name, passed);
            else                fail(name, failed, "expected NetworkException");
            SSL_CTX_free(ssl_ctx);
        }
    }

    // ─── tcp tls https ───────────────────────────────────────────────────────

    {
        std::string_view name = "tcp tls https GET returns 200";
        SchedCtx ctx;
        SSL_CTX* ssl_ctx = SSL_CTX_new(TLS_client_method());
        if (!ssl_ctx) {
            fail(name, failed, "SSL_CTX_new failed");
        } else {
            std::optional<Connection> conn;
            bool threw = false;
            try {
                run(ctx, [&]() -> slim::common::io::Task<void> {
                    conn.emplace(co_await Connection::create(ctx.sched, "example.com", 443, ssl_ctx));
                });
            } catch (...) { threw = true; }
            if (threw || !conn.has_value()) {
                fail(name, failed, "expected TLS connection");
            } else {
                std::vector<uint8_t> buf;
                try {
                    run(ctx, [&]() -> slim::common::io::Task<void> {
                        co_await conn->write(request);
                        co_await conn->read(buf);
                    });
                } catch (...) { threw = true; }
                if (threw)
                    fail(name, failed, "write/read threw");
                else if (!std::string(buf.begin(), buf.end()).starts_with("HTTP/1.1 200 OK"))
                    fail(name, failed, "response did not start with HTTP/1.1 200 OK");
                else
                    pass(name, passed);
            }
            SSL_CTX_free(ssl_ctx);
        }
    }

    {
        std::string_view name = "tcp tls https write and read within timeout";
        const int timeout_ms = 2000;
        SchedCtx ctx;
        SSL_CTX* ssl_ctx = SSL_CTX_new(TLS_client_method());
        if (!ssl_ctx) {
            fail(name, failed, "SSL_CTX_new failed");
        } else {
            std::optional<Connection> conn;
            bool threw = false;
            try {
                run(ctx, [&]() -> slim::common::io::Task<void> {
                    conn.emplace(co_await Connection::create(ctx.sched, "example.com", 443, ssl_ctx, ms(timeout_ms)));
                });
            } catch (...) { threw = true; }
            if (threw || !conn.has_value()) {
                fail(name, failed, "expected TLS connection");
            } else {
                std::vector<uint8_t> buf;
                auto start = std::chrono::steady_clock::now();
                try {
                    run(ctx, [&]() -> slim::common::io::Task<void> {
                        co_await conn->write(request, ms(timeout_ms));
                        co_await conn->read(buf, ms(timeout_ms));
                    });
                } catch (...) { threw = true; }
                auto elapsed = std::chrono::duration_cast<ms>(
                    std::chrono::steady_clock::now() - start).count();
                if (threw)
                    fail(name, failed, "write/read threw");
                else if (!std::string(buf.begin(), buf.end()).starts_with("HTTP/1.1 200 OK"))
                    fail(name, failed, "response did not start with HTTP/1.1 200 OK");
                else if (elapsed >= timeout_ms + 50)
                    fail(name, failed, std::format("elapsed={}ms exceeded timeout+50", elapsed));
                else
                    pass(name, passed);
            }
            SSL_CTX_free(ssl_ctx);
        }
    }

    {
        std::string_view name = "tcp tls https bad request returns 4xx";
        SchedCtx ctx;
        SSL_CTX* ssl_ctx = SSL_CTX_new(TLS_client_method());
        if (!ssl_ctx) {
            fail(name, failed, "SSL_CTX_new failed");
        } else {
            std::optional<Connection> conn;
            bool threw = false;
            try {
                run(ctx, [&]() -> slim::common::io::Task<void> {
                    conn.emplace(co_await Connection::create(ctx.sched, "example.com", 443, ssl_ctx));
                });
            } catch (...) { threw = true; }
            if (threw || !conn.has_value()) {
                fail(name, failed, "expected TLS connection");
            } else {
                std::vector<uint8_t> buf;
                try {
                    run(ctx, [&]() -> slim::common::io::Task<void> {
                        co_await conn->write(bad_request);
                        co_await conn->read(buf);
                    });
                } catch (...) { threw = true; }
                if (threw)
                    fail(name, failed, "write/read threw");
                else if (!std::string(buf.begin(), buf.end()).starts_with("HTTP/1.1 4"))
                    fail(name, failed, "response did not start with HTTP/1.1 4");
                else
                    pass(name, passed);
            }
            SSL_CTX_free(ssl_ctx);
        }
    }

    // ─── tcp server handoff ───────────────────────────────────────────────────

    {
        std::string_view name = "tcp server handoff plain accepted fd read and write";
        int sv[2];
        if (::socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
            fail(name, failed, "socketpair failed");
        } else {
            ::send(sv[1], request.data(), request.size(), 0);
            SchedCtx ctx;
            std::optional<Connection> conn;
            bool threw = false;
            try {
                run(ctx, [&]() -> slim::common::io::Task<void> {
                    conn.emplace(co_await Connection::create(ctx.sched, sv[0]));
                });
            } catch (...) { threw = true; }
            if (threw || !conn.has_value()) {
                fail(name, failed, "Connection::create from fd failed");
            } else {
                std::vector<uint8_t> buf;
                try {
                    run(ctx, [&]() -> slim::common::io::Task<void> {
                        co_await conn->read(buf);
                        co_await conn->write(request);
                    });
                } catch (...) { threw = true; }
                if (threw) {
                    fail(name, failed, "read/write threw");
                } else if (std::string(buf.begin(), buf.end()) != request) {
                    fail(name, failed, "read buf did not match request");
                } else {
                    char peer_buf[4096]{};
                    ssize_t n = ::recv(sv[1], peer_buf, sizeof(peer_buf), 0);
                    if (n != static_cast<ssize_t>(request.size()))
                        fail(name, failed, std::format("peer recv n={} expected={}", n, request.size()));
                    else if (std::string(peer_buf, static_cast<size_t>(n)) != request)
                        fail(name, failed, "peer buf did not match request");
                    else
                        pass(name, passed);
                }
            }
            ::close(sv[1]);
        }
    }

    {
        std::string_view name = "tcp server handoff partial read exits without blocking";
        int sv[2];
        if (::socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
            fail(name, failed, "socketpair failed");
        } else {
            ::send(sv[1], request.data(), request.size(), 0);
            ::shutdown(sv[1], SHUT_WR);
            SchedCtx ctx;
            std::optional<Connection> conn;
            bool threw = false;
            try {
                run(ctx, [&]() -> slim::common::io::Task<void> {
                    conn.emplace(co_await Connection::create(ctx.sched, sv[0]));
                });
            } catch (...) { threw = true; }
            if (threw || !conn.has_value()) {
                fail(name, failed, "Connection::create from fd failed");
            } else {
                std::vector<uint8_t> buf;
                auto start = std::chrono::steady_clock::now();
                try {
                    run(ctx, [&]() -> slim::common::io::Task<void> {
                        co_await conn->read(buf);
                    });
                } catch (...) { threw = true; }
                auto elapsed = std::chrono::duration_cast<ms>(
                    std::chrono::steady_clock::now() - start).count();
                if (threw)
                    fail(name, failed, "unexpected exception");
                else if (std::string(buf.begin(), buf.end()) != request)
                    fail(name, failed, "buf did not match request");
                else if (elapsed >= 100)
                    fail(name, failed, std::format("elapsed={}ms exceeded 100ms", elapsed));
                else
                    pass(name, passed);
            }
            ::close(sv[1]);
        }
    }
}

// ─── main ─────────────────────────────────────────────────────────────────────

int main() {
    OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS, nullptr);
    res_init();
    _res.retrans = 1;
    _res.retry   = 1;
    int passed = 0;
    int failed = 0;

    run_tests(passed, failed);

    if (failed == 0)
        slim::common::log::debug({__func__, std::format("Results => {} passed => {} failed", passed, failed), __FILE__, __LINE__});
    else
        slim::common::log::error({__func__, std::format("Results => {} passed => {} failed", passed, failed), __FILE__, __LINE__});

    return failed == 0 ? 0 : 1;
}
