// Priority Fabric -- authoritative network priority classes.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// The framed transport, exercised against a real listener on real loopback sockets inside this
// process. Multiprocess coverage lives in the pf_multiprocess_tests binary.

#include <string>
#include <thread>
#include <vector>

#include "framework.hpp"
#include "priority_fabric/client.hpp"
#include "priority_fabric/node.hpp"
#include "support.hpp"

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

using namespace pftest;

namespace {

/// A raw client used only to send frames the real client would never produce.
class RawPeer {
public:
    explicit RawPeer(std::uint16_t port) {
        ensure_winsock();
#if defined(_WIN32)
        handle_ = static_cast<std::intptr_t>(::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP));
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_port = htons(port);
        ::inet_pton(AF_INET, "127.0.0.1", &address.sin_addr);
        if (handle_ >= 0 &&
            ::connect(static_cast<SOCKET>(handle_), reinterpret_cast<sockaddr*>(&address),
                      sizeof(address)) != 0) {
            ::closesocket(static_cast<SOCKET>(handle_));
            handle_ = -1;
        }
#else
        handle_ = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_port = htons(port);
        ::inet_pton(AF_INET, "127.0.0.1", &address.sin_addr);
        if (handle_ >= 0 && ::connect(handle_, reinterpret_cast<sockaddr*>(&address),
                                      sizeof(address)) != 0) {
            ::close(handle_);
            handle_ = -1;
        }
#endif
    }

    ~RawPeer() {
        if (handle_ >= 0) {
#if defined(_WIN32)
            ::closesocket(static_cast<SOCKET>(handle_));
#else
            ::close(handle_);
#endif
        }
    }

    RawPeer(const RawPeer&) = delete;
    RawPeer& operator=(const RawPeer&) = delete;

    [[nodiscard]] bool valid() const noexcept { return handle_ >= 0; }

    bool send(const std::string& bytes) {
        if (handle_ < 0) {
            return false;
        }
        std::size_t sent = 0;
        while (sent < bytes.size()) {
#if defined(_WIN32)
            const int written =
                ::send(static_cast<SOCKET>(handle_), bytes.data() + sent,
                       static_cast<int>(bytes.size() - sent), 0);
#else
            const ssize_t written =
                ::send(handle_, bytes.data() + sent, bytes.size() - sent, 0);
#endif
            if (written <= 0) {
                return false;
            }
            sent += static_cast<std::size_t>(written);
        }
        return true;
    }

private:
    static void ensure_winsock() {
#if defined(_WIN32)
        static bool once = []() {
            WSADATA data{};
            (void)::WSAStartup(MAKEWORD(2, 2), &data);
            return true;
        }();
        (void)once;
#endif
    }

    std::intptr_t handle_ = -1;
};

struct RunningNode {
    pf::FabricNode node;
    ScratchDirectory directory;
};

/// Starts a node on an operating-system chosen port.
bool start_node(RunningNode& running, std::string_view label,
                const pf::FabricNode::Options& overrides = {}) {
    pf::FabricNode::Options options;
    options.state_dir = running.directory.path() / "state";
    options.port = 0;
    options.create_if_missing = true;
    options.bind_address = overrides.bind_address;
    options.max_connections = overrides.max_connections == 64 ? 8 : overrides.max_connections;
    options.idle_timeout_ms = overrides.idle_timeout_ms;
    options.allow_non_loopback = overrides.allow_non_loopback;
    options.allow_remote_shutdown = overrides.allow_remote_shutdown;
    options.limits = overrides.limits;
    auto listened = running.node.listen(options);
    if (!listened.ok()) {
        return false;
    }
    auto started = running.node.start();
    if (!started.ok()) {
        return false;
    }
    (void)label;
    return true;
}

bool define_world(pf::NodeClient& client) {
    if (!client.define_class(make_class("net.gold", 900, pf::ClassKind::Tenant)).ok()) {
        return false;
    }
    if (!client.define_class(make_class("net.silver", 500, pf::ClassKind::Tenant)).ok()) {
        return false;
    }
    if (!client.define_scope(make_scope("root")).ok()) {
        return false;
    }
    if (!client.define_subject(pf::SubjectDef{subject_id("tenant.acme")}).ok()) {
        return false;
    }
    return true;
}

pf::PriorityQuery acme_query() {
    pf::PriorityQuery query;
    query.subject = subject_id("tenant.acme");
    query.scope = scope_id("root");
    return query;
}

}  // namespace

PF_TEST(transport, a_full_session_round_trips_over_the_wire) {
    RunningNode running;
    PF_REQUIRE(start_node(running, "transport-basic"));
    PF_CHECK(running.node.port() != 0);

    pf::NodeClient client;
    pf::NodeClient::Options options;
    options.port = running.node.port();
    PF_REQUIRE_OK(client.connect(options));
    auto hello = client.hello(publisher_id("wire.publisher"), boot_for("transport-basic"));
    PF_REQUIRE_OK(hello);
    PF_CHECK(hello.value().epoch.is_established());
    PF_CHECK(hello.value().token.is_valid());
    PF_CHECK_EQ(hello.value().node_id.str(), running.node.node_id().str());

    PF_REQUIRE(define_world(client));
    PF_REQUIRE_OK(client.assign(make_assignment("a.gold", "tenant.acme", "root", "net.gold")));

    auto decision = client.evaluate(acme_query());
    PF_REQUIRE_OK(decision);
    PF_CHECK(decision.value().outcome == pf::Outcome::Assigned);
    PF_CHECK(decision.value().cls == class_id("net.gold"));

    // Repeating the question over the wire must give a byte-identical decision.
    auto again = client.evaluate(acme_query());
    PF_REQUIRE_OK(again);
    PF_CHECK(again.value().digest == decision.value().digest);
    PF_CHECK_EQ(again.value().to_json(), decision.value().to_json());

    auto stats = client.stats();
    PF_REQUIRE_OK(stats);
    PF_CHECK(stats.value().second.classes == 2);
    PF_CHECK(stats.value().first.evaluations >= 2);

    auto integrity = client.integrity();
    PF_REQUIRE_OK(integrity);
    PF_CHECK(integrity.value().ok);

    PF_REQUIRE_OK(client.ping());
    client.disconnect();
    running.node.stop();
}

PF_TEST(transport, refusals_carry_their_status_code) {
    RunningNode running;
    PF_REQUIRE(start_node(running, "transport-refusals"));
    pf::NodeClient client;
    pf::NodeClient::Options options;
    options.port = running.node.port();
    PF_REQUIRE_OK(client.connect(options));
    PF_REQUIRE_OK(client.hello(publisher_id("wire.publisher"), boot_for("transport-refusals")));
    PF_REQUIRE(define_world(client));

    PF_REQUIRE_FAILS(client.define_class(make_class("net.dupe", 900)),
                     pf::StatusCode::DuplicatePrecedence);
    PF_REQUIRE_FAILS(client.assign(make_assignment("a.ghost", "tenant.absent", "root", "net.gold")),
                     pf::StatusCode::NotFound);
    // A question the fabric cannot answer is a REJECTED decision, not a transport error: the
    // client learns the fabric's reasoning rather than a bare failure.
    auto rejected = client.evaluate([]() {
        pf::PriorityQuery query;
        query.subject = subject_id("tenant.absent");
        query.scope = scope_id("root");
        return query;
    }());
    PF_REQUIRE_OK(rejected);
    PF_CHECK(rejected.value().outcome == pf::Outcome::Rejected);
    PF_CHECK_EQ(rejected.value().reason_code, std::string("subject_not_registered"));

    // The client set a session that the node no longer honours.
    pf::Session stale = client.session();
    stale.epoch = pf::FabricEpoch{stale.epoch.value + 5};
    client.set_session(stale);
    PF_REQUIRE_FAILS(client.define_class(make_class("net.after", 1300)),
                     pf::StatusCode::StaleEpoch);
    client.disconnect();
    running.node.stop();
}

PF_TEST(transport, a_second_incarnation_takes_over_the_epoch) {
    RunningNode running;
    PF_REQUIRE(start_node(running, "transport-takeover"));

    pf::NodeClient first;
    pf::NodeClient::Options options;
    options.port = running.node.port();
    PF_REQUIRE_OK(first.connect(options));
    auto first_hello = first.hello(publisher_id("wire.publisher"), boot_for("transport-first"));
    PF_REQUIRE_OK(first_hello);
    PF_REQUIRE(define_world(first));
    PF_REQUIRE_OK(first.assign(make_assignment("a.gold", "tenant.acme", "root", "net.gold")));

    pf::NodeClient second;
    PF_REQUIRE_OK(second.connect(options));
    auto second_hello = second.hello(publisher_id("wire.publisher"), boot_for("transport-second"));
    PF_REQUIRE_OK(second_hello);
    PF_CHECK(second_hello.value().epoch.value > first_hello.value().epoch.value);

    auto fenced = second.evaluate(acme_query());
    PF_REQUIRE_OK(fenced);
    PF_CHECK(fenced.value().outcome == pf::Outcome::Fenced);

    PF_REQUIRE_FAILS(first.assign(make_assignment("a.late", "tenant.acme", "root", "net.silver")),
                     pf::StatusCode::StaleEpoch);

    PF_REQUIRE_OK(second.assign(make_assignment("a.fresh", "tenant.acme", "root", "net.silver")));
    auto refreshed = second.evaluate(acme_query());
    PF_REQUIRE_OK(refreshed);
    PF_CHECK(refreshed.value().outcome == pf::Outcome::Assigned);
    PF_CHECK(refreshed.value().cls == class_id("net.silver"));

    first.disconnect();
    second.disconnect();
    running.node.stop();
}

PF_TEST(transport, malformed_frames_are_refused_and_the_node_keeps_serving) {
    RunningNode running;
    PF_REQUIRE(start_node(running, "transport-malformed"));
    const std::uint16_t port = running.node.port();

    // Wrong magic.
    {
        RawPeer peer(port);
        PF_REQUIRE(peer.valid());
        PF_CHECK(peer.send(std::string("XXXX") + std::string(64, '\0')));
    }
    // Correct magic, wrong format version.
    {
        RawPeer peer(port);
        PF_REQUIRE(peer.valid());
        std::string frame;
        frame.append("PFW1", 4);
        frame.push_back('\x09');
        frame.push_back('\x00');
        frame.append(30, '\0');
        PF_CHECK(peer.send(frame));
    }
    // Correct header, reserved flags set.
    {
        RawPeer peer(port);
        PF_REQUIRE(peer.valid());
        std::string frame;
        frame.append("PFW1", 4);
        frame.push_back('\x01');
        frame.push_back('\x00');
        frame.append("\x01\x00\x00\x00", 4);
        frame.append(12, '\0');
        PF_CHECK(peer.send(frame));
    }
    // Oversized declared payload.
    {
        RawPeer peer(port);
        PF_REQUIRE(peer.valid());
        std::string frame;
        frame.append("PFW1", 4);
        frame.push_back('\x01');
        frame.push_back('\x00');
        frame.append(4, '\0');
        frame.append(8, '\0');
        frame.append("\xFF\xFF\xFF\xFF", 4);
        PF_CHECK(peer.send(frame));
    }
    // Valid framing, valid checksum, garbage payload.
    {
        RawPeer peer(port);
        PF_REQUIRE(peer.valid());
        const std::string payload = "not a hello at all";
        std::string frame;
        frame.append("PFW1", 4);
        frame.push_back('\x01');
        frame.push_back('\x00');
        frame.append(4, '\0');
        frame.append(8, '\0');
        const std::uint32_t length = static_cast<std::uint32_t>(payload.size());
        for (int i = 0; i < 4; ++i) {
            frame.push_back(static_cast<char>((length >> (8 * i)) & 0xFF));
        }
        frame.append(payload);
        const std::uint32_t crc = pf::crc32c(frame.data(), frame.size());
        for (int i = 0; i < 4; ++i) {
            frame.push_back(static_cast<char>((crc >> (8 * i)) & 0xFF));
        }
        PF_CHECK(peer.send(frame));
    }

    // After all of that the node must still serve a well-behaved client.
    pf::NodeClient client;
    pf::NodeClient::Options options;
    options.port = port;
    PF_REQUIRE_OK(client.connect(options));
    PF_REQUIRE_OK(client.hello(publisher_id("wire.publisher"), boot_for("transport-after-garbage")));
    PF_REQUIRE(define_world(client));
    PF_REQUIRE_OK(client.ping());
    PF_CHECK(running.node.connections_accepted() >= 5);
    client.disconnect();
    running.node.stop();
}

PF_TEST(transport, a_truncated_frame_does_not_desynchronize_the_node) {
    RunningNode running;
    PF_REQUIRE(start_node(running, "transport-truncated"));
    const std::uint16_t port = running.node.port();
    {
        RawPeer peer(port);
        PF_REQUIRE(peer.valid());
        std::string frame;
        frame.append("PFW1", 4);
        frame.push_back('\x01');
        frame.push_back('\x00');
        frame.append(4, '\0');
        frame.append(8, '\0');
        frame.append("\x40\x00\x00\x00", 4);
        frame.append(10, '\0');  // far less than the declared payload
        PF_CHECK(peer.send(frame));
    }
    pf::NodeClient client;
    pf::NodeClient::Options options;
    options.port = port;
    PF_REQUIRE_OK(client.connect(options));
    PF_REQUIRE_OK(client.hello(publisher_id("wire.publisher"), boot_for("transport-truncated")));
    PF_REQUIRE_OK(client.ping());
    client.disconnect();
    running.node.stop();
}

PF_TEST(transport, many_clients_publish_concurrently_and_the_state_stays_consistent) {
    RunningNode running;
    pf::FabricNode::Options overrides;
    overrides.max_connections = 16;
    PF_REQUIRE(start_node(running, "transport-concurrent", overrides));

    constexpr int kClients = 6;
    std::atomic<int> succeeded{0};
    std::vector<std::thread> threads;
    for (int i = 0; i < kClients; ++i) {
        threads.emplace_back([&running, &succeeded, i]() {
            pf::NodeClient client;
            pf::NodeClient::Options options;
            options.port = running.node.port();
            if (!client.connect(options).ok()) {
                return;
            }
            if (!client
                     .hello(publisher_id("wire.client" + std::to_string(i)),
                            boot_for("transport-concurrent/" + std::to_string(i)))
                     .ok()) {
                return;
            }
            bool ok = true;
            // Identical content, so the republication is an idempotent no-op for every client
            // after the first.
            ok = ok && client.define_class(make_class("net.gold", 900, pf::ClassKind::Tenant))
                           .ok();
            ok = ok && client.define_scope(make_scope("client.scope" + std::to_string(i))).ok();
            ok = ok && client.define_subject(pf::SubjectDef{subject_id("client.subject" +
                                                                      std::to_string(i))})
                           .ok();
            ok = ok &&
                 client.assign(make_assignment("client.assign." + std::to_string(i),
                                               "client.subject" + std::to_string(i),
                                               "client.scope" + std::to_string(i), "net.gold"))
                     .ok();
            if (ok) {
                succeeded.fetch_add(1);
            }
            client.disconnect();
        });
    }
    for (auto& thread : threads) {
        thread.join();
    }
    PF_CHECK(succeeded.load() > 0);

    const pf::FabricRuntime* runtime = running.node.runtime();
    PF_REQUIRE(runtime != nullptr);
    const pf::StateStats stats = runtime->state_stats();
    PF_CHECK_EQ(stats.subjects, static_cast<std::uint64_t>(succeeded.load()));
    PF_CHECK(stats.durable_bytes > 0);
    running.node.stop();
}

PF_TEST(transport, a_node_refuses_a_non_loopback_bind_without_the_override) {
    ScratchDirectory directory("transport-bind");
    pf::FabricNode node;
    pf::FabricNode::Options options;
    options.state_dir = directory.path() / "state";
    options.bind_address = "0.0.0.0";
    options.port = 0;
    auto listened = node.listen(options);
    PF_REQUIRE_FAILS(listened, pf::StatusCode::Unauthorized);

    options.allow_non_loopback = true;
    auto allowed = node.listen(options);
    PF_REQUIRE_OK(allowed);
    node.stop();
}

PF_TEST(transport, remote_shutdown_can_be_refused) {
    RunningNode running;
    pf::FabricNode::Options overrides;
    overrides.allow_remote_shutdown = false;
    PF_REQUIRE(start_node(running, "transport-noshutdown", overrides));
    pf::NodeClient client;
    pf::NodeClient::Options options;
    options.port = running.node.port();
    PF_REQUIRE_OK(client.connect(options));
    PF_REQUIRE_OK(client.hello(publisher_id("wire.publisher"), boot_for("transport-noshutdown")));
    PF_REQUIRE_FAILS(client.shutdown_node(), pf::StatusCode::Unauthorized);
    PF_REQUIRE_OK(client.ping());
    client.disconnect();
    running.node.stop();
}

PF_TEST(transport, a_polite_shutdown_stops_the_accept_loop) {
    RunningNode running;
    PF_REQUIRE(start_node(running, "transport-shutdown"));
    pf::NodeClient client;
    pf::NodeClient::Options options;
    options.port = running.node.port();
    PF_REQUIRE_OK(client.connect(options));
    PF_REQUIRE_OK(client.hello(publisher_id("wire.publisher"), boot_for("transport-shutdown")));
    PF_REQUIRE_OK(client.shutdown_node());
    // stop() is what actually joins the accept thread; the request must have asked for exactly
    // that and nothing more.
    running.node.stop();
    PF_CHECK(running.node.active_connections() == 0);
}
