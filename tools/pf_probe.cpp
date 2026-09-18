// Priority Fabric -- authoritative network priority classes.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// pf_probe: a real client process used by the multiprocess test suite. It performs one
// scripted exchange against a running node and exits with a status that says whether the
// exchange behaved as asked. It is also usable by hand against a live node.

#include <chrono>
#include <cstdlib>
#include <iostream>
#include <string>
#include <thread>

#include "priority_fabric/client.hpp"
#include "priority_fabric/version.hpp"

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

namespace {

struct Arguments {
    std::string mode;
    std::string publisher = "probe.publisher";
    std::string boot = "probe";
    std::string expect;
    std::string host = "127.0.0.1";
    std::uint16_t port = 0;
    std::uint64_t hold_ms = 60000;
    bool json = false;
};

void usage() {
    std::cout <<
        "usage: pf_probe --port N --mode MODE [options]\n"
        "\n"
        "modes:\n"
        "  publish     handshake, define a small world, publish an assignment, query it\n"
        "  query       handshake, ask one question and report the outcome\n"
        "  takeover    handshake with a new boot id and republish\n"
        "  hold        handshake, then keep the connection open for --hold-ms\n"
        "  garbage     send malformed frames from a raw socket\n"
        "  stats       handshake, then report node statistics\n"
        "  integrity   handshake, then ask the node to verify its durable state\n"
        "\n"
        "options:\n"
        "  --host ADDRESS --publisher ID --boot LABEL --expect OUTCOME\n"
        "  --hold-ms N --json --version --help\n";
}

bool parse(int argc, char** argv, Arguments& arguments) {
    for (int i = 1; i < argc; ++i) {
        const std::string flag(argv[i]);
        const auto next = [&](std::string& out) {
            if (i + 1 >= argc) {
                std::cerr << "pf_probe: " << flag << " needs a value\n";
                return false;
            }
            out = argv[++i];
            return true;
        };
        if (flag == "--help" || flag == "-h") {
            usage();
            std::exit(0);
        } else if (flag == "--version") {
            std::cout << "pf_probe " << pf::version_string() << "\n";
            std::exit(0);
        } else if (flag == "--mode") {
            if (!next(arguments.mode)) {
                return false;
            }
        } else if (flag == "--port") {
            std::string value;
            if (!next(value)) {
                return false;
            }
            arguments.port = static_cast<std::uint16_t>(std::strtoul(value.c_str(), nullptr, 10));
        } else if (flag == "--host") {
            if (!next(arguments.host)) {
                return false;
            }
        } else if (flag == "--publisher") {
            if (!next(arguments.publisher)) {
                return false;
            }
        } else if (flag == "--boot") {
            if (!next(arguments.boot)) {
                return false;
            }
        } else if (flag == "--expect") {
            if (!next(arguments.expect)) {
                return false;
            }
        } else if (flag == "--hold-ms") {
            std::string value;
            if (!next(value)) {
                return false;
            }
            arguments.hold_ms = std::strtoull(value.c_str(), nullptr, 10);
        } else if (flag == "--json") {
            arguments.json = true;
        } else {
            std::cerr << "pf_probe: unknown option " << flag << "\n";
            return false;
        }
    }
    if (arguments.mode.empty() || arguments.port == 0) {
        std::cerr << "pf_probe: --mode and --port are required\n";
        return false;
    }
    return true;
}

pf::PriorityClassId class_id(std::string_view text) {
    auto parsed = pf::PriorityClassId::parse(text, pf::Limits{});
    return parsed.ok() ? parsed.value() : pf::PriorityClassId{};
}

pf::SubjectId subject_id(std::string_view text) {
    auto parsed = pf::SubjectId::parse(text, pf::Limits{});
    return parsed.ok() ? parsed.value() : pf::SubjectId{};
}

pf::PolicyScopeId scope_id(std::string_view text) {
    auto parsed = pf::PolicyScopeId::parse(text, pf::Limits{});
    return parsed.ok() ? parsed.value() : pf::PolicyScopeId{};
}

pf::PriorityAssignmentId assignment_id(std::string_view text) {
    auto parsed = pf::PriorityAssignmentId::parse(text, pf::Limits{});
    return parsed.ok() ? parsed.value() : pf::PriorityAssignmentId{};
}

pf::PublisherId publisher_id(std::string_view text) {
    auto parsed = pf::PublisherId::parse(text, pf::Limits{});
    return parsed.ok() ? parsed.value() : pf::PublisherId{};
}

pf::PriorityQuery probe_query() {
    pf::PriorityQuery query;
    query.subject = subject_id("probe.subject");
    query.scope = scope_id("probe.scope");
    return query;
}

void report(const char* key, const std::string& value) {
    std::cout << "probe " << key << "=" << value << std::endl;
}

int fail(const std::string& what) {
    std::cout << "probe result=fail reason=" << what << std::endl;
    return 1;
}

bool define_world(pf::NodeClient& client) {
    pf::PriorityClassDef gold;
    gold.id = class_id("net.gold");
    gold.precedence = pf::PrecedenceRank::make(900);
    gold.kind = pf::ClassKind::Tenant;
    pf::PriorityClassDef silver;
    silver.id = class_id("net.silver");
    silver.precedence = pf::PrecedenceRank::make(500);
    silver.kind = pf::ClassKind::Tenant;

    pf::PolicyScopeDef scope;
    scope.id = scope_id("probe.scope");
    pf::SubjectDef subject;
    subject.id = subject_id("probe.subject");

    // Republication with identical content is a no-op, so a probe may run repeatedly against
    // the same node without disturbing it.
    if (!client.define_class(gold).ok()) {
        return false;
    }
    if (!client.define_class(silver).ok()) {
        return false;
    }
    if (!client.define_scope(scope).ok()) {
        return false;
    }
    if (!client.define_subject(subject).ok()) {
        return false;
    }
    return true;
}

int run_garbage(std::uint16_t port) {
#if defined(_WIN32)
    WSADATA data{};
    (void)::WSAStartup(MAKEWORD(2, 2), &data);
#endif
    int sent = 0;
    for (int variant = 0; variant < 5; ++variant) {
#if defined(_WIN32)
        const SOCKET handle = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (handle == INVALID_SOCKET) {
            return fail("socket");
        }
#else
        const int handle = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (handle < 0) {
            return fail("socket");
        }
#endif
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_port = htons(port);
        ::inet_pton(AF_INET, "127.0.0.1", &address.sin_addr);
#if defined(_WIN32)
        const int connected =
            ::connect(handle, reinterpret_cast<sockaddr*>(&address), sizeof(address));
#else
        const int connected = ::connect(handle, reinterpret_cast<sockaddr*>(&address), sizeof(address));
#endif
        if (connected != 0) {
#if defined(_WIN32)
            ::closesocket(handle);
#else
            ::close(handle);
#endif
            continue;
        }
        std::string frame;
        switch (variant) {
            case 0:
                frame.assign("NOTPFABRIC-AT-ALL-0123456789", 28);
                break;
            case 1:
                frame.append("PFW1", 4);
                frame.push_back('\x09');
                frame.push_back('\x00');
                frame.append(30, '\0');
                break;
            case 2:
                frame.append("PFW1", 4);
                frame.push_back('\x01');
                frame.push_back('\x00');
                frame.append("\x08\x00\x00\x00", 4);  // reserved flags set
                frame.append(12, '\0');
                break;
            case 3:
                frame.append("PFW1", 4);
                frame.push_back('\x01');
                frame.push_back('\x00');
                frame.append(4, '\0');
                frame.append(8, '\0');
                frame.append("\xFF\xFF\xFF\x7F", 4);  // absurd declared length
                break;
            default: {
                const std::string payload = "neither a hello nor a request";
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
                break;
            }
        }
        std::size_t written = 0;
        while (written < frame.size()) {
#if defined(_WIN32)
            const int n = ::send(handle, frame.data() + written,
                                 static_cast<int>(frame.size() - written), 0);
#else
            const ssize_t n = ::send(handle, frame.data() + written, frame.size() - written, 0);
#endif
            if (n <= 0) {
                break;
            }
            written += static_cast<std::size_t>(n);
        }
        if (written == frame.size()) {
            ++sent;
        }
#if defined(_WIN32)
        ::closesocket(handle);
#else
        ::close(handle);
#endif
    }
    report("garbage_sent", std::to_string(sent));
    if (sent != 5) {
        return fail("could not send every malformed frame");
    }
    std::cout << "probe result=ok mode=garbage" << std::endl;
    return 0;
}

}  // namespace

int main(int argc, char** argv) {
    Arguments arguments;
    if (!parse(argc, argv, arguments)) {
        return 2;
    }

    if (arguments.mode == "garbage") {
        return run_garbage(arguments.port);
    }

    pf::NodeClient client;
    pf::NodeClient::Options options;
    options.host = arguments.host;
    options.port = arguments.port;
    auto connected = client.connect(options);
    if (!connected.ok()) {
        return fail("connect: " + connected.status().to_string());
    }
    auto hello = client.hello(publisher_id(arguments.publisher),
                              pf::BootId::from_seed("probe/" + arguments.boot));
    if (!hello.ok()) {
        return fail("hello: " + hello.status().to_string());
    }
    report("epoch", std::to_string(hello.value().epoch.value));
    report("token", std::to_string(hello.value().token.value));
    report("boot", hello.value().node_boot.hex());

    if (arguments.mode == "stats") {
        auto stats = client.stats();
        if (!stats.ok()) {
            return fail("stats: " + stats.status().to_string());
        }
        report("classes", std::to_string(stats.value().second.classes));
        report("assignments", std::to_string(stats.value().second.assignments));
        report("evaluations", std::to_string(stats.value().first.evaluations));
        std::cout << "probe result=ok mode=stats" << std::endl;
        return 0;
    }

    if (arguments.mode == "integrity") {
        auto report_result = client.integrity();
        if (!report_result.ok()) {
            return fail("integrity: " + report_result.status().to_string());
        }
        report("integrity_ok", report_result.value().ok ? "true" : "false");
        report("records_applied", std::to_string(report_result.value().records_applied));
        std::cout << "probe result=ok mode=integrity" << std::endl;
        return report_result.value().ok ? 0 : 1;
    }

    if (arguments.mode == "hold") {
        const auto deadline =
            std::chrono::steady_clock::now() + std::chrono::milliseconds(arguments.hold_ms);
        while (std::chrono::steady_clock::now() < deadline) {
            std::this_thread::sleep_for(std::chrono::milliseconds(25));
        }
        std::cout << "probe result=ok mode=hold" << std::endl;
        return 0;
    }

    if (!define_world(client)) {
        return fail("could not define the probe world");
    }

    if (arguments.mode == "publish" || arguments.mode == "takeover") {
        pf::PriorityAssignment assignment;
        assignment.id = assignment_id("probe.assignment");
        assignment.subject = subject_id("probe.subject");
        assignment.scope = scope_id("probe.scope");
        assignment.cls = class_id("net.gold");
        assignment.kind = pf::AssignmentKind::Explicit;
        auto assigned = client.assign(assignment);
        if (!assigned.ok()) {
            return fail("assign: " + assigned.status().to_string());
        }
        report("assignment_generation", std::to_string(assigned.value().value));
    }

    auto decision = client.evaluate(probe_query());
    if (!decision.ok()) {
        return fail("query: " + decision.status().to_string());
    }
    report("outcome", pf::to_string(decision.value().outcome));
    report("class", decision.value().cls.valid() ? decision.value().cls.str() : "-");
    report("reason_code", decision.value().reason_code);
    report("digest", decision.value().digest.hex());
    if (arguments.json) {
        std::cout << decision.value().to_json() << std::endl;
    }

    if (!arguments.expect.empty()) {
        const std::string actual = pf::to_string(decision.value().outcome);
        std::string expected = arguments.expect;
        for (char& c : expected) {
            c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
        }
        if (expected != actual) {
            return fail("expected outcome " + expected + " but the fabric answered " + actual);
        }
    }
    std::cout << "probe result=ok mode=" << arguments.mode << std::endl;
    client.disconnect();
    return 0;
}
