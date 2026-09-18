// Priority Fabric -- authoritative network priority classes.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// pf_node: the process that owns a fabric state directory and serves the framed protocol.

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

#include "priority_fabric/node.hpp"
#include "priority_fabric/version.hpp"

namespace {

struct Arguments {
    std::string state;
    std::string bind = "127.0.0.1";
    std::uint16_t port = 0;
    std::string ready_file;
    std::uint64_t run_for_ms = 0;
    std::uint32_t max_connections = 64;
    std::uint32_t idle_timeout_ms = 0;
    bool quiet = false;
    bool fence_on_disconnect = false;
    bool allow_remote_shutdown = true;
    bool allow_non_loopback = false;
    bool advance_epoch_on_open = true;
    bool valid = false;
};

void usage() {
    std::cout <<
        "usage: pf_node --state DIR [options]\n"
        "\n"
        "  --state DIR              state directory (required)\n"
        "  --bind ADDRESS           address to bind (default 127.0.0.1)\n"
        "  --port N                 port, 0 lets the operating system choose (default 0)\n"
        "  --ready-file PATH        write the resolved port and node identity here\n"
        "  --run-for-ms N           stop after N milliseconds (0 = run until stopped)\n"
        "  --max-connections N      concurrent connection ceiling (default 64)\n"
        "  --idle-timeout-ms N      socket deadline for an idle connection (0 = none)\n"
        "  --fence-on-disconnect    advance the epoch when a publisher's socket closes\n"
        "  --no-remote-shutdown     refuse the Shutdown operation\n"
        "  --allow-non-loopback     permit binding a routable address\n"
        "  --no-epoch-advance       do not advance the epoch when taking the store over\n"
        "  --quiet                  only report the listening endpoint\n"
        "  --version                print the version and exit\n"
        "  --help                   print this text and exit\n";
}

bool parse(int argc, char** argv, Arguments& arguments) {
    for (int i = 1; i < argc; ++i) {
        const std::string flag(argv[i]);
        const auto next = [&](std::string& out) {
            if (i + 1 >= argc) {
                std::cerr << "pf_node: " << flag << " needs a value\n";
                return false;
            }
            out = argv[++i];
            return true;
        };
        if (flag == "--help" || flag == "-h") {
            usage();
            std::exit(0);
        }
        if (flag == "--version") {
            std::cout << "pf_node " << pf::version_string() << "\n";
            std::exit(0);
        }
        if (flag == "--state") {
            if (!next(arguments.state)) {
                return false;
            }
        } else if (flag == "--bind") {
            if (!next(arguments.bind)) {
                return false;
            }
        } else if (flag == "--ready-file") {
            if (!next(arguments.ready_file)) {
                return false;
            }
        } else if (flag == "--port") {
            std::string value;
            if (!next(value)) {
                return false;
            }
            arguments.port = static_cast<std::uint16_t>(std::strtoul(value.c_str(), nullptr, 10));
        } else if (flag == "--run-for-ms") {
            std::string value;
            if (!next(value)) {
                return false;
            }
            arguments.run_for_ms = std::strtoull(value.c_str(), nullptr, 10);
        } else if (flag == "--max-connections") {
            std::string value;
            if (!next(value)) {
                return false;
            }
            arguments.max_connections =
                static_cast<std::uint32_t>(std::strtoul(value.c_str(), nullptr, 10));
        } else if (flag == "--idle-timeout-ms") {
            std::string value;
            if (!next(value)) {
                return false;
            }
            arguments.idle_timeout_ms =
                static_cast<std::uint32_t>(std::strtoul(value.c_str(), nullptr, 10));
        } else if (flag == "--fence-on-disconnect") {
            arguments.fence_on_disconnect = true;
        } else if (flag == "--no-remote-shutdown") {
            arguments.allow_remote_shutdown = false;
        } else if (flag == "--allow-non-loopback") {
            arguments.allow_non_loopback = true;
        } else if (flag == "--no-epoch-advance") {
            arguments.advance_epoch_on_open = false;
        } else if (flag == "--quiet") {
            arguments.quiet = true;
        } else {
            std::cerr << "pf_node: unknown option " << flag << "\n";
            usage();
            return false;
        }
    }
    if (arguments.state.empty()) {
        std::cerr << "pf_node: --state is required\n";
        return false;
    }
    arguments.valid = true;
    return true;
}

}  // namespace

int main(int argc, char** argv) {
    Arguments arguments;
    if (!parse(argc, argv, arguments)) {
        return 2;
    }

    pf::FabricNode node;
    pf::FabricNode::Options options;
    options.state_dir = arguments.state;
    options.bind_address = arguments.bind;
    options.port = arguments.port;
    options.create_if_missing = true;
    options.max_connections = arguments.max_connections;
    options.idle_timeout_ms = arguments.idle_timeout_ms;
    options.ready_file = arguments.ready_file;
    options.allow_non_loopback = arguments.allow_non_loopback;
    options.fence_on_disconnect = arguments.fence_on_disconnect;
    options.allow_remote_shutdown = arguments.allow_remote_shutdown;
    options.advance_epoch_on_open = arguments.advance_epoch_on_open;

    auto listened = node.listen(options);
    if (!listened.ok()) {
        std::cerr << "pf_node: " << listened.status().to_string() << "\n";
        return 1;
    }

    std::atomic<bool> timer_done{true};
    std::thread timer;
    if (arguments.run_for_ms > 0) {
        timer_done.store(false);
        timer = std::thread([&node, &timer_done, &arguments]() {
            const auto deadline = std::chrono::steady_clock::now() +
                                  std::chrono::milliseconds(arguments.run_for_ms);
            while (std::chrono::steady_clock::now() < deadline) {
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }
            node.stop();
            timer_done.store(true);
        });
    }

    if (!arguments.quiet) {
        std::cout << "pf_node: listening on " << node.bind_address() << ":" << node.port()
                  << " node=" << node.node_id().str() << " boot=" << node.node_boot().hex()
                  << " state=" << arguments.state << std::endl;
    } else {
        std::cout << node.bind_address() << " " << node.port() << " " << node.node_id().str()
                  << " " << node.node_boot().hex() << std::endl;
    }

    // serve() returns as soon as the listener is closed, whether by stop() from the timer, by
    // a Shutdown request, or by the process being told to end.
    auto served = node.serve();
    if (!served.ok() && !arguments.quiet) {
        std::cerr << "pf_node: " << served.status().to_string() << "\n";
    }
    node.stop();
    if (timer.joinable()) {
        timer.join();
    }
    if (!arguments.quiet) {
        std::cout << "pf_node: stopped after serving "
                  << static_cast<unsigned long long>(node.connections_accepted())
                  << " connection(s)" << std::endl;
    }
    return served.ok() ? 0 : 1;
}
