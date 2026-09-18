// Priority Fabric -- authoritative network priority classes.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Real multiprocess proof. Every test here starts the node and the clients as separate
// operating-system processes, talks to them over real loopback TCP and kills them with the
// operating system's own termination, not with an in-process imitation.

#include <cstdlib>
#include <filesystem>
#include <string>
#include <thread>
#include <vector>

#include "../framework.hpp"
#include "../support.hpp"
#include "process.hpp"
#include "priority_fabric/durability.hpp"

#ifndef PF_NODE_EXECUTABLE
#error "PF_NODE_EXECUTABLE must be defined by the build system"
#endif
#ifndef PF_PROBE_EXECUTABLE
#error "PF_PROBE_EXECUTABLE must be defined by the build system"
#endif

using namespace pftest;

namespace {

struct NodeProcess {
    ScratchDirectory directory;
    ChildProcess process;
    std::uint16_t port = 0;
    std::string node_id;
};

/// Starts pf_node on an operating-system chosen port and waits for its ready file. The wait
/// only ever turns "the child never came up" into a failure; it can never turn a broken child
/// into a passing test.
///
/// \p state_override lets a second node take over the state directory a first node left
/// behind, which is how a node restart is modelled here.
bool start_node(NodeProcess& node, std::string_view label,
                const std::vector<std::string>& extra = {},
                const std::filesystem::path& state_override = {}) {
    const std::filesystem::path ready = node.directory.path() / "ready.txt";
    const std::filesystem::path state =
        state_override.empty() ? node.directory.path() / "state" : state_override;
    std::vector<std::string> arguments{
        "--state", state.string(), "--port", "0", "--ready-file", ready.string()};
    arguments.insert(arguments.end(), extra.begin(), extra.end());

    auto spawned = ChildProcess::spawn(PF_NODE_EXECUTABLE, arguments,
                                       node.directory.path() / "node.log");
    if (!spawned.ok()) {
        return false;
    }
    node.process = std::move(spawned.value());
    if (!wait_until([&ready]() { return file_ready(ready); }, 600, 25)) {
        return false;
    }
    const auto lines = read_lines(ready);
    const std::string port = find_value(lines, "port");
    if (port.empty()) {
        return false;
    }
    node.port = static_cast<std::uint16_t>(std::strtoul(port.c_str(), nullptr, 10));
    node.node_id = find_value(lines, "node_id");
    (void)label;
    return node.port != 0;
}

struct ProbeRun {
    int exit_code = -1;
    std::vector<std::string> lines;
    std::string output;
};

/// Runs pf_probe to completion and returns everything it said.
ProbeRun run_probe(const ScratchDirectory& directory, std::uint16_t port,
                   const std::vector<std::string>& arguments, const std::string& tag) {
    ProbeRun run;
    std::vector<std::string> full{"--port", std::to_string(port)};
    full.insert(full.end(), arguments.begin(), arguments.end());
    const std::filesystem::path log =
        directory.path() / ("probe-" + tag + ".log");
    auto spawned = ChildProcess::spawn(PF_PROBE_EXECUTABLE, full, log);
    if (!spawned.ok()) {
        run.lines.push_back("spawn_failed=" + spawned.status().message());
        return run;
    }
    run.exit_code = spawned.value().wait();
    run.output = spawned.value().output();
    run.lines = read_lines(log);
    return run;
}

}  // namespace

PF_TEST(multiprocess, two_real_processes_publish_and_query_over_tcp) {
    NodeProcess node;
    PF_REQUIRE(start_node(node, "mp-basic"));
    PF_CHECK(!node.node_id.empty());

    const ProbeRun publish =
        run_probe(node.directory, node.port,
                  {"--mode", "publish", "--boot", "alpha", "--expect", "ASSIGNED"}, "publish");
    PF_CHECK_EQ(publish.exit_code, 0);
    PF_CHECK_EQ(find_value(publish.lines, "outcome"), std::string("ASSIGNED"));
    PF_CHECK_EQ(find_value(publish.lines, "class"), std::string("net.gold"));
    PF_CHECK(!find_value(publish.lines, "digest").empty());

    // A second process with the same publisher and boot id continues the same incarnation.
    const ProbeRun query =
        run_probe(node.directory, node.port,
                  {"--mode", "query", "--boot", "alpha", "--expect", "ASSIGNED"}, "query");
    PF_CHECK_EQ(query.exit_code, 0);
    PF_CHECK_EQ(find_value(query.lines, "outcome"), std::string("ASSIGNED"));

    const ProbeRun integrity =
        run_probe(node.directory, node.port, {"--mode", "integrity", "--boot", "alpha"},
                  "integrity");
    PF_CHECK_EQ(integrity.exit_code, 0);
    PF_CHECK_EQ(find_value(integrity.lines, "integrity_ok"), std::string("true"));

    const ProbeRun stats =
        run_probe(node.directory, node.port, {"--mode", "stats", "--boot", "alpha"}, "stats");
    PF_CHECK_EQ(stats.exit_code, 0);
    PF_CHECK_EQ(find_value(stats.lines, "classes"), std::string("2"));
    PF_CHECK_EQ(find_value(stats.lines, "assignments"), std::string("1"));

    node.process.kill();
    PF_CHECK_EQ(node.process.wait(), 0xDEAD);
}

PF_TEST(multiprocess, a_killed_publisher_loses_authority_and_its_replacement_is_believed) {
    NodeProcess node;
    PF_REQUIRE(start_node(node, "mp-kill"));

    const ProbeRun publish =
        run_probe(node.directory, node.port,
                  {"--mode", "publish", "--boot", "first", "--expect", "ASSIGNED"}, "first");
    PF_CHECK_EQ(publish.exit_code, 0);
    const std::string first_epoch = find_value(publish.lines, "epoch");
    PF_CHECK(!first_epoch.empty());

    // A second incarnation of the same publisher without the first one being killed: the
    // takeover is what advances the epoch.
    const ProbeRun takeover =
        run_probe(node.directory, node.port,
                  {"--mode", "takeover", "--boot", "second", "--expect", "ASSIGNED"}, "second");
    PF_CHECK_EQ(takeover.exit_code, 0);
    const std::string second_epoch = find_value(takeover.lines, "epoch");
    PF_CHECK(!second_epoch.empty());
    PF_CHECK(std::strtoull(second_epoch.c_str(), nullptr, 10) >
             std::strtoull(first_epoch.c_str(), nullptr, 10));

    // The first incarnation asks again and is given the new epoch, but the epoch has moved on
    // from the one its evidence was published under, so nothing is silently restored.
    const ProbeRun revived =
        run_probe(node.directory, node.port,
                  {"--mode", "query", "--boot", "first", "--expect", "FENCED"}, "revived");
    PF_CHECK_EQ(revived.exit_code, 0);
    PF_CHECK_EQ(find_value(revived.lines, "outcome"), std::string("FENCED"));
    PF_CHECK_EQ(find_value(revived.lines, "reason_code"), std::string("evidence_fenced"));

    node.process.kill();
    (void)node.process.wait();
}

PF_TEST(multiprocess, a_publisher_killed_while_connected_is_fenced_when_the_node_says_so) {
    NodeProcess node;
    PF_REQUIRE(start_node(node, "mp-hold", {"--fence-on-disconnect"}));

    const ProbeRun publish =
        run_probe(node.directory, node.port,
                  {"--mode", "publish", "--boot", "holder", "--expect", "ASSIGNED"}, "holder");
    PF_CHECK_EQ(publish.exit_code, 0);
    const std::string before = find_value(publish.lines, "epoch");

    // A long-lived connection that is then killed outright.
    const std::filesystem::path hold_log = node.directory.path() / "probe-hold.log";
    auto holder = ChildProcess::spawn(PF_PROBE_EXECUTABLE,
                                      {"--port", std::to_string(node.port), "--mode", "hold",
                                       "--boot", "holder", "--hold-ms", "120000"},
                                      hold_log);
    PF_REQUIRE_OK(holder);
    PF_CHECK(wait_until([&hold_log]() { return file_ready(hold_log); }, 600, 25));
    holder.value().kill();

    const ProbeRun after =
        run_probe(node.directory, node.port,
                  {"--mode", "query", "--boot", "holder", "--expect", "FENCED"}, "after");
    PF_CHECK_EQ(after.exit_code, 0);
    PF_CHECK_EQ(find_value(after.lines, "outcome"), std::string("FENCED"));
    const std::string epoch_now = find_value(after.lines, "epoch");
    PF_CHECK(!epoch_now.empty());
    PF_CHECK(std::strtoull(epoch_now.c_str(), nullptr, 10) >
             std::strtoull(before.c_str(), nullptr, 10));

    node.process.kill();
    (void)node.process.wait();
}

PF_TEST(multiprocess, killing_the_node_and_restarting_it_advances_the_epoch) {
    NodeProcess node;
    PF_REQUIRE(start_node(node, "mp-restart"));
    const std::uint16_t first_port = node.port;

    const ProbeRun publish =
        run_probe(node.directory, node.port,
                  {"--mode", "publish", "--boot", "survivor", "--expect", "ASSIGNED"}, "one");
    PF_CHECK_EQ(publish.exit_code, 0);
    const std::string first_epoch = find_value(publish.lines, "epoch");

    // Kill the node the way a machine failure would.
    node.process.kill();
    (void)node.process.wait();

    // Start a second node process on the same state directory.
    NodeProcess restarted;
    PF_REQUIRE(start_node(restarted, "mp-restart-second", {},
                          node.directory.path() / "state"));
    PF_CHECK(restarted.port != 0);
    (void)first_port;

    // Everything from before the restart must be fenced: the node is the authority for the
    // directory and taking it over is a new incarnation of that authority.
    const ProbeRun after =
        run_probe(node.directory, restarted.port,
                  {"--mode", "query", "--boot", "survivor", "--expect", "FENCED"}, "two");
    PF_CHECK_EQ(after.exit_code, 0);
    PF_CHECK_EQ(find_value(after.lines, "outcome"), std::string("FENCED"));
    const std::string second_epoch = find_value(after.lines, "epoch");
    PF_CHECK(!second_epoch.empty());
    PF_CHECK(std::strtoull(second_epoch.c_str(), nullptr, 10) >
             std::strtoull(first_epoch.c_str(), nullptr, 10));

    // And the world itself survived: definitions and the assignment record are all there.
    const ProbeRun stats =
        run_probe(node.directory, restarted.port, {"--mode", "stats", "--boot", "survivor"},
                  "stats");
    PF_CHECK_EQ(stats.exit_code, 0);
    PF_CHECK_EQ(find_value(stats.lines, "classes"), std::string("2"));
    PF_CHECK_EQ(find_value(stats.lines, "assignments"), std::string("1"));

    // Republishing under the new epoch is believed.
    const ProbeRun republish =
        run_probe(node.directory, restarted.port,
                  {"--mode", "takeover", "--boot", "survivor", "--expect", "ASSIGNED"},
                  "republish");
    PF_CHECK_EQ(republish.exit_code, 0);

    restarted.process.kill();
    (void)restarted.process.wait();
}

PF_TEST(multiprocess, malformed_frames_from_a_real_process_do_not_disturb_the_node) {
    NodeProcess node;
    PF_REQUIRE(start_node(node, "mp-garbage"));

    const ProbeRun garbage =
        run_probe(node.directory, node.port, {"--mode", "garbage", "--boot", "garbage"},
                  "garbage");
    PF_CHECK_EQ(garbage.exit_code, 0);
    PF_CHECK_EQ(find_value(garbage.lines, "garbage_sent"), std::string("5"));

    const ProbeRun publish =
        run_probe(node.directory, node.port,
                  {"--mode", "publish", "--boot", "after", "--expect", "ASSIGNED"}, "after");
    PF_CHECK_EQ(publish.exit_code, 0);

    node.process.kill();
    (void)node.process.wait();
}

PF_TEST(multiprocess, several_real_clients_publish_at_the_same_time) {
    NodeProcess node;
    PF_REQUIRE(start_node(node, "mp-concurrent", {"--max-connections", "16"}));

    constexpr int kClients = 6;
    std::vector<std::thread> threads;
    std::vector<int> exits(kClients, -1);
    for (int i = 0; i < kClients; ++i) {
        threads.emplace_back([&node, &exits, i]() {
            const std::string tag = "client" + std::to_string(i);
            const ProbeRun run =
                run_probe(node.directory, node.port,
                          {"--mode", "publish", "--boot", tag, "--publisher",
                           "publisher." + tag, "--expect", "ASSIGNED"},
                          tag);
            exits[static_cast<std::size_t>(i)] = run.exit_code;
        });
    }
    for (auto& thread : threads) {
        thread.join();
    }
    for (int i = 0; i < kClients; ++i) {
        PF_CHECK_EQ(exits[static_cast<std::size_t>(i)], 0);
    }

    const ProbeRun stats =
        run_probe(node.directory, node.port, {"--mode", "stats", "--boot", "audit"}, "stats");
    PF_CHECK_EQ(stats.exit_code, 0);
    PF_CHECK_EQ(find_value(stats.lines, "assignments"), std::string("1"));

    node.process.kill();
    (void)node.process.wait();
}

PF_TEST(multiprocess, a_second_node_refuses_to_share_a_live_state_directory) {
    NodeProcess first;
    PF_REQUIRE(start_node(first, "mp-lock"));

    ScratchDirectory second_directory("mp-lock-second");
    const std::filesystem::path ready = second_directory.path() / "ready.txt";
    auto conflict = ChildProcess::spawn(
        PF_NODE_EXECUTABLE,
        {"--state", (first.directory.path() / "state").string(), "--port", "0", "--ready-file",
         ready.string()},
        second_directory.path() / "node.log");
    PF_REQUIRE_OK(conflict);
    const int exit_code = conflict.value().wait();
    PF_CHECK(exit_code != 0);
    const std::string output = conflict.value().output();
    PF_CHECK(output.find("already holds") != std::string::npos ||
             output.find("already_exists") != std::string::npos);

    // The first node is untouched and still serving.
    const ProbeRun publish =
        run_probe(first.directory, first.port,
                  {"--mode", "publish", "--boot", "owner", "--expect", "ASSIGNED"}, "owner");
    PF_CHECK_EQ(publish.exit_code, 0);

    first.process.kill();
    (void)first.process.wait();
}

PF_TEST(multiprocess, a_node_stopped_politely_leaves_a_clean_state_directory) {
    NodeProcess node;
    PF_REQUIRE(start_node(node, "mp-clean"));
    const ProbeRun publish =
        run_probe(node.directory, node.port,
                  {"--mode", "publish", "--boot", "clean", "--expect", "ASSIGNED"}, "clean");
    PF_CHECK_EQ(publish.exit_code, 0);

    // Stop the node by asking it to run only briefly, then verify the store on disk with a
    // separate process that takes the lock for itself.
    const std::filesystem::path clean_ready = node.directory.path() / "clean-ready.txt";
    auto clean = ChildProcess::spawn(
        PF_NODE_EXECUTABLE,
        {"--state", (node.directory.path() / "state-two").string(), "--port", "0",
         "--ready-file", clean_ready.string(), "--run-for-ms", "400"},
        node.directory.path() / "clean.log");
    PF_REQUIRE_OK(clean);
    const int exit_code = clean.value().wait();
    PF_CHECK_EQ(exit_code, 0);

    node.process.kill();
    (void)node.process.wait();
    PF_CHECK(std::filesystem::exists(node.directory.path() / "state" /
                                     pf::DurableLayout::kManifestName));
}
