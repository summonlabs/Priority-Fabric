// Priority Fabric -- authoritative network priority classes.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Throughput measurements over a SYNTHETIC population held in one process's memory and one
// local state directory. Nothing here touches a network interface, a switch, a NIC or a
// queue: the numbers describe how fast the fabric answers, not how fast a link moves bytes.
// Every measurement counts *completed* work.

#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

#include "priority_fabric/runtime.hpp"
#include "priority_fabric/version.hpp"

namespace {

constexpr const char* kSyntheticLabel =
    "SYNTHETIC: in-process population over one local state directory; no physical network";

pf::PriorityClassId class_id(const std::string& text) {
    return pf::PriorityClassId::parse(text, pf::Limits{}).value();
}

pf::SubjectId subject_id(const std::string& text) {
    return pf::SubjectId::parse(text, pf::Limits{}).value();
}

pf::PolicyScopeId scope_id(const std::string& text) {
    return pf::PolicyScopeId::parse(text, pf::Limits{}).value();
}

pf::PriorityAssignmentId assignment_id(const std::string& text) {
    return pf::PriorityAssignmentId::parse(text, pf::Limits{}).value();
}

double seconds_since(const std::chrono::steady_clock::time_point& start) {
    const auto elapsed = std::chrono::steady_clock::now() - start;
    return std::chrono::duration<double>(elapsed).count();
}

struct Population {
    int classes = 0;
    int scopes = 0;
    int subjects = 0;
    int assignments = 0;
};

bool build(pf::FabricRuntime& runtime, const pf::Session& session, const Population& population) {
    for (int i = 0; i < population.classes; ++i) {
        pf::PriorityClassDef definition;
        definition.id = class_id("bench.class." + std::to_string(i));
        definition.precedence =
            pf::PrecedenceRank::make(100u + static_cast<std::uint32_t>(i) * 10u);
        definition.kind = pf::ClassKind::Tenant;
        if (!runtime.define_class(session, definition).ok()) {
            return false;
        }
    }
    for (int i = 0; i < population.scopes; ++i) {
        pf::PolicyScopeDef definition;
        definition.id = scope_id("bench.scope." + std::to_string(i));
        if (i > 0) {
            definition.parent = scope_id("bench.scope." + std::to_string(i - 1));
        }
        if (!runtime.define_scope(session, definition).ok()) {
            return false;
        }
    }
    for (int i = 0; i < population.subjects; ++i) {
        pf::SubjectDef definition;
        definition.id = subject_id("bench.subject." + std::to_string(i));
        if (i > 0 && i % 4 == 0) {
            definition.inherits_from.push_back(subject_id("bench.subject." + std::to_string(i / 4)));
        }
        if (!runtime.define_subject(session, definition).ok()) {
            return false;
        }
    }
    for (int i = 0; i < population.assignments; ++i) {
        pf::PriorityAssignment assignment;
        assignment.id = assignment_id("bench.assignment." + std::to_string(i));
        assignment.subject = subject_id("bench.subject." + std::to_string(i % population.subjects));
        assignment.scope =
            scope_id("bench.scope." + std::to_string(i % population.scopes));
        assignment.cls = class_id("bench.class." + std::to_string(i % population.classes));
        assignment.kind = pf::AssignmentKind::Explicit;
        if (!runtime.assign(session, assignment).ok()) {
            return false;
        }
    }
    return true;
}

}  // namespace

int main(int argc, char** argv) {
    bool quick = false;
    for (int i = 1; i < argc; ++i) {
        const std::string argument(argv[i]);
        if (argument == "--quick") {
            quick = true;
        } else if (argument == "--help") {
            std::cout << "usage: pf_bench [--quick]\n";
            return 0;
        }
    }

    Population population;
    population.classes = quick ? 16 : 128;
    population.scopes = quick ? 4 : 8;
    population.subjects = quick ? 256 : 4096;
    population.assignments = quick ? 1024 : 65536;

    std::error_code ec;
    const auto root = std::filesystem::temp_directory_path(ec) /
                      ("pf-bench-" + std::to_string(
                                         std::chrono::steady_clock::now().time_since_epoch().count()));
    std::filesystem::remove_all(root, ec);

    pf::FabricRuntime::Options options;
    options.state_dir = root / "state";
    options.create_if_missing = true;
    options.fsync_records = false;  // the durable path is measured separately, with fsync on

    auto opened = pf::FabricRuntime::open(options);
    if (!opened.ok()) {
        std::cerr << "pf_bench: " << opened.status().to_string() << "\n";
        return 1;
    }
    pf::FabricRuntime runtime = std::move(opened.value());
    auto session = runtime.grant_authority(
        pf::PublisherId::parse("bench.publisher", runtime.limits()).value(),
        pf::BootId::from_seed("bench"));
    if (!session.ok()) {
        std::cerr << "pf_bench: " << session.status().to_string() << "\n";
        return 1;
    }

    auto load_start = std::chrono::steady_clock::now();
    if (!build(runtime, session.value(), population)) {
        std::cerr << "pf_bench: could not build the synthetic population\n";
        return 1;
    }
    const double load_seconds = seconds_since(load_start);

    std::cout << "priority fabric " << pf::version_string() << " benchmark\n";
    std::cout << kSyntheticLabel << "\n";
    std::cout << "population classes=" << population.classes << " scopes=" << population.scopes
              << " subjects=" << population.subjects
              << " assignments=" << population.assignments << "\n";
    std::cout << "load.seconds=" << load_seconds << " load.ops_per_second="
              << (static_cast<double>(population.classes + population.scopes +
                                      population.subjects + population.assignments) /
                  load_seconds)
              << "\n";

    const int iterations = quick ? 20000 : 200000;
    std::vector<pf::PriorityQuery> queries;
    queries.reserve(static_cast<std::size_t>(iterations));
    for (int i = 0; i < iterations; ++i) {
        pf::PriorityQuery query;
        query.subject = subject_id("bench.subject." + std::to_string(i % population.subjects));
        query.scope = scope_id("bench.scope." + std::to_string(i % population.scopes));
        query.max_explanation_steps = 8;
        queries.push_back(query);
    }

    std::uint64_t authoritative = 0;
    auto evaluate_start = std::chrono::steady_clock::now();
    for (const auto& query : queries) {
        const pf::PriorityDecision decision = runtime.evaluate(query);
        if (decision.authoritative) {
            ++authoritative;
        }
    }
    const double evaluate_seconds = seconds_since(evaluate_start);
    std::cout << "evaluate.single_thread.completed=" << iterations
              << " seconds=" << evaluate_seconds
              << " evaluations_per_second=" << (static_cast<double>(iterations) / evaluate_seconds)
              << " authoritative=" << authoritative << "\n";

    const unsigned hardware = std::thread::hardware_concurrency();
    const unsigned threads = hardware == 0 ? 2u : (hardware > 8u ? 8u : hardware);
    std::vector<std::thread> workers;
    std::vector<std::uint64_t> local(threads, 0);
    auto parallel_start = std::chrono::steady_clock::now();
    for (unsigned t = 0; t < threads; ++t) {
        workers.emplace_back([&runtime, &queries, &local, t, threads]() {
            std::uint64_t completed = 0;
            for (std::size_t i = t; i < queries.size(); i += threads) {
                (void)runtime.evaluate(queries[i]);
                ++completed;
            }
            local[t] = completed;
        });
    }
    for (auto& worker : workers) {
        worker.join();
    }
    const double parallel_seconds = seconds_since(parallel_start);
    std::uint64_t completed = 0;
    for (std::uint64_t value : local) {
        completed += value;
    }
    std::cout << "evaluate.parallel.completed=" << completed << " threads=" << threads
              << " seconds=" << parallel_seconds << " evaluations_per_second="
              << (static_cast<double>(completed) / parallel_seconds) << "\n";

    // Durable path, measured with the platform flush enabled.
    const int durable_commits = quick ? 200 : 2000;
    pf::FabricRuntime::Options durable_options;
    durable_options.state_dir = root / "durable";
    durable_options.create_if_missing = true;
    durable_options.fsync_records = true;
    auto durable_opened = pf::FabricRuntime::open(durable_options);
    if (!durable_opened.ok()) {
        std::cerr << "pf_bench: " << durable_opened.status().to_string() << "\n";
        return 1;
    }
    {
        pf::FabricRuntime durable = std::move(durable_opened.value());
        auto durable_session = durable.grant_authority(
            pf::PublisherId::parse("bench.publisher", durable.limits()).value(),
            pf::BootId::from_seed("bench"));
        if (!durable_session.ok()) {
            std::cerr << "pf_bench: " << durable_session.status().to_string() << "\n";
            return 1;
        }
        auto commit_start = std::chrono::steady_clock::now();
        for (int i = 0; i < durable_commits; ++i) {
            pf::PriorityClassDef definition;
            definition.id = class_id("bench.durable." + std::to_string(i));
            definition.precedence = pf::PrecedenceRank::make(200000u + static_cast<std::uint32_t>(i));
            if (!durable.define_class(durable_session.value(), definition).ok()) {
                std::cerr << "pf_bench: durable commit failed at " << i << "\n";
                return 1;
            }
        }
        const double commit_seconds = seconds_since(commit_start);
        std::cout << "durable.commits.completed=" << durable_commits
                  << " seconds=" << commit_seconds << " commits_per_second="
                  << (static_cast<double>(durable_commits) / commit_seconds)
                  << " bytes=" << durable.state_stats().durable_bytes << "\n";
    }

    std::filesystem::remove_all(root, ec);
    return 0;
}
