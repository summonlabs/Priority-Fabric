// Priority Fabric -- authoritative network priority classes.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Concurrency and race coverage. Nothing here is timing-dependent: every worker performs a
// fixed number of iterations and every assertion is about an invariant that must hold for any
// interleaving.

#include <atomic>
#include <string>
#include <thread>
#include <vector>

#include "framework.hpp"
#include "support.hpp"

using namespace pftest;

namespace {

bool build(Fabric& fabric, std::string_view label) {
    if (!open_fabric(fabric, label)) {
        return false;
    }
    for (int i = 0; i < 8; ++i) {
        if (!fabric.runtime
                 .define_class(fabric.session,
                               make_class("net.tier" + std::to_string(i),
                                          100u + static_cast<std::uint32_t>(i) * 100u))
                 .ok()) {
            return false;
        }
    }
    if (!fabric.runtime.define_scope(fabric.session, make_scope("root")).ok()) {
        return false;
    }
    for (int i = 0; i < 4; ++i) {
        if (!fabric.runtime
                 .define_subject(fabric.session,
                                 pf::SubjectDef{subject_id("tenant." + std::to_string(i))})
                 .ok()) {
            return false;
        }
    }
    return true;
}

pf::PriorityQuery query_for(int subject) {
    pf::PriorityQuery query;
    query.subject = subject_id("tenant." + std::to_string(subject));
    query.scope = scope_id("root");
    query.max_explanation_steps = 16;
    return query;
}

}  // namespace

PF_TEST(concurrency, readers_and_a_writer_never_observe_a_torn_decision) {
    Fabric fabric;
    PF_REQUIRE(build(fabric, "concurrency-readers"));

    std::atomic<bool> started{false};
    std::atomic<std::uint64_t> observed{0};
    std::atomic<std::uint64_t> inconsistent{0};

    constexpr int kReaders = 6;
    constexpr int kRounds = 300;
    std::vector<std::thread> readers;
    readers.reserve(kReaders);
    for (int r = 0; r < kReaders; ++r) {
        readers.emplace_back([&fabric, &started, &observed, &inconsistent, r]() {
            while (!started.load()) {
                std::this_thread::yield();
            }
            for (int round = 0; round < kRounds; ++round) {
                const pf::PriorityDecision decision = fabric.runtime.evaluate(query_for(r % 4));
                observed.fetch_add(1);
                if (decision.authoritative) {
                    const bool shape_ok = decision.cls.valid() &&
                                          decision.precedence.is_declared() &&
                                          pf::outcome_carries_authority(decision.outcome);
                    if (!shape_ok) {
                        inconsistent.fetch_add(1);
                    }
                } else if (decision.cls.valid()) {
                    // A decision that carries no authority must not name a class.
                    inconsistent.fetch_add(1);
                }
                if (decision.digest.is_zero()) {
                    inconsistent.fetch_add(1);
                }
            }
        });
    }

    started.store(true);
    for (int round = 0; round < kRounds; ++round) {
        const int subject = round % 4;
        (void)fabric.runtime.assign(
            fabric.session,
            make_assignment("a.round." + std::to_string(round),
                            "tenant." + std::to_string(subject), "root",
                            "net.tier" + std::to_string(round % 8)));
    }
    for (auto& reader : readers) {
        reader.join();
    }
    PF_CHECK_EQ(inconsistent.load(), std::uint64_t{0});
    PF_CHECK_EQ(observed.load(), std::uint64_t{kReaders * kRounds});
}

PF_TEST(concurrency, concurrent_registrations_produce_one_grant_per_incarnation) {
    Fabric fabric;
    PF_REQUIRE(build(fabric, "concurrency-register"));

    constexpr int kThreads = 8;
    std::vector<std::thread> threads;
    std::vector<pf::Result<pf::Session>> results(kThreads, pf::Status{});
    threads.reserve(kThreads);
    for (int i = 0; i < kThreads; ++i) {
        threads.emplace_back([&fabric, &results, i]() {
            // Each thread registers a distinct incarnation of the same publisher.
            results[static_cast<std::size_t>(i)] = fabric.runtime.grant_authority(
                publisher_id("concurrent.publisher"),
                pf::BootId::from_seed("concurrency-register/" + std::to_string(i)));
        });
    }
    for (auto& thread : threads) {
        thread.join();
    }

    std::vector<pf::BootId> granted;
    std::uint64_t max_epoch = 0;
    for (const auto& result : results) {
        PF_REQUIRE_OK(result);
        granted.push_back(result.value().boot);
        max_epoch = std::max(max_epoch, result.value().epoch.value);
    }
    // Exactly one incarnation may hold authority at the end, and the epoch must have advanced
    // once per takeover.
    std::uint64_t granted_count = 0;
    for (const auto& boot : granted) {
        auto state = fabric.runtime.authority_state(publisher_id("concurrent.publisher"), boot);
        PF_REQUIRE_OK(state);
        if (state.value() == pf::AuthorityState::Granted) {
            ++granted_count;
        }
    }
    PF_CHECK_EQ(granted_count, std::uint64_t{1});
    PF_CHECK(max_epoch >= 1);
}

PF_TEST(concurrency, a_fence_racing_an_assign_leaves_no_partial_state) {
    Fabric fabric;
    PF_REQUIRE(build(fabric, "concurrency-fence-race"));

    // Two incarnations per round against a bound of 64 per publisher.
    constexpr int kRounds = 24;
    for (int round = 0; round < kRounds; ++round) {
        const pf::BootId second_boot =
            pf::BootId::from_seed("concurrency-fence-race/" + std::to_string(round));
        auto replacement =
            fabric.runtime.grant_authority(publisher_id("test.publisher"), second_boot);
        PF_REQUIRE_OK(replacement);

        std::atomic<int> accepted{0};
        std::atomic<int> refused{0};
        std::thread fencer([&fabric, &replacement]() {
            // The incarnation fences itself: the actor must itself hold live authority, which
            // is exactly what makes this a race rather than a no-op.
            (void)fabric.runtime.fence(replacement.value(), publisher_id("test.publisher"),
                                       replacement.value().boot, "racing fence");
        });
        std::thread writer([&fabric, &replacement, &accepted, &refused, round]() {
            const auto assigned = fabric.runtime.assign(
                replacement.value(),
                make_assignment("a.race." + std::to_string(round), "tenant.1", "root",
                                "net.tier1"));
            if (assigned.ok()) {
                accepted.fetch_add(1);
            } else {
                refused.fetch_add(1);
            }
        });
        fencer.join();
        writer.join();
        PF_CHECK_EQ(accepted.load() + refused.load(), 1);

        // Whichever way the race went, the fabric must be in a consistent state and the fenced
        // incarnation must not be able to write afterwards.
        PF_REQUIRE_FAILS(
            fabric.runtime.assign(replacement.value(),
                                  make_assignment("a.after." + std::to_string(round), "tenant.1",
                                                  "root", "net.tier2")),
            pf::StatusCode::Fenced);

        // Fencing is final for an incarnation, so the next round uses a fresh one.
        auto revived = fabric.runtime.grant_authority(
            publisher_id("test.publisher"),
            pf::BootId::from_seed("concurrency-fence-race/next/" + std::to_string(round)));
        PF_REQUIRE_OK(revived);
        fabric.session = revived.value();
    }
}

PF_TEST(concurrency, closing_while_readers_run_is_safe_and_final) {
    Fabric fabric;
    PF_REQUIRE(build(fabric, "concurrency-close"));
    PF_REQUIRE_OK(fabric.runtime.assign(
        fabric.session, make_assignment("a.gold", "tenant.0", "root", "net.tier7")));

    constexpr int kReaders = 4;
    std::atomic<bool> stop{false};
    std::atomic<std::uint64_t> rejections{0};
    std::atomic<std::uint64_t> answers{0};
    std::vector<std::thread> readers;
    for (int i = 0; i < kReaders; ++i) {
        readers.emplace_back([&fabric, &stop, &rejections, &answers]() {
            while (!stop.load()) {
                const pf::PriorityDecision decision = fabric.runtime.evaluate(query_for(0));
                if (decision.outcome == pf::Outcome::Rejected) {
                    rejections.fetch_add(1);
                } else {
                    answers.fetch_add(1);
                }
            }
        });
    }

    // Wait for every reader to have seen at least one answer before closing, so the test does
    // not depend on a reader happening to be scheduled inside a narrow window.
    while (answers.load() < static_cast<std::uint64_t>(kReaders)) {
        std::this_thread::yield();
    }
    PF_REQUIRE_OK(fabric.runtime.close());
    // After close every evaluation is rejected, so this spin is guaranteed to terminate. It is
    // a join condition, not a timeout: if it never terminates, that is the defect.
    while (rejections.load() < static_cast<std::uint64_t>(kReaders)) {
        std::this_thread::yield();
    }
    stop.store(true);
    for (auto& reader : readers) {
        reader.join();
    }
    PF_CHECK(rejections.load() >= static_cast<std::uint64_t>(kReaders));
    // After close the runtime answers nothing but rejections.
    for (int i = 0; i < 20; ++i) {
        PF_CHECK(fabric.runtime.evaluate(query_for(0)).outcome == pf::Outcome::Rejected);
    }
    PF_CHECK(fabric.runtime.closed());
    PF_REQUIRE_OK(fabric.runtime.close());  // idempotent
}

PF_TEST(concurrency, statistics_stay_consistent_under_parallel_evaluation) {
    Fabric fabric;
    PF_REQUIRE(build(fabric, "concurrency-stats"));
    PF_REQUIRE_OK(fabric.runtime.assign(
        fabric.session, make_assignment("a.gold", "tenant.0", "root", "net.tier7")));

    constexpr int kThreads = 4;
    constexpr int kPerThread = 250;
    std::vector<std::thread> threads;
    for (int i = 0; i < kThreads; ++i) {
        threads.emplace_back([&fabric]() {
            for (int round = 0; round < kPerThread; ++round) {
                (void)fabric.runtime.evaluate(query_for(0));
            }
        });
    }
    for (auto& thread : threads) {
        thread.join();
    }
    const pf::FabricStats stats = fabric.runtime.stats();
    PF_CHECK_EQ(stats.evaluations, std::uint64_t{kThreads * kPerThread});
    PF_CHECK_EQ(stats.evaluations_assigned, std::uint64_t{kThreads * kPerThread});
}
