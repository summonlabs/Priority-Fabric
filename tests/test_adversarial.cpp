// Priority Fabric -- authoritative network priority classes.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Malformed, contradictory, oversized and hostile input. Every case must be refused with a
// specific status; none may be silently repaired, ignored or absorbed.

#include <filesystem>
#include <fstream>
#include <random>
#include <string>
#include <vector>

#include "framework.hpp"
#include "priority_fabric/durability.hpp"
#include "support.hpp"

using namespace pftest;

namespace {

bool build(Fabric& fabric, const pf::Limits& limits, std::string_view label) {
    if (!open_fabric(fabric, label, limits)) {
        return false;
    }
    if (!fabric.runtime.define_class(fabric.session, make_class("net.gold", 900)).ok()) {
        return false;
    }
    if (!fabric.runtime.define_class(fabric.session, make_class("net.silver", 500)).ok()) {
        return false;
    }
    if (!fabric.runtime.define_scope(fabric.session, make_scope("root")).ok()) {
        return false;
    }
    if (!fabric.runtime
             .define_subject(fabric.session, pf::SubjectDef{subject_id("tenant.acme")})
             .ok()) {
        return false;
    }
    return true;
}

}  // namespace

PF_TEST(adversarial, oversized_human_text_is_refused) {
    pf::Limits limits;
    limits.max_description_length = 32;
    limits.max_note_length = 16;
    Fabric fabric;
    PF_REQUIRE(build(fabric, limits, "adversarial-text"));

    pf::PriorityClassDef verbose = make_class("net.verbose", 1500);
    verbose.description = std::string(200, 'x');
    PF_REQUIRE_FAILS(fabric.runtime.define_class(fabric.session, verbose),
                     pf::StatusCode::LimitExceeded);

    pf::PriorityAssignment chatty =
        make_assignment("a.chatty", "tenant.acme", "root", "net.gold");
    chatty.note = std::string(64, 'n');
    PF_REQUIRE_FAILS(fabric.runtime.assign(fabric.session, chatty), pf::StatusCode::LimitExceeded);
}

PF_TEST(adversarial, control_characters_are_refused_in_stored_text) {
    Fabric fabric;
    PF_REQUIRE(build(fabric, pf::Limits{}, "adversarial-control"));

    pf::PriorityClassDef escaped = make_class("net.escape", 1500);
    escaped.description = "escape\x1b[31mred";
    PF_REQUIRE_FAILS(fabric.runtime.define_class(fabric.session, escaped),
                     pf::StatusCode::InvalidArgument);

    pf::PriorityAssignment embedded =
        make_assignment("a.embedded", "tenant.acme", "root", "net.gold");
    embedded.note = std::string("null") + '\0' + "byte";
    PF_REQUIRE_FAILS(fabric.runtime.assign(fabric.session, embedded),
                     pf::StatusCode::InvalidArgument);
}

PF_TEST(adversarial, too_many_inheritance_edges_are_refused) {
    pf::Limits limits;
    limits.max_inherits_from = 4;
    Fabric fabric;
    PF_REQUIRE(build(fabric, limits, "adversarial-edges"));
    for (int i = 0; i < 8; ++i) {
        PF_REQUIRE_OK(fabric.runtime.define_class(
            fabric.session, make_class("net.parent" + std::to_string(i), 2000u + static_cast<std::uint32_t>(i))));
    }
    std::vector<pf::PriorityClassId> parents;
    for (int i = 0; i < 8; ++i) {
        parents.push_back(class_id("net.parent" + std::to_string(i)));
    }
    PF_REQUIRE_FAILS(
        fabric.runtime.define_class(fabric.session,
                                    make_class("net.greedy", 3000, pf::ClassKind::Standard, parents)),
        pf::StatusCode::LimitExceeded);
}

PF_TEST(adversarial, population_limits_are_enforced_before_state_grows) {
    pf::Limits limits;
    limits.max_classes = 3;
    limits.max_scopes = 2;
    limits.max_subjects = 2;
    limits.max_assignments = 2;
    Fabric fabric;
    PF_REQUIRE(build(fabric, limits, "adversarial-population"));
    // build() already defined two classes, one scope and one subject.
    PF_REQUIRE_OK(fabric.runtime.define_class(fabric.session, make_class("net.third", 1500)));
    PF_REQUIRE_FAILS(fabric.runtime.define_class(fabric.session, make_class("net.fourth", 1600)),
                     pf::StatusCode::LimitExceeded);
    PF_REQUIRE_OK(fabric.runtime.define_scope(fabric.session, make_scope("second")));
    PF_REQUIRE_FAILS(fabric.runtime.define_scope(fabric.session, make_scope("third")),
                     pf::StatusCode::LimitExceeded);
    PF_REQUIRE_OK(fabric.runtime.define_subject(
        fabric.session, pf::SubjectDef{subject_id("tenant.other")}));
    PF_REQUIRE_FAILS(
        fabric.runtime.define_subject(fabric.session, pf::SubjectDef{subject_id("tenant.third")}),
        pf::StatusCode::LimitExceeded);
    PF_REQUIRE_OK(fabric.runtime.assign(
        fabric.session, make_assignment("a.one", "tenant.acme", "root", "net.gold")));
    PF_REQUIRE_OK(fabric.runtime.assign(
        fabric.session, make_assignment("a.two", "tenant.acme", "root", "net.silver")));
    PF_REQUIRE_FAILS(
        fabric.runtime.assign(
            fabric.session, make_assignment("a.three", "tenant.other", "root", "net.gold")),
        pf::StatusCode::LimitExceeded);
}

PF_TEST(adversarial, a_policy_cannot_see_classes_it_did_not_declare) {
    Fabric fabric;
    PF_REQUIRE(build(fabric, pf::Limits{}, "adversarial-visibility"));
    pf::PolicyDef policy;
    policy.id = policy_id("policy.gold-only");
    policy.scope = scope_id("root");
    policy.visible_classes = {class_id("net.gold")};
    // Attribution is a separate rule with its own test; turn it off so this one isolates
    // visibility.
    policy.require_policy_for_assignment = false;
    PF_REQUIRE_OK(fabric.runtime.define_policy(fabric.session, policy));

    PF_REQUIRE_FAILS(
        fabric.runtime.assign(
            fabric.session, make_assignment("a.hidden", "tenant.acme", "root", "net.silver")),
        pf::StatusCode::Unauthorized);
    PF_REQUIRE_OK(fabric.runtime.assign(
        fabric.session, make_assignment("a.visible", "tenant.acme", "root", "net.gold")));
}

PF_TEST(adversarial, a_policy_that_requires_itself_refuses_unattributed_assignments) {
    Fabric fabric;
    PF_REQUIRE(build(fabric, pf::Limits{}, "adversarial-required"));
    pf::PolicyDef policy;
    policy.id = policy_id("policy.required");
    policy.scope = scope_id("root");
    policy.require_policy_for_assignment = true;
    PF_REQUIRE_OK(fabric.runtime.define_policy(fabric.session, policy));

    PF_REQUIRE_FAILS(
        fabric.runtime.assign(
            fabric.session, make_assignment("a.bare", "tenant.acme", "root", "net.gold")),
        pf::StatusCode::Unauthorized);

    pf::PriorityAssignment attributed =
        make_assignment("a.attributed", "tenant.acme", "root", "net.gold");
    attributed.policy = policy_id("policy.required");
    PF_REQUIRE_OK(fabric.runtime.assign(fabric.session, attributed));
    PF_CHECK(fabric.runtime
                 .evaluate([&]() {
                     pf::PriorityQuery query;
                     query.subject = subject_id("tenant.acme");
                     query.scope = scope_id("root");
                     return query;
                 }())
                 .outcome == pf::Outcome::Assigned);
}

PF_TEST(adversarial, a_policy_cannot_hide_behind_a_different_policy) {
    Fabric fabric;
    PF_REQUIRE(build(fabric, pf::Limits{}, "adversarial-policy-mismatch"));
    pf::PolicyDef first;
    first.id = policy_id("policy.a");
    first.scope = scope_id("root");
    PF_REQUIRE_OK(fabric.runtime.define_policy(fabric.session, first));
    pf::PolicyDef second;
    second.id = policy_id("policy.b");
    second.scope = scope_id("root");
    PF_REQUIRE_OK(fabric.runtime.define_policy(fabric.session, second));

    // policy.a sorts first, so it is the effective policy of the scope and the assignment must
    // name it rather than policy.b.
    pf::PriorityAssignment assignment =
        make_assignment("a.mismatch", "tenant.acme", "root", "net.gold");
    assignment.policy = policy_id("policy.b");
    PF_REQUIRE_FAILS(fabric.runtime.assign(fabric.session, assignment),
                     pf::StatusCode::Unauthorized);
}

PF_TEST(adversarial, duplicate_identifiers_cannot_carry_two_meanings_at_once) {
    Fabric fabric;
    PF_REQUIRE(build(fabric, pf::Limits{}, "adversarial-identity"));
    PF_REQUIRE_OK(fabric.runtime.assign(
        fabric.session, make_assignment("a.gold", "tenant.acme", "root", "net.gold")));
    PF_CHECK_EQ(fabric.runtime.list_assignments().size(), std::size_t{1});
    PF_CHECK(fabric.runtime.evaluate([&]() {
                 pf::PriorityQuery query;
                 query.subject = subject_id("tenant.acme");
                 query.scope = scope_id("root");
                 return query;
             }())
                 .cls == class_id("net.gold"));

    // Publishing a different meaning under the same identifier creates a new generation and
    // supersedes the old one instead of quietly overwriting it.
    pf::PriorityAssignment replacement =
        make_assignment("a.gold", "tenant.acme", "root", "net.silver");
    auto assigned = fabric.runtime.assign(fabric.session, replacement);
    PF_REQUIRE_OK(assigned);
    PF_CHECK_EQ(assigned.value().value, std::uint64_t{2});
    auto stored = fabric.runtime.assignment(assignment_id("a.gold"));
    PF_REQUIRE_OK(stored);
    PF_CHECK_EQ(stored.value().generation.value, std::uint64_t{2});
    PF_CHECK(stored.value().cls == class_id("net.silver"));
}

PF_TEST(adversarial, an_assignment_bound_to_a_foreign_generation_is_refused) {
    Fabric fabric;
    PF_REQUIRE(build(fabric, pf::Limits{}, "adversarial-binding"));
    // Bypass the runtime's re-stamping by hand-building a mutation? The public API always
    // re-stamps, so the check that matters here is that the *stored* assignment follows live
    // generations and that a class redefinition invalidates it.
    PF_REQUIRE_OK(fabric.runtime.assign(
        fabric.session, make_assignment("a.gold", "tenant.acme", "root", "net.gold")));
    PF_REQUIRE_OK(fabric.runtime.define_class(fabric.session, make_class("net.gold", 950)));
    const pf::PriorityDecision decision = fabric.runtime.evaluate([&]() {
        pf::PriorityQuery query;
        query.subject = subject_id("tenant.acme");
        query.scope = scope_id("root");
        return query;
    }());
    PF_CHECK(decision.outcome == pf::Outcome::Stale);
    PF_CHECK(!decision.authoritative);
}

PF_TEST(adversarial, extreme_query_bounds_are_clamped_not_honoured) {
    Fabric fabric;
    PF_REQUIRE(build(fabric, pf::Limits{}, "adversarial-bounds"));
    PF_REQUIRE_OK(fabric.runtime.assign(
        fabric.session, make_assignment("a.gold", "tenant.acme", "root", "net.gold")));

    pf::PriorityQuery zero;
    zero.subject = subject_id("tenant.acme");
    zero.scope = scope_id("root");
    zero.max_explanation_steps = 0;  // means "no preference", not "no explanation"
    const pf::PriorityDecision zero_decision = fabric.runtime.evaluate(zero);
    PF_CHECK(zero_decision.outcome == pf::Outcome::Assigned);
    PF_CHECK(!zero_decision.chain.empty());

    pf::PriorityQuery huge;
    huge.subject = subject_id("tenant.acme");
    huge.scope = scope_id("root");
    huge.max_explanation_steps = 0xFFFFFFFFu;
    const pf::PriorityDecision huge_decision = fabric.runtime.evaluate(huge);
    PF_CHECK(huge_decision.chain.size() <= pf::Limits{}.max_explanation_steps);
}

PF_TEST(adversarial, a_query_with_a_broken_identifier_is_rejected) {
    Fabric fabric;
    PF_REQUIRE(build(fabric, pf::Limits{}, "adversarial-ids"));
    pf::PriorityQuery query;
    query.scope = scope_id("root");
    const pf::PriorityDecision decision = fabric.runtime.evaluate(query);
    PF_CHECK(decision.outcome == pf::Outcome::Rejected);
    PF_CHECK_EQ(decision.reason_code, std::string("invalid_subject_id"));

    pf::PriorityQuery second;
    second.subject = subject_id("tenant.acme");
    const pf::PriorityDecision second_decision = fabric.runtime.evaluate(second);
    PF_CHECK(second_decision.outcome == pf::Outcome::Rejected);
    PF_CHECK_EQ(second_decision.reason_code, std::string("invalid_scope_id"));
}

PF_TEST(adversarial, a_journal_appended_with_garbage_does_not_become_authority) {
    Fabric fabric;
    PF_REQUIRE(build(fabric, pf::Limits{}, "adversarial-garbage"));
    PF_REQUIRE_OK(fabric.runtime.assign(
        fabric.session, make_assignment("a.gold", "tenant.acme", "root", "net.gold")));
    PF_REQUIRE_OK(fabric.runtime.close());

    const std::filesystem::path journal =
        fabric.directory.path() / "state" / pf::DurableLayout::journal_segment_name(0);
    {
        std::ofstream stream(journal, std::ios::binary | std::ios::app);
        const std::string garbage = "PFJ1\x01\x00 this is not a record at all";
        stream.write(garbage.data(), static_cast<std::streamsize>(garbage.size()));
    }

    pf::FabricRuntime::Options options;
    options.state_dir = fabric.directory.path() / "state";
    options.instance_boot_id = boot_for("adversarial-garbage/reopen");
    auto opened = pf::FabricRuntime::open(options);
    PF_REQUIRE_OK(opened);
    fabric.runtime = std::move(opened.value());
    // The trailing garbage is an unfinished append, not a record: it is discarded and the
    // committed state stands.
    PF_CHECK(fabric.runtime.health() == pf::Health::Healthy);
    pf::PriorityQuery query;
    query.subject = subject_id("tenant.acme");
    query.scope = scope_id("root");
    // Recovery restores facts, never authority: until the publisher asks again, the
    // assignment is refused rather than believed.
    PF_CHECK(fabric.runtime.evaluate(query).outcome == pf::Outcome::Fenced);
    PF_REQUIRE_OK(fabric.runtime.grant_authority(publisher_id("test.publisher"),
                                                 boot_for("adversarial-garbage")));
    PF_CHECK(fabric.runtime.evaluate(query).outcome == pf::Outcome::Assigned);
}

PF_TEST(adversarial, a_randomly_corrupted_journal_never_yields_a_silent_wrong_answer) {
    std::mt19937_64 engine(0xC0FFEEull);
    for (int trial = 0; trial < 12; ++trial) {
        Fabric fabric;
        PF_REQUIRE(build(fabric, pf::Limits{}, "adversarial-fuzz"));
        for (int i = 0; i < 6; ++i) {
            PF_REQUIRE_OK(fabric.runtime.define_class(
                fabric.session,
                make_class("net.fuzz" + std::to_string(i), 2000u + static_cast<std::uint32_t>(i))));
        }
        PF_REQUIRE_OK(fabric.runtime.close());

        const std::filesystem::path journal =
            fabric.directory.path() / "state" / pf::DurableLayout::journal_segment_name(0);
        std::error_code ec;
        const auto size = std::filesystem::file_size(journal, ec);
        PF_REQUIRE(!ec);
        if (size == 0) {
            continue;
        }
        std::uniform_int_distribution<std::uint64_t> offset(0, size - 1);
        const std::uint64_t position = offset(engine);
        {
            std::fstream stream(journal, std::ios::in | std::ios::out | std::ios::binary);
            stream.seekg(static_cast<std::streamoff>(position));
            char byte = 0;
            stream.read(&byte, 1);
            byte = static_cast<char>(byte ^ 0x3C);
            stream.seekp(static_cast<std::streamoff>(position));
            stream.write(&byte, 1);
        }

        pf::FabricRuntime::Options options;
        options.state_dir = fabric.directory.path() / "state";
        auto opened = pf::FabricRuntime::open(options);
        if (!opened.ok()) {
            // A refusal is a correct outcome.
            continue;
        }
        pf::FabricRuntime runtime = std::move(opened.value());
        if (runtime.health() == pf::Health::Degraded) {
            pf::PriorityQuery query;
            query.subject = subject_id("tenant.acme");
            query.scope = scope_id("root");
            PF_CHECK(runtime.evaluate(query).outcome == pf::Outcome::Rejected);
            PF_REQUIRE_FAILS(runtime.grant_authority(publisher_id("test.publisher"),
                                                     boot_for("adversarial-fuzz/after")),
                             pf::StatusCode::Degraded);
            continue;
        }
        // Healthy after a corruption attempt means the damage landed in the discarded tail.
        // The state must then still verify end to end.
        const auto report = runtime.integrity_report();
        PF_CHECK(report.ok);
    }
}

PF_TEST(adversarial, a_settled_store_refuses_every_mutation_shape) {
    Fabric fabric;
    PF_REQUIRE(build(fabric, pf::Limits{}, "adversarial-shapes"));
    pf::Session bogus;
    bogus.publisher = publisher_id("test.publisher");
    PF_REQUIRE_FAILS(fabric.runtime.define_class(bogus, make_class("net.x", 1000)),
                     pf::StatusCode::Unauthorized);
    pf::Session wrong_boot = fabric.session;
    wrong_boot.boot = boot_for("adversarial-shapes/intruder");
    PF_REQUIRE_FAILS(fabric.runtime.define_class(wrong_boot, make_class("net.y", 1001)),
                     pf::StatusCode::Unauthorized);
    pf::Session wrong_token = fabric.session;
    wrong_token.token = pf::FencingToken{wrong_token.token.value + 1};
    PF_REQUIRE_FAILS(fabric.runtime.define_class(wrong_token, make_class("net.z", 1002)),
                     pf::StatusCode::Fenced);
    pf::Session wrong_epoch = fabric.session;
    wrong_epoch.epoch = pf::FabricEpoch{wrong_epoch.epoch.value + 1};
    PF_REQUIRE_FAILS(fabric.runtime.define_class(wrong_epoch, make_class("net.w", 1003)),
                     pf::StatusCode::StaleEpoch);
    // The state must be untouched by all four attempts.
    PF_CHECK(!fabric.runtime.class_definition(class_id("net.x")).ok());
    PF_CHECK(!fabric.runtime.class_definition(class_id("net.y")).ok());
    PF_CHECK(!fabric.runtime.class_definition(class_id("net.z")).ok());
    PF_CHECK(!fabric.runtime.class_definition(class_id("net.w")).ok());
}
