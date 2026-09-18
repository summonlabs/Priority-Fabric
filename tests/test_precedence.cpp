// Priority Fabric -- authoritative network priority classes.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "framework.hpp"
#include "support.hpp"

using namespace pftest;

namespace {

/// Defines a minimal, valid fabric: two classes, one root scope, one subject.
bool build_minimal(Fabric& fabric) {
    if (!open_fabric(fabric, "precedence")) {
        return false;
    }
    if (!fabric.runtime
             .define_class(fabric.session,
                           make_class("net.gold", 900, pf::ClassKind::Tenant))
             .ok()) {
        return false;
    }
    if (!fabric.runtime
             .define_class(fabric.session,
                           make_class("net.silver", 500, pf::ClassKind::Tenant))
             .ok()) {
        return false;
    }
    if (!fabric.runtime.define_scope(fabric.session, make_scope("root")).ok()) {
        return false;
    }
    if (!fabric.runtime.define_subject(fabric.session, pf::SubjectDef{subject_id("tenant.acme")})
             .ok()) {
        return false;
    }
    return true;
}

}  // namespace

PF_TEST(precedence, ranks_must_be_declared_and_unique) {
    Fabric fabric;
    PF_REQUIRE(build_minimal(fabric));

    pf::PriorityClassDef undeclared = make_class("net.undeclared", 0);
    undeclared.precedence = pf::PrecedenceRank::undeclared();
    PF_REQUIRE_FAILS(fabric.runtime.define_class(fabric.session, undeclared),
                     pf::StatusCode::InvalidArgument);

    PF_REQUIRE_FAILS(
        fabric.runtime.define_class(fabric.session, make_class("net.duplicate", 900)),
        pf::StatusCode::DuplicatePrecedence);

    // Redefining the same class with the same rank is a legitimate republication.
    auto republished = fabric.runtime.define_class(
        fabric.session, make_class("net.gold", 900, pf::ClassKind::Tenant));
    PF_REQUIRE_OK(republished);
    PF_CHECK_EQ(republished.value().value, std::uint64_t{1});
}

PF_TEST(precedence, identical_republication_is_a_noop_and_changes_bump_the_generation) {
    Fabric fabric;
    PF_REQUIRE(build_minimal(fabric));
    const pf::Generation before = fabric.runtime.state_generation();

    auto same = fabric.runtime.define_class(
        fabric.session, make_class("net.gold", 900, pf::ClassKind::Tenant));
    PF_REQUIRE_OK(same);
    PF_CHECK_EQ(same.value().value, std::uint64_t{1});
    PF_CHECK_EQ(fabric.runtime.state_generation().value, before.value);

    auto changed = fabric.runtime.define_class(
        fabric.session, make_class("net.gold", 901, pf::ClassKind::Tenant));
    PF_REQUIRE_OK(changed);
    PF_CHECK_EQ(changed.value().value, std::uint64_t{2});
    PF_CHECK(fabric.runtime.state_generation().value > before.value);

    auto definition = fabric.runtime.class_definition(class_id("net.gold"));
    PF_REQUIRE_OK(definition);
    PF_CHECK_EQ(definition.value().generation.value, std::uint64_t{2});
    PF_CHECK_EQ(definition.value().precedence.value, 901u);
}

PF_TEST(precedence, an_identical_republication_from_another_incarnation_keeps_the_entity_generation) {
    Fabric fabric;
    PF_REQUIRE(build_minimal(fabric));
    auto assigned = fabric.runtime.assign(
        fabric.session, make_assignment("a.gold", "tenant.acme", "root", "net.gold"));
    PF_REQUIRE_OK(assigned);

    // A second incarnation of the same publisher republishes exactly the same class. The
    // class means the same thing, so its generation must not move and the assignment bound to
    // it must stay usable.
    auto second = fabric.runtime.grant_authority(publisher_id("test.publisher"),
                                                 boot_for("precedence/second"));
    PF_REQUIRE_OK(second);
    const pf::Generation before = fabric.runtime.state_generation();
    auto republished = fabric.runtime.define_class(
        second.value(), make_class("net.gold", 900, pf::ClassKind::Tenant));
    PF_REQUIRE_OK(republished);
    PF_CHECK_EQ(republished.value().value, std::uint64_t{1});
    PF_CHECK(fabric.runtime.state_generation().value > before.value);

    auto definition = fabric.runtime.class_definition(class_id("net.gold"));
    PF_REQUIRE_OK(definition);
    PF_CHECK_EQ(definition.value().generation.value, std::uint64_t{1});
    PF_CHECK(fabric.runtime
                 .evaluate([&]() {
                     pf::PriorityQuery query;
                     query.subject = subject_id("tenant.acme");
                     query.scope = scope_id("root");
                     return query;
                 }())
                 .outcome == pf::Outcome::Fenced);
}

PF_TEST(precedence, inheritance_cycles_are_rejected_with_a_clear_reason) {
    Fabric fabric;
    PF_REQUIRE(build_minimal(fabric));

    PF_REQUIRE_OK(fabric.runtime.define_class(
        fabric.session, make_class("net.base", 100, pf::ClassKind::Standard)));
    PF_REQUIRE_OK(fabric.runtime.define_class(
        fabric.session,
        make_class("net.mid", 200, pf::ClassKind::Standard, {class_id("net.base")})));

    // mid -> base already exists; making base inherit mid would close the cycle.
    auto cycle = fabric.runtime.define_class(
        fabric.session,
        make_class("net.base", 100, pf::ClassKind::Standard, {class_id("net.mid")}));
    PF_REQUIRE_FAILS(cycle, pf::StatusCode::CycleDetected);

    PF_REQUIRE_FAILS(
        fabric.runtime.define_class(
            fabric.session,
            make_class("net.self", 300, pf::ClassKind::Standard, {class_id("net.self")})),
        pf::StatusCode::CycleDetected);

    PF_REQUIRE_FAILS(
        fabric.runtime.define_class(
            fabric.session,
            make_class("net.missing", 400, pf::ClassKind::Standard, {class_id("net.absent")})),
        pf::StatusCode::NotFound);

    std::vector<pf::PriorityClassId> duplicated{class_id("net.base"), class_id("net.base")};
    PF_REQUIRE_FAILS(
        fabric.runtime.define_class(fabric.session,
                                    make_class("net.dup", 500, pf::ClassKind::Standard,
                                               duplicated)),
        pf::StatusCode::InvalidArgument);

    // The rejected attempts must not have changed the state.
    PF_CHECK(!fabric.runtime.class_definition(class_id("net.self")).ok());
    PF_CHECK(!fabric.runtime.class_definition(class_id("net.missing")).ok());
}

PF_TEST(precedence, inheritance_depth_is_bounded) {
    Fabric fabric;
    PF_REQUIRE(build_minimal(fabric));
    pf::Limits limits;
    limits.max_inheritance_depth = 8;
    // The runtime was opened with default limits; a chain longer than the default depth must
    // be refused by the default limit.
    std::string previous = "net.gold";
    bool refused = false;
    for (int level = 0; level < 40; ++level) {
        const std::string name = "chain.level" + std::to_string(level);
        auto defined = fabric.runtime.define_class(
            fabric.session,
            make_class(name, 10000u + static_cast<std::uint32_t>(level), pf::ClassKind::Standard,
                       {class_id(previous)}));
        if (!defined.ok()) {
            refused = true;
            PF_CHECK_EQ(defined.status().code(), pf::StatusCode::LimitExceeded);
            break;
        }
        previous = name;
    }
    PF_CHECK(refused);
}

PF_TEST(precedence, scope_tree_rejects_cycles_and_missing_parents) {
    Fabric fabric;
    PF_REQUIRE(build_minimal(fabric));
    PF_REQUIRE_OK(fabric.runtime.define_scope(fabric.session, make_scope("region")));
    PF_REQUIRE_OK(fabric.runtime.define_scope(
        fabric.session, make_scope("region.eu", scope_id("region"))));
    PF_REQUIRE_OK(fabric.runtime.define_scope(
        fabric.session, make_scope("region.eu.west", scope_id("region.eu"))));

    PF_REQUIRE_FAILS(fabric.runtime.define_scope(fabric.session, make_scope("orphan", scope_id("nowhere"))),
                     pf::StatusCode::NotFound);

    // region -> region.eu -> region.eu.west; attaching region under its own descendant is a cycle.
    PF_REQUIRE_FAILS(
        fabric.runtime.define_scope(fabric.session,
                                    make_scope("region", scope_id("region.eu.west"))),
        pf::StatusCode::CycleDetected);

    PF_REQUIRE_FAILS(
        fabric.runtime.define_scope(fabric.session, make_scope("self", scope_id("self"))),
        pf::StatusCode::CycleDetected);
}

PF_TEST(precedence, unknown_default_must_name_a_registered_class) {
    Fabric fabric;
    PF_REQUIRE(build_minimal(fabric));
    PF_REQUIRE_FAILS(
        fabric.runtime.define_scope(fabric.session,
                                    make_scope("root2", std::nullopt,
                                               pf::ConflictResolution::Deny,
                                               class_id("net.absent"))),
        pf::StatusCode::NotFound);
    PF_REQUIRE_OK(fabric.runtime.define_scope(
        fabric.session, make_scope("root2", std::nullopt, pf::ConflictResolution::Deny,
                                   class_id("net.silver"))));
}

PF_TEST(precedence, subject_inheritance_is_a_dag_and_bounded) {
    Fabric fabric;
    PF_REQUIRE(build_minimal(fabric));
    PF_REQUIRE_OK(fabric.runtime.define_subject(
        fabric.session, make_subject("tenant.base", {}, "tenant root")));
    PF_REQUIRE_OK(fabric.runtime.define_subject(
        fabric.session, make_subject("tenant.child", {"tenant.base"})));

    pf::SubjectDef cycle;
    cycle.id = subject_id("tenant.base");
    cycle.inherits_from = {subject_id("tenant.child")};
    PF_REQUIRE_FAILS(fabric.runtime.define_subject(fabric.session, cycle),
                     pf::StatusCode::CycleDetected);

    PF_REQUIRE_FAILS(
        fabric.runtime.define_subject(fabric.session,
                                       make_subject("tenant.orphan", {"tenant.gone"})),
        pf::StatusCode::NotFound);
}

PF_TEST(precedence, policy_binds_to_the_exact_scope_generation_it_saw) {
    Fabric fabric;
    PF_REQUIRE(build_minimal(fabric));
    pf::PolicyDef policy;
    policy.id = policy_id("policy.traffic");
    policy.scope = scope_id("root");
    policy.visible_classes = {class_id("net.gold")};
    auto defined = fabric.runtime.define_policy(fabric.session, policy);
    PF_REQUIRE_OK(defined);

    // A caller cannot smuggle a scope generation in: the runtime re-stamps it from live state.
    pf::PolicyDef forged = policy;
    forged.id = policy_id("policy.forged");
    forged.scope_generation = pf::Generation{99};
    PF_REQUIRE_OK(fabric.runtime.define_policy(fabric.session, forged));
    auto stored = fabric.runtime.policy_definition(policy_id("policy.forged"));
    PF_REQUIRE_OK(stored);
    auto scope = fabric.runtime.scope_definition(scope_id("root"));
    PF_REQUIRE_OK(scope);
    PF_CHECK_EQ(stored.value().scope_generation.value, scope.value().generation.value);

    pf::PolicyDef missing = policy;
    missing.id = policy_id("policy.missing");
    missing.scope = scope_id("nowhere");
    PF_REQUIRE_FAILS(fabric.runtime.define_policy(fabric.session, missing),
                     pf::StatusCode::NotFound);
}

PF_TEST(precedence, assignments_are_stamped_with_the_generations_they_saw) {
    Fabric fabric;
    PF_REQUIRE(build_minimal(fabric));
    auto assigned = fabric.runtime.assign(
        fabric.session, make_assignment("assign.gold", "tenant.acme", "root", "net.gold"));
    PF_REQUIRE_OK(assigned);

    auto stored = fabric.runtime.assignment(assignment_id("assign.gold"));
    PF_REQUIRE_OK(stored);
    PF_CHECK_EQ(stored.value().subject_generation.value, std::uint64_t{1});
    PF_CHECK_EQ(stored.value().scope_generation.value, std::uint64_t{1});
    PF_CHECK_EQ(stored.value().class_generation.value, std::uint64_t{1});

    // A caller may not smuggle a generation in: the runtime re-stamps from live state.
    pf::PriorityAssignment forged =
        make_assignment("assign.forged", "tenant.acme", "root", "net.gold");
    forged.class_generation = pf::Generation{77};
    auto forged_result = fabric.runtime.assign(fabric.session, forged);
    PF_REQUIRE_OK(forged_result);
    auto forged_stored = fabric.runtime.assignment(assignment_id("assign.forged"));
    PF_REQUIRE_OK(forged_stored);
    PF_CHECK_EQ(forged_stored.value().class_generation.value, std::uint64_t{1});

    PF_REQUIRE_FAILS(fabric.runtime.assign(fabric.session,
                                           make_assignment("assign.ghost", "tenant.ghost", "root",
                                                           "net.gold")),
                     pf::StatusCode::NotFound);
    PF_REQUIRE_FAILS(fabric.runtime.assign(fabric.session,
                                           make_assignment("assign.bad", "tenant.acme", "nowhere",
                                                           "net.gold")),
                     pf::StatusCode::NotFound);
    PF_REQUIRE_FAILS(fabric.runtime.assign(fabric.session,
                                           make_assignment("assign.bad2", "tenant.acme", "root",
                                                           "net.absent")),
                     pf::StatusCode::NotFound);

    pf::PriorityAssignment as_default =
        make_assignment("assign.default", "tenant.acme", "root", "net.gold",
                        pf::AssignmentKind::Default);
    PF_REQUIRE_FAILS(fabric.runtime.assign(fabric.session, as_default),
                     pf::StatusCode::InvalidArgument);
}
