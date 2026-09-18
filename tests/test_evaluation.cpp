// Priority Fabric -- authoritative network priority classes.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "framework.hpp"
#include "support.hpp"

using namespace pftest;

namespace {

pf::PriorityQuery make_query(std::string_view subject, std::string_view scope) {
    pf::PriorityQuery query;
    query.subject = subject_id(subject);
    query.scope = scope_id(scope);
    query.max_explanation_steps = 32;
    return query;
}

/// A world with a class ladder, a three-level scope tree and two subjects where one
/// inherits from the other.
bool build_world(Fabric& fabric) {
    if (!open_fabric(fabric, "evaluation")) {
        return false;
    }
    struct ClassSpec {
        const char* id;
        std::uint32_t rank;
        pf::ClassKind kind;
    };
    const ClassSpec classes[] = {
        {"net.realtime", 1000, pf::ClassKind::System},
        {"net.gold", 900, pf::ClassKind::Tenant},
        {"net.silver", 500, pf::ClassKind::Tenant},
        {"net.bronze", 100, pf::ClassKind::Tenant},
        {"net.bulk", 50, pf::ClassKind::Tenant},
    };
    for (const auto& spec : classes) {
        auto defined = fabric.runtime.define_class(
            fabric.session, make_class(spec.id, spec.rank, spec.kind));
        if (!defined.ok()) {
            return false;
        }
    }
    if (!fabric.runtime.define_scope(fabric.session, make_scope("root")).ok()) {
        return false;
    }
    if (!fabric.runtime
             .define_scope(fabric.session, make_scope("region", scope_id("root")))
             .ok()) {
        return false;
    }
    if (!fabric.runtime
             .define_scope(fabric.session, make_scope("region.eu", scope_id("region")))
             .ok()) {
        return false;
    }
    if (!fabric.runtime.define_subject(fabric.session, pf::SubjectDef{subject_id("tenant.acme")})
             .ok()) {
        return false;
    }
    pf::SubjectDef child;
    child.id = subject_id("tenant.acme.gold");
    child.inherits_from = {subject_id("tenant.acme")};
    if (!fabric.runtime.define_subject(fabric.session, child).ok()) {
        return false;
    }
    return true;
}

}  // namespace

PF_TEST(evaluation, assigned_when_evidence_names_the_class_directly) {
    Fabric fabric;
    PF_REQUIRE(build_world(fabric));
    PF_REQUIRE_OK(fabric.runtime.assign(
        fabric.session, make_assignment("a.gold", "tenant.acme", "root", "net.gold")));

    const pf::PriorityDecision decision = fabric.runtime.evaluate(make_query("tenant.acme", "root"));
    PF_CHECK(decision.outcome == pf::Outcome::Assigned);
    PF_CHECK(decision.authoritative);
    PF_CHECK(decision.cls == class_id("net.gold"));
    PF_CHECK_EQ(decision.precedence.value, 900u);
    PF_CHECK_EQ(decision.reason_code, std::string("explicit_assignment"));
    PF_CHECK(!decision.digest.is_zero());
    PF_CHECK(!decision.chain.empty());
    // The chain must carry the evidence, not just a verdict.
    bool saw_assignment = false;
    for (const auto& step : decision.chain) {
        if (step.assignment.has_value() && *step.assignment == assignment_id("a.gold")) {
            saw_assignment = true;
            PF_CHECK(step.provenance.publisher == publisher_id("test.publisher"));
            PF_CHECK(step.provenance.epoch.value != 0);
            PF_CHECK(step.provenance.token.is_valid());
        }
    }
    PF_CHECK(saw_assignment);
}

PF_TEST(evaluation, unknown_stays_unknown_and_is_never_a_low_class) {
    Fabric fabric;
    PF_REQUIRE(build_world(fabric));
    const pf::PriorityDecision decision =
        fabric.runtime.evaluate(make_query("tenant.acme", "root"));
    PF_CHECK(decision.outcome == pf::Outcome::Unknown);
    PF_CHECK(!decision.authoritative);
    PF_CHECK(!decision.cls.valid());
    PF_CHECK(!decision.precedence.is_declared());
    PF_CHECK_EQ(decision.reason_code, std::string("no_authoritative_assignment"));
    PF_CHECK(pf::outcome_carries_authority(decision.outcome) == false);
}

PF_TEST(evaluation, a_policy_declared_default_is_the_only_way_unknown_becomes_a_class) {
    Fabric fabric;
    PF_REQUIRE(build_world(fabric));
    PF_REQUIRE_OK(fabric.runtime.define_scope(
        fabric.session, make_scope("root", std::nullopt, pf::ConflictResolution::Deny,
                                   class_id("net.bulk"))));

    const pf::PriorityDecision decision =
        fabric.runtime.evaluate(make_query("tenant.acme", "root"));
    PF_CHECK(decision.outcome == pf::Outcome::Assigned);
    PF_CHECK(decision.authoritative);
    PF_CHECK(decision.cls == class_id("net.bulk"));
    PF_CHECK_EQ(decision.resolution, std::string("policy_default"));
    PF_CHECK_EQ(decision.reason_code, std::string("policy_declared_default"));
}

PF_TEST(evaluation, a_default_that_is_not_visible_is_reported_rather_than_substituted) {
    Fabric fabric;
    PF_REQUIRE(build_world(fabric));
    PF_REQUIRE_OK(fabric.runtime.define_scope(
        fabric.session, make_scope("root", std::nullopt, pf::ConflictResolution::Deny,
                                   class_id("net.bulk"))));
    pf::PolicyDef policy;
    policy.id = policy_id("policy.gold-only");
    policy.scope = scope_id("root");
    policy.visible_classes = {class_id("net.gold")};
    PF_REQUIRE_OK(fabric.runtime.define_policy(fabric.session, policy));

    const pf::PriorityDecision decision =
        fabric.runtime.evaluate(make_query("tenant.acme", "root"));
    PF_CHECK(decision.outcome == pf::Outcome::Unknown);
    PF_CHECK(!decision.authoritative);
    PF_CHECK_EQ(decision.reason_code, std::string("default_class_unavailable"));
}

PF_TEST(evaluation, inherited_evidence_is_named_explicitly) {
    Fabric fabric;
    PF_REQUIRE(build_world(fabric));
    PF_REQUIRE_OK(fabric.runtime.assign(
        fabric.session, make_assignment("a.inherit", "tenant.acme", "root", "net.silver",
                                        pf::AssignmentKind::Inherited)));

    const pf::PriorityDecision direct =
        fabric.runtime.evaluate(make_query("tenant.acme", "root"));
    PF_CHECK(direct.outcome == pf::Outcome::Assigned);

    const pf::PriorityDecision inherited =
        fabric.runtime.evaluate(make_query("tenant.acme.gold", "root"));
    PF_CHECK(inherited.outcome == pf::Outcome::Inherited);
    PF_CHECK(inherited.authoritative);
    PF_CHECK(inherited.cls == class_id("net.silver"));
    PF_CHECK_EQ(inherited.reason_code, std::string("inherited_from_ancestor"));
}

PF_TEST(evaluation, an_explicit_assignment_on_a_descendant_displaces_inheritance) {
    Fabric fabric;
    PF_REQUIRE(build_world(fabric));
    PF_REQUIRE_OK(fabric.runtime.assign(
        fabric.session, make_assignment("a.base", "tenant.acme", "root", "net.silver",
                                        pf::AssignmentKind::Inherited)));
    PF_REQUIRE_OK(fabric.runtime.assign(
        fabric.session, make_assignment("a.own", "tenant.acme.gold", "root", "net.gold")));

    const pf::PriorityDecision decision =
        fabric.runtime.evaluate(make_query("tenant.acme.gold", "root"));
    PF_CHECK(decision.outcome == pf::Outcome::Assigned);
    PF_CHECK(decision.cls == class_id("net.gold"));
}

PF_TEST(evaluation, a_narrower_scope_overrides_a_broader_one) {
    Fabric fabric;
    PF_REQUIRE(build_world(fabric));
    PF_REQUIRE_OK(fabric.runtime.assign(
        fabric.session, make_assignment("a.broad", "tenant.acme", "root", "net.silver")));
    PF_REQUIRE_OK(fabric.runtime.assign(
        fabric.session, make_assignment("a.narrow", "tenant.acme", "region", "net.gold")));

    const pf::PriorityDecision decision =
        fabric.runtime.evaluate(make_query("tenant.acme", "region"));
    PF_CHECK(decision.outcome == pf::Outcome::Overridden);
    PF_CHECK(decision.authoritative);
    PF_CHECK(decision.cls == class_id("net.gold"));
    PF_CHECK_EQ(decision.resolution, std::string("narrower_scope"));
    PF_REQUIRE(!decision.superseded.empty());
    PF_CHECK(decision.superseded.front().assignment == assignment_id("a.broad"));
    PF_CHECK_EQ(decision.superseded.front().reason_code, std::string("broader_scope_displaced"));
}

PF_TEST(evaluation, references_outside_the_queried_scope_chain_are_not_evidence) {
    Fabric fabric;
    PF_REQUIRE(build_world(fabric));
    PF_REQUIRE_OK(fabric.runtime.define_scope(fabric.session, make_scope("other")));
    PF_REQUIRE_OK(fabric.runtime.assign(
        fabric.session, make_assignment("a.other", "tenant.acme", "other", "net.gold")));

    const pf::PriorityDecision decision =
        fabric.runtime.evaluate(make_query("tenant.acme", "region.eu"));
    PF_CHECK(decision.outcome == pf::Outcome::Unknown);
}

PF_TEST(evaluation, same_level_conflict_is_unresolved_by_default) {
    Fabric fabric;
    PF_REQUIRE(build_world(fabric));
    PF_REQUIRE_OK(fabric.runtime.assign(
        fabric.session, make_assignment("a.one", "tenant.acme", "root", "net.gold")));
    PF_REQUIRE_OK(fabric.runtime.assign(
        fabric.session, make_assignment("a.two", "tenant.acme", "root", "net.silver")));

    const pf::PriorityDecision decision =
        fabric.runtime.evaluate(make_query("tenant.acme", "root"));
    PF_CHECK(decision.outcome == pf::Outcome::Conflict);
    PF_CHECK(!decision.authoritative);
    PF_CHECK(!decision.cls.valid());
    PF_CHECK_EQ(decision.reason_code, std::string("conflict_unresolved"));
    PF_CHECK_EQ(decision.conflicts.size(), std::size_t{2});
}

PF_TEST(evaluation, a_policy_can_resolve_a_conflict_deterministically_and_still_report_it) {
    Fabric fabric;
    PF_REQUIRE(build_world(fabric));
    PF_REQUIRE_OK(fabric.runtime.define_scope(
        fabric.session, make_scope("root", std::nullopt, pf::ConflictResolution::HigherPrecedence)));
    PF_REQUIRE_OK(fabric.runtime.assign(
        fabric.session, make_assignment("a.one", "tenant.acme", "root", "net.gold")));
    PF_REQUIRE_OK(fabric.runtime.assign(
        fabric.session, make_assignment("a.two", "tenant.acme", "root", "net.silver")));

    const pf::PriorityDecision decision =
        fabric.runtime.evaluate(make_query("tenant.acme", "root"));
    PF_CHECK(decision.outcome == pf::Outcome::Conflict);
    PF_CHECK(decision.authoritative);
    PF_CHECK(decision.cls == class_id("net.gold"));
    PF_CHECK_EQ(decision.reason_code, std::string("conflict_resolved"));
    PF_CHECK(decision.conflicts.size() == 2);
    PF_CHECK(decision.superseded.size() == 1);
    PF_CHECK(decision.superseded.front().assignment == assignment_id("a.two"));
}

PF_TEST(evaluation, strict_conflicts_deny_even_when_a_policy_would_resolve) {
    Fabric fabric;
    PF_REQUIRE(build_world(fabric));
    PF_REQUIRE_OK(fabric.runtime.define_scope(
        fabric.session, make_scope("root", std::nullopt, pf::ConflictResolution::HigherPrecedence)));
    PF_REQUIRE_OK(fabric.runtime.assign(
        fabric.session, make_assignment("a.one", "tenant.acme", "root", "net.gold")));
    PF_REQUIRE_OK(fabric.runtime.assign(
        fabric.session, make_assignment("a.two", "tenant.acme", "root", "net.silver")));

    pf::PriorityQuery query = make_query("tenant.acme", "root");
    query.strict_conflicts = true;
    const pf::PriorityDecision decision = fabric.runtime.evaluate(query);
    PF_CHECK(decision.outcome == pf::Outcome::Conflict);
    PF_CHECK(!decision.authoritative);
    PF_CHECK_EQ(decision.resolution, std::string("denied_by_caller"));
}

PF_TEST(evaluation, conflicting_ids_at_the_same_level_may_be_order_resolved) {
    Fabric fabric;
    PF_REQUIRE(build_world(fabric));
    PF_REQUIRE_OK(fabric.runtime.define_scope(
        fabric.session, make_scope("root", std::nullopt, pf::ConflictResolution::AssignmentIdOrder)));
    PF_REQUIRE_OK(fabric.runtime.assign(
        fabric.session, make_assignment("a.bbb", "tenant.acme", "root", "net.silver")));
    PF_REQUIRE_OK(fabric.runtime.assign(
        fabric.session, make_assignment("a.aaa", "tenant.acme", "root", "net.gold")));

    const pf::PriorityDecision decision =
        fabric.runtime.evaluate(make_query("tenant.acme", "root"));
    PF_CHECK(decision.outcome == pf::Outcome::Conflict);
    PF_CHECK(decision.authoritative);
    PF_CHECK(decision.cls == class_id("net.gold"));
    PF_CHECK_EQ(decision.resolution, std::string("assignment_id_order_by_scope"));
}

PF_TEST(evaluation, a_redefined_class_makes_its_assignments_stale) {
    Fabric fabric;
    PF_REQUIRE(build_world(fabric));
    PF_REQUIRE_OK(fabric.runtime.assign(
        fabric.session, make_assignment("a.gold", "tenant.acme", "root", "net.gold")));
    PF_CHECK(fabric.runtime.evaluate(make_query("tenant.acme", "root")).outcome ==
             pf::Outcome::Assigned);

    PF_REQUIRE_OK(fabric.runtime.define_class(
        fabric.session, make_class("net.gold", 901, pf::ClassKind::Tenant)));

    const pf::PriorityDecision decision =
        fabric.runtime.evaluate(make_query("tenant.acme", "root"));
    PF_CHECK(decision.outcome == pf::Outcome::Stale);
    PF_CHECK(!decision.authoritative);
    PF_CHECK_EQ(decision.reason_code, std::string("evidence_stale"));
    PF_REQUIRE(!decision.rejected_evidence.empty());
    PF_CHECK_EQ(decision.rejected_evidence.front().reason_code,
                std::string("class_generation_stale"));
}

PF_TEST(evaluation, a_redefined_scope_makes_its_assignments_stale) {
    Fabric fabric;
    PF_REQUIRE(build_world(fabric));
    PF_REQUIRE_OK(fabric.runtime.assign(
        fabric.session, make_assignment("a.gold", "tenant.acme", "region", "net.gold")));
    // Redefining the scope with identical content is a no-op; a real change moves the
    // generation and must therefore invalidate everything bound to the old one.
    PF_REQUIRE_OK(
        fabric.runtime.define_scope(fabric.session, make_scope("region", scope_id("root"))));
    PF_CHECK(fabric.runtime.evaluate(make_query("tenant.acme", "region")).outcome ==
             pf::Outcome::Assigned);

    pf::PolicyScopeDef changed = make_scope("region", scope_id("root"));
    changed.description = "changed";
    PF_REQUIRE_OK(fabric.runtime.define_scope(fabric.session, changed));
    const pf::PriorityDecision decision =
        fabric.runtime.evaluate(make_query("tenant.acme", "region"));
    PF_CHECK(decision.outcome == pf::Outcome::Stale);
    PF_REQUIRE(!decision.rejected_evidence.empty());
    PF_CHECK_EQ(decision.rejected_evidence.front().reason_code,
                std::string("scope_generation_stale"));
}

PF_TEST(evaluation, superseded_policy_generations_cannot_authorize) {
    Fabric fabric;
    PF_REQUIRE(build_world(fabric));
    pf::PolicyDef policy;
    policy.id = policy_id("policy.traffic");
    policy.scope = scope_id("root");
    PF_REQUIRE_OK(fabric.runtime.define_policy(fabric.session, policy));

    pf::PriorityAssignment assignment =
        make_assignment("a.gold", "tenant.acme", "root", "net.gold");
    assignment.policy = policy_id("policy.traffic");
    PF_REQUIRE_OK(fabric.runtime.assign(fabric.session, assignment));
    PF_CHECK(fabric.runtime.evaluate(make_query("tenant.acme", "root")).outcome ==
             pf::Outcome::Assigned);

    policy.visible_classes = {class_id("net.gold"), class_id("net.silver")};
    PF_REQUIRE_OK(fabric.runtime.define_policy(fabric.session, policy));

    const pf::PriorityDecision decision =
        fabric.runtime.evaluate(make_query("tenant.acme", "root"));
    PF_CHECK(decision.outcome == pf::Outcome::Stale);
    PF_REQUIRE(!decision.rejected_evidence.empty());
    PF_CHECK_EQ(decision.rejected_evidence.front().reason_code,
                std::string("policy_generation_stale"));
}

PF_TEST(evaluation, a_fenced_publisher_incarnation_cannot_authorize) {
    Fabric fabric;
    PF_REQUIRE(build_world(fabric));
    PF_REQUIRE_OK(fabric.runtime.assign(
        fabric.session, make_assignment("a.gold", "tenant.acme", "root", "net.gold")));
    PF_CHECK(fabric.runtime.evaluate(make_query("tenant.acme", "root")).outcome ==
             pf::Outcome::Assigned);

    // A second incarnation of the same publisher takes over: the epoch advances and the first
    // incarnation's evidence loses authority.
    const pf::BootId replacement = boot_for("evaluation/replacement");
    auto session = fabric.runtime.grant_authority(publisher_id("test.publisher"), replacement);
    PF_REQUIRE_OK(session);
    PF_CHECK(session.value().epoch.value > fabric.session.epoch.value);

    const pf::PriorityDecision decision =
        fabric.runtime.evaluate(make_query("tenant.acme", "root"));
    PF_CHECK(decision.outcome == pf::Outcome::Fenced);
    PF_CHECK(!decision.authoritative);
    PF_REQUIRE(!decision.rejected_evidence.empty());
    PF_CHECK_EQ(decision.rejected_evidence.front().reason_code,
                std::string("publisher_incarnation_fenced"));

    // The displaced incarnation can no longer write.
    PF_REQUIRE_FAILS(fabric.runtime.assign(
                         fabric.session,
                         make_assignment("a.late", "tenant.acme", "root", "net.silver")),
                     pf::StatusCode::StaleEpoch);
    PF_REQUIRE_FAILS(fabric.runtime.define_class(
                         fabric.session, make_class("net.late", 2000)),
                     pf::StatusCode::StaleEpoch);
}

PF_TEST(evaluation, retired_evidence_is_reported_with_its_reason) {
    Fabric fabric;
    PF_REQUIRE(build_world(fabric));
    PF_REQUIRE_OK(fabric.runtime.assign(
        fabric.session, make_assignment("a.gold", "tenant.acme", "root", "net.gold")));
    PF_REQUIRE_OK(
        fabric.runtime.retire_assignment(fabric.session, assignment_id("a.gold"), "tenant left"));

    const pf::PriorityDecision decision =
        fabric.runtime.evaluate(make_query("tenant.acme", "root"));
    PF_CHECK(decision.outcome == pf::Outcome::Stale);
    PF_REQUIRE(!decision.rejected_evidence.empty());
    PF_CHECK_EQ(decision.rejected_evidence.front().reason_code, std::string("assignment_retired"));
    PF_CHECK(decision.rejected_evidence.front().reason.find("tenant left") != std::string::npos);
}

PF_TEST(evaluation, an_unregistered_subject_is_rejected_not_guessed) {
    Fabric fabric;
    PF_REQUIRE(build_world(fabric));
    const pf::PriorityDecision decision =
        fabric.runtime.evaluate(make_query("tenant.ghost", "root"));
    PF_CHECK(decision.outcome == pf::Outcome::Rejected);
    PF_CHECK_EQ(decision.reason_code, std::string("subject_not_registered"));

    const pf::PriorityDecision bad_scope =
        fabric.runtime.evaluate(make_query("tenant.acme", "nowhere"));
    PF_CHECK(bad_scope.outcome == pf::Outcome::Rejected);
    PF_CHECK_EQ(bad_scope.reason_code, std::string("scope_unusable"));
}

PF_TEST(evaluation, epoch_claims_are_checked_in_both_directions) {
    Fabric fabric;
    PF_REQUIRE(build_world(fabric));
    pf::PriorityQuery future = make_query("tenant.acme", "root");
    future.as_of_epoch = pf::FabricEpoch{fabric.runtime.epoch().value + 7};
    const pf::PriorityDecision rejected = fabric.runtime.evaluate(future);
    PF_CHECK(rejected.outcome == pf::Outcome::Rejected);
    PF_CHECK_EQ(rejected.reason_code, std::string("epoch_from_future"));

    // Advance the epoch, then ask as of the previous one.
    PF_REQUIRE_OK(fabric.runtime.advance_epoch(fabric.session, "test"));
    pf::PriorityQuery stale = make_query("tenant.acme", "root");
    stale.as_of_epoch = fabric.session.epoch;
    const pf::PriorityDecision stale_decision = fabric.runtime.evaluate(stale);
    PF_CHECK(stale_decision.outcome == pf::Outcome::Stale);
    PF_CHECK_EQ(stale_decision.reason_code, std::string("epoch_superseded"));
}

PF_TEST(evaluation, required_generations_gate_the_answer) {
    Fabric fabric;
    PF_REQUIRE(build_world(fabric));
    PF_REQUIRE_OK(fabric.runtime.assign(
        fabric.session, make_assignment("a.gold", "tenant.acme", "root", "net.gold")));

    pf::PriorityQuery demanding = make_query("tenant.acme", "root");
    demanding.require_scope_generation = pf::Generation{99};
    const pf::PriorityDecision decision = fabric.runtime.evaluate(demanding);
    PF_CHECK(decision.outcome == pf::Outcome::Stale);
    PF_CHECK_EQ(decision.reason_code, std::string("required_scope_generation_not_reached"));
}

PF_TEST(evaluation, an_exception_that_names_the_wrong_class_does_not_apply) {
    Fabric fabric;
    PF_REQUIRE(build_world(fabric));
    PF_REQUIRE_OK(fabric.runtime.assign(
        fabric.session, make_assignment("a.broad", "tenant.acme", "root", "net.silver")));

    pf::PriorityAssignment exception_assignment =
        make_assignment("a.exception", "tenant.acme", "region", "net.gold",
                        pf::AssignmentKind::Exception);
    exception_assignment.displaces = class_id("net.bronze");
    PF_REQUIRE_OK(fabric.runtime.assign(fabric.session, exception_assignment));

    const pf::PriorityDecision decision =
        fabric.runtime.evaluate(make_query("tenant.acme", "region"));
    PF_CHECK(decision.outcome == pf::Outcome::Assigned);
    PF_CHECK(decision.cls == class_id("net.silver"));
    bool saw_mismatch = false;
    for (const auto& note : decision.rejected_evidence) {
        if (note.reason_code == "exception_target_mismatch") {
            saw_mismatch = true;
        }
    }
    PF_CHECK(saw_mismatch);
}

PF_TEST(evaluation, an_exception_that_names_the_right_class_overrides_it) {
    Fabric fabric;
    PF_REQUIRE(build_world(fabric));
    PF_REQUIRE_OK(fabric.runtime.assign(
        fabric.session, make_assignment("a.broad", "tenant.acme", "root", "net.silver")));

    pf::PriorityAssignment exception_assignment =
        make_assignment("a.exception", "tenant.acme", "region", "net.gold",
                        pf::AssignmentKind::Exception);
    exception_assignment.displaces = class_id("net.silver");
    PF_REQUIRE_OK(fabric.runtime.assign(fabric.session, exception_assignment));

    const pf::PriorityDecision decision =
        fabric.runtime.evaluate(make_query("tenant.acme", "region"));
    PF_CHECK(decision.outcome == pf::Outcome::Overridden);
    PF_CHECK(decision.authoritative);
    PF_CHECK(decision.cls == class_id("net.gold"));
    PF_REQUIRE(!decision.superseded.empty());
    PF_CHECK(decision.superseded.front().assignment == assignment_id("a.broad"));
}

PF_TEST(evaluation, a_non_overridable_scope_beats_a_narrower_one) {
    Fabric fabric;
    PF_REQUIRE(build_world(fabric));
    PF_REQUIRE_OK(fabric.runtime.define_scope(
        fabric.session, make_scope("root", std::nullopt, pf::ConflictResolution::Deny,
                                   std::nullopt, /*allow_override=*/false)));
    PF_REQUIRE_OK(fabric.runtime.assign(
        fabric.session, make_assignment("a.broad", "tenant.acme", "root", "net.silver")));
    PF_REQUIRE_OK(fabric.runtime.assign(
        fabric.session, make_assignment("a.narrow", "tenant.acme", "region.eu", "net.gold")));

    const pf::PriorityDecision decision =
        fabric.runtime.evaluate(make_query("tenant.acme", "region.eu"));
    PF_CHECK(decision.outcome == pf::Outcome::Overridden);
    PF_CHECK(decision.cls == class_id("net.silver"));
    PF_REQUIRE(!decision.superseded.empty());
    PF_CHECK(decision.superseded.front().assignment == assignment_id("a.narrow"));
}

PF_TEST(evaluation, privileged_classes_are_flagged) {
    Fabric fabric;
    PF_REQUIRE(build_world(fabric));
    PF_REQUIRE_OK(fabric.runtime.define_class(
        fabric.session, make_class("net.emergency", 1100, pf::ClassKind::Emergency, {},
                                   /*privileged=*/true)));
    PF_REQUIRE_OK(fabric.runtime.assign(
        fabric.session, make_assignment("a.emergency", "tenant.acme", "root", "net.emergency")));

    const pf::PriorityDecision decision =
        fabric.runtime.evaluate(make_query("tenant.acme", "root"));
    PF_CHECK(decision.cls == class_id("net.emergency"));
    PF_CHECK(decision.privileged_class);
    PF_CHECK_EQ(decision.precedence.value, 1100u);
}

PF_TEST(evaluation, identical_questions_produce_identical_decisions) {
    Fabric fabric;
    PF_REQUIRE(build_world(fabric));
    PF_REQUIRE_OK(fabric.runtime.assign(
        fabric.session, make_assignment("a.gold", "tenant.acme", "root", "net.gold")));

    const pf::PriorityDecision first = fabric.runtime.evaluate(make_query("tenant.acme", "root"));
    for (int i = 0; i < 200; ++i) {
        const pf::PriorityDecision again =
            fabric.runtime.evaluate(make_query("tenant.acme", "root"));
        PF_CHECK(again.digest == first.digest);
        PF_CHECK(again.outcome == first.outcome);
        PF_CHECK(again.cls == first.cls);
        PF_CHECK_EQ(again.to_json(), first.to_json());
    }
}

PF_TEST(evaluation, the_explanation_budget_is_respected_and_announced) {
    Fabric fabric;
    PF_REQUIRE(build_world(fabric));
    for (int i = 0; i < 40; ++i) {
        PF_REQUIRE_OK(fabric.runtime.assign(
            fabric.session, make_assignment("a.many." + std::to_string(i), "tenant.acme", "root",
                                            "net.gold")));
    }
    pf::PriorityQuery query = make_query("tenant.acme", "root");
    query.max_explanation_steps = 5;
    const pf::PriorityDecision decision = fabric.runtime.evaluate(query);
    PF_CHECK(decision.chain.size() <= 5);
    bool truncated = false;
    for (const auto& step : decision.chain) {
        if (step.code == "truncated") {
            truncated = true;
        }
    }
    PF_CHECK(truncated);
}

PF_TEST(evaluation, a_closed_runtime_stops_answering_authoritatively) {
    Fabric fabric;
    PF_REQUIRE(build_world(fabric));
    PF_REQUIRE_OK(fabric.runtime.assign(
        fabric.session, make_assignment("a.gold", "tenant.acme", "root", "net.gold")));
    PF_REQUIRE_OK(fabric.runtime.close());
    const pf::PriorityDecision decision = fabric.runtime.evaluate(make_query("tenant.acme", "root"));
    PF_CHECK(decision.outcome == pf::Outcome::Rejected);
    PF_CHECK_EQ(decision.reason_code, std::string("runtime_closed"));
    PF_REQUIRE_FAILS(fabric.runtime.assign(fabric.session,
                                           make_assignment("a.late", "tenant.acme", "root",
                                                           "net.silver")),
                     pf::StatusCode::NotReady);
}
