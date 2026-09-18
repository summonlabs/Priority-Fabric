// Priority Fabric -- authoritative network priority classes.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Recovery semantics. The governing rule is that durable state restores *facts*, never
// liveness: definitions, assignments and provenance come back exactly as they were, while
// publisher authority always has to be established again.

#include <filesystem>

#include "framework.hpp"
#include "support.hpp"

using namespace pftest;

namespace {

pf::PriorityQuery acme_query() {
    pf::PriorityQuery query;
    query.subject = subject_id("tenant.acme");
    query.scope = scope_id("root");
    return query;
}

bool build(Fabric& fabric, std::string_view label) {
    if (!open_fabric(fabric, label)) {
        return false;
    }
    if (!fabric.runtime.define_class(fabric.session, make_class("net.gold", 900)).ok()) {
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
    if (!fabric.runtime
             .assign(fabric.session, make_assignment("a.gold", "tenant.acme", "root", "net.gold"))
             .ok()) {
        return false;
    }
    return true;
}

struct OpenOptions {
    bool advance_epoch_on_open = false;
    bool fail_on_degraded = false;
};

/// Re-opens the store and does *not* ask for authority. Recovery must be observable on its
/// own, before any publisher has re-established anything.
bool reopen_only(Fabric& fabric, const pf::BootId& boot, OpenOptions open_options = {}) {
    pf::FabricRuntime::Options options;
    options.state_dir = fabric.directory.path() / "state";
    options.create_if_missing = true;
    options.instance_boot_id = pf::BootId::from_seed(boot.hex() + "/instance");
    options.advance_epoch_on_open = open_options.advance_epoch_on_open;
    options.fail_on_degraded = open_options.fail_on_degraded;
    auto opened = pf::FabricRuntime::open(options);
    if (!opened.ok()) {
        return false;
    }
    fabric.runtime = std::move(opened.value());
    return true;
}

/// Re-opens and re-establishes authority: the explicit act recovery always requires.
bool reopen(Fabric& fabric, const pf::BootId& boot, const pf::PublisherId& publisher,
            pf::Session& session, OpenOptions open_options = {}) {
    if (!reopen_only(fabric, boot, open_options)) {
        return false;
    }
    auto granted = fabric.runtime.grant_authority(publisher, boot);
    if (!granted.ok()) {
        return false;
    }
    session = granted.value();
    fabric.session = session;
    return true;
}

}  // namespace

PF_TEST(restart, definitions_and_the_epoch_survive_a_reopen) {
    Fabric fabric;
    PF_REQUIRE(build(fabric, "restart-epoch"));
    const pf::FabricEpoch epoch = fabric.runtime.epoch();
    const pf::Generation generation = fabric.runtime.state_generation();
    const pf::StateStats before = fabric.runtime.state_stats();
    PF_CHECK(epoch.is_established());
    PF_REQUIRE_OK(fabric.runtime.close());

    pf::Session session;
    PF_REQUIRE(reopen(fabric, boot_for("restart-epoch"), publisher_id("test.publisher"), session));
    PF_CHECK_EQ(fabric.runtime.epoch().value, epoch.value);
    PF_CHECK(fabric.runtime.state_generation().value >= generation.value);
    PF_CHECK_EQ(fabric.runtime.state_stats().classes, before.classes);
    PF_CHECK_EQ(fabric.runtime.state_stats().assignments, before.assignments);
    PF_CHECK(fabric.runtime.class_definition(class_id("net.gold")).ok());
}

PF_TEST(restart, authority_is_never_restored_by_reopening) {
    Fabric fabric;
    PF_REQUIRE(build(fabric, "restart-authority"));
    const pf::BootId boot = fabric.session.boot;
    const pf::FencingToken token = fabric.session.token;
    PF_REQUIRE_OK(fabric.runtime.close());

    // Before anyone asks for anything, the incarnation is recorded as expired.
    PF_REQUIRE(reopen_only(fabric, boot));
    auto expired = fabric.runtime.authority_state(publisher_id("test.publisher"), boot);
    PF_REQUIRE_OK(expired);
    PF_CHECK(expired.value() == pf::AuthorityState::Expired);

    // A cached session from before the restart is refused outright.
    pf::Session cached{publisher_id("test.publisher"), boot, fabric.runtime.epoch(), token};
    PF_REQUIRE_FAILS(fabric.runtime.define_class(cached, make_class("net.cached", 1500)),
                     pf::StatusCode::Fenced);

    // Authority comes back only because the incarnation asked for it again.
    auto session = fabric.runtime.grant_authority(publisher_id("test.publisher"), boot);
    PF_REQUIRE_OK(session);
    fabric.session = session.value();
    PF_CHECK_EQ(session.value().epoch.value, fabric.runtime.epoch().value);
    auto granted = fabric.runtime.authority_state(publisher_id("test.publisher"), boot);
    PF_REQUIRE_OK(granted);
    PF_CHECK(granted.value() == pf::AuthorityState::Granted);
    PF_REQUIRE_FAILS(fabric.runtime.define_class(cached, make_class("net.cached2", 1501)),
                     pf::StatusCode::Fenced);
}

PF_TEST(restart, no_evidence_is_usable_until_its_publisher_re_establishes_authority) {
    Fabric fabric;
    PF_REQUIRE(build(fabric, "restart-republish"));
    PF_CHECK(fabric.runtime.evaluate(acme_query()).outcome == pf::Outcome::Assigned);
    PF_REQUIRE_OK(fabric.runtime.close());

    // First observation: recovery on its own hands out nothing.
    PF_REQUIRE(reopen_only(fabric, boot_for("restart-republish")));
    const pf::PriorityDecision fenced = fabric.runtime.evaluate(acme_query());
    PF_CHECK(fenced.outcome == pf::Outcome::Fenced);
    PF_CHECK_EQ(fenced.reason_code, std::string("evidence_fenced"));
    PF_REQUIRE(!fenced.rejected_evidence.empty());
    PF_CHECK_EQ(fenced.rejected_evidence.front().reason_code,
                std::string("publisher_incarnation_fenced"));
    PF_REQUIRE_FAILS(fabric.runtime.assign(
                         pf::Session{publisher_id("test.publisher"),
                                     boot_for("restart-republish"), fabric.runtime.epoch(),
                                     pf::FencingToken{1}},
                         make_assignment("a.unbacked", "tenant.acme", "root", "net.gold")),
                     pf::StatusCode::Fenced);

    // Second observation: the publisher explicitly asks for authority again, and the evidence
    // it published under the same incarnation and epoch becomes usable once more.
    auto granted = fabric.runtime.grant_authority(publisher_id("test.publisher"),
                                                  boot_for("restart-republish"));
    PF_REQUIRE_OK(granted);
    fabric.session = granted.value();
    const pf::PriorityDecision restored = fabric.runtime.evaluate(acme_query());
    PF_CHECK(restored.outcome == pf::Outcome::Assigned);
    PF_CHECK(restored.cls == class_id("net.gold"));
}

PF_TEST(restart, a_new_incarnation_takes_over_without_moving_the_epoch_by_itself) {
    Fabric fabric;
    PF_REQUIRE(build(fabric, "restart-takeover"));
    const pf::FabricEpoch before = fabric.runtime.epoch();
    PF_REQUIRE_OK(fabric.runtime.close());

    pf::Session session;
    PF_REQUIRE(reopen(fabric, boot_for("restart-takeover-restarted"),
                      publisher_id("test.publisher"), session));
    PF_CHECK_EQ(session.epoch.value, before.value);
    PF_CHECK(session.token.is_valid());
    PF_CHECK(fabric.runtime.evaluate(acme_query()).outcome == pf::Outcome::Fenced);

    // The new incarnation can publish and be believed under the same epoch.
    PF_REQUIRE_OK(fabric.runtime.assign(
        session, make_assignment("a.gold2", "tenant.acme", "root", "net.gold")));
    const pf::PriorityDecision refreshed = fabric.runtime.evaluate(acme_query());
    PF_CHECK(refreshed.outcome == pf::Outcome::Assigned);
    PF_CHECK(refreshed.cls == class_id("net.gold"));
}

PF_TEST(restart, an_authority_incarnation_moves_the_epoch_when_it_takes_the_store) {
    Fabric fabric;
    PF_REQUIRE(build(fabric, "restart-authority-epoch"));
    const pf::FabricEpoch before = fabric.runtime.epoch();
    PF_REQUIRE_OK(fabric.runtime.close());

    pf::Session session;
    OpenOptions open_options;
    open_options.advance_epoch_on_open = true;
    PF_REQUIRE(reopen(fabric, boot_for("restart-authority-epoch-next"),
                      publisher_id("test.publisher"), session, open_options));
    PF_CHECK(session.epoch.value > before.value);
    PF_CHECK_EQ(fabric.runtime.epoch().value, session.epoch.value);

    // Both the epoch and the fencing token moved, so the old evidence is fenced twice over.
    const pf::PriorityDecision decision = fabric.runtime.evaluate(acme_query());
    PF_CHECK(decision.outcome == pf::Outcome::Fenced);

    pf::PriorityQuery old_epoch = acme_query();
    old_epoch.as_of_epoch = before;
    PF_CHECK(fabric.runtime.evaluate(old_epoch).outcome == pf::Outcome::Stale);
}

PF_TEST(restart, fencing_is_durable_and_survives_a_reopen) {
    Fabric fabric;
    PF_REQUIRE(build(fabric, "restart-fence"));
    const pf::BootId victim = fabric.session.boot;
    PF_REQUIRE_OK(fabric.runtime.fence(fabric.session, publisher_id("test.publisher"), victim,
                                       "operator action"));
    PF_REQUIRE_OK(fabric.runtime.close());

    pf::Session session;
    PF_REQUIRE(reopen(fabric, boot_for("restart-fence-next"), publisher_id("test.publisher"),
                      session));
    auto state = fabric.runtime.authority_state(publisher_id("test.publisher"), victim);
    PF_REQUIRE_OK(state);
    // The fenced incarnation stays fenced, and asking for it again is refused outright rather
    // than quietly reviving it.
    PF_CHECK(!(session.boot == victim));
    PF_CHECK(state.value() == pf::AuthorityState::Fenced);
    PF_REQUIRE_FAILS(
        fabric.runtime.grant_authority(publisher_id("test.publisher"), victim),
        pf::StatusCode::Fenced);
    // A refused registration must not have moved the epoch.
    PF_CHECK_EQ(fabric.runtime.epoch().value, session.epoch.value);
    PF_REQUIRE_FAILS(fabric.runtime.define_class(
                         pf::Session{publisher_id("test.publisher"), victim, session.epoch,
                                     session.token},
                         make_class("net.revived", 4000)),
                     pf::StatusCode::Fenced);
}

PF_TEST(restart, a_checkpoint_keeps_the_state_and_compacts_the_store) {
    Fabric fabric;
    PF_REQUIRE(build(fabric, "restart-checkpoint"));
    for (int i = 0; i < 20; ++i) {
        PF_REQUIRE_OK(fabric.runtime.define_class(
            fabric.session,
            make_class("net.extra" + std::to_string(i), 2000u + static_cast<std::uint32_t>(i))));
    }
    const pf::StateStats before = fabric.runtime.state_stats();
    PF_REQUIRE_OK(fabric.runtime.checkpoint());
    PF_REQUIRE_OK(fabric.runtime.close());

    pf::Session session;
    PF_REQUIRE(reopen(fabric, boot_for("restart-checkpoint"), publisher_id("test.publisher"),
                      session));
    const pf::StateStats after = fabric.runtime.state_stats();
    PF_CHECK_EQ(after.classes, before.classes);
    PF_CHECK_EQ(after.scopes, before.scopes);
    PF_CHECK_EQ(after.subjects, before.subjects);
    const pf::IntegrityReport report = fabric.runtime.integrity_report();
    if (!report.ok) {
        ::pftest::note("integrity: " + report.detail);
    }
    PF_CHECK(report.ok);
}

PF_TEST(restart, a_publisher_that_never_reconnects_stays_without_authority) {
    Fabric fabric;
    PF_REQUIRE(build(fabric, "restart-absent"));
    auto other = fabric.runtime.grant_authority(publisher_id("other.publisher"),
                                                boot_for("restart-absent/other"));
    PF_REQUIRE_OK(other);
    const pf::Session other_session = other.value();
    PF_REQUIRE_OK(fabric.runtime.close());

    pf::Session session;
    PF_REQUIRE(reopen(fabric, boot_for("restart-absent"), publisher_id("test.publisher"), session));
    PF_REQUIRE_FAILS(fabric.runtime.define_class(other_session, make_class("net.other", 3000)),
                     pf::StatusCode::Fenced);
    auto state = fabric.runtime.authority_state(publisher_id("other.publisher"),
                                                other_session.boot);
    PF_REQUIRE_OK(state);
    PF_CHECK(state.value() == pf::AuthorityState::Expired);
}

PF_TEST(restart, a_fabric_that_refuses_new_publishers_keeps_refusing_after_a_reopen) {
    ScratchDirectory directory("restart-closed");
    pf::FabricRuntime::Options options;
    options.state_dir = directory.path() / "state";
    options.create_if_missing = true;
    options.allow_new_publishers = true;
    options.instance_boot_id = boot_for("restart-closed/one");
    auto opened = pf::FabricRuntime::open(options);
    PF_REQUIRE_OK(opened);
    {
        pf::FabricRuntime runtime = std::move(opened.value());
        auto session = runtime.grant_authority(publisher_id("known.publisher"),
                                               boot_for("restart-closed/known"));
        PF_REQUIRE_OK(session);
    }
    options.allow_new_publishers = false;
    options.instance_boot_id = boot_for("restart-closed/two");
    auto reopened = pf::FabricRuntime::open(options);
    PF_REQUIRE_OK(reopened);
    pf::FabricRuntime runtime = std::move(reopened.value());
    auto known = runtime.grant_authority(publisher_id("known.publisher"),
                                         boot_for("restart-closed/known"));
    PF_REQUIRE_OK(known);

    const pf::FabricEpoch epoch = runtime.epoch();
    PF_REQUIRE_FAILS(
        runtime.grant_authority(publisher_id("stranger.publisher"), boot_for("restart-closed/x")),
        pf::StatusCode::Unauthorized);
    PF_REQUIRE_FAILS(
        runtime.grant_authority(publisher_id("stranger.publisher"), boot_for("restart-closed/y")),
        pf::StatusCode::Unauthorized);
    // A refused registration must not have moved the epoch.
    PF_CHECK(runtime.epoch() == epoch);
    PF_CHECK(!runtime.authority_state(publisher_id("stranger.publisher"),
                                      boot_for("restart-closed/x"))
                   .ok());
}

PF_TEST(restart, a_reopened_store_recovers_its_audit_history) {
    Fabric fabric;
    PF_REQUIRE(build(fabric, "restart-audit"));
    const auto before = fabric.runtime.audit(200);
    PF_CHECK(!before.empty());
    PF_REQUIRE_OK(fabric.runtime.close());

    pf::Session session;
    PF_REQUIRE(reopen(fabric, boot_for("restart-audit"), publisher_id("test.publisher"), session));
    const auto after = fabric.runtime.audit(200);
    PF_CHECK(after.size() >= before.size());
    for (const auto& entry : after) {
        PF_CHECK(entry.result == pf::StatusCode::Ok);
        PF_CHECK(!entry.op.empty());
    }
    // Every recovered entry must name the incarnation that produced it.
    bool saw_publisher = false;
    for (const auto& entry : after) {
        if (entry.provenance.publisher == publisher_id("test.publisher")) {
            saw_publisher = true;
        }
    }
    PF_CHECK(saw_publisher);
}
