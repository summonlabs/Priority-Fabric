// Priority Fabric -- authoritative network priority classes.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// What happens when the process that published a priority dies, and what it takes for the
// next incarnation to be believed again.

#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <string>

#include "priority_fabric/runtime.hpp"

namespace {

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

pf::PriorityQuery make_query() {
    pf::PriorityQuery query;
    query.subject = subject_id("tenant.acme");
    query.scope = scope_id("dc");
    return query;
}

int fail(const std::string& what) {
    std::cerr << "example: " << what << "\n";
    return 1;
}

}  // namespace

int main() {
    std::error_code ec;
    const std::filesystem::path root =
        std::filesystem::temp_directory_path(ec) / "pf-example-fencing";
    std::filesystem::remove_all(root, ec);
    const std::filesystem::path state = root / "state";

    const std::string publisher_text = "worker.publisher";
    const pf::BootId first_boot = pf::BootId::from_seed("example-fencing/first");

    {
        pf::FabricRuntime::Options options;
        options.state_dir = state;
        options.create_if_missing = true;
        options.advance_epoch_on_open = true;
        auto opened = pf::FabricRuntime::open(options);
        if (!opened.ok()) {
            return fail(opened.status().to_string());
        }
        pf::FabricRuntime runtime = std::move(opened.value());
        auto session = runtime.grant_authority(
            pf::PublisherId::parse(publisher_text, runtime.limits()).value(), first_boot);
        if (!session.ok()) {
            return fail(session.status().to_string());
        }

        pf::PriorityClassDef gold;
        gold.id = class_id("net.gold");
        gold.precedence = pf::PrecedenceRank::make(900);
        (void)runtime.define_class(session.value(), gold);
        pf::PolicyScopeDef scope;
        scope.id = scope_id("dc");
        (void)runtime.define_scope(session.value(), scope);
        pf::SubjectDef subject;
        subject.id = subject_id("tenant.acme");
        (void)runtime.define_subject(session.value(), subject);

        pf::PriorityAssignment assignment;
        assignment.id = assignment_id("assign.gold");
        assignment.subject = subject_id("tenant.acme");
        assignment.scope = scope_id("dc");
        assignment.cls = class_id("net.gold");
        auto assigned = runtime.assign(session.value(), assignment);
        if (!assigned.ok()) {
            return fail(assigned.status().to_string());
        }

        const pf::PriorityDecision decision = runtime.evaluate(make_query());
        std::cout << "before the restart: " << pf::to_string(decision.outcome) << " class="
                  << decision.cls.str() << " epoch=" << decision.epoch.value << "\n";
        std::cout << "  explanation: " << decision.reason << "\n";
    }

    std::cout << "\n-- the publishing process is killed --\n\n";

    {
        pf::FabricRuntime::Options options;
        options.state_dir = state;
        options.create_if_missing = true;
        options.advance_epoch_on_open = true;
        auto opened = pf::FabricRuntime::open(options);
        if (!opened.ok()) {
            return fail(opened.status().to_string());
        }
        pf::FabricRuntime runtime = std::move(opened.value());

        // Recovery alone hands out nothing: no publisher holds authority yet.
        const pf::PriorityDecision fenced = runtime.evaluate(make_query());
        std::cout << "after recovery, before anyone reconnects: "
                  << pf::to_string(fenced.outcome) << " class="
                  << (fenced.cls.valid() ? fenced.cls.str() : "<none>")
                  << " reason=" << fenced.reason_code << "\n";
        if (!fenced.rejected_evidence.empty()) {
            std::cout << "  rejected evidence: " << fenced.rejected_evidence.front().assignment.str()
                      << " because " << fenced.rejected_evidence.front().reason_code << "\n";
        }

        const pf::BootId second_boot = pf::BootId::from_seed("example-fencing/second");
        auto session = runtime.grant_authority(
            pf::PublisherId::parse(publisher_text, runtime.limits()).value(), second_boot);
        if (!session.ok()) {
            return fail(session.status().to_string());
        }
        std::cout << "  the new incarnation was granted epoch " << session.value().epoch.value
                  << " with fencing token " << session.value().token.value << "\n";

        const pf::PriorityDecision still_fenced = runtime.evaluate(make_query());
        std::cout << "after the new incarnation connects: "
                  << pf::to_string(still_fenced.outcome) << " reason=" << still_fenced.reason_code
                  << "\n";

        pf::PriorityAssignment fresh;
        fresh.id = assignment_id("assign.gold.fresh");
        fresh.subject = subject_id("tenant.acme");
        fresh.scope = scope_id("dc");
        fresh.cls = class_id("net.gold");
        auto assigned = runtime.assign(session.value(), fresh);
        if (!assigned.ok()) {
            return fail(assigned.status().to_string());
        }
        const pf::PriorityDecision restored = runtime.evaluate(make_query());
        std::cout << "after it republishes: " << pf::to_string(restored.outcome) << " class="
                  << restored.cls.str() << " epoch=" << restored.epoch.value << "\n";
        std::cout << "  explanation: " << restored.reason << "\n";
    }

    std::filesystem::remove_all(root, ec);
    return 0;
}
