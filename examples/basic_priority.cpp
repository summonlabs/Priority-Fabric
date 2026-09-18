// Priority Fabric -- authoritative network priority classes.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// The smallest complete story: define classes and scopes, assign a priority, ask the fabric
// what is authoritative and read the explanation it gives back.

#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <string>

#include "priority_fabric/runtime.hpp"
#include "priority_fabric/version.hpp"

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

int fail(const std::string& what) {
    std::cerr << "example: " << what << "\n";
    return 1;
}

}  // namespace

int main() {
    std::error_code ec;
    const std::filesystem::path root =
        std::filesystem::temp_directory_path(ec) / "pf-example-basic";
    std::filesystem::remove_all(root, ec);

    pf::FabricRuntime::Options options;
    options.state_dir = root / "state";
    options.create_if_missing = true;
    auto opened = pf::FabricRuntime::open(options);
    if (!opened.ok()) {
        return fail(opened.status().to_string());
    }
    pf::FabricRuntime runtime = std::move(opened.value());

    auto session = runtime.grant_authority(
        pf::PublisherId::parse("example.publisher", runtime.limits()).value(),
        pf::BootId::from_seed("example-basic"));
    if (!session.ok()) {
        return fail(session.status().to_string());
    }

    // No hidden numbers: every class states its own precedence explicitly.
    struct ClassSpec {
        const char* id;
        std::uint32_t rank;
        pf::ClassKind kind;
    };
    const ClassSpec classes[] = {
        {"net.realtime", 1000, pf::ClassKind::System},
        {"net.gold", 900, pf::ClassKind::Tenant},
        {"net.silver", 500, pf::ClassKind::Tenant},
        {"net.bulk", 50, pf::ClassKind::Tenant},
    };
    for (const auto& spec : classes) {
        pf::PriorityClassDef definition;
        definition.id = class_id(spec.id);
        definition.precedence = pf::PrecedenceRank::make(spec.rank);
        definition.kind = spec.kind;
        auto defined = runtime.define_class(session.value(), definition);
        if (!defined.ok()) {
            return fail(defined.status().to_string());
        }
    }

    pf::PolicyScopeDef datacenter;
    datacenter.id = scope_id("dc");
    if (!runtime.define_scope(session.value(), datacenter).ok()) {
        return fail("could not define the datacenter scope");
    }
    pf::PolicyScopeDef tenant_scope;
    tenant_scope.id = scope_id("dc.tenant-acme");
    tenant_scope.parent = scope_id("dc");
    // Unassigned subjects stay UNKNOWN unless a policy says otherwise; here it does.
    tenant_scope.unknown_default = class_id("net.bulk");
    if (!runtime.define_scope(session.value(), tenant_scope).ok()) {
        return fail("could not define the tenant scope");
    }

    pf::SubjectDef tenant;
    tenant.id = subject_id("tenant.acme");
    if (!runtime.define_subject(session.value(), tenant).ok()) {
        return fail("could not define the tenant subject");
    }
    pf::SubjectDef workload;
    workload.id = subject_id("tenant.acme.analytics");
    workload.inherits_from = {subject_id("tenant.acme")};
    if (!runtime.define_subject(session.value(), workload).ok()) {
        return fail("could not define the workload subject");
    }

    pf::PriorityAssignment assignment;
    assignment.id = assignment_id("assign.tenant-gold");
    assignment.subject = subject_id("tenant.acme");
    assignment.scope = scope_id("dc");
    assignment.cls = class_id("net.gold");
    assignment.kind = pf::AssignmentKind::Inherited;
    assignment.note = "contract tier";
    auto assigned = runtime.assign(session.value(), assignment);
    if (!assigned.ok()) {
        return fail(assigned.status().to_string());
    }

    pf::PriorityQuery query;
    query.subject = subject_id("tenant.acme.analytics");
    query.scope = scope_id("dc.tenant-acme");
    const pf::PriorityDecision decision = runtime.evaluate(query);
    std::cout << decision.to_text();
    std::cout << "\njson:\n" << decision.to_json() << "\n";

    const pf::IntegrityReport report = runtime.integrity_report();
    std::cout << "\ndurable state ok=" << (report.ok ? "yes" : "no")
              << " records=" << report.records_applied
              << " digest=" << report.state_digest.short_hex(16) << "\n";

    std::filesystem::remove_all(root, ec);
    return decision.authoritative ? 0 : 1;
}
