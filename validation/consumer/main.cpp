// An independent downstream consumer of the installed Priority Fabric package.
//
// It is deliberately written the way somebody outside the project would write it: only the
// installed headers, only the documented API, and a real round trip through a state directory.

#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <string>

#include "priority_fabric/runtime.hpp"
#include "priority_fabric/version.hpp"

namespace {

int fail(const std::string& what) {
    std::cerr << "consumer: " << what << "\n";
    return 1;
}

pf::PriorityClassId class_id(const std::string& text, const pf::Limits& limits) {
    return pf::PriorityClassId::parse(text, limits).value();
}

pf::SubjectId subject_id(const std::string& text, const pf::Limits& limits) {
    return pf::SubjectId::parse(text, limits).value();
}

pf::PolicyScopeId scope_id(const std::string& text, const pf::Limits& limits) {
    return pf::PolicyScopeId::parse(text, limits).value();
}

pf::PriorityAssignmentId assignment_id(const std::string& text, const pf::Limits& limits) {
    return pf::PriorityAssignmentId::parse(text, limits).value();
}

}  // namespace

int main() {
    std::cout << "linked priority fabric " << pf::version_string() << " (format "
              << pf::format_version() << ")\n";

    std::error_code ec;
    const std::filesystem::path root =
        std::filesystem::temp_directory_path(ec) / "pf-consumer";
    std::filesystem::remove_all(root, ec);

    pf::FabricRuntime::Options options;
    options.state_dir = root / "state";
    options.create_if_missing = true;
    auto opened = pf::FabricRuntime::open(options);
    if (!opened.ok()) {
        return fail(opened.status().to_string());
    }
    pf::FabricRuntime fabric = std::move(opened.value());
    const pf::Limits& limits = fabric.limits();

    auto session = fabric.grant_authority(
        pf::PublisherId::parse("consumer.publisher", limits).value(),
        pf::BootId::from_seed("consumer"));
    if (!session.ok()) {
        return fail(session.status().to_string());
    }

    pf::PriorityClassDef gold;
    gold.id = class_id("net.gold", limits);
    gold.precedence = pf::PrecedenceRank::make(900);
    if (!fabric.define_class(session.value(), gold).ok()) {
        return fail("could not define net.gold");
    }
    pf::PriorityClassDef bulk;
    bulk.id = class_id("net.bulk", limits);
    bulk.precedence = pf::PrecedenceRank::make(50);
    if (!fabric.define_class(session.value(), bulk).ok()) {
        return fail("could not define net.bulk");
    }

    pf::PolicyScopeDef scope;
    scope.id = scope_id("dc", limits);
    scope.unknown_default = class_id("net.bulk", limits);
    if (!fabric.define_scope(session.value(), scope).ok()) {
        return fail("could not define the dc scope");
    }
    pf::SubjectDef subject;
    subject.id = subject_id("tenant.acme", limits);
    if (!fabric.define_subject(session.value(), subject).ok()) {
        return fail("could not define the subject");
    }

    pf::PriorityAssignment assignment;
    assignment.id = assignment_id("assign.gold", limits);
    assignment.subject = subject_id("tenant.acme", limits);
    assignment.scope = scope_id("dc", limits);
    assignment.cls = class_id("net.gold", limits);
    if (!fabric.assign(session.value(), assignment).ok()) {
        return fail("could not publish the assignment");
    }

    pf::PriorityQuery query;
    query.subject = subject_id("tenant.acme", limits);
    query.scope = scope_id("dc", limits);
    const pf::PriorityDecision decision = fabric.evaluate(query);

    std::cout << "outcome=" << pf::to_string(decision.outcome)
              << " class=" << decision.cls.str()
              << " precedence=" << decision.precedence.value
              << " digest=" << decision.digest.short_hex(16) << "\n";
    if (decision.outcome != pf::Outcome::Assigned || !(decision.cls == gold.id) ||
        decision.precedence.value != 900u) {
        return fail("the installed library did not answer as expected");
    }

    const pf::IntegrityReport report = fabric.integrity_report();
    if (!report.ok) {
        return fail("integrity: " + report.detail);
    }

    // The declared default must be reachable for a subject with no assignment of its own.
    pf::SubjectDef other;
    other.id = subject_id("tenant.other", limits);
    if (!fabric.define_subject(session.value(), other).ok()) {
        return fail("could not define the second subject");
    }
    pf::PriorityQuery default_query;
    default_query.subject = subject_id("tenant.other", limits);
    default_query.scope = scope_id("dc", limits);
    const pf::PriorityDecision fallback = fabric.evaluate(default_query);
    if (fallback.outcome != pf::Outcome::Assigned || !(fallback.cls == bulk.id)) {
        return fail("the policy-declared default was not applied");
    }
    std::cout << "default_resolution=" << fallback.resolution
              << " class=" << fallback.cls.str() << "\n";

    if (!fabric.close().ok()) {
        return fail("could not close the runtime");
    }
    std::filesystem::remove_all(root, ec);
    std::cout << "consumer: ok\n";
    return 0;
}
