// Priority Fabric -- authoritative network priority classes.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "support.hpp"

#include <atomic>
#include <system_error>

#include "priority_fabric/ident.hpp"

namespace pftest {
namespace {

std::atomic<std::uint64_t> g_counter{0};

std::filesystem::path temporary_root() {
    std::error_code ec;
    auto root = std::filesystem::temp_directory_path(ec);
    if (ec) {
        root = std::filesystem::current_path();
    }
    return root;
}

}  // namespace

ScratchDirectory::ScratchDirectory(std::string_view label) {
    const std::uint64_t sequence = ++g_counter;
    const std::string name = "pf-" + std::string(label) + "-" +
                             std::to_string(static_cast<unsigned long long>(sequence)) + "-" +
                             pf::BootId::from_seed(std::string(label) + std::to_string(sequence))
                                 .hex()
                                 .substr(0, 12);
    path_ = temporary_root() / name;
    std::error_code ec;
    std::filesystem::remove_all(path_, ec);
    std::filesystem::create_directories(path_, ec);
}

ScratchDirectory::~ScratchDirectory() {
    cleanup();
}

void ScratchDirectory::cleanup() {
    if (removed_) {
        return;
    }
    std::error_code ec;
    std::filesystem::remove_all(path_, ec);
    removed_ = !std::filesystem::exists(path_);
}

pf::PriorityClassId class_id(std::string_view text) {
    auto parsed = pf::PriorityClassId::parse(text, pf::Limits{});
    return parsed.ok() ? parsed.value() : pf::PriorityClassId{};
}

pf::SubjectId subject_id(std::string_view text) {
    auto parsed = pf::SubjectId::parse(text, pf::Limits{});
    return parsed.ok() ? parsed.value() : pf::SubjectId{};
}

pf::PolicyScopeId scope_id(std::string_view text) {
    auto parsed = pf::PolicyScopeId::parse(text, pf::Limits{});
    return parsed.ok() ? parsed.value() : pf::PolicyScopeId{};
}

pf::PolicyId policy_id(std::string_view text) {
    auto parsed = pf::PolicyId::parse(text, pf::Limits{});
    return parsed.ok() ? parsed.value() : pf::PolicyId{};
}

pf::PriorityAssignmentId assignment_id(std::string_view text) {
    auto parsed = pf::PriorityAssignmentId::parse(text, pf::Limits{});
    return parsed.ok() ? parsed.value() : pf::PriorityAssignmentId{};
}

pf::PublisherId publisher_id(std::string_view text) {
    auto parsed = pf::PublisherId::parse(text, pf::Limits{});
    return parsed.ok() ? parsed.value() : pf::PublisherId{};
}

pf::PriorityClassDef make_class(std::string_view id, std::uint32_t precedence, pf::ClassKind kind,
                                std::vector<pf::PriorityClassId> parents, bool privileged) {
    pf::PriorityClassDef definition;
    definition.id = class_id(id);
    definition.precedence = pf::PrecedenceRank::make(precedence);
    definition.kind = kind;
    definition.inherits_from = std::move(parents);
    definition.privileged = privileged;
    return definition;
}

pf::PolicyScopeDef make_scope(std::string_view id, std::optional<pf::PolicyScopeId> parent,
                              pf::ConflictResolution conflict,
                              std::optional<pf::PriorityClassId> unknown_default,
                              bool allow_override) {
    pf::PolicyScopeDef definition;
    definition.id = scope_id(id);
    definition.parent = parent;
    definition.conflict_resolution = conflict;
    definition.unknown_default = unknown_default;
    definition.allow_override = allow_override;
    return definition;
}

pf::PriorityAssignment make_assignment(std::string_view id, std::string_view subject,
                                       std::string_view scope, std::string_view cls,
                                       pf::AssignmentKind kind) {
    pf::PriorityAssignment assignment;
    assignment.id = assignment_id(id);
    assignment.subject = subject_id(subject);
    assignment.scope = scope_id(scope);
    assignment.cls = class_id(cls);
    assignment.kind = kind;
    return assignment;
}

pf::SubjectDef make_subject(std::string_view id, std::vector<std::string> parents,
                            std::string description) {
    pf::SubjectDef definition;
    definition.id = subject_id(id);
    for (const auto& parent : parents) {
        definition.inherits_from.push_back(subject_id(parent));
    }
    definition.description = std::move(description);
    return definition;
}

pf::BootId boot_for(std::string_view label) {
    return pf::BootId::from_seed(std::string("test-boot/") + std::string(label));
}

bool open_fabric(Fabric& fabric, std::string_view label, const pf::Limits& limits, bool fsync) {
    pf::FabricRuntime::Options options;
    options.state_dir = fabric.directory.path() / "state";
    options.limits = limits;
    options.create_if_missing = true;
    options.fsync_records = fsync;
    options.instance_boot_id = boot_for(std::string(label) + "/instance");
    auto opened = pf::FabricRuntime::open(options);
    if (!opened.ok()) {
        return false;
    }
    fabric.runtime = std::move(opened.value());
    fabric.boot = boot_for(label);
    auto session =
        fabric.runtime.grant_authority(publisher_id("test.publisher"), fabric.boot);
    if (!session.ok()) {
        return false;
    }
    fabric.session = session.value();
    return true;
}

}  // namespace pftest
