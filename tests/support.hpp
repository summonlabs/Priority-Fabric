// Priority Fabric -- authoritative network priority classes.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#ifndef PRIORITY_FABRIC_TESTS_SUPPORT_HPP
#define PRIORITY_FABRIC_TESTS_SUPPORT_HPP

#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

#include "priority_fabric/runtime.hpp"

namespace pftest {

/// A scratch state directory that removes itself, and the runtime that owns it.
class ScratchDirectory {
public:
    ScratchDirectory() : ScratchDirectory("scratch") {}
    explicit ScratchDirectory(std::string_view label);
    ~ScratchDirectory();

    ScratchDirectory(const ScratchDirectory&) = delete;
    ScratchDirectory& operator=(const ScratchDirectory&) = delete;

    [[nodiscard]] const std::filesystem::path& path() const noexcept { return path_; }
    [[nodiscard]] bool removed() const noexcept { return removed_; }

    /// Removes the directory. Windows keeps a directory busy while a handle is open, so this
    /// is called after the runtime that owns it has been destroyed.
    void cleanup();

private:
    std::filesystem::path path_;
    bool removed_ = false;
};

// ---- identifier helpers ---------------------------------------------------------------

[[nodiscard]] pf::PriorityClassId class_id(std::string_view text);
[[nodiscard]] pf::SubjectId subject_id(std::string_view text);
[[nodiscard]] pf::PolicyScopeId scope_id(std::string_view text);
[[nodiscard]] pf::PolicyId policy_id(std::string_view text);
[[nodiscard]] pf::PriorityAssignmentId assignment_id(std::string_view text);
[[nodiscard]] pf::PublisherId publisher_id(std::string_view text);

// ---- builder helpers ------------------------------------------------------------------

[[nodiscard]] pf::PriorityClassDef make_class(std::string_view id, std::uint32_t precedence,
                                              pf::ClassKind kind = pf::ClassKind::Standard,
                                              std::vector<pf::PriorityClassId> parents = {},
                                              bool privileged = false);

[[nodiscard]] pf::PolicyScopeDef make_scope(
    std::string_view id, std::optional<pf::PolicyScopeId> parent = std::nullopt,
    pf::ConflictResolution conflict = pf::ConflictResolution::Deny,
    std::optional<pf::PriorityClassId> unknown_default = std::nullopt,
    bool allow_override = true);

[[nodiscard]] pf::PriorityAssignment make_assignment(std::string_view id, std::string_view subject,
                                                     std::string_view scope,
                                                     std::string_view cls,
                                                     pf::AssignmentKind kind =
                                                         pf::AssignmentKind::Explicit);

/// Subject definitions carry four fields, so tests build them through a named helper rather
/// than a positional aggregate initializer that silently binds to the wrong member.
[[nodiscard]] pf::SubjectDef make_subject(std::string_view id,
                                          std::vector<std::string> parents = {},
                                          std::string description = {});

/// A runtime plus an established session, opened over a scratch directory.
struct Fabric {
    ScratchDirectory directory;
    pf::FabricRuntime runtime;
    pf::Session session;
    /// The incarnation this fabric was opened with. A restart that wants to resume the same
    /// publisher has to ask for exactly this boot id.
    pf::BootId boot;
};

/// Opens a fabric in a fresh scratch directory and registers a publisher. The runtime is
/// built with the given limits so that bound tests can lower them.
[[nodiscard]] bool open_fabric(Fabric& fabric, std::string_view label,
                               const pf::Limits& limits = pf::Limits{},
                               bool fsync = true);

/// Deterministic boot id derived from a label, so a test never depends on entropy.
[[nodiscard]] pf::BootId boot_for(std::string_view label);

}  // namespace pftest

#endif  // PRIORITY_FABRIC_TESTS_SUPPORT_HPP
