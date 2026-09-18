// Priority Fabric -- authoritative network priority classes.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "priority_fabric/model.hpp"

#include <array>
#include <utility>

#include "priority_fabric/text.hpp"

namespace pf {
namespace {

struct EnumName {
    std::string_view name;
    std::uint32_t value;
};

template <std::size_t N>
bool lookup(const std::array<EnumName, N>& table, std::string_view text,
            std::uint32_t& out) noexcept {
    const std::string lowered = ascii_lower(text);
    for (const auto& entry : table) {
        if (entry.name == lowered) {
            out = entry.value;
            return true;
        }
    }
    return false;
}

constexpr std::array<EnumName, 4> kClassKinds{{
    {"standard", 0},
    {"tenant", 1},
    {"system", 2},
    {"emergency", 3},
}};

constexpr std::array<EnumName, 4> kConflictModes{{
    {"deny", 0},
    {"higher-precedence", 1},
    {"higher_precedence", 1},
    {"assignment-id-order", 2},
}};

constexpr std::array<EnumName, 5> kAssignmentKinds{{
    {"explicit", 0},
    {"inherited", 1},
    {"override", 2},
    {"exception", 3},
    {"default", 4},
}};

constexpr std::array<EnumName, 4> kAuthorityStates{{
    {"granted", 0},
    {"superseded", 1},
    {"fenced", 2},
    {"expired", 3},
}};

}  // namespace

const char* to_string(ClassKind kind) noexcept {
    switch (kind) {
        case ClassKind::Standard: return "standard";
        case ClassKind::Tenant: return "tenant";
        case ClassKind::System: return "system";
        case ClassKind::Emergency: return "emergency";
    }
    return "unknown";
}

bool parse_class_kind(std::string_view text, ClassKind& out) noexcept {
    std::uint32_t value = 0;
    if (!lookup(kClassKinds, text, value)) {
        return false;
    }
    out = static_cast<ClassKind>(value);
    return true;
}

const char* to_string(ConflictResolution mode) noexcept {
    switch (mode) {
        case ConflictResolution::Deny: return "deny";
        case ConflictResolution::HigherPrecedence: return "higher-precedence";
        case ConflictResolution::AssignmentIdOrder: return "assignment-id-order";
    }
    return "unknown";
}

bool parse_conflict_resolution(std::string_view text, ConflictResolution& out) noexcept {
    std::uint32_t value = 0;
    if (!lookup(kConflictModes, text, value)) {
        return false;
    }
    out = static_cast<ConflictResolution>(value);
    return true;
}

const char* to_string(AssignmentKind kind) noexcept {
    switch (kind) {
        case AssignmentKind::Explicit: return "explicit";
        case AssignmentKind::Inherited: return "inherited";
        case AssignmentKind::Override: return "override";
        case AssignmentKind::Exception: return "exception";
        case AssignmentKind::Default: return "default";
    }
    return "unknown";
}

bool parse_assignment_kind(std::string_view text, AssignmentKind& out) noexcept {
    std::uint32_t value = 0;
    if (!lookup(kAssignmentKinds, text, value)) {
        return false;
    }
    out = static_cast<AssignmentKind>(value);
    return true;
}

const char* to_string(AuthorityState state) noexcept {
    switch (state) {
        case AuthorityState::Granted: return "granted";
        case AuthorityState::Superseded: return "superseded";
        case AuthorityState::Fenced: return "fenced";
        case AuthorityState::Expired: return "expired";
    }
    return "unknown";
}

}  // namespace pf
