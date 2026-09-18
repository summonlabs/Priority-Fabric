// Priority Fabric -- authoritative network priority classes.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#ifndef PRIORITY_FABRIC_MODEL_HPP
#define PRIORITY_FABRIC_MODEL_HPP

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "priority_fabric/checked.hpp"
#include "priority_fabric/digest.hpp"
#include "priority_fabric/export.hpp"
#include "priority_fabric/ident.hpp"

namespace pf {

// ---------------------------------------------------------------------------------------
// Enumerations
// ---------------------------------------------------------------------------------------

/// Provenance category of a canonical priority class. The category is descriptive and
/// audited; it never changes ordering. Ordering comes only from the declared precedence
/// rank, so there is no hidden "system beats tenant" rule anywhere in the fabric.
enum class ClassKind : std::uint8_t {
    Standard = 0,
    Tenant = 1,
    System = 2,
    Emergency = 3,
};

[[nodiscard]] PF_API const char* to_string(ClassKind kind) noexcept;
[[nodiscard]] PF_API bool parse_class_kind(std::string_view text, ClassKind& out) noexcept;

/// What the fabric does when two assignments at the *same* specificity level select
/// different classes for the same subject. The default denies: contradictory explicit
/// declarations are surfaced as CONFLICT and produce no authoritative class.
enum class ConflictResolution : std::uint8_t {
    Deny = 0,             ///< contradictory evidence never becomes authority
    HigherPrecedence = 1, ///< the higher declared rank wins; the conflict is still reported
    AssignmentIdOrder = 2 ///< the lexicographically smaller assignment id wins; reported
};

[[nodiscard]] PF_API const char* to_string(ConflictResolution mode) noexcept;
[[nodiscard]] PF_API bool parse_conflict_resolution(std::string_view text,
                                                    ConflictResolution& out) noexcept;

/// How an assignment came to exist. The kind is declarative input; the outcome of an
/// evaluation is derived from it together with what the assignment displaced.
enum class AssignmentKind : std::uint8_t {
    Explicit = 0,   ///< declared directly for the subject in the scope
    Inherited = 1,  ///< declared for an ancestor class of the subject's declared class
    Override = 2,   ///< declared to displace a broader-scope assignment
    Exception = 3,  ///< declared as a bounded exception to an existing assignment
    Default = 4,    ///< produced by a policy-declared default, never by the fabric's opinion
};

[[nodiscard]] PF_API const char* to_string(AssignmentKind kind) noexcept;
[[nodiscard]] PF_API bool parse_assignment_kind(std::string_view text,
                                                AssignmentKind& out) noexcept;

// ---------------------------------------------------------------------------------------
// Definitions
// ---------------------------------------------------------------------------------------

/// A canonical priority class.
///
/// Identity rule: within one authoritative state, a class identifier maps to exactly one
/// definition. Submitting a different definition under an existing identifier creates a
/// new *generation* of that class; every assignment and every decision records the exact
/// generation it was bound to, so a superseded definition can never silently authorize a
/// decision.
struct PF_API PriorityClassDef {
    PriorityClassId id;
    Generation generation = Generation::unset();  ///< unset on input: the fabric assigns one
    PrecedenceRank precedence = PrecedenceRank::undeclared();
    ClassKind kind = ClassKind::Standard;
    std::vector<PriorityClassId> inherits_from;  ///< direct ancestors; must form a DAG
    std::string description;
    /// Emergency (or otherwise privileged) classes may be marked so that every decision
    /// that lands on them is flagged in the explanation for audit.
    bool privileged = false;
};

/// A node of the policy scope tree. Scopes form a forest; evaluation walks from the
/// queried scope towards its root and the narrowest scope with valid evidence wins.
struct PF_API PolicyScopeDef {
    PolicyScopeId id;
    Generation generation = Generation::unset();
    std::optional<PolicyScopeId> parent;  ///< absent = this scope is a root
    ConflictResolution conflict_resolution = ConflictResolution::Deny;
    /// Policy-declared default class for subjects with no assignment. Absent (the default)
    /// means an unassigned subject stays UNKNOWN; the fabric never invents a low class.
    std::optional<PriorityClassId> unknown_default;
    bool allow_override = true;  ///< when false, a descendant scope may not displace this one
    std::string description;
};

/// A policy document. Policies gate which classes a scope may use and may tighten the
/// conflict behaviour of the scope they belong to.
struct PF_API PolicyDef {
    PolicyId id;
    Generation generation = Generation::unset();
    PolicyScopeId scope;
    Generation scope_generation = Generation::unset();
    std::vector<PriorityClassId> visible_classes;  ///< bounded by Limits::max_policy_classes
    std::optional<ConflictResolution> conflict_resolution;  ///< absent = inherit from scope
    std::optional<PriorityClassId> unknown_default;         ///< absent = inherit from scope
    bool require_policy_for_assignment = true;
    std::string description;
};

/// A subject: the identity whose priority is being decided (a flow class, a workload, a
/// tenant, a control plane endpoint). Subjects may inherit from other subjects; the
/// inheritance graph must be a DAG and is depth-bounded.
struct PF_API SubjectDef {
    SubjectId id;
    Generation generation = Generation::unset();
    std::vector<SubjectId> inherits_from;
    std::string description;
};

/// An authoritative statement that a subject holds a priority class in a scope.
struct PF_API PriorityAssignment {
    PriorityAssignmentId id;
    Generation generation = Generation::unset();
    SubjectId subject;
    Generation subject_generation = Generation::unset();
    PolicyScopeId scope;
    Generation scope_generation = Generation::unset();
    PriorityClassId cls;
    Generation class_generation = Generation::unset();
    AssignmentKind kind = AssignmentKind::Explicit;
    /// The class this assignment is declared to displace, for Override/Exception kinds.
    /// When absent, the assignment displaces whatever the enclosing scope chain offers.
    std::optional<PriorityClassId> displaces;
    std::optional<PolicyId> policy;
    Generation policy_generation = Generation::unset();
    std::string note;
};

// ---------------------------------------------------------------------------------------
// Provenance / audit
// ---------------------------------------------------------------------------------------

/// Where a durable fact came from and under which authority it was admitted. Provenance is
/// recorded for every mutation; it is evidence, never authority by itself.
struct PF_API Provenance {
    PublisherId publisher;
    BootId boot;
    FabricEpoch epoch;
    FencingToken token;
    Generation state_generation = Generation::unset();
    std::uint64_t audit_sequence = 0;
    std::uint64_t recorded_at_ms = 0;  ///< informational; never used for ordering
    std::string op;
};

/// One durable audit record. Rejected attempts are recorded too: an operator must be able
/// to see that a fenced publisher tried to write.
struct PF_API AuditEntry {
    std::uint64_t sequence = 0;
    std::string op;
    StatusCode result = StatusCode::Ok;
    std::string detail;
    Provenance provenance;
    Generation state_generation = Generation::unset();
    Digest digest;  ///< content digest of the admitted mutation (zero for rejections)
};

/// Snapshot of authoritative state size. Used for bounds enforcement and reporting.
struct PF_API StateStats {
    std::uint64_t classes = 0;
    std::uint64_t scopes = 0;
    std::uint64_t policies = 0;
    std::uint64_t subjects = 0;
    std::uint64_t assignments = 0;
    std::uint64_t retired_assignments = 0;
    std::uint64_t publishers = 0;
    std::uint64_t fenced_boots = 0;
    std::uint64_t audit_entries = 0;
    std::uint64_t durable_bytes = 0;
    std::uint64_t journal_records = 0;
    Generation state_generation = Generation::unset();
    FabricEpoch epoch;

    friend bool operator==(const StateStats&, const StateStats&) = default;
};

// ---------------------------------------------------------------------------------------
// Authority
// ---------------------------------------------------------------------------------------

/// Lifecycle of one publisher incarnation.
enum class AuthorityState : std::uint8_t {
    Granted = 0,   ///< the boot holds a live grant for the current epoch
    Superseded = 1,///< a newer boot of the same publisher replaced it
    Fenced = 2,    ///< explicitly fenced by an operator or by epoch advancement
    Expired = 3,   ///< the epoch it was granted under is no longer current
};

[[nodiscard]] PF_API const char* to_string(AuthorityState state) noexcept;

}  // namespace pf

#endif  // PRIORITY_FABRIC_MODEL_HPP
