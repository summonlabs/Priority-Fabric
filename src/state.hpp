// Priority Fabric -- authoritative network priority classes.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Internal: the authoritative state image, the mutation record that transforms it, and the
// canonical encoding of both.

#ifndef PRIORITY_FABRIC_SRC_STATE_HPP
#define PRIORITY_FABRIC_SRC_STATE_HPP

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include "priority_fabric/decision.hpp"
#include "priority_fabric/digest.hpp"
#include "priority_fabric/limits.hpp"
#include "priority_fabric/model.hpp"
#include "priority_fabric/status.hpp"

namespace pf::detail {

/// A definition together with the provenance of the mutation that admitted it.
struct ClassEntry {
    PriorityClassDef definition;
    Provenance provenance;
};

struct ScopeEntry {
    PolicyScopeDef definition;
    Provenance provenance;
};

struct PolicyEntry {
    PolicyDef definition;
    Provenance provenance;
};

struct SubjectEntry {
    SubjectDef definition;
    Provenance provenance;
};

struct AssignmentEntry {
    PriorityAssignment assignment;
    Provenance provenance;
    bool active = true;
    std::string retirement_reason;
    Provenance retired_by;
};

struct AuthorityEntry {
    PublisherId publisher;
    BootId boot;
    FabricEpoch epoch;
    FencingToken token;
    AuthorityState state = AuthorityState::Granted;
    Provenance provenance;
};

/// The complete authoritative state. Everything the fabric can answer from lives here, and
/// exactly this structure is what a snapshot contains and what a journal replay rebuilds.
struct StateImage {
    FabricEpoch epoch;
    Generation generation;
    std::uint64_t last_sequence = 0;
    std::uint64_t next_fencing_token = 1;
    std::uint64_t next_audit_sequence = 1;
    Limits limits{};

    std::map<PriorityClassId, ClassEntry> classes;
    std::map<PolicyScopeId, ScopeEntry> scopes;
    std::map<PolicyId, PolicyEntry> policies;
    std::map<SubjectId, SubjectEntry> subjects;
    std::map<PriorityAssignmentId, AssignmentEntry> assignments;
    /// Derived index: assignments grouped by the subject they name, each group sorted by
    /// assignment id. Rebuilt deterministically after a decode and maintained on insert, so
    /// two images with the same content always iterate in the same order.
    std::map<SubjectId, std::vector<PriorityAssignmentId>> assignments_by_subject;
    std::map<std::pair<PublisherId, BootId>, AuthorityEntry> authority;
    std::vector<AuditEntry> audit;

    Health health = Health::Healthy;
    std::string health_detail;
};

/// Operations that can be journaled. The numbering is part of the durable format.
enum class MutationOp : std::uint16_t {
    DefineClass = 1,
    DefineScope = 2,
    DefinePolicy = 3,
    DefineSubject = 4,
    Assign = 5,
    RetireAssignment = 6,
    GrantAuthority = 7,
    FenceAuthority = 8,
    AdvanceEpoch = 9,
};

[[nodiscard]] const char* to_string(MutationOp op) noexcept;

/// One durable transition. Exactly one op field is meaningful for each MutationOp.
struct Mutation {
    MutationOp op = MutationOp::DefineClass;
    FabricEpoch epoch;
    PublisherId publisher;
    BootId boot;
    FencingToken token;
    std::uint64_t recorded_at_ms = 0;
    std::string reason;

    PriorityClassDef cls;
    PolicyScopeDef scope;
    PolicyDef policy;
    SubjectDef subject;
    PriorityAssignment assignment;
    PriorityAssignmentId retire_target;
    PublisherId fence_publisher;
    BootId fence_boot;

    /// The generation this mutation must produce when applied. Written by the planner,
    /// verified by the applier: a mismatch means the durable stream and the in-memory image
    /// disagree and the store is degraded rather than silently repaired.
    Generation resulting_generation;
    /// Set only for transitions the fabric initiates about itself (establishing the epoch,
    /// granting the first authority to a publisher). A system mutation is not subject to the
    /// authority check because it is the check's own bootstrap; it is never reachable from an
    /// external request path.
    bool system = false;
};

// ---- encoding ---------------------------------------------------------------------------

[[nodiscard]] std::string encode_state(const StateImage& image);
[[nodiscard]] Result<StateImage> decode_state(const std::string& payload, const Limits& limits);
[[nodiscard]] Digest state_digest(const StateImage& image);

[[nodiscard]] std::string encode_mutation(const Mutation& mutation);
[[nodiscard]] Result<Mutation> decode_mutation(const std::string& payload, const Limits& limits);

// ---- validation and application -----------------------------------------------------------

/// Checks a mutation against p image without changing it. In replay mode the authority
/// checks are skipped: the records being replayed already passed them when they were
/// committed, and the authority table is rebuilt by the replay itself.
[[nodiscard]] VoidResult validate_mutation(const StateImage& image, const Mutation& mutation,
                                           bool replay);

/// Applies a validated mutation. Fails when the mutation cannot be applied at all.
[[nodiscard]] VoidResult apply_mutation(StateImage& image, const Mutation& mutation, bool replay);

/// Rebuilds every derived index from the primary maps, in canonical order. Called after a
/// decode; the apply path maintains the indexes incrementally.
void rebuild_indexes(StateImage& image);

/// The generation the affected entity will hold once \p mutation is applied, computed
/// without changing anything. The planner uses it to report a result; the applier verifies
/// its own computation against the same function, so the two can never drift.
[[nodiscard]] Generation preview_entity_generation(const StateImage& image,
                                                   const Mutation& mutation);

/// True when applying \p mutation would change nothing (an identical republication).
[[nodiscard]] bool mutation_is_idempotent(const StateImage& image, const Mutation& mutation);

// ---- structural helpers -------------------------------------------------------------------

/// True when p candidate is p required or inherits from it, transitively.
[[nodiscard]] bool class_implies(const StateImage& image, const PriorityClassId& candidate,
                                 const PriorityClassId& required);

/// Distance from the root of the inheritance DAG; longest path, bounded. Returns -1 when the
/// cycle guard trips, which means the stored graph is cyclic and the state is degraded.
[[nodiscard]] int class_depth(const StateImage& image, const PriorityClassId& id);

/// Depth of a scope in its tree; -1 when the chain is cyclic or longer than the bound.
[[nodiscard]] int scope_depth(const StateImage& image, const PolicyScopeId& id);

/// Validates a proposed inheritance list against the current registry: parents must exist,
/// must not be the subject itself and must not create a cycle or exceed the depth bound.
[[nodiscard]] VoidResult validate_inheritance(const StateImage& image, const PriorityClassId& self,
                                              const std::vector<PriorityClassId>& parents);

[[nodiscard]] VoidResult validate_subject_inheritance(const StateImage& image,
                                                      const SubjectId& self,
                                                      const std::vector<SubjectId>& parents);

/// Ancestors of a subject in deterministic order: breadth-first by distance, ascending
/// subject id within a distance. Bounded by Limits::max_query_steps.
[[nodiscard]] Result<std::vector<std::pair<SubjectId, std::uint32_t>>> subject_ancestors(
    const StateImage& image, const SubjectId& id);

/// The effective policy for a scope: the lexicographically smallest policy bound to the
/// nearest scope on the chain that has one. Deterministic by construction.
[[nodiscard]] std::optional<PolicyId> effective_policy(const StateImage& image,
                                                       const PolicyScopeId& scope);

/// The scope chain from p scope to its root, narrowest first. Bounded.
[[nodiscard]] Result<std::vector<PolicyScopeId>> scope_chain(const StateImage& image,
                                                             const PolicyScopeId& scope);

/// The class visibility set imposed by the nearest enclosing policy that declares one.
/// nullopt means unrestricted.
[[nodiscard]] std::optional<std::vector<PriorityClassId>> effective_visibility(
    const StateImage& image, const PolicyScopeId& scope);

/// Appends an audit entry, trimming the oldest entries when the bound is reached.
void append_audit(StateImage& image, AuditEntry entry, const Limits& limits);

/// Recomputes and stores a stable content digest over the authoritative fields of a decision.
[[nodiscard]] Digest compute_decision_digest(const PriorityDecision& decision);

}  // namespace pf::detail

#endif  // PRIORITY_FABRIC_SRC_STATE_HPP
