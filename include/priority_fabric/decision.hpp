// Priority Fabric -- authoritative network priority classes.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#ifndef PRIORITY_FABRIC_DECISION_HPP
#define PRIORITY_FABRIC_DECISION_HPP

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "priority_fabric/digest.hpp"
#include "priority_fabric/export.hpp"
#include "priority_fabric/ident.hpp"
#include "priority_fabric/model.hpp"

namespace pf {

/// The eight authoritative answers this runtime can give. Every evaluation returns
/// exactly one of them, and only the first three carry an authoritative class.
enum class Outcome : std::uint8_t {
    Assigned = 0,   ///< evidence names the class directly
    Inherited = 1,  ///< the class comes from an ancestor subject, named explicitly
    Overridden = 2, ///< a narrower scope displaced a broader assignment
    Conflict = 3,   ///< contradictory evidence; authoritative only if policy resolved it
    Unknown = 4,    ///< no evidence at all; stays UNKNOWN unless policy declares a default
    Stale = 5,      ///< evidence exists but is bound to superseded generations
    Fenced = 6,     ///< evidence exists but its publisher incarnation lost authority
    Rejected = 7,   ///< the question or the state is structurally invalid; no answer given
};

[[nodiscard]] PF_API const char* to_string(Outcome outcome) noexcept;
[[nodiscard]] PF_API bool outcome_carries_authority(Outcome outcome) noexcept;

/// A single step of the explanation chain. Steps are ordered outermost-cause-first:
/// the query, then each scope level examined, then the winning or displacing evidence.
struct PF_API ExplanationStep {
    /// Stable machine-readable stage name, e.g. "query.validate", "scope.visit",
    /// "candidate.accept", "candidate.reject", "conflict.detect", "conflict.resolve",
    /// "inherit.walk", "default.apply".
    std::string stage;
    /// Stable machine-readable detail code, e.g. "binding_ok", "generation_mismatch".
    std::string code;
    /// Human-readable one-line detail, bounded by Limits::max_description_length.
    std::string detail;
    std::optional<PriorityAssignmentId> assignment;
    Generation assignment_generation = Generation::unset();
    std::optional<PriorityClassId> cls;
    Generation class_generation = Generation::unset();
    std::optional<PolicyScopeId> scope;
    std::optional<PolicyId> policy;
    Provenance provenance;
};

/// A provenance-only record used for superseded / rejected evidence.
struct PF_API EvidenceNote {
    PriorityAssignmentId assignment;
    Generation assignment_generation = Generation::unset();
    PriorityClassId cls;
    Generation class_generation = Generation::unset();
    PolicyScopeId scope;
    std::optional<SubjectId> via_subject;  ///< set for inherited evidence
    std::string reason_code;
    std::string reason;
    Provenance provenance;
};

/// The authoritative answer.
struct PF_API PriorityDecision {
    Outcome outcome = Outcome::Unknown;

    /// True when the decision names a class that consumers may act on. A CONFLICT that the
    /// policy resolved deterministically is authoritative *and* still reports the
    /// contradiction; a CONFLICT under Deny is not authoritative.
    bool authoritative = false;

    PriorityClassId cls;
    Generation class_generation = Generation::unset();
    PrecedenceRank precedence = PrecedenceRank::undeclared();

    /// The winning chain: assignment, inheritance hop and scope walk that produced the
    /// answer, in evaluation order. Bounded by Limits::max_explanation_steps.
    std::vector<ExplanationStep> chain;
    /// Evidence that was displaced by a narrower or higher-precedence candidate.
    std::vector<EvidenceNote> superseded;
    /// Evidence that was present but had lost authority (stale, fenced, rejected).
    std::vector<EvidenceNote> rejected_evidence;
    /// Human-readable statements of the contradictions that were detected.
    std::vector<std::string> conflicts;

    /// Stable machine-readable reason code for the outcome.
    std::string reason_code;
    /// Human-readable reason, bounded by Limits::max_description_length.
    std::string reason;
    /// How a conflict was resolved, or "none".
    std::string resolution;

    /// The exact fabric state the decision was bound to. A consumer that caches this
    /// decision must re-validate when any of these move.
    FabricEpoch epoch;
    Generation state_generation = Generation::unset();
    Generation policy_generation = Generation::unset();
    Generation scope_generation = Generation::unset();

    /// Content digest over the decision's authoritative fields. Two evaluations of the same
    /// question against the same state produce the same digest, by construction.
    Digest digest;
    /// True when the class is flagged privileged in the current registry.
    bool privileged_class = false;

    [[nodiscard]] std::string to_json() const;
    [[nodiscard]] std::string to_text() const;
};

/// The question. Everything the fabric is allowed to look at when answering.
struct PF_API PriorityQuery {
    SubjectId subject;
    Generation subject_generation = Generation::unset();  ///< 0 = "current generation"
    PolicyScopeId scope;

    /// The epoch the caller believes is current. Absent = the caller accepts the current
    /// epoch. A caller that supplies a superseded epoch is answered STALE, never with a
    /// decision computed against today's state on behalf of yesterday's authority.
    std::optional<FabricEpoch> as_of_epoch;

    /// Minimum generations the caller requires. When the fabric has moved past them the
    /// answer is still produced, but the decision records the generations it used so the
    /// caller can detect the movement. When the fabric is *behind* a required generation
    /// the answer is STALE.
    Generation require_policy_generation = Generation::unset();
    Generation require_scope_generation = Generation::unset();

    /// When set, any contradictory evidence produces CONFLICT even if the policy declares a
    /// deterministic resolution. Used by callers that must refuse ambiguity outright.
    bool strict_conflicts = false;

    /// Bound on the explanation chain this caller wants. Clamped to Limits::max_explanation_steps.
    std::uint32_t max_explanation_steps = 32;

    /// Caller-supplied correlation id. Never affects the answer or its digest.
    std::uint64_t correlation = 0;
};

/// Health of the authoritative state. A degraded fabric answers REJECTED instead of
/// guessing: recovering a journal that failed verification must not silently become
/// authority.
enum class Health : std::uint8_t {
    Healthy = 0,
    Degraded = 1,
};

[[nodiscard]] PF_API const char* to_string(Health health) noexcept;

/// Result of a full integrity verification of the durable state.
struct PF_API IntegrityReport {
    bool ok = false;
    Health health = Health::Healthy;
    std::uint64_t records_scanned = 0;
    std::uint64_t records_applied = 0;
    std::uint64_t records_rejected = 0;
    std::uint64_t unfinished_attempts = 0;
    std::uint64_t trailing_bytes_discarded = 0;
    std::string detail;
    Digest state_digest;
    Generation state_generation = Generation::unset();
    FabricEpoch epoch;
};

/// Counters describing what the fabric has done. Monotonic within a process lifetime.
struct PF_API FabricStats {
    std::uint64_t evaluations = 0;
    std::uint64_t evaluations_assigned = 0;
    std::uint64_t evaluations_inherited = 0;
    std::uint64_t evaluations_overridden = 0;
    std::uint64_t evaluations_conflict = 0;
    std::uint64_t evaluations_unknown = 0;
    std::uint64_t evaluations_stale = 0;
    std::uint64_t evaluations_fenced = 0;
    std::uint64_t evaluations_rejected = 0;
    std::uint64_t mutations_accepted = 0;
    std::uint64_t mutations_rejected = 0;
    std::uint64_t idempotent_noops = 0;
    std::uint64_t durable_commits = 0;
    std::uint64_t recoveries = 0;
    std::uint64_t epoch_advances = 0;
    std::uint64_t fences_issued = 0;
    std::uint64_t authorities_granted = 0;

    friend bool operator==(const FabricStats&, const FabricStats&) = default;
};

}  // namespace pf

#endif  // PRIORITY_FABRIC_DECISION_HPP
