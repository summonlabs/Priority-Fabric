// Priority Fabric -- authoritative network priority classes.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// The evaluation engine: given a subject, a scope and the current authoritative state,
// decide the priority class and explain exactly why.

#include "evaluate.hpp"

#include <algorithm>
#include <optional>
#include <string>
#include <vector>

#include "priority_fabric/text.hpp"

namespace pf::detail {
namespace {

/// One piece of evidence that survived every binding check.
struct Candidate {
    std::size_t level = 0;
    const AssignmentEntry* entry = nullptr;
    SubjectId via_subject;
    std::uint32_t inheritance_distance = 0;
};

struct RejectedEvidence {
    const AssignmentEntry* entry = nullptr;
    SubjectId via_subject;
    std::string code;
    std::string detail;
    bool authority_related = false;
};

/// Bounded explanation builder: never emits more steps than the caller asked for, and says
/// so explicitly when it had to stop early.
class ChainBuilder {
public:
    ChainBuilder(std::vector<ExplanationStep>& steps, std::uint32_t limit)
        : steps_(steps), limit_(limit) {}

    void push(ExplanationStep step) {
        if (steps_.size() + 1 >= limit_) {
            if (!truncated_) {
                truncated_ = true;
                ExplanationStep marker;
                marker.stage = "explanation";
                marker.code = "truncated";
                marker.detail = "the explanation chain reached the caller's step budget of " +
                                std::to_string(limit_);
                steps_.push_back(std::move(marker));
            }
            return;
        }
        steps_.push_back(std::move(step));
    }

private:
    std::vector<ExplanationStep>& steps_;
    std::uint32_t limit_;
    bool truncated_ = false;
};

std::string describe_assignment(const PriorityAssignment& assignment) {
    return std::string(to_string(assignment.kind)) + " assignment '" + assignment.id.str() +
           "' in scope '" + assignment.scope.str() + "' selects class '" + assignment.cls.str() +
           "'";
}

ExplanationStep make_step(std::string stage, std::string code, std::string detail,
                          const AssignmentEntry& entry, const SubjectId& via) {
    ExplanationStep step;
    step.stage = std::move(stage);
    step.code = std::move(code);
    step.detail = std::move(detail);
    step.assignment = entry.assignment.id;
    step.assignment_generation = entry.assignment.generation;
    step.cls = entry.assignment.cls;
    step.class_generation = entry.assignment.class_generation;
    step.scope = entry.assignment.scope;
    step.policy = entry.assignment.policy;
    step.provenance = entry.provenance;
    if (via.valid() && via != entry.assignment.subject) {
        step.detail += " (inherited through '" + via.str() + "')";
    }
    return step;
}

EvidenceNote make_note(const AssignmentEntry& entry, const SubjectId& via, std::string code,
                       std::string detail) {
    EvidenceNote note;
    note.assignment = entry.assignment.id;
    note.assignment_generation = entry.assignment.generation;
    note.cls = entry.assignment.cls;
    note.class_generation = entry.assignment.class_generation;
    note.scope = entry.assignment.scope;
    if (via.valid() && via != entry.assignment.subject) {
        note.via_subject = via;
    }
    note.reason_code = std::move(code);
    note.reason = std::move(detail);
    note.provenance = entry.provenance;
    return note;
}

PriorityDecision rejected_decision(const Limits& limits, std::string code, std::string reason,
                                   FabricEpoch epoch, Generation generation) {
    PriorityDecision decision;
    decision.outcome = Outcome::Rejected;
    decision.authoritative = false;
    decision.reason_code = std::move(code);
    decision.reason = bound_text(reason, limits.max_description_length);
    decision.resolution = "none";
    decision.epoch = epoch;
    decision.state_generation = generation;
    decision.digest = compute_decision_digest(decision);
    return decision;
}

struct ConflictMode {
    ConflictResolution mode = ConflictResolution::Deny;
    std::string source = "default";
};

ConflictMode effective_conflict_mode(const StateImage& image, const PolicyScopeId& scope) {
    ConflictMode out;
    const auto scope_entry = image.scopes.find(scope);
    if (scope_entry != image.scopes.end()) {
        out.mode = scope_entry->second.definition.conflict_resolution;
        out.source = "scope";
    }
    for (const auto& entry : image.policies) {
        if (entry.second.definition.scope == scope &&
            entry.second.definition.conflict_resolution.has_value()) {
            out.mode = *entry.second.definition.conflict_resolution;
            out.source = "policy:" + entry.first.str();
            return out;
        }
    }
    return out;
}

struct DefaultResolution {
    bool found = false;
    PriorityClassId cls;
    Generation class_generation;
    PrecedenceRank precedence;
    std::string source;
    bool privileged = false;
    bool available = false;
};

DefaultResolution resolve_unknown_default(const StateImage& image, const PolicyScopeId& scope) {
    DefaultResolution out;
    auto chain = scope_chain(image, scope);
    if (!chain.ok()) {
        return out;
    }
    for (const auto& level : chain.value()) {
        std::optional<PriorityClassId> candidate;
        std::string source;
        for (const auto& entry : image.policies) {
            if (entry.second.definition.scope == level &&
                entry.second.definition.unknown_default.has_value()) {
                candidate = entry.second.definition.unknown_default;
                source = "policy:" + entry.first.str();
                break;
            }
        }
        if (!candidate.has_value()) {
            const auto node = image.scopes.find(level);
            if (node != image.scopes.end() && node->second.definition.unknown_default.has_value()) {
                candidate = node->second.definition.unknown_default;
                source = "scope";
            }
        }
        if (candidate.has_value()) {
            out.found = true;
            out.cls = *candidate;
            out.source = std::move(source);
            const auto definition = image.classes.find(*candidate);
            if (definition == image.classes.end()) {
                out.available = false;
                return out;
            }
            out.class_generation = definition->second.definition.generation;
            out.precedence = definition->second.definition.precedence;
            out.privileged = definition->second.definition.privileged;
            const auto visibility = effective_visibility(image, scope);
            out.available = true;
            if (visibility.has_value()) {
                bool visible = false;
                for (const auto& allowed : *visibility) {
                    if (class_implies(image, *candidate, allowed)) {
                        visible = true;
                        break;
                    }
                }
                if (!visible) {
                    out.available = false;
                }
            }
            return out;
        }
    }
    return out;
}

}  // namespace

PriorityDecision evaluate_query(const StateImage& image, const PriorityQuery& query) {
    const Limits& limits = image.limits;

    if (image.health != Health::Healthy) {
        return rejected_decision(limits, "state_degraded",
                                 "the fabric state is degraded and cannot authorize a priority: " +
                                     image.health_detail,
                                 image.epoch, image.generation);
    }
    if (!query.subject.valid()) {
        return rejected_decision(limits, "invalid_subject_id",
                                 "the query does not name a subject", image.epoch,
                                 image.generation);
    }
    if (!query.scope.valid()) {
        return rejected_decision(limits, "invalid_scope_id",
                                 "the query does not name a policy scope", image.epoch,
                                 image.generation);
    }
    if (query.as_of_epoch.has_value()) {
        if (query.as_of_epoch->value > image.epoch.value) {
            return rejected_decision(
                limits, "epoch_from_future",
                "the query claims epoch " + std::to_string(query.as_of_epoch->value) +
                    " but the fabric has only reached epoch " + std::to_string(image.epoch.value),
                image.epoch, image.generation);
        }
        if (query.as_of_epoch->value < image.epoch.value) {
            PriorityDecision decision;
            decision.outcome = Outcome::Stale;
            decision.reason_code = "epoch_superseded";
            decision.reason = "the query was asked against epoch " +
                              std::to_string(query.as_of_epoch->value) +
                              " which the fabric has superseded; the current epoch is " +
                              std::to_string(image.epoch.value);
            decision.resolution = "none";
            decision.epoch = image.epoch;
            decision.state_generation = image.generation;
            ExplanationStep step;
            step.stage = "query";
            step.code = "epoch_superseded";
            step.detail = decision.reason;
            decision.chain.push_back(std::move(step));
            decision.digest = compute_decision_digest(decision);
            return decision;
        }
    }

    const auto subject_entry = image.subjects.find(query.subject);
    if (subject_entry == image.subjects.end()) {
        return rejected_decision(limits, "subject_not_registered",
                                 "subject '" + query.subject.str() +
                                     "' is not registered in this fabric state",
                                 image.epoch, image.generation);
    }
    if (query.subject_generation.is_set() &&
        query.subject_generation != subject_entry->second.definition.generation) {
        PriorityDecision decision;
        decision.outcome = Outcome::Stale;
        decision.reason_code = "subject_generation_superseded";
        decision.reason = "the query names subject '" + query.subject.str() + "' generation " +
                          std::to_string(query.subject_generation.value) +
                          " but the subject is at generation " +
                          std::to_string(subject_entry->second.definition.generation.value);
        decision.resolution = "none";
        decision.epoch = image.epoch;
        decision.state_generation = image.generation;
        decision.digest = compute_decision_digest(decision);
        return decision;
    }

    auto chain_scopes = scope_chain(image, query.scope);
    if (!chain_scopes.ok()) {
        return rejected_decision(limits, "scope_unusable", chain_scopes.status().message(),
                                 image.epoch, image.generation);
    }
    const std::vector<PolicyScopeId>& scopes = chain_scopes.value();

    const auto effective = effective_policy(image, query.scope);
    Generation effective_policy_generation = Generation::unset();
    if (effective.has_value()) {
        const auto entry = image.policies.find(*effective);
        if (entry != image.policies.end()) {
            effective_policy_generation = entry->second.definition.generation;
        }
    }
    const auto scope_node = image.scopes.find(query.scope);
    const Generation query_scope_generation =
        scope_node == image.scopes.end() ? Generation::unset()
                                         : scope_node->second.definition.generation;

    if (query.require_policy_generation.is_set() &&
        effective_policy_generation.value < query.require_policy_generation.value) {
        PriorityDecision decision;
        decision.outcome = Outcome::Stale;
        decision.reason_code = "required_policy_generation_not_reached";
        decision.reason = "the caller requires policy generation " +
                          std::to_string(query.require_policy_generation.value) +
                          " but the effective policy of scope '" + query.scope.str() +
                          "' is at generation " +
                          std::to_string(effective_policy_generation.value);
        decision.resolution = "none";
        decision.epoch = image.epoch;
        decision.state_generation = image.generation;
        decision.policy_generation = effective_policy_generation;
        decision.scope_generation = query_scope_generation;
        decision.digest = compute_decision_digest(decision);
        return decision;
    }
    if (query.require_scope_generation.is_set() &&
        query_scope_generation.value < query.require_scope_generation.value) {
        PriorityDecision decision;
        decision.outcome = Outcome::Stale;
        decision.reason_code = "required_scope_generation_not_reached";
        decision.reason = "the caller requires scope generation " +
                          std::to_string(query.require_scope_generation.value) +
                          " but scope '" + query.scope.str() + "' is at generation " +
                          std::to_string(query_scope_generation.value);
        decision.resolution = "none";
        decision.epoch = image.epoch;
        decision.state_generation = image.generation;
        decision.policy_generation = effective_policy_generation;
        decision.scope_generation = query_scope_generation;
        decision.digest = compute_decision_digest(decision);
        return decision;
    }

    const std::uint32_t step_budget =
        std::max<std::uint32_t>(2, std::min<std::uint32_t>(
                                        query.max_explanation_steps == 0
                                            ? limits.max_explanation_steps
                                            : query.max_explanation_steps,
                                        limits.max_explanation_steps));
    std::vector<ExplanationStep> chain;
    ChainBuilder builder(chain, step_budget);

    ExplanationStep query_step;
    query_step.stage = "query";
    query_step.code = "validated";
    query_step.detail = "subject '" + query.subject.str() + "' generation " +
                        std::to_string(subject_entry->second.definition.generation.value) +
                        " in scope '" + query.scope.str() + "' generation " +
                        std::to_string(query_scope_generation.value) + " at epoch " +
                        std::to_string(image.epoch.value);
    builder.push(std::move(query_step));

    // ---- collect evidence ---------------------------------------------------------------
    std::vector<Candidate> accepted;
    std::vector<RejectedEvidence> rejected;

    auto collect_for_subject = [&](const SubjectId& subject, std::uint32_t distance) {
        std::size_t steps = 0;
        const auto bucket = image.assignments_by_subject.find(subject);
        if (bucket == image.assignments_by_subject.end()) {
            return;
        }
        for (const auto& id : bucket->second) {
            const auto entry = image.assignments.find(id);
            if (entry == image.assignments.end()) {
                continue;
            }
            const AssignmentEntry& assignment_entry = entry->second;
            if (++steps > limits.max_query_steps) {
                RejectedEvidence overflow;
                overflow.entry = &assignment_entry;
                overflow.via_subject = subject;
                overflow.code = "evidence_scan_budget_exhausted";
                overflow.detail = "subject '" + subject.str() + "' holds more assignments than "
                                  "the evaluation budget of " +
                                  std::to_string(limits.max_query_steps);
                rejected.push_back(std::move(overflow));
                return;
            }
            if (distance > 0 && assignment_entry.assignment.kind != AssignmentKind::Inherited) {
                continue;  // this assignment was not declared to propagate to descendants
            }
            const auto level_it =
                std::find(scopes.begin(), scopes.end(), assignment_entry.assignment.scope);
            if (level_it == scopes.end()) {
                continue;  // bound to a scope outside this query's chain
            }
            const std::size_t level =
                static_cast<std::size_t>(std::distance(scopes.begin(), level_it));

            RejectedEvidence reject;
            reject.entry = &assignment_entry;
            reject.via_subject = subject;

            if (!assignment_entry.active) {
                reject.code = "assignment_retired";
                reject.detail = "assignment '" + assignment_entry.assignment.id.str() +
                                "' was retired: " +
                                (assignment_entry.retirement_reason.empty()
                                     ? std::string("no reason recorded")
                                     : assignment_entry.retirement_reason);
                rejected.push_back(std::move(reject));
                continue;
            }

            const auto authority =
                image.authority.find({assignment_entry.provenance.publisher,
                                      assignment_entry.provenance.boot});
            if (authority == image.authority.end() ||
                authority->second.state != AuthorityState::Granted) {
                reject.code = "publisher_incarnation_fenced";
                reject.authority_related = true;
                reject.detail = "assignment '" + assignment_entry.assignment.id.str() +
                                "' was published by publisher '" +
                                assignment_entry.provenance.publisher.str() + "' incarnation " +
                                assignment_entry.provenance.boot.hex() +
                                " which no longer holds authority";
                rejected.push_back(std::move(reject));
                continue;
            }
            if (assignment_entry.provenance.epoch != image.epoch) {
                reject.code = "epoch_superseded";
                reject.authority_related = true;
                reject.detail = "assignment '" + assignment_entry.assignment.id.str() +
                                "' was published under epoch " +
                                std::to_string(assignment_entry.provenance.epoch.value) +
                                " and the fabric is at epoch " +
                                std::to_string(image.epoch.value);
                rejected.push_back(std::move(reject));
                continue;
            }


            const auto subject_node = image.subjects.find(assignment_entry.assignment.subject);
            if (subject_node == image.subjects.end() ||
                subject_node->second.definition.generation !=
                    assignment_entry.assignment.subject_generation) {
                reject.code = "subject_generation_stale";
                reject.detail = "assignment '" + assignment_entry.assignment.id.str() +
                                "' binds subject '" +
                                assignment_entry.assignment.subject.str() + "' generation " +
                                std::to_string(assignment_entry.assignment.subject_generation.value) +
                                " which has been superseded";
                rejected.push_back(std::move(reject));
                continue;
            }
            const auto scope_node_for_assignment =
                image.scopes.find(assignment_entry.assignment.scope);
            if (scope_node_for_assignment == image.scopes.end() ||
                scope_node_for_assignment->second.definition.generation !=
                    assignment_entry.assignment.scope_generation) {
                reject.code = "scope_generation_stale";
                reject.detail = "assignment '" + assignment_entry.assignment.id.str() +
                                "' binds scope '" + assignment_entry.assignment.scope.str() +
                                "' generation " +
                                std::to_string(assignment_entry.assignment.scope_generation.value) +
                                " which has been superseded";
                rejected.push_back(std::move(reject));
                continue;
            }
            const auto class_node = image.classes.find(assignment_entry.assignment.cls);
            if (class_node == image.classes.end()) {
                reject.code = "class_not_registered";
                reject.detail = "assignment '" + assignment_entry.assignment.id.str() +
                                "' names class '" + assignment_entry.assignment.cls.str() +
                                "' which is no longer registered";
                rejected.push_back(std::move(reject));
                continue;
            }
            if (class_node->second.definition.generation !=
                assignment_entry.assignment.class_generation) {
                reject.code = "class_generation_stale";
                reject.detail = "assignment '" + assignment_entry.assignment.id.str() +
                                "' binds class '" + assignment_entry.assignment.cls.str() +
                                "' generation " +
                                std::to_string(assignment_entry.assignment.class_generation.value) +
                                " which has been superseded by generation " +
                                std::to_string(class_node->second.definition.generation.value);
                rejected.push_back(std::move(reject));
                continue;
            }
            if (assignment_entry.assignment.policy.has_value()) {
                const auto policy_node =
                    image.policies.find(*assignment_entry.assignment.policy);
                if (policy_node == image.policies.end() ||
                    policy_node->second.definition.generation !=
                        assignment_entry.assignment.policy_generation) {
                    reject.code = "policy_generation_stale";
                    reject.detail = "assignment '" + assignment_entry.assignment.id.str() +
                                    "' binds policy '" +
                                    assignment_entry.assignment.policy->str() +
                                    "' generation " +
                                    std::to_string(
                                        assignment_entry.assignment.policy_generation.value) +
                                    " which has been superseded";
                    rejected.push_back(std::move(reject));
                    continue;
                }
            }

            const auto visibility = effective_visibility(image, assignment_entry.assignment.scope);
            if (visibility.has_value()) {
                bool visible = false;
                for (const auto& allowed : *visibility) {
                    if (class_implies(image, assignment_entry.assignment.cls, allowed)) {
                        visible = true;
                        break;
                    }
                }
                if (!visible) {
                    reject.code = "class_not_visible";
                    reject.detail = "class '" + assignment_entry.assignment.cls.str() +
                                    "' is not visible in scope '" +
                                    assignment_entry.assignment.scope.str() +
                                    "' under the effective policy";
                    rejected.push_back(std::move(reject));
                    continue;
                }
            }

            Candidate candidate;
            candidate.level = level;
            candidate.entry = &assignment_entry;
            candidate.via_subject = subject;
            candidate.inheritance_distance = distance;
            accepted.push_back(std::move(candidate));
        }
    };

    // Tier 1: evidence declared for the queried subject itself.
    collect_for_subject(query.subject, 0);

    if (accepted.empty()) {
        auto ancestors = subject_ancestors(image, query.subject);
        if (!ancestors.ok()) {
            return rejected_decision(limits, "inheritance_unusable",
                                     ancestors.status().message(), image.epoch,
                                     image.generation);
        }
        for (const auto& ancestor : ancestors.value()) {
            const std::size_t before_accepted = accepted.size();
            const std::size_t before_rejected = rejected.size();
            collect_for_subject(ancestor.first, ancestor.second);
            // The closest ancestor that offered any evidence at all decides the tier: either
            // it supplied the class or it is the reason the inheritance lookup stopped.
            if (accepted.size() > before_accepted || rejected.size() > before_rejected) {
                break;
            }
        }
    }

    // Exception/override filtering: an assignment that names the class it displaces only
    // applies when a strictly broader scope actually offers that class.
    auto displaces_target = [&](const Candidate& candidate) {
        const auto& displaces = candidate.entry->assignment.displaces;
        if (!displaces.has_value()) {
            return true;
        }
        for (const auto& other : accepted) {
            if (other.level > candidate.level && other.entry->assignment.cls == *displaces) {
                return true;
            }
        }
        return false;
    };

    std::vector<Candidate> filtered;
    filtered.reserve(accepted.size());
    for (const auto& candidate : accepted) {
        if (candidate.entry->assignment.kind == AssignmentKind::Exception &&
            !candidate.entry->assignment.displaces.has_value()) {
            RejectedEvidence reject;
            reject.entry = candidate.entry;
            reject.via_subject = candidate.via_subject;
            reject.code = "exception_without_target";
            reject.detail = "assignment '" + candidate.entry->assignment.id.str() +
                            "' is declared as an exception but names no class to displace";
            rejected.push_back(std::move(reject));
            continue;
        }
        if (candidate.entry->assignment.displaces.has_value() && !displaces_target(candidate)) {
            RejectedEvidence reject;
            reject.entry = candidate.entry;
            reject.via_subject = candidate.via_subject;
            reject.code = "exception_target_mismatch";
            reject.detail = "assignment '" + candidate.entry->assignment.id.str() +
                            "' displaces class '" +
                            candidate.entry->assignment.displaces->str() +
                            "' but no valid broader assignment offers that class";
            rejected.push_back(std::move(reject));
            continue;
        }
        filtered.push_back(candidate);
    }
    accepted = std::move(filtered);

    for (const auto& candidate : accepted) {
        builder.push(make_step("candidate.accept", "binding_ok",
                               describe_assignment(candidate.entry->assignment), *candidate.entry,
                               candidate.via_subject));
    }
    for (const auto& item : rejected) {
        builder.push(make_step("candidate.reject", item.code, item.detail, *item.entry,
                               item.via_subject));
    }

    PriorityDecision decision;
    decision.epoch = image.epoch;
    decision.state_generation = image.generation;
    decision.policy_generation = effective_policy_generation;
    decision.scope_generation = query_scope_generation;

    // Every candidate that lost its authority is reported, whichever branch the outcome takes:
    // a caller must be able to see that evidence existed and why it was refused.
    const std::size_t rejected_bound = limits.max_query_steps;
    if (rejected.size() > rejected_bound) {
        rejected.resize(rejected_bound);
    }
    for (const auto& item : rejected) {
        decision.rejected_evidence.push_back(
            make_note(*item.entry, item.via_subject, item.code, item.detail));
    }

    if (accepted.empty()) {
        const DefaultResolution fallback = resolve_unknown_default(image, query.scope);
        const bool any_authority_rejection =
            std::any_of(rejected.begin(), rejected.end(),
                        [](const RejectedEvidence& item) { return item.authority_related; });
        if (!rejected.empty()) {
            decision.outcome = any_authority_rejection ? Outcome::Fenced : Outcome::Stale;
            decision.reason_code =
                any_authority_rejection ? "evidence_fenced" : "evidence_stale";
            decision.reason =
                "the fabric holds " + std::to_string(rejected.size()) +
                " piece(s) of evidence for this subject and scope, and every one of them lost "
                "its authority: " + rejected.front().code;
            decision.resolution = "none";
        } else if (fallback.found && fallback.available) {
            decision.outcome = Outcome::Assigned;
            decision.authoritative = true;
            decision.cls = fallback.cls;
            decision.class_generation = fallback.class_generation;
            decision.precedence = fallback.precedence;
            decision.privileged_class = fallback.privileged;
            decision.reason_code = "policy_declared_default";
            decision.reason = "no assignment exists for subject '" + query.subject.str() +
                              "' in scope '" + query.scope.str() +
                              "'; the policy declared by " + fallback.source +
                              " supplies the default class '" + fallback.cls.str() + "'";
            decision.resolution = "policy_default";
            ExplanationStep step;
            step.stage = "default.apply";
            step.code = "policy_declared_default";
            step.detail = decision.reason;
            step.cls = fallback.cls;
            step.class_generation = fallback.class_generation;
            builder.push(std::move(step));
        } else if (fallback.found) {
            decision.outcome = Outcome::Unknown;
            decision.reason_code = "default_class_unavailable";
            decision.reason = "the policy declares default class '" + fallback.cls.str() +
                              "' for unassigned subjects but that class is not usable in scope '" +
                              query.scope.str() + "'; the fabric does not substitute another class";
            decision.resolution = "none";
        } else {
            decision.outcome = Outcome::Unknown;
            decision.reason_code = "no_authoritative_assignment";
            decision.reason = "no assignment, inheritance or policy default covers subject '" +
                              query.subject.str() + "' in scope '" + query.scope.str() +
                              "'; the fabric reports UNKNOWN rather than assuming a low class";
            decision.resolution = "none";
        }
        ExplanationStep final_step;
        final_step.stage = "decision";
        final_step.code = decision.reason_code;
        final_step.detail = decision.reason;
        builder.push(std::move(final_step));
        decision.chain = std::move(chain);
        decision.digest = compute_decision_digest(decision);
        return decision;
    }

    // ---- choose the deciding level --------------------------------------------------------
    // Normally the narrowest scope with valid evidence decides. A scope that declares itself
    // non-overridable claims that role from every narrower scope, so it is chosen explicitly
    // rather than by accident of iteration order.
    std::size_t narrowest_level = accepted.front().level;
    std::optional<std::size_t> authoritative_level;
    for (const auto& candidate : accepted) {
        narrowest_level = std::min(narrowest_level, candidate.level);
        const auto scope_node_for_level = image.scopes.find(scopes[candidate.level]);
        if (scope_node_for_level != image.scopes.end() &&
            !scope_node_for_level->second.definition.allow_override) {
            if (!authoritative_level.has_value() || candidate.level < *authoritative_level) {
                authoritative_level = candidate.level;
            }
        }
    }
    const std::size_t deciding_level =
        authoritative_level.has_value() ? *authoritative_level : narrowest_level;

    std::vector<const Candidate*> winning;
    std::vector<const Candidate*> superseded;
    for (const auto& candidate : accepted) {
        if (candidate.level == deciding_level) {
            winning.push_back(&candidate);
        } else {
            superseded.push_back(&candidate);
        }
    }

    bool conflict = false;
    for (std::size_t i = 1; i < winning.size(); ++i) {
        if (!(winning[i]->entry->assignment.cls == winning[0]->entry->assignment.cls)) {
            conflict = true;
            break;
        }
    }

    const Candidate* winner = winning.front();
    std::string resolution = "unique";
    bool authoritative = true;

    if (conflict) {
        const ConflictMode mode = effective_conflict_mode(image, scopes[deciding_level]);
        for (const auto* candidate : winning) {
            decision.conflicts.push_back(
                describe_assignment(candidate->entry->assignment) +
                " (subject '" +
                (candidate->via_subject.valid() ? candidate->via_subject.str()
                                                : candidate->entry->assignment.subject.str()) +
                "')");
        }
        const bool deny = query.strict_conflicts || mode.mode == ConflictResolution::Deny;
        if (deny) {
            authoritative = false;
            resolution = query.strict_conflicts ? "denied_by_caller" : "denied_by_" + mode.source;
            winner = nullptr;
        } else if (mode.mode == ConflictResolution::HigherPrecedence) {
            resolution = "higher_precedence_by_" + mode.source;
            for (const auto* candidate : winning) {
                const auto node = image.classes.find(candidate->entry->assignment.cls);
                if (node == image.classes.end()) {
                    continue;
                }
                const auto best = image.classes.find(winner->entry->assignment.cls);
                if (best == image.classes.end() ||
                    node->second.definition.precedence.value >
                        best->second.definition.precedence.value) {
                    winner = candidate;
                }
            }
        } else {
            resolution = "assignment_id_order_by_" + mode.source;
            for (const auto* candidate : winning) {
                if (candidate->entry->assignment.id < winner->entry->assignment.id) {
                    winner = candidate;
                }
            }
        }
        for (const auto* candidate : winning) {
            if (candidate == winner) {
                continue;
            }
            decision.superseded.push_back(
                make_note(*candidate->entry, candidate->via_subject, "conflict_loser",
                          describe_assignment(candidate->entry->assignment) +
                              " lost the deterministic conflict resolution (" + resolution + ")"));
        }
    }

    // ---- outcome ---------------------------------------------------------------------------
    if (conflict) {
        decision.outcome = Outcome::Conflict;
        decision.authoritative = authoritative;
        decision.resolution = resolution;
        if (authoritative) {
            decision.reason_code = "conflict_resolved";
            decision.reason = "contradictory assignments were found at scope '" +
                              scopes[deciding_level].str() +
                              "'; the policy resolved them deterministically (" + resolution + ")";
        } else {
            decision.reason_code = "conflict_unresolved";
            decision.reason = "contradictory assignments were found at scope '" +
                              scopes[deciding_level].str() +
                              "' and the effective conflict policy denies rather than guessing";
        }
    } else {
        decision.authoritative = true;
        decision.resolution = superseded.empty() ? "unique" : "narrower_scope";
        if (!superseded.empty()) {
            decision.outcome = Outcome::Overridden;
            decision.reason_code = "narrower_scope_overrides";
            decision.reason = "assignment '" + winner->entry->assignment.id.str() + "' in scope '" +
                              scopes[deciding_level].str() +
                              "' displaces broader evidence in the enclosing scopes";
        } else if (winner->inheritance_distance > 0) {
            decision.outcome = Outcome::Inherited;
            decision.reason_code = "inherited_from_ancestor";
            decision.reason = "subject '" + query.subject.str() +
                              "' holds no assignment of its own; the class comes from ancestor '" +
                              winner->via_subject.str() + "' at inheritance distance " +
                              std::to_string(winner->inheritance_distance);
        } else {
            decision.outcome = Outcome::Assigned;
            decision.reason_code = "explicit_assignment";
            decision.reason = "assignment '" + winner->entry->assignment.id.str() +
                              "' names subject '" + query.subject.str() + "' directly in scope '" +
                              scopes[deciding_level].str() + "'";
        }
    }

    if (winner != nullptr && decision.authoritative) {
        const auto node = image.classes.find(winner->entry->assignment.cls);
        if (node == image.classes.end()) {
            decision.authoritative = false;
            decision.outcome = Outcome::Rejected;
            decision.reason_code = "class_disappeared";
            decision.reason = "the winning assignment names a class that is not registered";
        } else {
            decision.cls = winner->entry->assignment.cls;
            decision.class_generation = node->second.definition.generation;
            decision.precedence = node->second.definition.precedence;
            decision.privileged_class = node->second.definition.privileged;
        }
    }

    for (const auto* candidate : superseded) {
        const bool narrower = candidate->level < deciding_level;
        decision.superseded.push_back(make_note(
            *candidate->entry, candidate->via_subject,
            narrower ? "displaced_by_authoritative_scope" : "broader_scope_displaced",
            describe_assignment(candidate->entry->assignment) +
                (narrower ? " was displaced because scope '" + scopes[deciding_level].str() +
                                "' declares itself non-overridable"
                          : " was displaced by narrower evidence in scope '" +
                                scopes[deciding_level].str() + "'")));
    }

    if (winner != nullptr && decision.authoritative) {
        ExplanationStep final_step;
        final_step.stage = "decision";
        final_step.code = decision.reason_code;
        final_step.detail = decision.reason;
        final_step.assignment = winner->entry->assignment.id;
        final_step.assignment_generation = winner->entry->assignment.generation;
        final_step.cls = decision.cls;
        final_step.class_generation = decision.class_generation;
        final_step.scope = winner->entry->assignment.scope;
        final_step.provenance = winner->entry->provenance;
        builder.push(std::move(final_step));
    } else {
        ExplanationStep final_step;
        final_step.stage = "decision";
        final_step.code = decision.reason_code;
        final_step.detail = decision.reason;
        builder.push(std::move(final_step));
    }

    decision.chain = std::move(chain);
    decision.digest = compute_decision_digest(decision);
    return decision;
}

}  // namespace pf::detail
