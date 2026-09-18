// Priority Fabric -- authoritative network priority classes.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "state.hpp"

#include <algorithm>
#include <cstddef>
#include <limits>
#include <set>
#include <utility>

#include "priority_fabric/checked.hpp"
#include "priority_fabric/codec.hpp"
#include "priority_fabric/model_codec.hpp"
#include "priority_fabric/text.hpp"
#include "priority_fabric/version.hpp"

namespace pf::detail {
namespace {

constexpr std::uint32_t kStateMagic = 0x31544650u;  // "PFT1"

void encode_blob(Encoder& encoder, const std::string& blob) {
    encoder.u32(static_cast<std::uint32_t>(blob.size()));
    encoder.raw(blob.data(), blob.size());
}

Result<std::string> decode_blob(Decoder& decoder, std::uint32_t bound) {
    return decoder.str(bound);
}

/// Ordering helper: the lexicographically smallest id in a range of pairs.
template <typename Map>
std::optional<typename Map::key_type> smallest_key(const Map& map) {
    if (map.empty()) {
        return std::nullopt;
    }
    return map.begin()->first;
}

/// An entity is only an identical republication when the same incarnation republishes it
/// under the same epoch. The same content from a new incarnation refreshes the authority
/// binding, which is a real state change even though the definition is unchanged.
bool same_authority_binding(const Provenance& provenance, const Mutation& mutation) {
    return provenance.publisher == mutation.publisher && provenance.boot == mutation.boot &&
           provenance.epoch == mutation.epoch;
}

bool same_class_content(const PriorityClassDef& a, const PriorityClassDef& b) {
    return a.id == b.id && a.precedence == b.precedence && a.kind == b.kind &&
           a.inherits_from == b.inherits_from && a.description == b.description &&
           a.privileged == b.privileged;
}

bool same_scope_content(const PolicyScopeDef& a, const PolicyScopeDef& b) {
    return a.id == b.id && a.parent == b.parent &&
           a.conflict_resolution == b.conflict_resolution &&
           a.unknown_default == b.unknown_default && a.allow_override == b.allow_override &&
           a.description == b.description;
}

bool same_policy_content(const PolicyDef& a, const PolicyDef& b) {
    return a.id == b.id && a.scope == b.scope && a.visible_classes == b.visible_classes &&
           a.conflict_resolution == b.conflict_resolution &&
           a.unknown_default == b.unknown_default &&
           a.require_policy_for_assignment == b.require_policy_for_assignment &&
           a.description == b.description;
}

bool same_subject_content(const SubjectDef& a, const SubjectDef& b) {
    return a.id == b.id && a.inherits_from == b.inherits_from && a.description == b.description;
}

bool same_assignment_content(const PriorityAssignment& a, const PriorityAssignment& b) {
    return a.id == b.id && a.subject == b.subject && a.subject_generation == b.subject_generation &&
           a.scope == b.scope && a.scope_generation == b.scope_generation && a.cls == b.cls &&
           a.class_generation == b.class_generation && a.kind == b.kind &&
           a.displaces == b.displaces && a.policy == b.policy &&
           a.policy_generation == b.policy_generation && a.note == b.note;
}

/// True when p target is reachable from p start by following \p next edges, without
/// ever traversing the edges of \p excluded.
template <typename Id, typename NextFn>
bool reaches(const Id& start, const Id& target, const Id& excluded, std::size_t bound,
             NextFn next) {
    std::vector<Id> stack;
    std::set<Id> visited;
    stack.push_back(start);
    std::size_t steps = 0;
    while (!stack.empty()) {
        if (++steps > bound) {
            return false;
        }
        const Id current = stack.back();
        stack.pop_back();
        if (current == target) {
            return true;
        }
        if (current == excluded) {
            continue;
        }
        if (!visited.insert(current).second) {
            continue;
        }
        for (const Id& parent : next(current)) {
            stack.push_back(parent);
        }
    }
    return false;
}

}  // namespace

const char* to_string(MutationOp op) noexcept {
    switch (op) {
        case MutationOp::DefineClass: return "define_class";
        case MutationOp::DefineScope: return "define_scope";
        case MutationOp::DefinePolicy: return "define_policy";
        case MutationOp::DefineSubject: return "define_subject";
        case MutationOp::Assign: return "assign";
        case MutationOp::RetireAssignment: return "retire_assignment";
        case MutationOp::GrantAuthority: return "grant_authority";
        case MutationOp::FenceAuthority: return "fence_authority";
        case MutationOp::AdvanceEpoch: return "advance_epoch";
    }
    return "unknown";
}

// ---------------------------------------------------------------------------------------
// Structural helpers
// ---------------------------------------------------------------------------------------

bool class_implies(const StateImage& image, const PriorityClassId& candidate,
                   const PriorityClassId& required) {
    if (candidate == required) {
        return true;
    }
    std::vector<PriorityClassId> stack;
    std::set<PriorityClassId> visited;
    stack.push_back(candidate);
    std::size_t steps = 0;
    const std::size_t bound =
        (static_cast<std::size_t>(image.limits.max_classes) + 1u) *
        (static_cast<std::size_t>(image.limits.max_inheritance_depth) + 1u);
    while (!stack.empty()) {
        if (++steps > bound) {
            return false;
        }
        const PriorityClassId current = stack.back();
        stack.pop_back();
        if (current == required) {
            return true;
        }
        if (!visited.insert(current).second) {
            continue;
        }
        const auto it = image.classes.find(current);
        if (it == image.classes.end()) {
            continue;
        }
        for (const auto& parent : it->second.definition.inherits_from) {
            stack.push_back(parent);
        }
    }
    return false;
}

int class_depth(const StateImage& image, const PriorityClassId& id) {
    // Iterative post-order longest-path over the inheritance DAG.
    std::map<PriorityClassId, int> depth;
    std::set<PriorityClassId> in_progress;
    std::vector<std::pair<PriorityClassId, bool>> stack;
    stack.emplace_back(id, false);
    while (!stack.empty()) {
        auto [current, expanded] = stack.back();
        stack.pop_back();
        if (expanded) {
            in_progress.erase(current);
            int best = 0;
            const auto it = image.classes.find(current);
            if (it == image.classes.end()) {
                depth[current] = -1;
                continue;
            }
            for (const auto& parent : it->second.definition.inherits_from) {
                const auto found = depth.find(parent);
                if (found == depth.end() || found->second < 0) {
                    best = -1;
                    break;
                }
                best = std::max(best, found->second + 1);
            }
            if (best >= 0 && static_cast<std::uint32_t>(best) > image.limits.max_inheritance_depth) {
                best = -1;
            }
            depth[current] = best;
            continue;
        }
        const auto known = depth.find(current);
        if (known != depth.end()) {
            continue;
        }
        if (!in_progress.insert(current).second) {
            depth[current] = -1;  // cycle
            continue;
        }
        stack.emplace_back(current, true);
        const auto it = image.classes.find(current);
        if (it == image.classes.end()) {
            continue;
        }
        for (const auto& parent : it->second.definition.inherits_from) {
            if (depth.find(parent) == depth.end()) {
                stack.emplace_back(parent, false);
            }
        }
    }
    const auto found = depth.find(id);
    return found == depth.end() ? -1 : found->second;
}

int scope_depth(const StateImage& image, const PolicyScopeId& id) {
    int depth = 0;
    PolicyScopeId current = id;
    std::set<PolicyScopeId> visited;
    while (true) {
        if (!visited.insert(current).second) {
            return -1;
        }
        const auto it = image.scopes.find(current);
        if (it == image.scopes.end()) {
            return -1;
        }
        if (!it->second.definition.parent.has_value()) {
            return depth;
        }
        ++depth;
        if (static_cast<std::uint32_t>(depth) > image.limits.max_scope_depth) {
            return -1;
        }
        current = *it->second.definition.parent;
    }
}

VoidResult validate_inheritance(const StateImage& image, const PriorityClassId& self,
                                const std::vector<PriorityClassId>& parents) {
    if (parents.size() > image.limits.max_inherits_from) {
        return make_error(StatusCode::LimitExceeded,
                          "class declares " + std::to_string(parents.size()) +
                              " parents, limit is " +
                              std::to_string(image.limits.max_inherits_from));
    }
    std::set<PriorityClassId> unique;
    for (const auto& parent : parents) {
        if (!parent.valid()) {
            return make_error(StatusCode::MalformedId, "inheritance list holds an empty id");
        }
        if (parent == self) {
            return make_error(StatusCode::CycleDetected,
                              "class '" + self.str() + "' cannot inherit from itself");
        }
        if (!unique.insert(parent).second) {
            return make_error(StatusCode::InvalidArgument,
                              "class '" + self.str() + "' lists parent '" + parent.str() +
                                  "' more than once");
        }
        if (image.classes.find(parent) == image.classes.end()) {
            return make_error(StatusCode::NotFound, "parent class '" + parent.str() +
                                                        "' is not defined in this fabric state");
        }
    }

    // Adding self -> parent creates a cycle exactly when self is reachable from parent
    // through the graph that does not use self's own existing edges.
    for (const auto& parent : parents) {
        const bool cyclic = reaches<PriorityClassId>(
            parent, self, self,
            (static_cast<std::size_t>(image.limits.max_classes) + 1u) *
                (static_cast<std::size_t>(image.limits.max_inheritance_depth) + 1u),
            [&image](const PriorityClassId& node) {
                const auto it = image.classes.find(node);
                if (it == image.classes.end()) {
                    return std::vector<PriorityClassId>{};
                }
                return it->second.definition.inherits_from;
            });
        if (cyclic) {
            return make_error(StatusCode::CycleDetected,
                              "inheriting '" + parent.str() + "' from '" + self.str() +
                                  "' would create a precedence cycle");
        }
    }

    for (const auto& parent : parents) {
        const int parent_depth = class_depth(image, parent);
        if (parent_depth < 0) {
            return make_error(StatusCode::Degraded,
                              "class '" + parent.str() +
                                  "' already sits on a cyclic or over-deep inheritance chain");
        }
        if (static_cast<std::uint32_t>(parent_depth + 1) > image.limits.max_inheritance_depth) {
            return make_error(StatusCode::LimitExceeded,
                              "inheriting '" + parent.str() + "' would exceed the inheritance "
                              "depth limit of " +
                                  std::to_string(image.limits.max_inheritance_depth));
        }
    }
    return VoidResult{};
}

VoidResult validate_subject_inheritance(const StateImage& image, const SubjectId& self,
                                        const std::vector<SubjectId>& parents) {
    if (parents.size() > image.limits.max_inherits_from) {
        return make_error(StatusCode::LimitExceeded,
                          "subject declares " + std::to_string(parents.size()) +
                              " parents, limit is " +
                              std::to_string(image.limits.max_inherits_from));
    }
    std::set<SubjectId> unique;
    for (const auto& parent : parents) {
        if (!parent.valid()) {
            return make_error(StatusCode::MalformedId, "subject inheritance list holds an empty id");
        }
        if (parent == self) {
            return make_error(StatusCode::CycleDetected,
                              "subject '" + self.str() + "' cannot inherit from itself");
        }
        if (!unique.insert(parent).second) {
            return make_error(StatusCode::InvalidArgument,
                              "subject '" + self.str() + "' lists parent '" + parent.str() +
                                  "' more than once");
        }
        if (image.subjects.find(parent) == image.subjects.end()) {
            return make_error(StatusCode::NotFound, "parent subject '" + parent.str() +
                                                        "' is not defined in this fabric state");
        }
    }
    for (const auto& parent : parents) {
        const bool cyclic = reaches<SubjectId>(
            parent, self, self,
            (static_cast<std::size_t>(image.limits.max_subjects) + 1u) *
                (static_cast<std::size_t>(image.limits.max_inheritance_depth) + 1u),
            [&image](const SubjectId& node) {
                const auto it = image.subjects.find(node);
                if (it == image.subjects.end()) {
                    return std::vector<SubjectId>{};
                }
                return it->second.definition.inherits_from;
            });
        if (cyclic) {
            return make_error(StatusCode::CycleDetected,
                              "inheriting '" + parent.str() + "' from '" + self.str() +
                                  "' would create an inheritance cycle");
        }
    }
    return VoidResult{};
}

Result<std::vector<PolicyScopeId>> scope_chain(const StateImage& image,
                                              const PolicyScopeId& scope) {
    std::vector<PolicyScopeId> chain;
    PolicyScopeId current = scope;
    std::set<PolicyScopeId> visited;
    while (true) {
        if (!visited.insert(current).second) {
            return make_error(StatusCode::Degraded,
                              "scope chain of '" + scope.str() + "' is cyclic");
        }
        const auto it = image.scopes.find(current);
        if (it == image.scopes.end()) {
            return make_error(StatusCode::NotFound, "scope '" + current.str() + "' is not defined");
        }
        chain.push_back(current);
        if (chain.size() > image.limits.max_scope_depth) {
            return make_error(StatusCode::LimitExceeded,
                              "scope chain of '" + scope.str() + "' is longer than " +
                                  std::to_string(image.limits.max_scope_depth));
        }
        if (!it->second.definition.parent.has_value()) {
            break;
        }
        current = *it->second.definition.parent;
    }
    return chain;
}

Result<std::vector<std::pair<SubjectId, std::uint32_t>>> subject_ancestors(
    const StateImage& image, const SubjectId& id) {
    std::vector<std::pair<SubjectId, std::uint32_t>> out;
    std::set<SubjectId> seen;
    seen.insert(id);
    std::vector<std::pair<SubjectId, std::uint32_t>> frontier;
    const auto root = image.subjects.find(id);
    if (root == image.subjects.end()) {
        return make_error(StatusCode::NotFound, "subject '" + id.str() + "' is not defined");
    }
    for (const auto& parent : root->second.definition.inherits_from) {
        frontier.emplace_back(parent, 1u);
    }
    while (!frontier.empty()) {
        std::vector<std::pair<SubjectId, std::uint32_t>> next;
        for (const auto& entry : frontier) {
            if (!seen.insert(entry.first).second) {
                continue;
            }
            if (entry.second > image.limits.max_inheritance_depth) {
                return make_error(StatusCode::LimitExceeded,
                                  "subject '" + id.str() + "' has an inheritance chain deeper than " +
                                      std::to_string(image.limits.max_inheritance_depth));
            }
            const auto it = image.subjects.find(entry.first);
            if (it == image.subjects.end()) {
                return make_error(StatusCode::Degraded,
                                  "subject '" + entry.first.str() +
                                      "' is referenced but not defined");
            }
            out.push_back(entry);
            if (out.size() > image.limits.max_query_steps) {
                return make_error(StatusCode::LimitExceeded,
                                  "subject '" + id.str() + "' has more than " +
                                      std::to_string(image.limits.max_query_steps) + " ancestors");
            }
            for (const auto& grand : it->second.definition.inherits_from) {
                next.emplace_back(grand, entry.second + 1u);
            }
        }
        frontier = std::move(next);
    }
    std::sort(out.begin(), out.end(), [](const auto& a, const auto& b) {
        if (a.second != b.second) {
            return a.second < b.second;
        }
        return a.first < b.first;
    });
    return out;
}

std::optional<PolicyId> effective_policy(const StateImage& image, const PolicyScopeId& scope) {
    auto chain = scope_chain(image, scope);
    if (!chain.ok()) {
        return std::nullopt;
    }
    for (const auto& level : chain.value()) {
        for (const auto& entry : image.policies) {
            if (entry.second.definition.scope == level) {
                return entry.first;
            }
        }
    }
    return std::nullopt;
}

std::optional<std::vector<PriorityClassId>> effective_visibility(const StateImage& image,
                                                                 const PolicyScopeId& scope) {
    auto chain = scope_chain(image, scope);
    if (!chain.ok()) {
        return std::nullopt;
    }
    for (const auto& level : chain.value()) {
        for (const auto& entry : image.policies) {
            if (entry.second.definition.scope == level &&
                !entry.second.definition.visible_classes.empty()) {
                return entry.second.definition.visible_classes;
            }
        }
    }
    return std::nullopt;
}

void append_audit(StateImage& image, AuditEntry entry, const Limits& limits) {
    if (limits.max_audit_entries == 0) {
        return;
    }
    if (image.audit.size() >= limits.max_audit_entries) {
        const std::size_t drop = image.audit.size() - limits.max_audit_entries + 1;
        image.audit.erase(image.audit.begin(),
                          image.audit.begin() + static_cast<std::ptrdiff_t>(drop));
    }
    image.audit.push_back(std::move(entry));
}

Digest compute_decision_digest(const PriorityDecision& decision) {
    PriorityDecision copy = decision;
    copy.digest = Digest::zero();
    const std::string encoded = encode_decision(copy);
    return Sha256::hash(encoded);
}

// ---------------------------------------------------------------------------------------
// State encoding
// ---------------------------------------------------------------------------------------

std::string encode_state(const StateImage& image) {
    Encoder encoder;
    encoder.u32(kStateMagic);
    encoder.u16(static_cast<std::uint16_t>(PRIORITY_FABRIC_FORMAT_VERSION));
    encoder.u64(image.epoch.value);
    encoder.u64(image.generation.value);
    encoder.u64(image.last_sequence);
    encoder.u64(image.next_fencing_token);
    encoder.u64(image.next_audit_sequence);
    encoder.u8(static_cast<std::uint8_t>(image.health));
    encoder.str(image.health_detail);

    encoder.u32(static_cast<std::uint32_t>(image.classes.size()));
    for (const auto& entry : image.classes) {
        encode_blob(encoder, encode_class_definition(entry.second.definition));
        encode_blob(encoder, encode_provenance(entry.second.provenance));
    }
    encoder.u32(static_cast<std::uint32_t>(image.scopes.size()));
    for (const auto& entry : image.scopes) {
        encode_blob(encoder, encode_scope_definition(entry.second.definition));
        encode_blob(encoder, encode_provenance(entry.second.provenance));
    }
    encoder.u32(static_cast<std::uint32_t>(image.policies.size()));
    for (const auto& entry : image.policies) {
        encode_blob(encoder, encode_policy_definition(entry.second.definition));
        encode_blob(encoder, encode_provenance(entry.second.provenance));
    }
    encoder.u32(static_cast<std::uint32_t>(image.subjects.size()));
    for (const auto& entry : image.subjects) {
        encode_blob(encoder, encode_subject_definition(entry.second.definition));
        encode_blob(encoder, encode_provenance(entry.second.provenance));
    }
    encoder.u32(static_cast<std::uint32_t>(image.assignments.size()));
    for (const auto& entry : image.assignments) {
        encode_blob(encoder, encode_assignment(entry.second.assignment));
        encode_blob(encoder, encode_provenance(entry.second.provenance));
        encoder.boolean(entry.second.active);
        encoder.str(entry.second.retirement_reason);
        encode_blob(encoder, encode_provenance(entry.second.retired_by));
    }
    encoder.u32(static_cast<std::uint32_t>(image.authority.size()));
    for (const auto& entry : image.authority) {
        encoder.str(entry.second.publisher.str());
        encoder.raw(entry.second.boot.bytes.data(), entry.second.boot.bytes.size());
        encoder.u64(entry.second.epoch.value);
        encoder.u64(entry.second.token.value);
        encoder.u8(static_cast<std::uint8_t>(entry.second.state));
        encode_blob(encoder, encode_provenance(entry.second.provenance));
    }
    encoder.u32(static_cast<std::uint32_t>(image.audit.size()));
    for (const auto& entry : image.audit) {
        encode_blob(encoder, encode_audit_entry(entry));
    }
    return encoder.take();
}

Result<StateImage> decode_state(const std::string& payload, const Limits& limits) {
    Decoder decoder(payload.data(), payload.size(), limits);
    StateImage image;
    image.limits = limits;

    auto magic = decoder.u32();
    if (!magic.ok()) {
        return magic.status();
    }
    if (magic.value() != kStateMagic) {
        return make_error(StatusCode::Corrupt, "state image has a wrong magic value");
    }
    auto format = decoder.u16();
    if (!format.ok()) {
        return format.status();
    }
    if (format.value() != PRIORITY_FABRIC_FORMAT_VERSION) {
        return make_error(StatusCode::Unsupported,
                          "state image declares format version " +
                              std::to_string(format.value()) + ", this build implements " +
                              std::to_string(PRIORITY_FABRIC_FORMAT_VERSION));
    }
    auto epoch = decoder.u64();
    if (!epoch.ok()) {
        return epoch.status();
    }
    image.epoch = FabricEpoch{epoch.value()};
    auto generation = decoder.u64();
    if (!generation.ok()) {
        return generation.status();
    }
    image.generation = Generation{generation.value()};
    auto last_sequence = decoder.u64();
    if (!last_sequence.ok()) {
        return last_sequence.status();
    }
    image.last_sequence = last_sequence.value();
    auto next_token = decoder.u64();
    if (!next_token.ok()) {
        return next_token.status();
    }
    image.next_fencing_token = next_token.value();
    auto next_audit = decoder.u64();
    if (!next_audit.ok()) {
        return next_audit.status();
    }
    image.next_audit_sequence = next_audit.value();
    auto health = decoder.u8();
    if (!health.ok()) {
        return health.status();
    }
    if (health.value() > static_cast<std::uint8_t>(Health::Degraded)) {
        return make_error(StatusCode::Corrupt, "state image carries an unknown health value");
    }
    image.health = static_cast<Health>(health.value());
    auto health_detail = decoder.str(1024);
    if (!health_detail.ok()) {
        return health_detail.status();
    }
    image.health_detail = std::move(health_detail.value());

    auto read_entity_count = [&decoder, &limits](std::uint32_t bound,
                                                 const char* what) -> Result<std::uint32_t> {
        auto count = decoder.u32();
        if (!count.ok()) {
            return count.status();
        }
        if (count.value() > bound) {
            return make_error(StatusCode::LimitExceeded,
                              std::string("state image declares ") + std::to_string(count.value()) +
                                  " " + what + ", limit is " + std::to_string(bound));
        }
        return count.value();
    };

    auto class_count = read_entity_count(limits.max_classes, "classes");
    if (!class_count.ok()) {
        return class_count.status();
    }
    for (std::uint32_t i = 0; i < class_count.value(); ++i) {
        auto definition_blob = decode_blob(decoder, limits.max_record_payload);
        if (!definition_blob.ok()) {
            return definition_blob.status();
        }
        auto definition = decode_class_definition(definition_blob.value(), limits);
        if (!definition.ok()) {
            return definition.status();
        }
        auto provenance_blob = decode_blob(decoder, limits.max_record_payload);
        if (!provenance_blob.ok()) {
            return provenance_blob.status();
        }
        Decoder provenance_decoder(provenance_blob.value().data(), provenance_blob.value().size(),
                                   limits);
        auto provenance = decode_provenance(provenance_decoder);
        if (!provenance.ok()) {
            return provenance.status();
        }
        ClassEntry entry;
        entry.definition = std::move(definition.value());
        entry.provenance = std::move(provenance.value());
        image.classes.emplace(entry.definition.id, std::move(entry));
    }

    auto scope_count = read_entity_count(limits.max_scopes, "scopes");
    if (!scope_count.ok()) {
        return scope_count.status();
    }
    for (std::uint32_t i = 0; i < scope_count.value(); ++i) {
        auto definition_blob = decode_blob(decoder, limits.max_record_payload);
        if (!definition_blob.ok()) {
            return definition_blob.status();
        }
        auto definition = decode_scope_definition(definition_blob.value(), limits);
        if (!definition.ok()) {
            return definition.status();
        }
        auto provenance_blob = decode_blob(decoder, limits.max_record_payload);
        if (!provenance_blob.ok()) {
            return provenance_blob.status();
        }
        Decoder provenance_decoder(provenance_blob.value().data(), provenance_blob.value().size(),
                                   limits);
        auto provenance = decode_provenance(provenance_decoder);
        if (!provenance.ok()) {
            return provenance.status();
        }
        ScopeEntry entry;
        entry.definition = std::move(definition.value());
        entry.provenance = std::move(provenance.value());
        image.scopes.emplace(entry.definition.id, std::move(entry));
    }

    auto policy_count = read_entity_count(limits.max_policies, "policies");
    if (!policy_count.ok()) {
        return policy_count.status();
    }
    for (std::uint32_t i = 0; i < policy_count.value(); ++i) {
        auto definition_blob = decode_blob(decoder, limits.max_record_payload);
        if (!definition_blob.ok()) {
            return definition_blob.status();
        }
        auto definition = decode_policy_definition(definition_blob.value(), limits);
        if (!definition.ok()) {
            return definition.status();
        }
        auto provenance_blob = decode_blob(decoder, limits.max_record_payload);
        if (!provenance_blob.ok()) {
            return provenance_blob.status();
        }
        Decoder provenance_decoder(provenance_blob.value().data(), provenance_blob.value().size(),
                                   limits);
        auto provenance = decode_provenance(provenance_decoder);
        if (!provenance.ok()) {
            return provenance.status();
        }
        PolicyEntry entry;
        entry.definition = std::move(definition.value());
        entry.provenance = std::move(provenance.value());
        image.policies.emplace(entry.definition.id, std::move(entry));
    }

    auto subject_count = read_entity_count(limits.max_subjects, "subjects");
    if (!subject_count.ok()) {
        return subject_count.status();
    }
    for (std::uint32_t i = 0; i < subject_count.value(); ++i) {
        auto definition_blob = decode_blob(decoder, limits.max_record_payload);
        if (!definition_blob.ok()) {
            return definition_blob.status();
        }
        auto definition = decode_subject_definition(definition_blob.value(), limits);
        if (!definition.ok()) {
            return definition.status();
        }
        auto provenance_blob = decode_blob(decoder, limits.max_record_payload);
        if (!provenance_blob.ok()) {
            return provenance_blob.status();
        }
        Decoder provenance_decoder(provenance_blob.value().data(), provenance_blob.value().size(),
                                   limits);
        auto provenance = decode_provenance(provenance_decoder);
        if (!provenance.ok()) {
            return provenance.status();
        }
        SubjectEntry entry;
        entry.definition = std::move(definition.value());
        entry.provenance = std::move(provenance.value());
        image.subjects.emplace(entry.definition.id, std::move(entry));
    }

    auto assignment_count = read_entity_count(limits.max_assignments, "assignments");
    if (!assignment_count.ok()) {
        return assignment_count.status();
    }
    for (std::uint32_t i = 0; i < assignment_count.value(); ++i) {
        auto definition_blob = decode_blob(decoder, limits.max_record_payload);
        if (!definition_blob.ok()) {
            return definition_blob.status();
        }
        auto definition = decode_assignment(definition_blob.value(), limits);
        if (!definition.ok()) {
            return definition.status();
        }
        auto provenance_blob = decode_blob(decoder, limits.max_record_payload);
        if (!provenance_blob.ok()) {
            return provenance_blob.status();
        }
        Decoder provenance_decoder(provenance_blob.value().data(), provenance_blob.value().size(),
                                   limits);
        auto provenance = decode_provenance(provenance_decoder);
        if (!provenance.ok()) {
            return provenance.status();
        }
        auto active = decoder.boolean();
        if (!active.ok()) {
            return active.status();
        }
        auto retirement_reason = decoder.str(limits.max_note_length);
        if (!retirement_reason.ok()) {
            return retirement_reason.status();
        }
        auto retired_by_blob = decode_blob(decoder, limits.max_record_payload);
        if (!retired_by_blob.ok()) {
            return retired_by_blob.status();
        }
        Decoder retired_decoder(retired_by_blob.value().data(), retired_by_blob.value().size(),
                                limits);
        auto retired_by = decode_provenance(retired_decoder);
        if (!retired_by.ok()) {
            return retired_by.status();
        }
        AssignmentEntry entry;
        entry.assignment = std::move(definition.value());
        entry.provenance = std::move(provenance.value());
        entry.active = active.value();
        entry.retirement_reason = std::move(retirement_reason.value());
        entry.retired_by = std::move(retired_by.value());
        image.assignments.emplace(entry.assignment.id, std::move(entry));
    }

    auto authority_count = read_entity_count(limits.max_publishers, "authority records");
    if (!authority_count.ok()) {
        return authority_count.status();
    }
    for (std::uint32_t i = 0; i < authority_count.value(); ++i) {
        auto publisher = decoder.id<PublisherTag>();
        if (!publisher.ok()) {
            return publisher.status();
        }
        auto boot_bytes = decoder.raw(BootId::kSize);
        if (!boot_bytes.ok()) {
            return boot_bytes.status();
        }
        BootId boot;
        for (std::size_t k = 0; k < BootId::kSize; ++k) {
            boot.bytes[k] = static_cast<std::uint8_t>(boot_bytes.value()[k]);
        }
        auto epoch_value = decoder.u64();
        if (!epoch_value.ok()) {
            return epoch_value.status();
        }
        auto token_value = decoder.u64();
        if (!token_value.ok()) {
            return token_value.status();
        }
        auto state = decoder.u8();
        if (!state.ok()) {
            return state.status();
        }
        if (state.value() > static_cast<std::uint8_t>(AuthorityState::Expired)) {
            return make_error(StatusCode::Corrupt,
                              "authority record carries an unknown lifecycle state");
        }
        auto provenance_blob = decode_blob(decoder, limits.max_record_payload);
        if (!provenance_blob.ok()) {
            return provenance_blob.status();
        }
        Decoder provenance_decoder(provenance_blob.value().data(), provenance_blob.value().size(),
                                   limits);
        auto provenance = decode_provenance(provenance_decoder);
        if (!provenance.ok()) {
            return provenance.status();
        }
        AuthorityEntry entry;
        entry.publisher = std::move(publisher.value());
        entry.boot = boot;
        entry.epoch = FabricEpoch{epoch_value.value()};
        entry.token = FencingToken{token_value.value()};
        entry.state = static_cast<AuthorityState>(state.value());
        entry.provenance = std::move(provenance.value());
        const auto key = std::make_pair(entry.publisher, entry.boot);
        if (image.authority.size() >= limits.max_publishers * limits.max_boots_per_publisher) {
            return make_error(StatusCode::LimitExceeded,
                              "state image holds more authority records than the limit allows");
        }
        image.authority.emplace(key, std::move(entry));
    }

    auto audit_count = read_entity_count(limits.max_audit_entries, "audit entries");
    if (!audit_count.ok()) {
        return audit_count.status();
    }
    for (std::uint32_t i = 0; i < audit_count.value(); ++i) {
        auto entry_blob = decode_blob(decoder, limits.max_record_payload);
        if (!entry_blob.ok()) {
            return entry_blob.status();
        }
        Decoder entry_decoder(entry_blob.value().data(), entry_blob.value().size(), limits);
        auto entry = decode_audit_entry(entry_decoder);
        if (!entry.ok()) {
            return entry.status();
        }
        auto finished_entry = entry_decoder.finish();
        if (!finished_entry.ok()) {
            return finished_entry.status();
        }
        image.audit.push_back(std::move(entry.value()));
    }

    auto finished = decoder.finish();
    if (!finished.ok()) {
        return finished.status();
    }
    rebuild_indexes(image);
    return image;
}

void rebuild_indexes(StateImage& image) {
    image.assignments_by_subject.clear();
    for (const auto& entry : image.assignments) {
        image.assignments_by_subject[entry.second.assignment.subject].push_back(entry.first);
    }
}

Digest state_digest(const StateImage& image) {
    const std::string encoded = encode_state(image);
    return Sha256::hash(encoded);
}

// ---------------------------------------------------------------------------------------
// Mutation encoding
// ---------------------------------------------------------------------------------------

std::string encode_mutation(const Mutation& mutation) {
    Encoder encoder;
    encoder.u16(static_cast<std::uint16_t>(mutation.op));
    encoder.u64(mutation.epoch.value);
    encoder.str(mutation.publisher.str());
    encoder.raw(mutation.boot.bytes.data(), mutation.boot.bytes.size());
    encoder.u64(mutation.token.value);
    encoder.u64(mutation.recorded_at_ms);
    encoder.str(mutation.reason);
    switch (mutation.op) {
        case MutationOp::DefineClass:
            encode_blob(encoder, encode_class_definition(mutation.cls));
            break;
        case MutationOp::DefineScope:
            encode_blob(encoder, encode_scope_definition(mutation.scope));
            break;
        case MutationOp::DefinePolicy:
            encode_blob(encoder, encode_policy_definition(mutation.policy));
            break;
        case MutationOp::DefineSubject:
            encode_blob(encoder, encode_subject_definition(mutation.subject));
            break;
        case MutationOp::Assign:
            encode_blob(encoder, encode_assignment(mutation.assignment));
            break;
        case MutationOp::RetireAssignment:
            encoder.str(mutation.retire_target.str());
            break;
        case MutationOp::GrantAuthority:
        case MutationOp::AdvanceEpoch:
            break;
        case MutationOp::FenceAuthority:
            encoder.str(mutation.fence_publisher.str());
            encoder.raw(mutation.fence_boot.bytes.data(), mutation.fence_boot.bytes.size());
            break;
    }
    encoder.u64(mutation.resulting_generation.value);
    return encoder.take();
}

Result<Mutation> decode_mutation(const std::string& payload, const Limits& limits) {
    Decoder decoder(payload.data(), payload.size(), limits);
    Mutation mutation;
    auto op = decoder.u16();
    if (!op.ok()) {
        return op.status();
    }
    if (op.value() < static_cast<std::uint16_t>(MutationOp::DefineClass) ||
        op.value() > static_cast<std::uint16_t>(MutationOp::AdvanceEpoch)) {
        return make_error(StatusCode::Corrupt,
                          "journal record carries an unknown operation " + std::to_string(op.value()));
    }
    mutation.op = static_cast<MutationOp>(op.value());
    auto epoch = decoder.u64();
    if (!epoch.ok()) {
        return epoch.status();
    }
    mutation.epoch = FabricEpoch{epoch.value()};
    auto publisher = decoder.id<PublisherTag>();
    if (!publisher.ok()) {
        return publisher.status();
    }
    mutation.publisher = std::move(publisher.value());
    auto boot_bytes = decoder.raw(BootId::kSize);
    if (!boot_bytes.ok()) {
        return boot_bytes.status();
    }
    for (std::size_t i = 0; i < BootId::kSize; ++i) {
        mutation.boot.bytes[i] = static_cast<std::uint8_t>(boot_bytes.value()[i]);
    }
    auto token = decoder.u64();
    if (!token.ok()) {
        return token.status();
    }
    mutation.token = FencingToken{token.value()};
    auto recorded_at = decoder.u64();
    if (!recorded_at.ok()) {
        return recorded_at.status();
    }
    mutation.recorded_at_ms = recorded_at.value();
    auto reason = decoder.str(limits.max_note_length);
    if (!reason.ok()) {
        return reason.status();
    }
    mutation.reason = std::move(reason.value());

    switch (mutation.op) {
        case MutationOp::DefineClass: {
            auto blob = decode_blob(decoder, limits.max_record_payload);
            if (!blob.ok()) {
                return blob.status();
            }
            auto definition = decode_class_definition(blob.value(), limits);
            if (!definition.ok()) {
                return definition.status();
            }
            mutation.cls = std::move(definition.value());
            break;
        }
        case MutationOp::DefineScope: {
            auto blob = decode_blob(decoder, limits.max_record_payload);
            if (!blob.ok()) {
                return blob.status();
            }
            auto definition = decode_scope_definition(blob.value(), limits);
            if (!definition.ok()) {
                return definition.status();
            }
            mutation.scope = std::move(definition.value());
            break;
        }
        case MutationOp::DefinePolicy: {
            auto blob = decode_blob(decoder, limits.max_record_payload);
            if (!blob.ok()) {
                return blob.status();
            }
            auto definition = decode_policy_definition(blob.value(), limits);
            if (!definition.ok()) {
                return definition.status();
            }
            mutation.policy = std::move(definition.value());
            break;
        }
        case MutationOp::DefineSubject: {
            auto blob = decode_blob(decoder, limits.max_record_payload);
            if (!blob.ok()) {
                return blob.status();
            }
            auto definition = decode_subject_definition(blob.value(), limits);
            if (!definition.ok()) {
                return definition.status();
            }
            mutation.subject = std::move(definition.value());
            break;
        }
        case MutationOp::Assign: {
            auto blob = decode_blob(decoder, limits.max_record_payload);
            if (!blob.ok()) {
                return blob.status();
            }
            auto definition = decode_assignment(blob.value(), limits);
            if (!definition.ok()) {
                return definition.status();
            }
            mutation.assignment = std::move(definition.value());
            break;
        }
        case MutationOp::RetireAssignment: {
            auto target = decoder.id<PriorityAssignmentTag>();
            if (!target.ok()) {
                return target.status();
            }
            mutation.retire_target = std::move(target.value());
            break;
        }
        case MutationOp::GrantAuthority:
        case MutationOp::AdvanceEpoch:
            break;
        case MutationOp::FenceAuthority: {
            auto fence_publisher = decoder.id<PublisherTag>();
            if (!fence_publisher.ok()) {
                return fence_publisher.status();
            }
            mutation.fence_publisher = std::move(fence_publisher.value());
            auto fence_boot_bytes = decoder.raw(BootId::kSize);
            if (!fence_boot_bytes.ok()) {
                return fence_boot_bytes.status();
            }
            for (std::size_t i = 0; i < BootId::kSize; ++i) {
                mutation.fence_boot.bytes[i] =
                    static_cast<std::uint8_t>(fence_boot_bytes.value()[i]);
            }
            break;
        }
    }
    auto resulting = decoder.u64();
    if (!resulting.ok()) {
        return resulting.status();
    }
    mutation.resulting_generation = Generation{resulting.value()};
    auto finished = decoder.finish();
    if (!finished.ok()) {
        return finished.status();
    }
    return mutation;
}

// ---------------------------------------------------------------------------------------
// Mutation validation
// ---------------------------------------------------------------------------------------

namespace {

VoidResult check_text_bounds(const std::string& text, std::uint32_t limit, const char* what) {
    if (text.size() > limit) {
        return make_error(StatusCode::LimitExceeded,
                          std::string(what) + " is " + std::to_string(text.size()) +
                              " bytes, limit is " + std::to_string(limit));
    }
    if (!is_printable_text(text)) {
        return make_error(StatusCode::InvalidArgument,
                          std::string(what) + " contains control characters");
    }
    return VoidResult{};
}

VoidResult check_precedence_free(const StateImage& image, const PriorityClassId& self,
                                 const PrecedenceRank& rank) {
    for (const auto& entry : image.classes) {
        if (entry.first == self) {
            continue;
        }
        if (entry.second.definition.precedence == rank) {
            return make_error(StatusCode::DuplicatePrecedence,
                              "precedence rank " + std::to_string(rank.value) +
                                  " is already declared by class '" + entry.first.str() +
                                  "'; a rank must name exactly one class");
        }
    }
    return VoidResult{};
}

VoidResult check_authority(const StateImage& image, const Mutation& mutation) {
    if (mutation.publisher.valid() == false || mutation.boot.is_zero()) {
        return make_error(StatusCode::Unauthorized,
                          "mutation carries no publisher incarnation");
    }
    if (!image.epoch.is_established()) {
        return make_error(StatusCode::NotReady,
                          "the fabric epoch has not been established; no authority can exist yet");
    }
    if (mutation.epoch != image.epoch) {
        return make_error(StatusCode::StaleEpoch,
                          "mutation was prepared under epoch " +
                              std::to_string(mutation.epoch.value) + " but the fabric is at epoch " +
                              std::to_string(image.epoch.value));
    }
    const auto key = std::make_pair(mutation.publisher, mutation.boot);
    const auto it = image.authority.find(key);
    if (it == image.authority.end()) {
        return make_error(StatusCode::Unauthorized,
                          "publisher '" + mutation.publisher.str() +
                              "' never held authority in this fabric");
    }
    if (it->second.state != AuthorityState::Granted) {
        return make_error(StatusCode::Fenced,
                          "publisher '" + mutation.publisher.str() + "' incarnation " +
                              mutation.boot.hex() + " is " +
                              to_string(it->second.state));
    }
    if (it->second.epoch != image.epoch) {
        return make_error(StatusCode::StaleEpoch,
                          "authority of publisher '" + mutation.publisher.str() +
                              "' was granted under epoch " +
                              std::to_string(it->second.epoch.value) + ", the fabric is at epoch " +
                              std::to_string(image.epoch.value));
    }
    if (!(it->second.token == mutation.token)) {
        return make_error(StatusCode::Fenced,
                          "fencing token mismatch for publisher '" + mutation.publisher.str() +
                              "' incarnation " + mutation.boot.hex());
    }
    return VoidResult{};
}

}  // namespace

VoidResult validate_mutation(const StateImage& image, const Mutation& mutation, bool replay) {
    // Structural validation is deliberately identical on the commit path and on replay: a
    // record that would not be accepted today must not be resurrected by a restart. Only the
    // authority binding is replay-invariant, and that lives in apply_mutation.
    (void)replay;
    switch (mutation.op) {
        case MutationOp::DefineClass: {
            const auto& definition = mutation.cls;
            if (!definition.id.valid()) {
                return make_error(StatusCode::MalformedId, "class definition has no identifier");
            }
            if (!definition.precedence.is_declared()) {
                return make_error(StatusCode::InvalidArgument,
                                  "class '" + definition.id.str() +
                                      "' declares no precedence rank; priority semantics are never "
                                      "inferred by the fabric");
            }
            if (definition.precedence.value > PrecedenceRank::kMaxRank) {
                return make_error(StatusCode::InvalidArgument,
                                  "class '" + definition.id.str() +
                                      "' declares a precedence rank above the ceiling");
            }
            auto text = check_text_bounds(definition.description, image.limits.max_description_length,
                                          "class description");
            if (!text.ok()) {
                return text.status();
            }
            auto depth = validate_inheritance(image, definition.id, definition.inherits_from);
            if (!depth.ok()) {
                return depth.status();
            }
            const auto existing = image.classes.find(definition.id);
            if (existing == image.classes.end()) {
                if (image.classes.size() >= image.limits.max_classes) {
                    return make_error(StatusCode::LimitExceeded,
                                      "the fabric already holds " +
                                          std::to_string(image.classes.size()) +
                                          " classes, limit is " +
                                          std::to_string(image.limits.max_classes));
                }
            } else if (same_class_content(existing->second.definition, definition)) {
                return VoidResult{};  // idempotent republication
            }
            return check_precedence_free(image, definition.id, definition.precedence);
        }
        case MutationOp::DefineScope: {
            const auto& definition = mutation.scope;
            if (!definition.id.valid()) {
                return make_error(StatusCode::MalformedId, "scope definition has no identifier");
            }
            auto text = check_text_bounds(definition.description, image.limits.max_description_length,
                                          "scope description");
            if (!text.ok()) {
                return text.status();
            }
            if (definition.unknown_default.has_value() &&
                image.classes.find(*definition.unknown_default) == image.classes.end()) {
                return make_error(StatusCode::NotFound,
                                  "scope '" + definition.id.str() + "' names default class '" +
                                      definition.unknown_default->str() +
                                      "' which is not defined in this fabric state");
            }
            if (definition.parent.has_value()) {
                if (*definition.parent == definition.id) {
                    return make_error(StatusCode::CycleDetected,
                                      "scope '" + definition.id.str() +
                                          "' cannot be its own parent");
                }
                if (image.scopes.find(*definition.parent) == image.scopes.end()) {
                    return make_error(StatusCode::NotFound, "parent scope '" +
                                                                definition.parent->str() +
                                                                "' is not defined");
                }
                // Walking up from the proposed parent must terminate before reaching this scope.
                PolicyScopeId cursor = *definition.parent;
                std::set<PolicyScopeId> visited;
                std::uint32_t hops = 0;
                while (true) {
                    if (cursor == definition.id) {
                        return make_error(StatusCode::CycleDetected,
                                          "attaching scope '" + definition.id.str() + "' under '" +
                                              definition.parent->str() +
                                              "' would create a scope cycle");
                    }
                    if (!visited.insert(cursor).second) {
                        return make_error(StatusCode::Degraded,
                                          "the scope tree already contains a cycle at '" +
                                              cursor.str() + "'");
                    }
                    if (++hops > image.limits.max_scope_depth) {
                        return make_error(StatusCode::LimitExceeded,
                                          "scope chain would exceed the depth limit of " +
                                              std::to_string(image.limits.max_scope_depth));
                    }
                    const auto node = image.scopes.find(cursor);
                    if (node == image.scopes.end()) {
                        return make_error(StatusCode::NotFound,
                                          "scope '" + cursor.str() + "' is not defined");
                    }
                    if (!node->second.definition.parent.has_value()) {
                        break;
                    }
                    cursor = *node->second.definition.parent;
                }
            }
            const auto existing = image.scopes.find(definition.id);
            if (existing == image.scopes.end()) {
                if (image.scopes.size() >= image.limits.max_scopes) {
                    return make_error(StatusCode::LimitExceeded,
                                      "the fabric already holds " +
                                          std::to_string(image.scopes.size()) + " scopes, limit is " +
                                          std::to_string(image.limits.max_scopes));
                }
            }
            return VoidResult{};
        }
        case MutationOp::DefinePolicy: {
            const auto& definition = mutation.policy;
            if (!definition.id.valid()) {
                return make_error(StatusCode::MalformedId, "policy definition has no identifier");
            }
            auto text = check_text_bounds(definition.description, image.limits.max_description_length,
                                          "policy description");
            if (!text.ok()) {
                return text.status();
            }
            const auto scope = image.scopes.find(definition.scope);
            if (scope == image.scopes.end()) {
                return make_error(StatusCode::NotFound, "policy '" + definition.id.str() +
                                                            "' names scope '" +
                                                            definition.scope.str() +
                                                            "' which is not defined");
            }
            if (!definition.scope_generation.is_set() ||
                definition.scope_generation != scope->second.definition.generation) {
                return make_error(StatusCode::StaleGeneration,
                                  "policy '" + definition.id.str() + "' is bound to scope '" +
                                      definition.scope.str() + "' generation " +
                                      std::to_string(definition.scope_generation.value) +
                                      " but the scope is at generation " +
                                      std::to_string(scope->second.definition.generation.value));
            }
            if (definition.visible_classes.size() > image.limits.max_policy_classes) {
                return make_error(StatusCode::LimitExceeded,
                                  "policy '" + definition.id.str() + "' lists " +
                                      std::to_string(definition.visible_classes.size()) +
                                      " classes, limit is " +
                                      std::to_string(image.limits.max_policy_classes));
            }
            std::set<PriorityClassId> unique;
            for (const auto& cls : definition.visible_classes) {
                if (!unique.insert(cls).second) {
                    return make_error(StatusCode::InvalidArgument,
                                      "policy '" + definition.id.str() + "' lists class '" +
                                          cls.str() + "' more than once");
                }
                if (image.classes.find(cls) == image.classes.end()) {
                    return make_error(StatusCode::NotFound,
                                      "policy '" + definition.id.str() + "' lists class '" +
                                          cls.str() + "' which is not defined");
                }
            }
            if (definition.unknown_default.has_value() &&
                image.classes.find(*definition.unknown_default) == image.classes.end()) {
                return make_error(StatusCode::NotFound,
                                  "policy '" + definition.id.str() + "' names default class '" +
                                      definition.unknown_default->str() +
                                      "' which is not defined");
            }
            const auto existing = image.policies.find(definition.id);
            if (existing == image.policies.end()) {
                if (image.policies.size() >= image.limits.max_policies) {
                    return make_error(StatusCode::LimitExceeded,
                                      "the fabric already holds " +
                                          std::to_string(image.policies.size()) +
                                          " policies, limit is " +
                                          std::to_string(image.limits.max_policies));
                }
            }
            return VoidResult{};
        }
        case MutationOp::DefineSubject: {
            const auto& definition = mutation.subject;
            if (!definition.id.valid()) {
                return make_error(StatusCode::MalformedId, "subject definition has no identifier");
            }
            auto text = check_text_bounds(definition.description, image.limits.max_description_length,
                                          "subject description");
            if (!text.ok()) {
                return text.status();
            }
            auto inheritance = validate_subject_inheritance(image, definition.id,
                                                            definition.inherits_from);
            if (!inheritance.ok()) {
                return inheritance.status();
            }
            const auto existing = image.subjects.find(definition.id);
            if (existing == image.subjects.end()) {
                if (image.subjects.size() >= image.limits.max_subjects) {
                    return make_error(StatusCode::LimitExceeded,
                                      "the fabric already holds " +
                                          std::to_string(image.subjects.size()) +
                                          " subjects, limit is " +
                                          std::to_string(image.limits.max_subjects));
                }
            }
            return VoidResult{};
        }
        case MutationOp::Assign: {
            const auto& assignment = mutation.assignment;
            if (!assignment.id.valid()) {
                return make_error(StatusCode::MalformedId, "assignment has no identifier");
            }
            auto note = check_text_bounds(assignment.note, image.limits.max_note_length,
                                          "assignment note");
            if (!note.ok()) {
                return note.status();
            }
            const auto subject = image.subjects.find(assignment.subject);
            if (subject == image.subjects.end()) {
                return make_error(StatusCode::NotFound, "assignment '" + assignment.id.str() +
                                                            "' names subject '" +
                                                            assignment.subject.str() +
                                                            "' which is not defined");
            }
            const auto scope = image.scopes.find(assignment.scope);
            if (scope == image.scopes.end()) {
                return make_error(StatusCode::NotFound, "assignment '" + assignment.id.str() +
                                                            "' names scope '" +
                                                            assignment.scope.str() +
                                                            "' which is not defined");
            }
            const auto cls = image.classes.find(assignment.cls);
            if (cls == image.classes.end()) {
                return make_error(StatusCode::NotFound, "assignment '" + assignment.id.str() +
                                                            "' names class '" +
                                                            assignment.cls.str() +
                                                            "' which is not defined");
            }
            if (assignment.subject_generation != subject->second.definition.generation) {
                return make_error(StatusCode::StaleGeneration,
                                  "assignment '" + assignment.id.str() + "' binds subject '" +
                                      assignment.subject.str() + "' generation " +
                                      std::to_string(assignment.subject_generation.value) +
                                      " but the subject is at generation " +
                                      std::to_string(subject->second.definition.generation.value));
            }
            if (assignment.scope_generation != scope->second.definition.generation) {
                return make_error(StatusCode::StaleGeneration,
                                  "assignment '" + assignment.id.str() + "' binds scope '" +
                                      assignment.scope.str() + "' generation " +
                                      std::to_string(assignment.scope_generation.value) +
                                      " but the scope is at generation " +
                                      std::to_string(scope->second.definition.generation.value));
            }
            if (assignment.class_generation != cls->second.definition.generation) {
                return make_error(StatusCode::StaleGeneration,
                                  "assignment '" + assignment.id.str() + "' binds class '" +
                                      assignment.cls.str() + "' generation " +
                                      std::to_string(assignment.class_generation.value) +
                                      " but the class is at generation " +
                                      std::to_string(cls->second.definition.generation.value));
            }
            if (assignment.policy.has_value()) {
                const auto policy = image.policies.find(*assignment.policy);
                if (policy == image.policies.end()) {
                    return make_error(StatusCode::NotFound, "assignment '" + assignment.id.str() +
                                                                "' names policy '" +
                                                                assignment.policy->str() +
                                                                "' which is not defined");
                }
                if (assignment.policy_generation != policy->second.definition.generation) {
                    return make_error(StatusCode::StaleGeneration,
                                      "assignment '" + assignment.id.str() + "' binds policy '" +
                                          assignment.policy->str() + "' generation " +
                                          std::to_string(assignment.policy_generation.value) +
                                          " but the policy is at generation " +
                                          std::to_string(policy->second.definition.generation.value));
                }
            } else if (assignment.policy_generation.is_set()) {
                return make_error(StatusCode::InvalidArgument,
                                  "assignment '" + assignment.id.str() +
                                      "' carries a policy generation without a policy");
            }
            if (assignment.displaces.has_value() &&
                image.classes.find(*assignment.displaces) == image.classes.end()) {
                return make_error(StatusCode::NotFound,
                                  "assignment '" + assignment.id.str() + "' displaces class '" +
                                      assignment.displaces->str() + "' which is not defined");
            }
            const auto visibility = effective_visibility(image, assignment.scope);
            if (visibility.has_value()) {
                bool visible = false;
                for (const auto& allowed : *visibility) {
                    if (class_implies(image, assignment.cls, allowed)) {
                        visible = true;
                        break;
                    }
                }
                if (!visible) {
                    return make_error(StatusCode::Unauthorized,
                                      "class '" + assignment.cls.str() +
                                          "' is not visible in scope '" + assignment.scope.str() +
                                          "'");
                }
            }
            const auto effective = effective_policy(image, assignment.scope);
            if (effective.has_value()) {
                const auto policy_entry = image.policies.find(*effective);
                if (policy_entry != image.policies.end() &&
                    policy_entry->second.definition.require_policy_for_assignment) {
                    if (!assignment.policy.has_value()) {
                        return make_error(StatusCode::Unauthorized,
                                          "scope '" + assignment.scope.str() +
                                              "' requires assignments to name the policy that "
                                              "authorizes them");
                    }
                    if (*assignment.policy != *effective) {
                        return make_error(StatusCode::Unauthorized,
                                          "assignment '" + assignment.id.str() + "' names policy '" +
                                              assignment.policy->str() +
                                              "' but the effective policy of scope '" +
                                              assignment.scope.str() + "' is '" +
                                              effective->str() + "'");
                    }
                }
            }
            const auto existing = image.assignments.find(assignment.id);
            if (existing == image.assignments.end()) {
                if (image.assignments.size() >= image.limits.max_assignments) {
                    return make_error(StatusCode::LimitExceeded,
                                      "the fabric already holds " +
                                          std::to_string(image.assignments.size()) +
                                          " assignments, limit is " +
                                          std::to_string(image.limits.max_assignments));
                }
            } else if (!existing->second.active &&
                       same_assignment_content(existing->second.assignment, assignment)) {
                return VoidResult{};
            }
            return VoidResult{};
        }
        case MutationOp::RetireAssignment: {
            if (!mutation.retire_target.valid()) {
                return make_error(StatusCode::MalformedId, "retirement names no assignment");
            }
            if (image.assignments.find(mutation.retire_target) == image.assignments.end()) {
                return make_error(StatusCode::NotFound, "assignment '" +
                                                            mutation.retire_target.str() +
                                                            "' is not defined");
            }
            auto reason = check_text_bounds(mutation.reason, image.limits.max_note_length,
                                            "retirement reason");
            if (!reason.ok()) {
                return reason.status();
            }
            return VoidResult{};
        }
        case MutationOp::GrantAuthority: {
            if (!mutation.publisher.valid()) {
                return make_error(StatusCode::MalformedId,
                                  "authority request carries no publisher identifier");
            }
            if (mutation.boot.is_zero()) {
                return make_error(StatusCode::InvalidArgument,
                                  "authority request carries an all-zero boot id");
            }
            std::size_t boots = 0;
            for (const auto& entry : image.authority) {
                if (entry.first.first == mutation.publisher) {
                    ++boots;
                    if (entry.first.second == mutation.boot) {
                        if (entry.second.state == AuthorityState::Fenced) {
                            // Fencing an incarnation is final. A process that was fenced must
                            // come back with a fresh boot id, which is what minting a boot id
                            // per process start guarantees.
                            return make_error(StatusCode::Fenced,
                                              "publisher '" + mutation.publisher.str() +
                                                  "' incarnation " + mutation.boot.hex() +
                                                  " was fenced; it cannot be granted authority "
                                                  "again");
                        }
                        if (entry.second.state == AuthorityState::Granted) {
                            return VoidResult{};  // idempotent re-registration
                        }
                    }
                }
            }
            if (boots >= image.limits.max_boots_per_publisher) {
                return make_error(StatusCode::LimitExceeded,
                                  "publisher '" + mutation.publisher.str() + "' already holds " +
                                      std::to_string(boots) +
                                      " incarnations, limit is " +
                                      std::to_string(image.limits.max_boots_per_publisher));
            }
            return VoidResult{};
        }
        case MutationOp::FenceAuthority: {
            if (!mutation.fence_publisher.valid() || mutation.fence_boot.is_zero()) {
                return make_error(StatusCode::InvalidArgument,
                                  "fence request names no publisher incarnation");
            }
            return VoidResult{};
        }
        case MutationOp::AdvanceEpoch: {
            if (!image.epoch.next().has_value()) {
                return make_error(StatusCode::Overflow,
                                  "the fabric epoch counter is exhausted");
            }
            return VoidResult{};
        }
    }
    return make_error(StatusCode::Internal, "unknown mutation operation");
}

// ---------------------------------------------------------------------------------------
// Mutation application
// ---------------------------------------------------------------------------------------

namespace {

bool is_idempotent(const StateImage& image, const Mutation& mutation) {
    switch (mutation.op) {
        case MutationOp::DefineClass: {
            const auto it = image.classes.find(mutation.cls.id);
            return it != image.classes.end() &&
                   same_class_content(it->second.definition, mutation.cls) &&
                   same_authority_binding(it->second.provenance, mutation);
        }
        case MutationOp::DefineScope: {
            const auto it = image.scopes.find(mutation.scope.id);
            return it != image.scopes.end() &&
                   same_scope_content(it->second.definition, mutation.scope) &&
                   same_authority_binding(it->second.provenance, mutation);
        }
        case MutationOp::DefinePolicy: {
            const auto it = image.policies.find(mutation.policy.id);
            return it != image.policies.end() &&
                   same_policy_content(it->second.definition, mutation.policy) &&
                   same_authority_binding(it->second.provenance, mutation);
        }
        case MutationOp::DefineSubject: {
            const auto it = image.subjects.find(mutation.subject.id);
            return it != image.subjects.end() &&
                   same_subject_content(it->second.definition, mutation.subject) &&
                   same_authority_binding(it->second.provenance, mutation);
        }
        case MutationOp::Assign: {
            const auto it = image.assignments.find(mutation.assignment.id);
            return it != image.assignments.end() && it->second.active &&
                   same_assignment_content(it->second.assignment, mutation.assignment) &&
                   same_authority_binding(it->second.provenance, mutation);
        }
        case MutationOp::RetireAssignment: {
            const auto it = image.assignments.find(mutation.retire_target);
            return it != image.assignments.end() && !it->second.active;
        }
        // Authority transitions never take the identical-content fast path. Their outcome
        // depends on the lifecycle state of a publisher incarnation, and that state is exactly
        // what recovery rewrites; deriving a generation from it would make the commit-time plan
        // and the replay disagree. Always moving the generation keeps the two in step.
        case MutationOp::GrantAuthority:
        case MutationOp::FenceAuthority:
            return false;
        case MutationOp::AdvanceEpoch:
            return false;
    }
    return false;
}

Generation bump(const StateImage& image, const Mutation& mutation) {
    switch (mutation.op) {
        case MutationOp::DefineClass: {
            const auto it = image.classes.find(mutation.cls.id);
            if (it == image.classes.end()) {
                return Generation::first();
            }
            return it->second.definition.generation.next().value_or(Generation::unset());
        }
        case MutationOp::DefineScope: {
            const auto it = image.scopes.find(mutation.scope.id);
            if (it == image.scopes.end()) {
                return Generation::first();
            }
            return it->second.definition.generation.next().value_or(Generation::unset());
        }
        case MutationOp::DefinePolicy: {
            const auto it = image.policies.find(mutation.policy.id);
            if (it == image.policies.end()) {
                return Generation::first();
            }
            return it->second.definition.generation.next().value_or(Generation::unset());
        }
        case MutationOp::DefineSubject: {
            const auto it = image.subjects.find(mutation.subject.id);
            if (it == image.subjects.end()) {
                return Generation::first();
            }
            return it->second.definition.generation.next().value_or(Generation::unset());
        }
        case MutationOp::Assign: {
            const auto it = image.assignments.find(mutation.assignment.id);
            if (it == image.assignments.end()) {
                return Generation::first();
            }
            return it->second.assignment.generation.next().value_or(Generation::unset());
        }
        case MutationOp::RetireAssignment: {
            const auto it = image.assignments.find(mutation.retire_target);
            if (it == image.assignments.end()) {
                return Generation::first();
            }
            return it->second.assignment.generation.next().value_or(Generation::unset());
        }
        case MutationOp::GrantAuthority:
            return image.next_fencing_token == 0 ? Generation::unset() : Generation::first();
        case MutationOp::FenceAuthority:
            return Generation::first();
        case MutationOp::AdvanceEpoch:
            return Generation::first();
    }
    return Generation::unset();
}

}  // namespace

bool mutation_is_idempotent(const StateImage& image, const Mutation& mutation) {
    return is_idempotent(image, mutation);
}

Generation current_entity_generation(const StateImage& image, const Mutation& mutation) {
    switch (mutation.op) {
        case MutationOp::DefineClass: {
            const auto it = image.classes.find(mutation.cls.id);
            return it == image.classes.end() ? Generation::unset()
                                             : it->second.definition.generation;
        }
        case MutationOp::DefineScope: {
            const auto it = image.scopes.find(mutation.scope.id);
            return it == image.scopes.end() ? Generation::unset()
                                            : it->second.definition.generation;
        }
        case MutationOp::DefinePolicy: {
            const auto it = image.policies.find(mutation.policy.id);
            return it == image.policies.end() ? Generation::unset()
                                              : it->second.definition.generation;
        }
        case MutationOp::DefineSubject: {
            const auto it = image.subjects.find(mutation.subject.id);
            return it == image.subjects.end() ? Generation::unset()
                                              : it->second.definition.generation;
        }
        case MutationOp::Assign: {
            const auto it = image.assignments.find(mutation.assignment.id);
            return it == image.assignments.end() ? Generation::unset()
                                                 : it->second.assignment.generation;
        }
        case MutationOp::RetireAssignment: {
            const auto it = image.assignments.find(mutation.retire_target);
            return it == image.assignments.end() ? Generation::unset()
                                                 : it->second.assignment.generation;
        }
        case MutationOp::GrantAuthority:
        case MutationOp::FenceAuthority:
        case MutationOp::AdvanceEpoch:
            return image.generation;
    }
    return Generation::unset();
}

bool content_unchanged(const StateImage& image, const Mutation& mutation) {
    switch (mutation.op) {
        case MutationOp::DefineClass: {
            const auto it = image.classes.find(mutation.cls.id);
            return it != image.classes.end() &&
                   same_class_content(it->second.definition, mutation.cls);
        }
        case MutationOp::DefineScope: {
            const auto it = image.scopes.find(mutation.scope.id);
            return it != image.scopes.end() &&
                   same_scope_content(it->second.definition, mutation.scope);
        }
        case MutationOp::DefinePolicy: {
            const auto it = image.policies.find(mutation.policy.id);
            return it != image.policies.end() &&
                   same_policy_content(it->second.definition, mutation.policy);
        }
        case MutationOp::DefineSubject: {
            const auto it = image.subjects.find(mutation.subject.id);
            return it != image.subjects.end() &&
                   same_subject_content(it->second.definition, mutation.subject);
        }
        case MutationOp::Assign: {
            const auto it = image.assignments.find(mutation.assignment.id);
            return it != image.assignments.end() && it->second.active &&
                   same_assignment_content(it->second.assignment, mutation.assignment);
        }
        case MutationOp::RetireAssignment:
        case MutationOp::GrantAuthority:
        case MutationOp::FenceAuthority:
        case MutationOp::AdvanceEpoch:
            return false;
    }
    return false;
}

Generation preview_entity_generation(const StateImage& image, const Mutation& mutation) {
    // Republication of unchanged content never moves the entity's generation: other publishers'
    // evidence is bound to that generation and the meaning of the identifier has not changed.
    // Only the provenance is refreshed, which is why the *state* generation still advances.
    if (is_idempotent(image, mutation) || content_unchanged(image, mutation)) {
        return current_entity_generation(image, mutation);
    }
    return bump(image, mutation);
}

VoidResult apply_mutation(StateImage& image, const Mutation& mutation, bool replay) {
    auto validated = validate_mutation(image, mutation, replay);
    if (!validated.ok()) {
        return validated.status();
    }
    if (!replay && !mutation.system) {
        auto authority = check_authority(image, mutation);
        if (!authority.ok()) {
            return authority.status();
        }
    }

    const bool idempotent = is_idempotent(image, mutation);
    const auto next_generation = image.generation.next();
    if (!idempotent && !next_generation.has_value()) {
        return make_error(StatusCode::Overflow, "the fabric state generation counter is exhausted");
    }
    const Generation expected = idempotent ? image.generation : *next_generation;
    if (mutation.resulting_generation.is_set() &&
        mutation.resulting_generation.value != expected.value) {
        return make_error(StatusCode::Corrupt,
                          "durable record claims generation " +
                              std::to_string(mutation.resulting_generation.value) +
                              " but replay produces " + std::to_string(expected.value));
    }

    Provenance provenance;
    provenance.publisher = mutation.publisher;
    provenance.boot = mutation.boot;
    provenance.epoch = mutation.epoch;
    provenance.token = mutation.token;
    provenance.state_generation = expected;
    provenance.audit_sequence = image.next_audit_sequence;
    provenance.recorded_at_ms = mutation.recorded_at_ms;
    provenance.op = to_string(mutation.op);
    ++image.next_audit_sequence;

    AuditEntry audit;
    audit.sequence = provenance.audit_sequence;
    audit.op = provenance.op;
    audit.result = StatusCode::Ok;
    audit.detail = mutation.reason.empty() ? std::string("accepted") : mutation.reason;
    audit.provenance = provenance;
    audit.state_generation = expected;
    audit.digest = Sha256::hash(encode_mutation(mutation));
    append_audit(image, std::move(audit), image.limits);

    switch (mutation.op) {
        case MutationOp::DefineClass: {
            if (idempotent) {
                return VoidResult{};
            }
            if (content_unchanged(image, mutation)) {
                image.classes.at(mutation.cls.id).provenance = provenance;
                break;
            }
            PriorityClassDef definition = mutation.cls;
            definition.generation = bump(image, mutation);
            if (!definition.generation.is_set()) {
                return make_error(StatusCode::Overflow,
                                  "class generation counter is exhausted for '" +
                                      definition.id.str() + "'");
            }
            ClassEntry entry;
            entry.definition = std::move(definition);
            entry.provenance = provenance;
            image.classes[entry.definition.id] = std::move(entry);
            break;
        }
        case MutationOp::DefineScope: {
            if (idempotent) {
                return VoidResult{};
            }
            if (content_unchanged(image, mutation)) {
                image.scopes.at(mutation.scope.id).provenance = provenance;
                break;
            }
            PolicyScopeDef definition = mutation.scope;
            definition.generation = bump(image, mutation);
            if (!definition.generation.is_set()) {
                return make_error(StatusCode::Overflow,
                                  "scope generation counter is exhausted for '" +
                                      definition.id.str() + "'");
            }
            ScopeEntry entry;
            entry.definition = std::move(definition);
            entry.provenance = provenance;
            image.scopes[entry.definition.id] = std::move(entry);
            break;
        }
        case MutationOp::DefinePolicy: {
            if (idempotent) {
                return VoidResult{};
            }
            if (content_unchanged(image, mutation)) {
                image.policies.at(mutation.policy.id).provenance = provenance;
                break;
            }
            PolicyDef definition = mutation.policy;
            definition.generation = bump(image, mutation);
            if (!definition.generation.is_set()) {
                return make_error(StatusCode::Overflow,
                                  "policy generation counter is exhausted for '" +
                                      definition.id.str() + "'");
            }
            PolicyEntry entry;
            entry.definition = std::move(definition);
            entry.provenance = provenance;
            image.policies[entry.definition.id] = std::move(entry);
            break;
        }
        case MutationOp::DefineSubject: {
            if (idempotent) {
                return VoidResult{};
            }
            if (content_unchanged(image, mutation)) {
                image.subjects.at(mutation.subject.id).provenance = provenance;
                break;
            }
            SubjectDef definition = mutation.subject;
            definition.generation = bump(image, mutation);
            if (!definition.generation.is_set()) {
                return make_error(StatusCode::Overflow,
                                  "subject generation counter is exhausted for '" +
                                      definition.id.str() + "'");
            }
            SubjectEntry entry;
            entry.definition = std::move(definition);
            entry.provenance = provenance;
            image.subjects[entry.definition.id] = std::move(entry);
            break;
        }
        case MutationOp::Assign: {
            if (idempotent) {
                return VoidResult{};
            }
            if (content_unchanged(image, mutation)) {
                // Same content, new incarnation or epoch: refresh the authority binding so the
                // evidence becomes usable again, without pretending the meaning changed.
                image.assignments.at(mutation.assignment.id).provenance = provenance;
                break;
            }
            PriorityAssignment assignment = mutation.assignment;
            assignment.generation = bump(image, mutation);
            if (!assignment.generation.is_set()) {
                return make_error(StatusCode::Overflow,
                                  "assignment generation counter is exhausted for '" +
                                      assignment.id.str() + "'");
            }
            AssignmentEntry entry;
            entry.assignment = std::move(assignment);
            entry.provenance = provenance;
            entry.active = true;
            const SubjectId subject = entry.assignment.subject;
            const PriorityAssignmentId id = entry.assignment.id;
            image.assignments[id] = std::move(entry);
            auto& bucket = image.assignments_by_subject[subject];
            const auto position =
                std::lower_bound(bucket.begin(), bucket.end(), id,
                                 [](const PriorityAssignmentId& a, const PriorityAssignmentId& b) {
                                     return a < b;
                                 });
            bucket.insert(position, id);
            break;
        }
        case MutationOp::RetireAssignment: {
            if (idempotent) {
                return VoidResult{};
            }
            auto it = image.assignments.find(mutation.retire_target);
            if (it == image.assignments.end()) {
                return make_error(StatusCode::NotFound, "assignment disappeared during retirement");
            }
            const auto bumped = it->second.assignment.generation.next();
            if (!bumped.has_value()) {
                return make_error(StatusCode::Overflow,
                                  "assignment generation counter is exhausted for '" +
                                      mutation.retire_target.str() + "'");
            }
            it->second.assignment.generation = *bumped;
            it->second.active = false;
            it->second.retirement_reason = mutation.reason;
            it->second.retired_by = provenance;
            break;
        }
        case MutationOp::GrantAuthority: {
            if (idempotent) {
                return VoidResult{};
            }
            if (image.next_fencing_token == 0 ||
                image.next_fencing_token == std::numeric_limits<std::uint64_t>::max()) {
                return make_error(StatusCode::Overflow, "the fencing token counter is exhausted");
            }
            for (auto& entry : image.authority) {
                if (entry.first.first == mutation.publisher &&
                    entry.first.second != mutation.boot &&
                    entry.second.state == AuthorityState::Granted) {
                    entry.second.state = AuthorityState::Superseded;
                }
            }
            AuthorityEntry entry;
            entry.publisher = mutation.publisher;
            entry.boot = mutation.boot;
            entry.epoch = image.epoch;
            entry.token = FencingToken{image.next_fencing_token};
            entry.state = AuthorityState::Granted;
            entry.provenance = provenance;
            image.authority[{entry.publisher, entry.boot}] = std::move(entry);
            ++image.next_fencing_token;
            break;
        }
        case MutationOp::FenceAuthority: {
            if (idempotent) {
                return VoidResult{};
            }
            auto it = image.authority.find({mutation.fence_publisher, mutation.fence_boot});
            if (it == image.authority.end()) {
                AuthorityEntry entry;
                entry.publisher = mutation.fence_publisher;
                entry.boot = mutation.fence_boot;
                entry.epoch = FabricEpoch::unestablished();
                entry.token = FencingToken::none();
                entry.state = AuthorityState::Fenced;
                entry.provenance = provenance;
                image.authority[{entry.publisher, entry.boot}] = std::move(entry);
            } else {
                it->second.state = AuthorityState::Fenced;
                it->second.provenance = provenance;
            }
            break;
        }
        case MutationOp::AdvanceEpoch: {
            const auto next = image.epoch.next();
            if (!next.has_value()) {
                return make_error(StatusCode::Overflow, "the fabric epoch counter is exhausted");
            }
            image.epoch = *next;
            for (auto& entry : image.authority) {
                if (entry.second.state == AuthorityState::Granted &&
                    entry.second.epoch != image.epoch) {
                    entry.second.state = AuthorityState::Expired;
                }
            }
            break;
        }
    }

    if (!idempotent) {
        image.generation = expected;
    }
    return VoidResult{};
}

}  // namespace pf::detail
