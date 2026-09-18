// Priority Fabric -- authoritative network priority classes.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "priority_fabric/model_codec.hpp"

#include <string>
#include <vector>

#include "priority_fabric/text.hpp"

namespace pf {
namespace {

constexpr std::uint32_t kMaxChainSteps = 4096;

template <typename IdList>
void encode_id_list(Encoder& encoder, const IdList& ids) {
    encoder.u32(static_cast<std::uint32_t>(ids.size()));
    for (const auto& id : ids) {
        encoder.str(id.str());
    }
}

template <typename Id>
Result<std::vector<Id>> decode_id_list(Decoder& decoder, std::uint32_t max_entries) {
    auto count = decoder.u32();
    if (!count.ok()) {
        return count.status();
    }
    if (count.value() > max_entries) {
        return make_error(StatusCode::LimitExceeded,
                          "list declares " + std::to_string(count.value()) +
                              " entries, limit is " + std::to_string(max_entries));
    }
    std::vector<Id> out;
    out.reserve(count.value());
    for (std::uint32_t i = 0; i < count.value(); ++i) {
        auto id = decoder.template id<typename Id::IdTag>();
        if (!id.ok()) {
            return id.status();
        }
        out.push_back(std::move(id.value()));
    }
    return out;
}

void encode_precedence(Encoder& encoder, const PrecedenceRank& rank) {
    encoder.boolean(rank.assigned);
    encoder.u32(rank.value);
}

Result<PrecedenceRank> decode_precedence(Decoder& decoder) {
    auto assigned = decoder.boolean();
    if (!assigned.ok()) {
        return assigned.status();
    }
    auto value = decoder.u32();
    if (!value.ok()) {
        return value.status();
    }
    if (!assigned.value()) {
        return PrecedenceRank::undeclared();
    }
    if (value.value() > PrecedenceRank::kMaxRank) {
        return make_error(StatusCode::InvalidArgument,
                          "precedence rank " + std::to_string(value.value()) + " exceeds the " +
                              std::to_string(PrecedenceRank::kMaxRank) + " ceiling");
    }
    return PrecedenceRank::make(value.value());
}

void encode_boot(Encoder& encoder, const BootId& boot) {
    encoder.raw(boot.bytes.data(), boot.bytes.size());
}

Result<BootId> decode_boot(Decoder& decoder) {
    auto bytes = decoder.raw(BootId::kSize);
    if (!bytes.ok()) {
        return bytes.status();
    }
    BootId boot;
    for (std::size_t i = 0; i < BootId::kSize; ++i) {
        boot.bytes[i] = static_cast<std::uint8_t>(bytes.value()[i]);
    }
    return boot;
}

}  // namespace

// ---------------------------------------------------------------------------------------
// Provenance
// ---------------------------------------------------------------------------------------

std::string encode_provenance(const Provenance& provenance) {
    Encoder encoder;
    // A provenance that records "nothing happened yet" has no publisher. It is a real state
    // (an assignment that was never retired carries one) and must round-trip.
    encoder.boolean(provenance.publisher.valid());
    if (provenance.publisher.valid()) {
        encoder.str(provenance.publisher.str());
    }
    encode_boot(encoder, provenance.boot);
    encoder.u64(provenance.epoch.value);
    encoder.u64(provenance.token.value);
    encoder.u64(provenance.state_generation.value);
    encoder.u64(provenance.audit_sequence);
    encoder.u64(provenance.recorded_at_ms);
    encoder.str(provenance.op);
    return encoder.take();
}

Result<Provenance> decode_provenance(Decoder& decoder) {
    Provenance provenance;
    auto has_publisher = decoder.boolean();
    if (!has_publisher.ok()) {
        return has_publisher.status();
    }
    if (has_publisher.value()) {
        auto publisher = decoder.id<PublisherTag>();
        if (!publisher.ok()) {
            return publisher.status();
        }
        provenance.publisher = std::move(publisher.value());
    }
    auto boot = decode_boot(decoder);
    if (!boot.ok()) {
        return boot.status();
    }
    provenance.boot = boot.value();
    auto epoch = decoder.u64();
    if (!epoch.ok()) {
        return epoch.status();
    }
    provenance.epoch = FabricEpoch{epoch.value()};
    auto token = decoder.u64();
    if (!token.ok()) {
        return token.status();
    }
    provenance.token = FencingToken{token.value()};
    auto generation = decoder.u64();
    if (!generation.ok()) {
        return generation.status();
    }
    provenance.state_generation = Generation{generation.value()};
    auto audit_sequence = decoder.u64();
    if (!audit_sequence.ok()) {
        return audit_sequence.status();
    }
    provenance.audit_sequence = audit_sequence.value();
    auto recorded_at = decoder.u64();
    if (!recorded_at.ok()) {
        return recorded_at.status();
    }
    provenance.recorded_at_ms = recorded_at.value();
    auto op = decoder.str(64);
    if (!op.ok()) {
        return op.status();
    }
    provenance.op = std::move(op.value());
    return provenance;
}

// ---------------------------------------------------------------------------------------
// Definitions
// ---------------------------------------------------------------------------------------

std::string encode_class_definition(const PriorityClassDef& definition) {
    Encoder encoder;
    encoder.str(definition.id.str());
    encoder.u64(definition.generation.value);
    encode_precedence(encoder, definition.precedence);
    encoder.u8(static_cast<std::uint8_t>(definition.kind));
    encode_id_list(encoder, definition.inherits_from);
    encoder.str(definition.description);
    encoder.boolean(definition.privileged);
    return encoder.take();
}

Result<PriorityClassDef> decode_class_definition(const std::string& payload, const Limits& limits) {
    Decoder decoder(payload.data(), payload.size(), limits);
    PriorityClassDef definition;
    auto id = decoder.id<PriorityClassTag>();
    if (!id.ok()) {
        return id.status();
    }
    definition.id = std::move(id.value());
    auto generation = decoder.u64();
    if (!generation.ok()) {
        return generation.status();
    }
    definition.generation = Generation{generation.value()};
    auto precedence = decode_precedence(decoder);
    if (!precedence.ok()) {
        return precedence.status();
    }
    definition.precedence = precedence.value();
    auto kind = decoder.u8();
    if (!kind.ok()) {
        return kind.status();
    }
    if (kind.value() > static_cast<std::uint8_t>(ClassKind::Emergency)) {
        return make_error(StatusCode::ProtocolError,
                          "class kind " + std::to_string(kind.value()) + " is not defined");
    }
    definition.kind = static_cast<ClassKind>(kind.value());
    auto parents = decode_id_list<PriorityClassId>(decoder, limits.max_inherits_from);
    if (!parents.ok()) {
        return parents.status();
    }
    definition.inherits_from = std::move(parents.value());
    auto description = decoder.str(limits.max_description_length);
    if (!description.ok()) {
        return description.status();
    }
    definition.description = std::move(description.value());
    auto privileged = decoder.boolean();
    if (!privileged.ok()) {
        return privileged.status();
    }
    definition.privileged = privileged.value();
    auto finished = decoder.finish();
    if (!finished.ok()) {
        return finished.status();
    }
    return definition;
}

std::string encode_scope_definition(const PolicyScopeDef& definition) {
    Encoder encoder;
    encoder.str(definition.id.str());
    encoder.u64(definition.generation.value);
    encoder.boolean(definition.parent.has_value());
    if (definition.parent.has_value()) {
        encoder.str(definition.parent->str());
    }
    encoder.u8(static_cast<std::uint8_t>(definition.conflict_resolution));
    encoder.boolean(definition.unknown_default.has_value());
    if (definition.unknown_default.has_value()) {
        encoder.str(definition.unknown_default->str());
    }
    encoder.boolean(definition.allow_override);
    encoder.str(definition.description);
    return encoder.take();
}

Result<PolicyScopeDef> decode_scope_definition(const std::string& payload, const Limits& limits) {
    Decoder decoder(payload.data(), payload.size(), limits);
    PolicyScopeDef definition;
    auto id = decoder.id<PolicyScopeTag>();
    if (!id.ok()) {
        return id.status();
    }
    definition.id = std::move(id.value());
    auto generation = decoder.u64();
    if (!generation.ok()) {
        return generation.status();
    }
    definition.generation = Generation{generation.value()};
    auto has_parent = decoder.boolean();
    if (!has_parent.ok()) {
        return has_parent.status();
    }
    if (has_parent.value()) {
        auto parent = decoder.id<PolicyScopeTag>();
        if (!parent.ok()) {
            return parent.status();
        }
        definition.parent = std::move(parent.value());
    }
    auto conflict = decoder.u8();
    if (!conflict.ok()) {
        return conflict.status();
    }
    if (conflict.value() > static_cast<std::uint8_t>(ConflictResolution::AssignmentIdOrder)) {
        return make_error(StatusCode::ProtocolError,
                          "conflict resolution mode " + std::to_string(conflict.value()) +
                              " is not defined");
    }
    definition.conflict_resolution = static_cast<ConflictResolution>(conflict.value());
    auto has_default = decoder.boolean();
    if (!has_default.ok()) {
        return has_default.status();
    }
    if (has_default.value()) {
        auto cls = decoder.id<PriorityClassTag>();
        if (!cls.ok()) {
            return cls.status();
        }
        definition.unknown_default = std::move(cls.value());
    }
    auto allow_override = decoder.boolean();
    if (!allow_override.ok()) {
        return allow_override.status();
    }
    definition.allow_override = allow_override.value();
    auto description = decoder.str(limits.max_description_length);
    if (!description.ok()) {
        return description.status();
    }
    definition.description = std::move(description.value());
    auto finished = decoder.finish();
    if (!finished.ok()) {
        return finished.status();
    }
    return definition;
}

std::string encode_policy_definition(const PolicyDef& definition) {
    Encoder encoder;
    encoder.str(definition.id.str());
    encoder.u64(definition.generation.value);
    encoder.str(definition.scope.str());
    encoder.u64(definition.scope_generation.value);
    encode_id_list(encoder, definition.visible_classes);
    encoder.boolean(definition.conflict_resolution.has_value());
    if (definition.conflict_resolution.has_value()) {
        encoder.u8(static_cast<std::uint8_t>(*definition.conflict_resolution));
    }
    encoder.boolean(definition.unknown_default.has_value());
    if (definition.unknown_default.has_value()) {
        encoder.str(definition.unknown_default->str());
    }
    encoder.boolean(definition.require_policy_for_assignment);
    encoder.str(definition.description);
    return encoder.take();
}

Result<PolicyDef> decode_policy_definition(const std::string& payload, const Limits& limits) {
    Decoder decoder(payload.data(), payload.size(), limits);
    PolicyDef definition;
    auto id = decoder.id<PolicyTag>();
    if (!id.ok()) {
        return id.status();
    }
    definition.id = std::move(id.value());
    auto generation = decoder.u64();
    if (!generation.ok()) {
        return generation.status();
    }
    definition.generation = Generation{generation.value()};
    auto scope = decoder.id<PolicyScopeTag>();
    if (!scope.ok()) {
        return scope.status();
    }
    definition.scope = std::move(scope.value());
    auto scope_generation = decoder.u64();
    if (!scope_generation.ok()) {
        return scope_generation.status();
    }
    definition.scope_generation = Generation{scope_generation.value()};
    auto visible = decode_id_list<PriorityClassId>(decoder, limits.max_policy_classes);
    if (!visible.ok()) {
        return visible.status();
    }
    definition.visible_classes = std::move(visible.value());
    auto has_conflict = decoder.boolean();
    if (!has_conflict.ok()) {
        return has_conflict.status();
    }
    if (has_conflict.value()) {
        auto conflict = decoder.u8();
        if (!conflict.ok()) {
            return conflict.status();
        }
        if (conflict.value() > static_cast<std::uint8_t>(ConflictResolution::AssignmentIdOrder)) {
            return make_error(StatusCode::ProtocolError,
                              "conflict resolution mode " + std::to_string(conflict.value()) +
                                  " is not defined");
        }
        definition.conflict_resolution = static_cast<ConflictResolution>(conflict.value());
    }
    auto has_default = decoder.boolean();
    if (!has_default.ok()) {
        return has_default.status();
    }
    if (has_default.value()) {
        auto cls = decoder.id<PriorityClassTag>();
        if (!cls.ok()) {
            return cls.status();
        }
        definition.unknown_default = std::move(cls.value());
    }
    auto require_policy = decoder.boolean();
    if (!require_policy.ok()) {
        return require_policy.status();
    }
    definition.require_policy_for_assignment = require_policy.value();
    auto description = decoder.str(limits.max_description_length);
    if (!description.ok()) {
        return description.status();
    }
    definition.description = std::move(description.value());
    auto finished = decoder.finish();
    if (!finished.ok()) {
        return finished.status();
    }
    return definition;
}

std::string encode_subject_definition(const SubjectDef& definition) {
    Encoder encoder;
    encoder.str(definition.id.str());
    encoder.u64(definition.generation.value);
    encode_id_list(encoder, definition.inherits_from);
    encoder.str(definition.description);
    return encoder.take();
}

Result<SubjectDef> decode_subject_definition(const std::string& payload, const Limits& limits) {
    Decoder decoder(payload.data(), payload.size(), limits);
    SubjectDef definition;
    auto id = decoder.id<SubjectTag>();
    if (!id.ok()) {
        return id.status();
    }
    definition.id = std::move(id.value());
    auto generation = decoder.u64();
    if (!generation.ok()) {
        return generation.status();
    }
    definition.generation = Generation{generation.value()};
    auto parents = decode_id_list<SubjectId>(decoder, limits.max_inherits_from);
    if (!parents.ok()) {
        return parents.status();
    }
    definition.inherits_from = std::move(parents.value());
    auto description = decoder.str(limits.max_description_length);
    if (!description.ok()) {
        return description.status();
    }
    definition.description = std::move(description.value());
    auto finished = decoder.finish();
    if (!finished.ok()) {
        return finished.status();
    }
    return definition;
}

std::string encode_assignment(const PriorityAssignment& assignment) {
    Encoder encoder;
    encoder.str(assignment.id.str());
    encoder.u64(assignment.generation.value);
    encoder.str(assignment.subject.str());
    encoder.u64(assignment.subject_generation.value);
    encoder.str(assignment.scope.str());
    encoder.u64(assignment.scope_generation.value);
    encoder.str(assignment.cls.str());
    encoder.u64(assignment.class_generation.value);
    encoder.u8(static_cast<std::uint8_t>(assignment.kind));
    encoder.boolean(assignment.displaces.has_value());
    if (assignment.displaces.has_value()) {
        encoder.str(assignment.displaces->str());
    }
    encoder.boolean(assignment.policy.has_value());
    if (assignment.policy.has_value()) {
        encoder.str(assignment.policy->str());
    }
    encoder.u64(assignment.policy_generation.value);
    encoder.str(assignment.note);
    return encoder.take();
}

Result<PriorityAssignment> decode_assignment(const std::string& payload, const Limits& limits) {
    Decoder decoder(payload.data(), payload.size(), limits);
    PriorityAssignment assignment;
    auto id = decoder.id<PriorityAssignmentTag>();
    if (!id.ok()) {
        return id.status();
    }
    assignment.id = std::move(id.value());
    auto generation = decoder.u64();
    if (!generation.ok()) {
        return generation.status();
    }
    assignment.generation = Generation{generation.value()};
    auto subject = decoder.id<SubjectTag>();
    if (!subject.ok()) {
        return subject.status();
    }
    assignment.subject = std::move(subject.value());
    auto subject_generation = decoder.u64();
    if (!subject_generation.ok()) {
        return subject_generation.status();
    }
    assignment.subject_generation = Generation{subject_generation.value()};
    auto scope = decoder.id<PolicyScopeTag>();
    if (!scope.ok()) {
        return scope.status();
    }
    assignment.scope = std::move(scope.value());
    auto scope_generation = decoder.u64();
    if (!scope_generation.ok()) {
        return scope_generation.status();
    }
    assignment.scope_generation = Generation{scope_generation.value()};
    auto cls = decoder.id<PriorityClassTag>();
    if (!cls.ok()) {
        return cls.status();
    }
    assignment.cls = std::move(cls.value());
    auto class_generation = decoder.u64();
    if (!class_generation.ok()) {
        return class_generation.status();
    }
    assignment.class_generation = Generation{class_generation.value()};
    auto kind = decoder.u8();
    if (!kind.ok()) {
        return kind.status();
    }
    if (kind.value() > static_cast<std::uint8_t>(AssignmentKind::Default)) {
        return make_error(StatusCode::ProtocolError,
                          "assignment kind " + std::to_string(kind.value()) + " is not defined");
    }
    assignment.kind = static_cast<AssignmentKind>(kind.value());
    auto has_displaces = decoder.boolean();
    if (!has_displaces.ok()) {
        return has_displaces.status();
    }
    if (has_displaces.value()) {
        auto displaced = decoder.id<PriorityClassTag>();
        if (!displaced.ok()) {
            return displaced.status();
        }
        assignment.displaces = std::move(displaced.value());
    }
    auto has_policy = decoder.boolean();
    if (!has_policy.ok()) {
        return has_policy.status();
    }
    if (has_policy.value()) {
        auto policy = decoder.id<PolicyTag>();
        if (!policy.ok()) {
            return policy.status();
        }
        assignment.policy = std::move(policy.value());
    }
    auto policy_generation = decoder.u64();
    if (!policy_generation.ok()) {
        return policy_generation.status();
    }
    assignment.policy_generation = Generation{policy_generation.value()};
    auto note = decoder.str(limits.max_note_length);
    if (!note.ok()) {
        return note.status();
    }
    assignment.note = std::move(note.value());
    auto finished = decoder.finish();
    if (!finished.ok()) {
        return finished.status();
    }
    return assignment;
}

// ---------------------------------------------------------------------------------------
// Audit
// ---------------------------------------------------------------------------------------

std::string encode_audit_entry(const AuditEntry& entry) {
    Encoder encoder;
    encoder.u64(entry.sequence);
    encoder.str(entry.op);
    encoder.u16(static_cast<std::uint16_t>(entry.result));
    encoder.str(entry.detail);
    encoder.str(encode_provenance(entry.provenance));
    encoder.u64(entry.state_generation.value);
    encoder.raw(entry.digest.bytes.data(), entry.digest.bytes.size());
    return encoder.take();
}

Result<AuditEntry> decode_audit_entry(Decoder& decoder) {
    AuditEntry entry;
    auto sequence = decoder.u64();
    if (!sequence.ok()) {
        return sequence.status();
    }
    entry.sequence = sequence.value();
    auto op = decoder.str(64);
    if (!op.ok()) {
        return op.status();
    }
    entry.op = std::move(op.value());
    auto result = decoder.u16();
    if (!result.ok()) {
        return result.status();
    }
    if (result.value() > static_cast<std::uint16_t>(StatusCode::BoundaryViolation)) {
        return make_error(StatusCode::ProtocolError,
                          "audit entry carries an undefined status code " +
                              std::to_string(result.value()));
    }
    entry.result = static_cast<StatusCode>(result.value());
    auto detail = decoder.str(1024);
    if (!detail.ok()) {
        return detail.status();
    }
    entry.detail = std::move(detail.value());
    auto provenance_blob = decoder.str(4096);
    if (!provenance_blob.ok()) {
        return provenance_blob.status();
    }
    Decoder provenance_decoder(provenance_blob.value().data(), provenance_blob.value().size(),
                               Limits{});
    auto provenance = decode_provenance(provenance_decoder);
    if (!provenance.ok()) {
        return provenance.status();
    }
    entry.provenance = provenance.value();
    auto generation = decoder.u64();
    if (!generation.ok()) {
        return generation.status();
    }
    entry.state_generation = Generation{generation.value()};
    auto digest = decoder.raw(Digest::kSize);
    if (!digest.ok()) {
        return digest.status();
    }
    for (std::size_t i = 0; i < Digest::kSize; ++i) {
        entry.digest.bytes[i] = static_cast<std::uint8_t>(digest.value()[i]);
    }
    return entry;
}

// ---------------------------------------------------------------------------------------
// Query and decision
// ---------------------------------------------------------------------------------------

std::string encode_query(const PriorityQuery& query) {
    Encoder encoder;
    encoder.str(query.subject.str());
    encoder.u64(query.subject_generation.value);
    encoder.str(query.scope.str());
    encoder.boolean(query.as_of_epoch.has_value());
    encoder.u64(query.as_of_epoch.has_value() ? query.as_of_epoch->value : 0u);
    encoder.u64(query.require_policy_generation.value);
    encoder.u64(query.require_scope_generation.value);
    encoder.boolean(query.strict_conflicts);
    encoder.u32(query.max_explanation_steps);
    encoder.u64(query.correlation);
    return encoder.take();
}

Result<PriorityQuery> decode_query(const std::string& payload, const Limits& limits) {
    Decoder decoder(payload.data(), payload.size(), limits);
    PriorityQuery query;
    auto subject = decoder.id<SubjectTag>();
    if (!subject.ok()) {
        return subject.status();
    }
    query.subject = std::move(subject.value());
    auto subject_generation = decoder.u64();
    if (!subject_generation.ok()) {
        return subject_generation.status();
    }
    query.subject_generation = Generation{subject_generation.value()};
    auto scope = decoder.id<PolicyScopeTag>();
    if (!scope.ok()) {
        return scope.status();
    }
    query.scope = std::move(scope.value());
    auto has_epoch = decoder.boolean();
    if (!has_epoch.ok()) {
        return has_epoch.status();
    }
    auto epoch = decoder.u64();
    if (!epoch.ok()) {
        return epoch.status();
    }
    if (has_epoch.value()) {
        query.as_of_epoch = FabricEpoch{epoch.value()};
    }
    auto policy_generation = decoder.u64();
    if (!policy_generation.ok()) {
        return policy_generation.status();
    }
    query.require_policy_generation = Generation{policy_generation.value()};
    auto scope_generation = decoder.u64();
    if (!scope_generation.ok()) {
        return scope_generation.status();
    }
    query.require_scope_generation = Generation{scope_generation.value()};
    auto strict = decoder.boolean();
    if (!strict.ok()) {
        return strict.status();
    }
    query.strict_conflicts = strict.value();
    auto steps = decoder.u32();
    if (!steps.ok()) {
        return steps.status();
    }
    query.max_explanation_steps = steps.value();
    auto correlation = decoder.u64();
    if (!correlation.ok()) {
        return correlation.status();
    }
    query.correlation = correlation.value();
    auto finished = decoder.finish();
    if (!finished.ok()) {
        return finished.status();
    }
    return query;
}

namespace {

void encode_explanation_step(Encoder& encoder, const ExplanationStep& step) {
    encoder.str(step.stage);
    encoder.str(step.code);
    encoder.str(step.detail);
    encoder.boolean(step.assignment.has_value());
    if (step.assignment.has_value()) {
        encoder.str(step.assignment->str());
    }
    encoder.u64(step.assignment_generation.value);
    encoder.boolean(step.cls.has_value());
    if (step.cls.has_value()) {
        encoder.str(step.cls->str());
    }
    encoder.u64(step.class_generation.value);
    encoder.boolean(step.scope.has_value());
    if (step.scope.has_value()) {
        encoder.str(step.scope->str());
    }
    encoder.boolean(step.policy.has_value());
    if (step.policy.has_value()) {
        encoder.str(step.policy->str());
    }
    encoder.str(encode_provenance(step.provenance));
}

Result<ExplanationStep> decode_explanation_step(Decoder& decoder, const Limits& limits) {
    ExplanationStep step;
    auto stage = decoder.str(64);
    if (!stage.ok()) {
        return stage.status();
    }
    step.stage = std::move(stage.value());
    auto code = decoder.str(64);
    if (!code.ok()) {
        return code.status();
    }
    step.code = std::move(code.value());
    auto detail = decoder.str(limits.max_description_length);
    if (!detail.ok()) {
        return detail.status();
    }
    step.detail = std::move(detail.value());
    auto has_assignment = decoder.boolean();
    if (!has_assignment.ok()) {
        return has_assignment.status();
    }
    if (has_assignment.value()) {
        auto id = decoder.id<PriorityAssignmentTag>();
        if (!id.ok()) {
            return id.status();
        }
        step.assignment = std::move(id.value());
    }
    auto assignment_generation = decoder.u64();
    if (!assignment_generation.ok()) {
        return assignment_generation.status();
    }
    step.assignment_generation = Generation{assignment_generation.value()};
    auto has_class = decoder.boolean();
    if (!has_class.ok()) {
        return has_class.status();
    }
    if (has_class.value()) {
        auto id = decoder.id<PriorityClassTag>();
        if (!id.ok()) {
            return id.status();
        }
        step.cls = std::move(id.value());
    }
    auto class_generation = decoder.u64();
    if (!class_generation.ok()) {
        return class_generation.status();
    }
    step.class_generation = Generation{class_generation.value()};
    auto has_scope = decoder.boolean();
    if (!has_scope.ok()) {
        return has_scope.status();
    }
    if (has_scope.value()) {
        auto id = decoder.id<PolicyScopeTag>();
        if (!id.ok()) {
            return id.status();
        }
        step.scope = std::move(id.value());
    }
    auto has_policy = decoder.boolean();
    if (!has_policy.ok()) {
        return has_policy.status();
    }
    if (has_policy.value()) {
        auto id = decoder.id<PolicyTag>();
        if (!id.ok()) {
            return id.status();
        }
        step.policy = std::move(id.value());
    }
    auto provenance_blob = decoder.str(4096);
    if (!provenance_blob.ok()) {
        return provenance_blob.status();
    }
    Decoder provenance_decoder(provenance_blob.value().data(), provenance_blob.value().size(),
                               limits);
    auto provenance = decode_provenance(provenance_decoder);
    if (!provenance.ok()) {
        return provenance.status();
    }
    step.provenance = provenance.value();
    auto finished = provenance_decoder.finish();
    if (!finished.ok()) {
        return finished.status();
    }
    return step;
}

void encode_evidence_note(Encoder& encoder, const EvidenceNote& note) {
    encoder.str(note.assignment.str());
    encoder.u64(note.assignment_generation.value);
    encoder.str(note.cls.str());
    encoder.u64(note.class_generation.value);
    encoder.str(note.scope.str());
    encoder.boolean(note.via_subject.has_value());
    if (note.via_subject.has_value()) {
        encoder.str(note.via_subject->str());
    }
    encoder.str(note.reason_code);
    encoder.str(note.reason);
    encoder.str(encode_provenance(note.provenance));
}

Result<EvidenceNote> decode_evidence_note(Decoder& decoder, const Limits& limits) {
    EvidenceNote note;
    auto assignment = decoder.id<PriorityAssignmentTag>();
    if (!assignment.ok()) {
        return assignment.status();
    }
    note.assignment = std::move(assignment.value());
    auto assignment_generation = decoder.u64();
    if (!assignment_generation.ok()) {
        return assignment_generation.status();
    }
    note.assignment_generation = Generation{assignment_generation.value()};
    auto cls = decoder.id<PriorityClassTag>();
    if (!cls.ok()) {
        return cls.status();
    }
    note.cls = std::move(cls.value());
    auto class_generation = decoder.u64();
    if (!class_generation.ok()) {
        return class_generation.status();
    }
    note.class_generation = Generation{class_generation.value()};
    auto scope = decoder.id<PolicyScopeTag>();
    if (!scope.ok()) {
        return scope.status();
    }
    note.scope = std::move(scope.value());
    auto has_subject = decoder.boolean();
    if (!has_subject.ok()) {
        return has_subject.status();
    }
    if (has_subject.value()) {
        auto subject = decoder.id<SubjectTag>();
        if (!subject.ok()) {
            return subject.status();
        }
        note.via_subject = std::move(subject.value());
    }
    auto reason_code = decoder.str(64);
    if (!reason_code.ok()) {
        return reason_code.status();
    }
    note.reason_code = std::move(reason_code.value());
    auto reason = decoder.str(limits.max_description_length);
    if (!reason.ok()) {
        return reason.status();
    }
    note.reason = std::move(reason.value());
    auto provenance_blob = decoder.str(4096);
    if (!provenance_blob.ok()) {
        return provenance_blob.status();
    }
    Decoder provenance_decoder(provenance_blob.value().data(), provenance_blob.value().size(),
                               limits);
    auto provenance = decode_provenance(provenance_decoder);
    if (!provenance.ok()) {
        return provenance.status();
    }
    note.provenance = provenance.value();
    auto finished = provenance_decoder.finish();
    if (!finished.ok()) {
        return finished.status();
    }
    return note;
}

}  // namespace

std::string encode_decision(const PriorityDecision& decision) {
    Encoder encoder;
    encoder.u8(static_cast<std::uint8_t>(decision.outcome));
    encoder.boolean(decision.authoritative);
    // A decision that carries no authority names no class, so the presence of the class is
    // part of the encoding rather than an empty identifier.
    encoder.boolean(decision.cls.valid());
    if (decision.cls.valid()) {
        encoder.str(decision.cls.str());
    }
    encoder.u64(decision.class_generation.value);
    encode_precedence(encoder, decision.precedence);
    encoder.u32(static_cast<std::uint32_t>(decision.chain.size()));
    for (const auto& step : decision.chain) {
        encode_explanation_step(encoder, step);
    }
    encoder.u32(static_cast<std::uint32_t>(decision.superseded.size()));
    for (const auto& note : decision.superseded) {
        encode_evidence_note(encoder, note);
    }
    encoder.u32(static_cast<std::uint32_t>(decision.rejected_evidence.size()));
    for (const auto& note : decision.rejected_evidence) {
        encode_evidence_note(encoder, note);
    }
    encoder.u32(static_cast<std::uint32_t>(decision.conflicts.size()));
    for (const auto& conflict : decision.conflicts) {
        encoder.str(conflict);
    }
    encoder.str(decision.reason_code);
    encoder.str(decision.reason);
    encoder.str(decision.resolution);
    encoder.u64(decision.epoch.value);
    encoder.u64(decision.state_generation.value);
    encoder.u64(decision.policy_generation.value);
    encoder.u64(decision.scope_generation.value);
    encoder.raw(decision.digest.bytes.data(), decision.digest.bytes.size());
    encoder.boolean(decision.privileged_class);
    return encoder.take();
}

Result<PriorityDecision> decode_decision(const std::string& payload, const Limits& limits) {
    Decoder decoder(payload.data(), payload.size(), limits);
    PriorityDecision decision;
    auto outcome = decoder.u8();
    if (!outcome.ok()) {
        return outcome.status();
    }
    if (outcome.value() > static_cast<std::uint8_t>(Outcome::Rejected)) {
        return make_error(StatusCode::ProtocolError,
                          "outcome " + std::to_string(outcome.value()) + " is not defined");
    }
    decision.outcome = static_cast<Outcome>(outcome.value());
    auto authoritative = decoder.boolean();
    if (!authoritative.ok()) {
        return authoritative.status();
    }
    decision.authoritative = authoritative.value();
    auto has_class = decoder.boolean();
    if (!has_class.ok()) {
        return has_class.status();
    }
    if (has_class.value()) {
        auto cls = decoder.id<PriorityClassTag>();
        if (!cls.ok()) {
            return cls.status();
        }
        decision.cls = std::move(cls.value());
    }
    auto class_generation = decoder.u64();
    if (!class_generation.ok()) {
        return class_generation.status();
    }
    decision.class_generation = Generation{class_generation.value()};
    auto precedence = decode_precedence(decoder);
    if (!precedence.ok()) {
        return precedence.status();
    }
    decision.precedence = precedence.value();

    auto chain_count = decoder.u32();
    if (!chain_count.ok()) {
        return chain_count.status();
    }
    if (chain_count.value() > limits.max_explanation_steps) {
        return make_error(StatusCode::LimitExceeded,
                          "decision carries " + std::to_string(chain_count.value()) +
                              " explanation steps, limit is " +
                              std::to_string(limits.max_explanation_steps));
    }
    decision.chain.reserve(chain_count.value());
    for (std::uint32_t i = 0; i < chain_count.value(); ++i) {
        auto step = decode_explanation_step(decoder, limits);
        if (!step.ok()) {
            return step.status();
        }
        decision.chain.push_back(std::move(step.value()));
    }

    auto superseded_count = decoder.u32();
    if (!superseded_count.ok()) {
        return superseded_count.status();
    }
    if (superseded_count.value() > kMaxChainSteps) {
        return make_error(StatusCode::LimitExceeded, "decision carries too many superseded notes");
    }
    decision.superseded.reserve(superseded_count.value());
    for (std::uint32_t i = 0; i < superseded_count.value(); ++i) {
        auto note = decode_evidence_note(decoder, limits);
        if (!note.ok()) {
            return note.status();
        }
        decision.superseded.push_back(std::move(note.value()));
    }

    auto rejected_count = decoder.u32();
    if (!rejected_count.ok()) {
        return rejected_count.status();
    }
    if (rejected_count.value() > kMaxChainSteps) {
        return make_error(StatusCode::LimitExceeded, "decision carries too many rejected notes");
    }
    decision.rejected_evidence.reserve(rejected_count.value());
    for (std::uint32_t i = 0; i < rejected_count.value(); ++i) {
        auto note = decode_evidence_note(decoder, limits);
        if (!note.ok()) {
            return note.status();
        }
        decision.rejected_evidence.push_back(std::move(note.value()));
    }

    auto conflict_count = decoder.u32();
    if (!conflict_count.ok()) {
        return conflict_count.status();
    }
    if (conflict_count.value() > kMaxChainSteps) {
        return make_error(StatusCode::LimitExceeded, "decision carries too many conflict notes");
    }
    decision.conflicts.reserve(conflict_count.value());
    for (std::uint32_t i = 0; i < conflict_count.value(); ++i) {
        auto conflict = decoder.str(limits.max_description_length);
        if (!conflict.ok()) {
            return conflict.status();
        }
        decision.conflicts.push_back(std::move(conflict.value()));
    }

    auto reason_code = decoder.str(64);
    if (!reason_code.ok()) {
        return reason_code.status();
    }
    decision.reason_code = std::move(reason_code.value());
    auto reason = decoder.str(limits.max_description_length);
    if (!reason.ok()) {
        return reason.status();
    }
    decision.reason = std::move(reason.value());
    auto resolution = decoder.str(64);
    if (!resolution.ok()) {
        return resolution.status();
    }
    decision.resolution = std::move(resolution.value());
    auto epoch = decoder.u64();
    if (!epoch.ok()) {
        return epoch.status();
    }
    decision.epoch = FabricEpoch{epoch.value()};
    auto state_generation = decoder.u64();
    if (!state_generation.ok()) {
        return state_generation.status();
    }
    decision.state_generation = Generation{state_generation.value()};
    auto policy_generation = decoder.u64();
    if (!policy_generation.ok()) {
        return policy_generation.status();
    }
    decision.policy_generation = Generation{policy_generation.value()};
    auto scope_generation = decoder.u64();
    if (!scope_generation.ok()) {
        return scope_generation.status();
    }
    decision.scope_generation = Generation{scope_generation.value()};
    auto digest = decoder.raw(Digest::kSize);
    if (!digest.ok()) {
        return digest.status();
    }
    for (std::size_t i = 0; i < Digest::kSize; ++i) {
        decision.digest.bytes[i] = static_cast<std::uint8_t>(digest.value()[i]);
    }
    auto privileged = decoder.boolean();
    if (!privileged.ok()) {
        return privileged.status();
    }
    decision.privileged_class = privileged.value();
    auto finished = decoder.finish();
    if (!finished.ok()) {
        return finished.status();
    }
    return decision;
}

// ---------------------------------------------------------------------------------------
// Scalar helpers
// ---------------------------------------------------------------------------------------

std::string encode_generation(Generation generation) {
    Encoder encoder;
    encoder.u64(generation.value);
    return encoder.take();
}

Result<Generation> decode_generation(const std::string& payload) {
    Limits limits{};
    Decoder decoder(payload.data(), payload.size(), limits);
    auto value = decoder.u64();
    if (!value.ok()) {
        return value.status();
    }
    auto finished = decoder.finish();
    if (!finished.ok()) {
        return finished.status();
    }
    return Generation{value.value()};
}

std::string encode_epoch(FabricEpoch epoch) {
    Encoder encoder;
    encoder.u64(epoch.value);
    return encoder.take();
}

Result<FabricEpoch> decode_epoch(const std::string& payload) {
    Limits limits{};
    Decoder decoder(payload.data(), payload.size(), limits);
    auto value = decoder.u64();
    if (!value.ok()) {
        return value.status();
    }
    auto finished = decoder.finish();
    if (!finished.ok()) {
        return finished.status();
    }
    return FabricEpoch{value.value()};
}

}  // namespace pf
