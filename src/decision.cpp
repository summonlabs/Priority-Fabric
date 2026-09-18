// Priority Fabric -- authoritative network priority classes.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "priority_fabric/decision.hpp"

#include <string>

namespace pf {
namespace {

void append_json_string(std::string& out, std::string_view text) {
    out.push_back('"');
    for (char c : text) {
        const auto byte = static_cast<unsigned char>(c);
        switch (c) {
            case '"': out.append("\\\""); break;
            case '\\': out.append("\\\\"); break;
            case '\n': out.append("\\n"); break;
            case '\r': out.append("\\r"); break;
            case '\t': out.append("\\t"); break;
            default:
                if (byte < 0x20u) {
                    constexpr char kHex[] = "0123456789abcdef";
                    out.append("\\u00");
                    out.push_back(kHex[(byte >> 4) & 0x0Fu]);
                    out.push_back(kHex[byte & 0x0Fu]);
                } else {
                    out.push_back(c);
                }
        }
    }
    out.push_back('"');
}

void append_key(std::string& out, std::string_view key, bool& first) {
    if (!first) {
        out.push_back(',');
    }
    first = false;
    out.push_back('"');
    out.append(key);
    out.append("\":");
}

void append_provenance_json(std::string& out, const Provenance& provenance) {
    std::string inner;
    bool first = true;
    append_key(inner, "publisher", first);
    append_json_string(inner, provenance.publisher.str());
    append_key(inner, "boot", first);
    append_json_string(inner, provenance.boot.hex());
    append_key(inner, "epoch", first);
    inner.append(std::to_string(provenance.epoch.value));
    append_key(inner, "fencing_token", first);
    inner.append(std::to_string(provenance.token.value));
    append_key(inner, "state_generation", first);
    inner.append(std::to_string(provenance.state_generation.value));
    append_key(inner, "audit_sequence", first);
    inner.append(std::to_string(provenance.audit_sequence));
    append_key(inner, "recorded_at_ms", first);
    inner.append(std::to_string(provenance.recorded_at_ms));
    append_key(inner, "op", first);
    append_json_string(inner, provenance.op);
    out.push_back('{');
    out.append(inner);
    out.push_back('}');
}

void append_evidence_json(std::string& out, const EvidenceNote& note) {
    std::string inner;
    bool first = true;
    append_key(inner, "assignment", first);
    append_json_string(inner, note.assignment.str());
    append_key(inner, "assignment_generation", first);
    inner.append(std::to_string(note.assignment_generation.value));
    append_key(inner, "class", first);
    append_json_string(inner, note.cls.str());
    append_key(inner, "class_generation", first);
    inner.append(std::to_string(note.class_generation.value));
    append_key(inner, "scope", first);
    append_json_string(inner, note.scope.str());
    if (note.via_subject.has_value()) {
        append_key(inner, "via_subject", first);
        append_json_string(inner, note.via_subject->str());
    }
    append_key(inner, "reason_code", first);
    append_json_string(inner, note.reason_code);
    append_key(inner, "reason", first);
    append_json_string(inner, note.reason);
    append_key(inner, "provenance", first);
    append_provenance_json(inner, note.provenance);
    out.push_back('{');
    out.append(inner);
    out.push_back('}');
}

}  // namespace

const char* to_string(Outcome outcome) noexcept {
    switch (outcome) {
        case Outcome::Assigned: return "ASSIGNED";
        case Outcome::Inherited: return "INHERITED";
        case Outcome::Overridden: return "OVERRIDDEN";
        case Outcome::Conflict: return "CONFLICT";
        case Outcome::Unknown: return "UNKNOWN";
        case Outcome::Stale: return "STALE";
        case Outcome::Fenced: return "FENCED";
        case Outcome::Rejected: return "REJECTED";
    }
    return "UNKNOWN";
}

bool outcome_carries_authority(Outcome outcome) noexcept {
    switch (outcome) {
        case Outcome::Assigned:
        case Outcome::Inherited:
        case Outcome::Overridden:
            return true;
        case Outcome::Conflict:
        case Outcome::Unknown:
        case Outcome::Stale:
        case Outcome::Fenced:
        case Outcome::Rejected:
            return false;
    }
    return false;
}

const char* to_string(Health health) noexcept {
    switch (health) {
        case Health::Healthy: return "healthy";
        case Health::Degraded: return "degraded";
    }
    return "unknown";
}

std::string PriorityDecision::to_json() const {
    std::string out = "{";
    bool first = true;

    append_key(out, "outcome", first);
    append_json_string(out, to_string(outcome));
    append_key(out, "authoritative", first);
    out.append(authoritative ? "true" : "false");
    append_key(out, "class", first);
    append_json_string(out, cls.str());
    append_key(out, "class_generation", first);
    out.append(std::to_string(class_generation.value));
    append_key(out, "precedence", first);
    if (precedence.is_declared()) {
        out.append(std::to_string(precedence.value));
    } else {
        out.append("null");
    }
    append_key(out, "privileged_class", first);
    out.append(privileged_class ? "true" : "false");
    append_key(out, "reason_code", first);
    append_json_string(out, reason_code);
    append_key(out, "reason", first);
    append_json_string(out, reason);
    append_key(out, "resolution", first);
    append_json_string(out, resolution);
    append_key(out, "epoch", first);
    out.append(std::to_string(epoch.value));
    append_key(out, "state_generation", first);
    out.append(std::to_string(state_generation.value));
    append_key(out, "policy_generation", first);
    out.append(std::to_string(policy_generation.value));
    append_key(out, "scope_generation", first);
    out.append(std::to_string(scope_generation.value));
    append_key(out, "decision_digest", first);
    append_json_string(out, digest.hex());

    append_key(out, "chain", first);
    out.push_back('[');
    for (std::size_t i = 0; i < chain.size(); ++i) {
        if (i != 0) {
            out.push_back(',');
        }
        const auto& step = chain[i];
        std::string inner;
        bool inner_first = true;
        append_key(inner, "stage", inner_first);
        append_json_string(inner, step.stage);
        append_key(inner, "code", inner_first);
        append_json_string(inner, step.code);
        append_key(inner, "detail", inner_first);
        append_json_string(inner, step.detail);
        if (step.assignment.has_value()) {
            append_key(inner, "assignment", inner_first);
            append_json_string(inner, step.assignment->str());
            append_key(inner, "assignment_generation", inner_first);
            inner.append(std::to_string(step.assignment_generation.value));
        }
        if (step.cls.has_value()) {
            append_key(inner, "class", inner_first);
            append_json_string(inner, step.cls->str());
            append_key(inner, "class_generation", inner_first);
            inner.append(std::to_string(step.class_generation.value));
        }
        if (step.scope.has_value()) {
            append_key(inner, "scope", inner_first);
            append_json_string(inner, step.scope->str());
        }
        if (step.policy.has_value()) {
            append_key(inner, "policy", inner_first);
            append_json_string(inner, step.policy->str());
        }
        append_key(inner, "provenance", inner_first);
        append_provenance_json(inner, step.provenance);
        out.push_back('{');
        out.append(inner);
        out.push_back('}');
    }
    out.push_back(']');

    append_key(out, "superseded", first);
    out.push_back('[');
    for (std::size_t i = 0; i < superseded.size(); ++i) {
        if (i != 0) {
            out.push_back(',');
        }
        append_evidence_json(out, superseded[i]);
    }
    out.push_back(']');

    append_key(out, "rejected_evidence", first);
    out.push_back('[');
    for (std::size_t i = 0; i < rejected_evidence.size(); ++i) {
        if (i != 0) {
            out.push_back(',');
        }
        append_evidence_json(out, rejected_evidence[i]);
    }
    out.push_back(']');

    append_key(out, "conflicts", first);
    out.push_back('[');
    for (std::size_t i = 0; i < conflicts.size(); ++i) {
        if (i != 0) {
            out.push_back(',');
        }
        append_json_string(out, conflicts[i]);
    }
    out.push_back(']');

    out.push_back('}');
    return out;
}

std::string PriorityDecision::to_text() const {
    std::string out;
    out.append("outcome            : ");
    out.append(to_string(outcome));
    out.push_back('\n');
    out.append("authoritative      : ");
    out.append(authoritative ? "yes" : "no");
    out.push_back('\n');
    out.append("class              : ");
    out.append(authoritative ? cls.str() : std::string("<none>"));
    out.push_back('\n');
    out.append("class generation   : ");
    out.append(std::to_string(class_generation.value));
    out.push_back('\n');
    out.append("precedence         : ");
    out.append(authoritative ? std::to_string(precedence.value) : std::string("<none>"));
    out.push_back('\n');
    out.append("reason code        : ");
    out.append(reason_code);
    out.push_back('\n');
    out.append("reason             : ");
    out.append(reason);
    out.push_back('\n');
    out.append("resolution         : ");
    out.append(resolution);
    out.push_back('\n');
    out.append("epoch              : ");
    out.append(std::to_string(epoch.value));
    out.push_back('\n');
    out.append("state generation   : ");
    out.append(std::to_string(state_generation.value));
    out.push_back('\n');
    out.append("policy generation  : ");
    out.append(std::to_string(policy_generation.value));
    out.push_back('\n');
    out.append("scope generation   : ");
    out.append(std::to_string(scope_generation.value));
    out.push_back('\n');
    out.append("decision digest    : ");
    out.append(digest.hex());
    out.push_back('\n');
    out.append("explanation chain  :\n");
    for (const auto& step : chain) {
        out.append("  [");
        out.append(step.stage);
        out.append("/");
        out.append(step.code);
        out.append("] ");
        out.append(step.detail);
        out.push_back('\n');
    }
    if (!superseded.empty()) {
        out.append("superseded evidence:\n");
        for (const auto& note : superseded) {
            out.append("  ");
            out.append(note.assignment.str());
            out.append(": ");
            out.append(note.reason);
            out.push_back('\n');
        }
    }
    if (!rejected_evidence.empty()) {
        out.append("rejected evidence  :\n");
        for (const auto& note : rejected_evidence) {
            out.append("  ");
            out.append(note.assignment.str());
            out.append(" [");
            out.append(note.reason_code);
            out.append("]: ");
            out.append(note.reason);
            out.push_back('\n');
        }
    }
    if (!conflicts.empty()) {
        out.append("conflicts          :\n");
        for (const auto& conflict : conflicts) {
            out.append("  ");
            out.append(conflict);
            out.push_back('\n');
        }
    }
    return out;
}

}  // namespace pf
