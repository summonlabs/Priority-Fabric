// Priority Fabric -- authoritative network priority classes.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#ifndef PRIORITY_FABRIC_MODEL_CODEC_HPP
#define PRIORITY_FABRIC_MODEL_CODEC_HPP

#include <string>

#include "priority_fabric/codec.hpp"
#include "priority_fabric/decision.hpp"
#include "priority_fabric/export.hpp"
#include "priority_fabric/limits.hpp"
#include "priority_fabric/model.hpp"
#include "priority_fabric/status.hpp"

namespace pf {

/// Canonical encodings of the fabric's domain types. The same bytes are used for durable
/// journal records, snapshots and protocol payloads, so a value that round-trips through
/// any of them is identical. Every decoder enforces the limits it was given and rejects
/// trailing bytes.
[[nodiscard]] PF_API std::string encode_provenance(const Provenance& provenance);
[[nodiscard]] PF_API Result<Provenance> decode_provenance(Decoder& decoder);

[[nodiscard]] PF_API std::string encode_class_definition(const PriorityClassDef& definition);
[[nodiscard]] PF_API Result<PriorityClassDef> decode_class_definition(const std::string& payload,
                                                                      const Limits& limits);
[[nodiscard]] PF_API std::string encode_scope_definition(const PolicyScopeDef& definition);
[[nodiscard]] PF_API Result<PolicyScopeDef> decode_scope_definition(const std::string& payload,
                                                                    const Limits& limits);
[[nodiscard]] PF_API std::string encode_policy_definition(const PolicyDef& definition);
[[nodiscard]] PF_API Result<PolicyDef> decode_policy_definition(const std::string& payload,
                                                                const Limits& limits);
[[nodiscard]] PF_API std::string encode_subject_definition(const SubjectDef& definition);
[[nodiscard]] PF_API Result<SubjectDef> decode_subject_definition(const std::string& payload,
                                                                  const Limits& limits);
[[nodiscard]] PF_API std::string encode_assignment(const PriorityAssignment& assignment);
[[nodiscard]] PF_API Result<PriorityAssignment> decode_assignment(const std::string& payload,
                                                                  const Limits& limits);
[[nodiscard]] PF_API std::string encode_audit_entry(const AuditEntry& entry);
[[nodiscard]] PF_API Result<AuditEntry> decode_audit_entry(Decoder& decoder);

[[nodiscard]] PF_API std::string encode_query(const PriorityQuery& query);
[[nodiscard]] PF_API Result<PriorityQuery> decode_query(const std::string& payload,
                                                        const Limits& limits);
[[nodiscard]] PF_API std::string encode_decision(const PriorityDecision& decision);
[[nodiscard]] PF_API Result<PriorityDecision> decode_decision(const std::string& payload,
                                                              const Limits& limits);

[[nodiscard]] PF_API std::string encode_generation(Generation generation);
[[nodiscard]] PF_API Result<Generation> decode_generation(const std::string& payload);
[[nodiscard]] PF_API std::string encode_epoch(FabricEpoch epoch);
[[nodiscard]] PF_API Result<FabricEpoch> decode_epoch(const std::string& payload);

}  // namespace pf

#endif  // PRIORITY_FABRIC_MODEL_CODEC_HPP
