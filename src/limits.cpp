// Priority Fabric -- authoritative network priority classes.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "priority_fabric/limits.hpp"

namespace pf {

Limits compiled_limits_ceiling() noexcept {
    return Limits{};
}

bool limits_within_compiled_ceiling(const Limits& l) noexcept {
    const Limits ceiling = compiled_limits_ceiling();
    return l.max_id_length <= ceiling.max_id_length &&
           l.max_description_length <= ceiling.max_description_length &&
           l.max_note_length <= ceiling.max_note_length &&
           l.max_classes <= ceiling.max_classes && l.max_scopes <= ceiling.max_scopes &&
           l.max_policies <= ceiling.max_policies && l.max_subjects <= ceiling.max_subjects &&
           l.max_assignments <= ceiling.max_assignments &&
           l.max_audit_entries <= ceiling.max_audit_entries &&
           l.max_publishers <= ceiling.max_publishers &&
           l.max_boots_per_publisher <= ceiling.max_boots_per_publisher &&
           l.max_scope_depth <= ceiling.max_scope_depth &&
           l.max_inheritance_depth <= ceiling.max_inheritance_depth &&
           l.max_inherits_from <= ceiling.max_inherits_from &&
           l.max_policy_classes <= ceiling.max_policy_classes &&
           l.max_explanation_steps <= ceiling.max_explanation_steps &&
           l.max_query_steps <= ceiling.max_query_steps &&
           l.max_record_payload <= ceiling.max_record_payload &&
           l.max_frame_payload <= ceiling.max_frame_payload &&
           l.max_state_bytes <= ceiling.max_state_bytes &&
           l.max_journal_segments <= ceiling.max_journal_segments &&
           l.max_connections <= ceiling.max_connections &&
           l.max_requests_per_connection <= ceiling.max_requests_per_connection &&
           l.max_audit_return <= ceiling.max_audit_return &&
           l.max_connect_attempts <= ceiling.max_connect_attempts &&
           l.max_reopen_attempts <= ceiling.max_reopen_attempts &&
           l.max_id_length > 0 && l.max_classes > 0 && l.max_scopes > 0 && l.max_policies > 0 &&
           l.max_subjects > 0 && l.max_assignments > 0 && l.max_scope_depth > 0 &&
           l.max_inheritance_depth > 0 && l.max_explanation_steps > 0 &&
           l.max_query_steps > 0 && l.max_record_payload > 0 && l.max_frame_payload > 0 &&
           l.max_connections > 0;
}

}  // namespace pf
