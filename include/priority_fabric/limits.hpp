// Priority Fabric -- authoritative network priority classes.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#ifndef PRIORITY_FABRIC_LIMITS_HPP
#define PRIORITY_FABRIC_LIMITS_HPP

#include <cstdint>

#include "priority_fabric/export.hpp"

namespace pf {

/// Every externally influenced size, count and depth is bounded here. Nothing in the
/// fabric sizes a container, a buffer, an explanation or a durable artifact from an
/// unbounded input. Callers may lower these values; raising them above the compiled
/// defaults is deliberately not supported for the transient values that protect the
/// evaluation path from adversarial input.
struct Limits {
    // ---- identifiers and human text -------------------------------------------------
    std::uint32_t max_id_length = 128;             ///< bytes, canonical form
    std::uint32_t max_description_length = 1024;   ///< bytes
    std::uint32_t max_note_length = 512;           ///< bytes

    // ---- population bounds ----------------------------------------------------------
    std::uint32_t max_classes = 65536;
    std::uint32_t max_scopes = 16384;
    std::uint32_t max_policies = 16384;
    std::uint32_t max_subjects = 262144;
    std::uint32_t max_assignments = 1048576;
    std::uint32_t max_audit_entries = 65536;
    std::uint32_t max_publishers = 4096;
    std::uint32_t max_boots_per_publisher = 64;

    // ---- structural depth bounds ----------------------------------------------------
    std::uint32_t max_scope_depth = 32;         ///< scope chain length
    std::uint32_t max_inheritance_depth = 32;   ///< subject/class inheritance chain length
    std::uint32_t max_inherits_from = 16;       ///< direct parents per class or subject
    std::uint32_t max_policy_classes = 4096;    ///< classes visible to one policy
    std::uint32_t max_explanation_steps = 64;   ///< steps in one decision explanation
    std::uint32_t max_query_steps = 256;        ///< internal evaluation budget per query

    // ---- durable / wire bounds ------------------------------------------------------
    std::uint32_t max_record_payload = 1048576;    ///< 1 MiB per journal record
    std::uint32_t max_frame_payload = 4194304;     ///< 4 MiB per transport frame
    std::uint64_t max_state_bytes = 268435456ull;  ///< 256 MiB durable growth bound
    std::uint32_t max_journal_segments = 1024;
    std::uint32_t max_connections = 64;
    std::uint64_t max_requests_per_connection = 1048576ull;
    std::uint32_t max_audit_return = 4096;

    // ---- timing / attempts ----------------------------------------------------------
    std::uint32_t max_connect_attempts = 400;   ///< bounded retry for a listener to appear
    std::uint32_t max_reopen_attempts = 8;      ///< bounded retry for a locked durable file

    friend bool operator==(const Limits&, const Limits&) = default;
};

/// Limits that are compiled into the evaluation path and may never be raised at runtime.
[[nodiscard]] PF_API bool limits_within_compiled_ceiling(const Limits& l) noexcept;

/// The compiled ceiling for each limit; values above these are rejected.
[[nodiscard]] PF_API Limits compiled_limits_ceiling() noexcept;

}  // namespace pf

#endif  // PRIORITY_FABRIC_LIMITS_HPP
