// Priority Fabric -- authoritative network priority classes.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "priority_fabric/status.hpp"

#include "priority_fabric/limits.hpp"
#include "priority_fabric/text.hpp"

namespace pf {
namespace {

constexpr std::size_t kMaxStatusMessage = 1024;

}  // namespace

const char* to_string(StatusCode code) noexcept {
    switch (code) {
        case StatusCode::Ok: return "ok";
        case StatusCode::InvalidArgument: return "invalid_argument";
        case StatusCode::MalformedId: return "malformed_id";
        case StatusCode::NotFound: return "not_found";
        case StatusCode::AlreadyExists: return "already_exists";
        case StatusCode::DuplicatePrecedence: return "duplicate_precedence";
        case StatusCode::CycleDetected: return "cycle_detected";
        case StatusCode::GenerationMismatch: return "generation_mismatch";
        case StatusCode::StaleGeneration: return "stale_generation";
        case StatusCode::StaleEpoch: return "stale_epoch";
        case StatusCode::Fenced: return "fenced";
        case StatusCode::Unauthorized: return "unauthorized";
        case StatusCode::Conflict: return "conflict";
        case StatusCode::LimitExceeded: return "limit_exceeded";
        case StatusCode::Overflow: return "overflow";
        case StatusCode::Corrupt: return "corrupt";
        case StatusCode::Truncated: return "truncated";
        case StatusCode::IntegrityFailure: return "integrity_failure";
        case StatusCode::IoError: return "io_error";
        case StatusCode::Unsupported: return "unsupported";
        case StatusCode::NotReady: return "not_ready";
        case StatusCode::Degraded: return "degraded";
        case StatusCode::Cancelled: return "cancelled";
        case StatusCode::Internal: return "internal";
        case StatusCode::TransportError: return "transport_error";
        case StatusCode::ProtocolError: return "protocol_error";
        case StatusCode::BoundaryViolation: return "boundary_violation";
    }
    return "unknown_status";
}

Status Status::failure(StatusCode code, std::string_view message) {
    Status s;
    s.code_ = code;
    s.message_ = bound_text(message, kMaxStatusMessage);
    return s;
}

std::string Status::to_string() const {
    if (ok()) {
        return "ok";
    }
    std::string out = pf::to_string(code_);
    if (!message_.empty()) {
        out.append(": ");
        out.append(message_);
    }
    return out;
}

Status make_error(StatusCode code, std::string_view message) {
    return Status::failure(code, message);
}

}  // namespace pf
