// Priority Fabric -- authoritative network priority classes.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "priority_fabric/wire.hpp"

#include <cstring>

#include "priority_fabric/checked.hpp"
#include "priority_fabric/text.hpp"
#include "priority_fabric/version.hpp"

namespace pf {
namespace {

void append_le(std::string& buffer, std::uint64_t value, std::size_t width) {
    for (std::size_t i = 0; i < width; ++i) {
        buffer.push_back(static_cast<char>((value >> (8 * i)) & 0xFFu));
    }
}

std::uint64_t read_le(const std::uint8_t* data, std::size_t width) noexcept {
    std::uint64_t value = 0;
    for (std::size_t i = 0; i < width; ++i) {
        value |= static_cast<std::uint64_t>(data[i]) << (8 * i);
    }
    return value;
}

}  // namespace

const char* to_string(Op op) noexcept {
    switch (op) {
        case Op::Hello: return "hello";
        case Op::HelloAck: return "hello_ack";
        case Op::DefineClass: return "define_class";
        case Op::DefineScope: return "define_scope";
        case Op::DefinePolicy: return "define_policy";
        case Op::DefineSubject: return "define_subject";
        case Op::Assign: return "assign";
        case Op::Retire: return "retire";
        case Op::Query: return "query";
        case Op::AdvanceEpoch: return "advance_epoch";
        case Op::Fence: return "fence";
        case Op::Stats: return "stats";
        case Op::Checkpoint: return "checkpoint";
        case Op::Audit: return "audit";
        case Op::Integrity: return "integrity";
        case Op::Ping: return "ping";
        case Op::Shutdown: return "shutdown";
        case Op::Response: return "response";
        case Op::Error: return "error";
    }
    return "unknown";
}

bool parse_op(std::string_view text, Op& out) noexcept {
    const std::string lowered = ascii_lower(text);
    if (lowered == "hello") { out = Op::Hello; return true; }
    if (lowered == "define-class") { out = Op::DefineClass; return true; }
    if (lowered == "define-scope") { out = Op::DefineScope; return true; }
    if (lowered == "define-policy") { out = Op::DefinePolicy; return true; }
    if (lowered == "define-subject") { out = Op::DefineSubject; return true; }
    if (lowered == "assign") { out = Op::Assign; return true; }
    if (lowered == "retire") { out = Op::Retire; return true; }
    if (lowered == "query") { out = Op::Query; return true; }
    if (lowered == "advance-epoch") { out = Op::AdvanceEpoch; return true; }
    if (lowered == "fence") { out = Op::Fence; return true; }
    if (lowered == "stats") { out = Op::Stats; return true; }
    if (lowered == "checkpoint") { out = Op::Checkpoint; return true; }
    if (lowered == "audit") { out = Op::Audit; return true; }
    if (lowered == "integrity") { out = Op::Integrity; return true; }
    if (lowered == "ping") { out = Op::Ping; return true; }
    if (lowered == "shutdown") { out = Op::Shutdown; return true; }
    return false;
}

// ---------------------------------------------------------------------------------------
// Framing
// ---------------------------------------------------------------------------------------

std::string encode_frame(const FrameHeader& header, std::string_view payload) {
    std::string frame;
    frame.reserve(FrameHeader::kHeaderBytes + payload.size() + FrameHeader::kTrailerBytes);
    append_le(frame, FrameHeader::kMagic, 4);
    append_le(frame, header.format, 2);
    append_le(frame, static_cast<std::uint64_t>(header.op), 2);
    append_le(frame, header.flags, 4);
    append_le(frame, header.request_id, 8);
    append_le(frame, static_cast<std::uint64_t>(payload.size()), 4);
    frame.append(payload);
    append_le(frame, crc32c(frame.data(), frame.size()), 4);
    return frame;
}

VoidResult validate_frame_header(const FrameHeader& header, const Limits& limits) {
    if (header.format != PRIORITY_FABRIC_FORMAT_VERSION) {
        return make_error(StatusCode::ProtocolError,
                          "frame declares format version " + std::to_string(header.format) +
                              "; this build implements " +
                              std::to_string(PRIORITY_FABRIC_FORMAT_VERSION));
    }
    if (header.flags != 0) {
        return make_error(StatusCode::ProtocolError,
                          "frame carries reserved flags (" + std::to_string(header.flags) +
                              "); reserved bits are rejected rather than ignored");
    }
    if (header.payload_length > limits.max_frame_payload) {
        return make_error(StatusCode::LimitExceeded,
                          "frame declares a payload of " + std::to_string(header.payload_length) +
                              " bytes, limit is " + std::to_string(limits.max_frame_payload));
    }
    return VoidResult{};
}

VoidResult verify_frame_checksum(const std::string& buffer, const FrameHeader& header) {
    const std::size_t expected =
        FrameHeader::kHeaderBytes + header.payload_length + FrameHeader::kTrailerBytes;
    if (buffer.size() != expected) {
        return make_error(StatusCode::ProtocolError,
                          "frame buffer holds " + std::to_string(buffer.size()) +
                              " bytes but the header describes " + std::to_string(expected));
    }
    const std::size_t covered = buffer.size() - FrameHeader::kTrailerBytes;
    const std::uint32_t actual = crc32c(buffer.data(), covered);
    const std::uint32_t declared = static_cast<std::uint32_t>(
        read_le(reinterpret_cast<const std::uint8_t*>(buffer.data()) + covered, 4));
    if (actual != declared) {
        return make_error(StatusCode::ProtocolError, "frame checksum mismatch");
    }
    return VoidResult{};
}

// ---------------------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------------------

std::string encode_hello(const HelloRequest& request) {
    Encoder encoder;
    encoder.str(request.publisher.str());
    encoder.raw(request.boot.bytes.data(), request.boot.bytes.size());
    encoder.str(bound_text(request.client_label, 128));
    encoder.u64(request.nonce);
    return encoder.take();
}

Result<HelloRequest> decode_hello(const std::string& payload, const Limits& limits) {
    Decoder decoder(payload.data(), payload.size(), limits);
    HelloRequest request;
    auto publisher = decoder.id<PublisherTag>();
    if (!publisher.ok()) {
        return publisher.status();
    }
    request.publisher = std::move(publisher.value());
    auto boot = decoder.raw(BootId::kSize);
    if (!boot.ok()) {
        return boot.status();
    }
    for (std::size_t i = 0; i < BootId::kSize; ++i) {
        request.boot.bytes[i] = static_cast<std::uint8_t>(boot.value()[i]);
    }
    auto label = decoder.str(128);
    if (!label.ok()) {
        return label.status();
    }
    request.client_label = std::move(label.value());
    auto nonce = decoder.u64();
    if (!nonce.ok()) {
        return nonce.status();
    }
    request.nonce = nonce.value();
    auto finished = decoder.finish();
    if (!finished.ok()) {
        return finished.status();
    }
    return request;
}

std::string encode_hello_response(const HelloResponse& response) {
    Encoder encoder;
    encoder.str(response.node_id.str());
    encoder.raw(response.node_boot.bytes.data(), response.node_boot.bytes.size());
    encoder.u64(response.epoch.value);
    encoder.u64(response.token.value);
    encoder.u64(response.state_generation.value);
    encoder.u64(response.node_pid);
    return encoder.take();
}

Result<HelloResponse> decode_hello_response(const std::string& payload, const Limits& limits) {
    Decoder decoder(payload.data(), payload.size(), limits);
    HelloResponse response;
    auto node_id = decoder.id<PublisherTag>();
    if (!node_id.ok()) {
        return node_id.status();
    }
    response.node_id = std::move(node_id.value());
    auto node_boot = decoder.raw(BootId::kSize);
    if (!node_boot.ok()) {
        return node_boot.status();
    }
    for (std::size_t i = 0; i < BootId::kSize; ++i) {
        response.node_boot.bytes[i] = static_cast<std::uint8_t>(node_boot.value()[i]);
    }
    auto epoch = decoder.u64();
    if (!epoch.ok()) {
        return epoch.status();
    }
    response.epoch = FabricEpoch{epoch.value()};
    auto token = decoder.u64();
    if (!token.ok()) {
        return token.status();
    }
    response.token = FencingToken{token.value()};
    auto generation = decoder.u64();
    if (!generation.ok()) {
        return generation.status();
    }
    response.state_generation = Generation{generation.value()};
    auto pid = decoder.u64();
    if (!pid.ok()) {
        return pid.status();
    }
    response.node_pid = pid.value();
    auto finished = decoder.finish();
    if (!finished.ok()) {
        return finished.status();
    }
    return response;
}

std::string encode_session(const WireSession& session) {
    Encoder encoder;
    encoder.str(session.publisher.str());
    encoder.raw(session.boot.bytes.data(), session.boot.bytes.size());
    encoder.u64(session.epoch.value);
    encoder.u64(session.token.value);
    return encoder.take();
}

Result<WireSession> decode_session(Decoder& decoder) {
    WireSession session;
    auto publisher = decoder.id<PublisherTag>();
    if (!publisher.ok()) {
        return publisher.status();
    }
    session.publisher = std::move(publisher.value());
    auto boot = decoder.raw(BootId::kSize);
    if (!boot.ok()) {
        return boot.status();
    }
    for (std::size_t i = 0; i < BootId::kSize; ++i) {
        session.boot.bytes[i] = static_cast<std::uint8_t>(boot.value()[i]);
    }
    auto epoch = decoder.u64();
    if (!epoch.ok()) {
        return epoch.status();
    }
    session.epoch = FabricEpoch{epoch.value()};
    auto token = decoder.u64();
    if (!token.ok()) {
        return token.status();
    }
    session.token = FencingToken{token.value()};
    return session;
}

std::string encode_retire_request(const PriorityAssignmentId& id, std::string_view reason) {
    Encoder encoder;
    encoder.str(id.str());
    encoder.str(bound_text(reason, 512));
    return encoder.take();
}

Result<std::pair<PriorityAssignmentId, std::string>> decode_retire_request(
    const std::string& payload, const Limits& limits) {
    Decoder decoder(payload.data(), payload.size(), limits);
    auto id = decoder.id<PriorityAssignmentTag>();
    if (!id.ok()) {
        return id.status();
    }
    auto reason = decoder.str(limits.max_note_length);
    if (!reason.ok()) {
        return reason.status();
    }
    auto finished = decoder.finish();
    if (!finished.ok()) {
        return finished.status();
    }
    return std::make_pair(std::move(id.value()), std::move(reason.value()));
}

std::string encode_fence_request(const PublisherId& publisher, const BootId& boot,
                                 std::string_view reason) {
    Encoder encoder;
    encoder.str(publisher.str());
    encoder.raw(boot.bytes.data(), boot.bytes.size());
    encoder.str(bound_text(reason, 512));
    return encoder.take();
}

Result<FenceRequest> decode_fence_request(const std::string& payload, const Limits& limits) {
    Decoder decoder(payload.data(), payload.size(), limits);
    FenceRequest request;
    auto publisher = decoder.id<PublisherTag>();
    if (!publisher.ok()) {
        return publisher.status();
    }
    request.publisher = std::move(publisher.value());
    auto boot = decoder.raw(BootId::kSize);
    if (!boot.ok()) {
        return boot.status();
    }
    for (std::size_t i = 0; i < BootId::kSize; ++i) {
        request.boot.bytes[i] = static_cast<std::uint8_t>(boot.value()[i]);
    }
    auto reason = decoder.str(limits.max_note_length);
    if (!reason.ok()) {
        return reason.status();
    }
    request.reason = std::move(reason.value());
    auto finished = decoder.finish();
    if (!finished.ok()) {
        return finished.status();
    }
    return request;
}

std::string encode_reason(std::string_view reason) {
    Encoder encoder;
    encoder.str(bound_text(reason, 512));
    return encoder.take();
}

Result<std::string> decode_reason(const std::string& payload, const Limits& limits) {
    Decoder decoder(payload.data(), payload.size(), limits);
    auto reason = decoder.str(limits.max_note_length);
    if (!reason.ok()) {
        return reason.status();
    }
    auto finished = decoder.finish();
    if (!finished.ok()) {
        return finished.status();
    }
    return reason.value();
}

std::string encode_stats_reply(const FabricStats& stats, const StateStats& state,
                               const BootId& node_boot, const PublisherId& node_id) {
    Encoder encoder;
    encoder.str(node_id.str());
    encoder.raw(node_boot.bytes.data(), node_boot.bytes.size());
    encoder.u64(stats.evaluations);
    encoder.u64(stats.evaluations_assigned);
    encoder.u64(stats.evaluations_inherited);
    encoder.u64(stats.evaluations_overridden);
    encoder.u64(stats.evaluations_conflict);
    encoder.u64(stats.evaluations_unknown);
    encoder.u64(stats.evaluations_stale);
    encoder.u64(stats.evaluations_fenced);
    encoder.u64(stats.evaluations_rejected);
    encoder.u64(stats.mutations_accepted);
    encoder.u64(stats.mutations_rejected);
    encoder.u64(stats.idempotent_noops);
    encoder.u64(stats.durable_commits);
    encoder.u64(stats.recoveries);
    encoder.u64(stats.epoch_advances);
    encoder.u64(stats.fences_issued);
    encoder.u64(stats.authorities_granted);
    encoder.u64(state.classes);
    encoder.u64(state.scopes);
    encoder.u64(state.policies);
    encoder.u64(state.subjects);
    encoder.u64(state.assignments);
    encoder.u64(state.retired_assignments);
    encoder.u64(state.publishers);
    encoder.u64(state.fenced_boots);
    encoder.u64(state.audit_entries);
    encoder.u64(state.durable_bytes);
    encoder.u64(state.journal_records);
    encoder.u64(state.state_generation.value);
    encoder.u64(state.epoch.value);
    return encoder.take();
}

Result<StatsReply> decode_stats_reply(const std::string& payload, const Limits& limits) {
    Decoder decoder(payload.data(), payload.size(), limits);
    StatsReply reply;
    auto node_id = decoder.id<PublisherTag>();
    if (!node_id.ok()) {
        return node_id.status();
    }
    reply.node_id = std::move(node_id.value());
    auto node_boot = decoder.raw(BootId::kSize);
    if (!node_boot.ok()) {
        return node_boot.status();
    }
    for (std::size_t i = 0; i < BootId::kSize; ++i) {
        reply.node_boot.bytes[i] = static_cast<std::uint8_t>(node_boot.value()[i]);
    }
    std::uint64_t* fields[] = {
        &reply.stats.evaluations,
        &reply.stats.evaluations_assigned,
        &reply.stats.evaluations_inherited,
        &reply.stats.evaluations_overridden,
        &reply.stats.evaluations_conflict,
        &reply.stats.evaluations_unknown,
        &reply.stats.evaluations_stale,
        &reply.stats.evaluations_fenced,
        &reply.stats.evaluations_rejected,
        &reply.stats.mutations_accepted,
        &reply.stats.mutations_rejected,
        &reply.stats.idempotent_noops,
        &reply.stats.durable_commits,
        &reply.stats.recoveries,
        &reply.stats.epoch_advances,
        &reply.stats.fences_issued,
        &reply.stats.authorities_granted,
        &reply.state.classes,
        &reply.state.scopes,
        &reply.state.policies,
        &reply.state.subjects,
        &reply.state.assignments,
        &reply.state.retired_assignments,
        &reply.state.publishers,
        &reply.state.fenced_boots,
        &reply.state.audit_entries,
        &reply.state.durable_bytes,
        &reply.state.journal_records,
        &reply.state.state_generation.value,
        &reply.state.epoch.value,
    };
    for (std::uint64_t* field : fields) {
        auto value = decoder.u64();
        if (!value.ok()) {
            return value.status();
        }
        *field = value.value();
    }
    auto finished = decoder.finish();
    if (!finished.ok()) {
        return finished.status();
    }
    return reply;
}

std::string encode_integrity_reply(const IntegrityReport& report) {
    Encoder encoder;
    encoder.boolean(report.ok);
    encoder.u8(static_cast<std::uint8_t>(report.health));
    encoder.u64(report.records_scanned);
    encoder.u64(report.records_applied);
    encoder.u64(report.records_rejected);
    encoder.u64(report.unfinished_attempts);
    encoder.u64(report.trailing_bytes_discarded);
    encoder.str(bound_text(report.detail, 1024));
    encoder.raw(report.state_digest.bytes.data(), report.state_digest.bytes.size());
    encoder.u64(report.state_generation.value);
    encoder.u64(report.epoch.value);
    return encoder.take();
}

Result<IntegrityReport> decode_integrity_reply(const std::string& payload, const Limits& limits) {
    Decoder decoder(payload.data(), payload.size(), limits);
    IntegrityReport report;
    auto ok = decoder.boolean();
    if (!ok.ok()) {
        return ok.status();
    }
    report.ok = ok.value();
    auto health = decoder.u8();
    if (!health.ok()) {
        return health.status();
    }
    if (health.value() > static_cast<std::uint8_t>(Health::Degraded)) {
        return make_error(StatusCode::ProtocolError, "integrity reply carries an unknown health");
    }
    report.health = static_cast<Health>(health.value());
    auto scanned = decoder.u64();
    if (!scanned.ok()) {
        return scanned.status();
    }
    report.records_scanned = scanned.value();
    auto applied = decoder.u64();
    if (!applied.ok()) {
        return applied.status();
    }
    report.records_applied = applied.value();
    auto rejected = decoder.u64();
    if (!rejected.ok()) {
        return rejected.status();
    }
    report.records_rejected = rejected.value();
    auto unfinished = decoder.u64();
    if (!unfinished.ok()) {
        return unfinished.status();
    }
    report.unfinished_attempts = unfinished.value();
    auto discarded = decoder.u64();
    if (!discarded.ok()) {
        return discarded.status();
    }
    report.trailing_bytes_discarded = discarded.value();
    auto detail = decoder.str(1024);
    if (!detail.ok()) {
        return detail.status();
    }
    report.detail = std::move(detail.value());
    auto digest = decoder.raw(Digest::kSize);
    if (!digest.ok()) {
        return digest.status();
    }
    for (std::size_t i = 0; i < Digest::kSize; ++i) {
        report.state_digest.bytes[i] = static_cast<std::uint8_t>(digest.value()[i]);
    }
    auto generation = decoder.u64();
    if (!generation.ok()) {
        return generation.status();
    }
    report.state_generation = Generation{generation.value()};
    auto epoch = decoder.u64();
    if (!epoch.ok()) {
        return epoch.status();
    }
    report.epoch = FabricEpoch{epoch.value()};
    auto finished = decoder.finish();
    if (!finished.ok()) {
        return finished.status();
    }
    return report;
}

std::string encode_error_reply(StatusCode code, std::string_view message) {
    Encoder encoder;
    encoder.u16(static_cast<std::uint16_t>(code));
    encoder.str(bound_text(message, 1024));
    return encoder.take();
}

Result<ErrorReply> decode_error_reply(const std::string& payload, const Limits& limits) {
    Decoder decoder(payload.data(), payload.size(), limits);
    ErrorReply reply;
    auto code = decoder.u16();
    if (!code.ok()) {
        return code.status();
    }
    if (code.value() > static_cast<std::uint16_t>(StatusCode::BoundaryViolation)) {
        return make_error(StatusCode::ProtocolError,
                          "error reply carries an undefined status code");
    }
    reply.code = static_cast<StatusCode>(code.value());
    auto message = decoder.str(1024);
    if (!message.ok()) {
        return message.status();
    }
    reply.message = std::move(message.value());
    auto finished = decoder.finish();
    if (!finished.ok()) {
        return finished.status();
    }
    return reply;
}

}  // namespace pf
