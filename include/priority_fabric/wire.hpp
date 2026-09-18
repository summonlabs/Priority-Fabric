// Priority Fabric -- authoritative network priority classes.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#ifndef PRIORITY_FABRIC_WIRE_HPP
#define PRIORITY_FABRIC_WIRE_HPP

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

#include "priority_fabric/decision.hpp"
#include "priority_fabric/export.hpp"
#include "priority_fabric/limits.hpp"
#include "priority_fabric/model.hpp"
#include "priority_fabric/model_codec.hpp"
#include "priority_fabric/runtime.hpp"
#include "priority_fabric/status.hpp"
#include "priority_fabric/version.hpp"

namespace pf {

/// Operations of the framed fabric protocol.
enum class Op : std::uint16_t {
    Hello = 1,       ///< client -> node: publisher id, boot id, client label, nonce
    HelloAck = 2,    ///< node -> client: granted epoch, fencing token, node identity
    DefineClass = 10,
    DefineScope = 11,
    DefinePolicy = 12,
    DefineSubject = 13,
    Assign = 14,
    Retire = 15,
    Query = 20,
    AdvanceEpoch = 30,
    Fence = 31,
    Stats = 40,
    Checkpoint = 41,
    Audit = 42,
    Integrity = 43,
    Ping = 50,
    Shutdown = 60,
    Response = 100,  ///< node -> client: generic successful reply carrying a typed payload
    Error = 101,     ///< node -> client: failure carrying StatusCode and a bounded message
};

[[nodiscard]] PF_API const char* to_string(Op op) noexcept;
[[nodiscard]] PF_API bool parse_op(std::string_view text, Op& out) noexcept;

/// Fixed frame header, little-endian on the wire:
///
///   u32 magic          DurableLayout-independent constant 0x50465731 ("PFW1")
///   u16 format         PRIORITY_FABRIC_FORMAT_VERSION
///   u16 op
///   u32 flags          reserved; a non-zero value is rejected, not ignored
///   u64 request_id
///   u32 payload_length
///   ... payload_length bytes ...
///   u32 crc32c         over the 24 header bytes followed by the payload
///
/// The decoder refuses oversized, truncated, mis-versioned, flag-carrying or
/// checksum-mismatched frames before looking at the payload body at all.
struct PF_API FrameHeader {
    static constexpr std::uint32_t kMagic = 0x50465731u;
    static constexpr std::size_t kHeaderBytes = 24;
    static constexpr std::size_t kTrailerBytes = 4;

    std::uint16_t format = PRIORITY_FABRIC_FORMAT_VERSION;
    Op op = Op::Ping;
    std::uint32_t flags = 0;
    std::uint64_t request_id = 0;
    std::uint32_t payload_length = 0;
};

/// Encodes a complete frame (header, payload, checksum).
[[nodiscard]] PF_API std::string encode_frame(const FrameHeader& header,
                                              std::string_view payload);

/// Result of decoding a frame header that has already been read.
struct PF_API DecodedFrame {
    FrameHeader header;
};

[[nodiscard]] PF_API VoidResult validate_frame_header(const FrameHeader& header,
                                                      const Limits& limits);

/// Verifies the checksum of a complete frame buffer. p buffer must contain
/// kHeaderBytes + payload_length + kTrailerBytes bytes.
[[nodiscard]] PF_API VoidResult verify_frame_checksum(const std::string& buffer,
                                                      const FrameHeader& header);

/// The authority block carried by every request after Hello.
struct PF_API WireSession {
    PublisherId publisher;
    BootId boot;
    FabricEpoch epoch;
    FencingToken token;

    [[nodiscard]] Session to_session() const {
        return Session{publisher, boot, epoch, token};
    }
    [[nodiscard]] static WireSession from_session(const Session& s) {
        return WireSession{s.publisher, s.boot, s.epoch, s.token};
    }
};

struct PF_API HelloRequest {
    PublisherId publisher;
    BootId boot;
    std::string client_label;
    std::uint64_t nonce = 0;
};

struct PF_API HelloResponse {
    PublisherId node_id;
    BootId node_boot;
    FabricEpoch epoch;
    FencingToken token;
    Generation state_generation = Generation::unset();
    std::uint64_t node_pid = 0;
};

/// A successful reply. The payload is a canonical encoding whose shape depends on the op.
struct PF_API WireReply {
    Op op = Op::Response;
    std::string payload;
};

// ---- typed request/reply encoders ------------------------------------------------------

[[nodiscard]] PF_API std::string encode_hello(const HelloRequest& request);
[[nodiscard]] PF_API Result<HelloRequest> decode_hello(const std::string& payload,
                                                       const Limits& limits);
[[nodiscard]] PF_API std::string encode_hello_response(const HelloResponse& response);
[[nodiscard]] PF_API Result<HelloResponse> decode_hello_response(const std::string& payload,
                                                                 const Limits& limits);

[[nodiscard]] PF_API std::string encode_session(const WireSession& session);
[[nodiscard]] PF_API Result<WireSession> decode_session(Decoder& decoder);

[[nodiscard]] PF_API std::string encode_retire_request(const PriorityAssignmentId& id,
                                                       std::string_view reason);
[[nodiscard]] PF_API Result<std::pair<PriorityAssignmentId, std::string>> decode_retire_request(
    const std::string& payload, const Limits& limits);

[[nodiscard]] PF_API std::string encode_fence_request(const PublisherId& publisher,
                                                      const BootId& boot, std::string_view reason);
struct PF_API FenceRequest {
    PublisherId publisher;
    BootId boot;
    std::string reason;
};
[[nodiscard]] PF_API Result<FenceRequest> decode_fence_request(const std::string& payload,
                                                               const Limits& limits);

[[nodiscard]] PF_API std::string encode_reason(std::string_view reason);
[[nodiscard]] PF_API Result<std::string> decode_reason(const std::string& payload,
                                                       const Limits& limits);

[[nodiscard]] PF_API std::string encode_stats_reply(const FabricStats& stats,
                                                    const StateStats& state,
                                                    const BootId& node_boot,
                                                    const PublisherId& node_id);
struct PF_API StatsReply {
    FabricStats stats;
    StateStats state;
    BootId node_boot;
    PublisherId node_id;
};
[[nodiscard]] PF_API Result<StatsReply> decode_stats_reply(const std::string& payload,
                                                           const Limits& limits);

[[nodiscard]] PF_API std::string encode_integrity_reply(const IntegrityReport& report);
[[nodiscard]] PF_API Result<IntegrityReport> decode_integrity_reply(const std::string& payload,
                                                                    const Limits& limits);

[[nodiscard]] PF_API std::string encode_error_reply(StatusCode code, std::string_view message);
struct PF_API ErrorReply {
    StatusCode code = StatusCode::Ok;
    std::string message;
};
[[nodiscard]] PF_API Result<ErrorReply> decode_error_reply(const std::string& payload,
                                                           const Limits& limits);

}  // namespace pf

#endif  // PRIORITY_FABRIC_WIRE_HPP
