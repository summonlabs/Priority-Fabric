// Priority Fabric -- authoritative network priority classes.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "priority_fabric/client.hpp"

#include <string>
#include <utility>

#include "net.hpp"
#include "priority_fabric/text.hpp"
#include "priority_fabric/wire.hpp"

namespace pf {
namespace {

std::uint64_t read_le(const std::uint8_t* data, std::size_t width) noexcept {
    std::uint64_t value = 0;
    for (std::size_t i = 0; i < width; ++i) {
        value |= static_cast<std::uint64_t>(data[i]) << (8 * i);
    }
    return value;
}

std::string encode_session_request(const Session& session, std::string_view inner) {
    Encoder encoder;
    encoder.str(encode_session(WireSession::from_session(session)));
    encoder.raw(inner.data(), inner.size());
    return encoder.take();
}

}  // namespace

namespace {

/// The client's mutable state. It lives at namespace scope so that the free helpers below
/// can use it; NodeClient::Impl is that state and nothing else.
struct ClientState {
    NodeClient::Options options;
    net::Socket socket;
    Session session;
    std::uint64_t next_request_id = 1;
};

/// Sends one request and reads exactly one reply frame. Every failure path returns an error;
/// there is no path on which a malformed, mismatched or unauthenticated reply becomes a
/// successful result.
Result<std::string> round_trip(ClientState& impl, Op op, const std::string& body) {
    if (!impl.socket.valid()) {
        return make_error(StatusCode::NotReady, "the client is not connected");
    }
    const std::uint64_t request_id = impl.next_request_id++;
    const std::string frame = encode_frame(
        FrameHeader{PRIORITY_FABRIC_FORMAT_VERSION, op, 0, request_id,
                    static_cast<std::uint32_t>(body.size())},
        body);
    auto sent = net::send_all(impl.socket.handle(), frame.data(), frame.size());
    if (!sent.ok()) {
        return sent.status();
    }

    std::string header_bytes(FrameHeader::kHeaderBytes, '\0');
    auto header_status =
        net::recv_exact(impl.socket.handle(), header_bytes.data(), header_bytes.size());
    if (!header_status.ok()) {
        return header_status.status();
    }
    const auto* header = reinterpret_cast<const std::uint8_t*>(header_bytes.data());
    if (read_le(header, 4) != FrameHeader::kMagic) {
        return make_error(StatusCode::ProtocolError, "the reply does not carry the fabric magic");
    }
    FrameHeader reply;
    reply.format = static_cast<std::uint16_t>(read_le(header + 4, 2));
    reply.op = static_cast<Op>(read_le(header + 6, 2));
    reply.flags = static_cast<std::uint32_t>(read_le(header + 8, 4));
    reply.request_id = read_le(header + 12, 8);
    reply.payload_length = static_cast<std::uint32_t>(read_le(header + 20, 4));

    auto header_ok = validate_frame_header(reply, impl.options.limits);
    if (!header_ok.ok()) {
        return header_ok.status();
    }
    if (reply.op != Op::Response && reply.op != Op::Error) {
        return make_error(StatusCode::ProtocolError,
                          "the node answered with '" + std::string(to_string(reply.op)) +
                              "' where a reply was expected");
    }
    if (reply.request_id != request_id) {
        return make_error(StatusCode::ProtocolError,
                          "the reply names request " + std::to_string(reply.request_id) +
                              " but request " + std::to_string(request_id) + " was sent");
    }

    std::string remainder(static_cast<std::size_t>(reply.payload_length) +
                              FrameHeader::kTrailerBytes,
                          '\0');
    auto body_status = net::recv_exact(impl.socket.handle(), remainder.data(), remainder.size());
    if (!body_status.ok()) {
        return body_status.status();
    }
    std::string buffer = header_bytes + remainder;
    auto checksum = verify_frame_checksum(buffer, reply);
    if (!checksum.ok()) {
        return checksum.status();
    }
    const std::string payload = buffer.substr(FrameHeader::kHeaderBytes, reply.payload_length);

    if (reply.op == Op::Error) {
        auto error = decode_error_reply(payload, impl.options.limits);
        if (!error.ok()) {
            return error.status();
        }
        return Status::failure(error.value().code, error.value().message);
    }
    return payload;
}

}  // namespace

struct NodeClient::Impl : ClientState {};

NodeClient::NodeClient() : impl_(std::make_unique<Impl>()) {}
NodeClient::~NodeClient() = default;
NodeClient::NodeClient(NodeClient&&) noexcept = default;
NodeClient& NodeClient::operator=(NodeClient&&) noexcept = default;

VoidResult NodeClient::connect(const Options& options) {
    if (!impl_) {
        return make_error(StatusCode::NotReady, "the client was never constructed");
    }
    if (!limits_within_compiled_ceiling(options.limits)) {
        return make_error(StatusCode::LimitExceeded, "the requested limits exceed the ceiling");
    }
    if (options.port == 0) {
        return make_error(StatusCode::InvalidArgument, "no port was given");
    }
    impl_->options = options;
    auto socket = net::connect_to(options.host, options.port, options.connect_attempts,
                                  options.connect_retry_delay_ms);
    if (!socket.ok()) {
        return socket.status();
    }
    if (options.io_deadline_ms > 0) {
        auto deadline = net::set_io_deadline(socket.value().handle(), options.io_deadline_ms);
        if (!deadline.ok()) {
            return deadline.status();
        }
    }
    impl_->socket = std::move(socket.value());
    impl_->session = Session{};
    impl_->next_request_id = 1;
    return VoidResult{};
}

bool NodeClient::connected() const noexcept {
    return impl_ && impl_->socket.valid();
}

void NodeClient::disconnect() {
    if (!impl_) {
        return;
    }
    impl_->socket.close();
    impl_->session = Session{};
}

Result<HelloResponse> NodeClient::hello(const PublisherId& publisher, const BootId& boot,
                                        std::string_view client_label) {
    if (!impl_) {
        return make_error(StatusCode::NotReady, "the client was never constructed");
    }
    if (!publisher.valid() || !boot.valid()) {
        return make_error(StatusCode::InvalidArgument,
                          "the handshake needs a publisher id and a boot id");
    }
    HelloRequest request;
    request.publisher = publisher;
    request.boot = boot;
    request.client_label = std::string(bound_text(client_label, 128));
    request.nonce = impl_->next_request_id;

    auto payload = round_trip(*impl_, Op::Hello, encode_hello(request));
    if (!payload.ok()) {
        return payload.status();
    }
    auto response = decode_hello_response(payload.value(), impl_->options.limits);
    if (!response.ok()) {
        return response.status();
    }
    impl_->session = Session{publisher, boot, response.value().epoch, response.value().token};
    return response.value();
}

const Session& NodeClient::session() const noexcept {
    static const Session empty;
    return impl_ ? impl_->session : empty;
}

void NodeClient::set_session(const Session& session) {
    if (impl_) {
        impl_->session = session;
    }
}

Result<Generation> NodeClient::define_class(const PriorityClassDef& definition) {
    auto payload = round_trip(*impl_, Op::DefineClass,
                              encode_session_request(impl_->session,
                                                     encode_class_definition(definition)));
    if (!payload.ok()) {
        return payload.status();
    }
    return decode_generation(payload.value());
}

Result<Generation> NodeClient::define_scope(const PolicyScopeDef& definition) {
    auto payload = round_trip(*impl_, Op::DefineScope,
                              encode_session_request(impl_->session,
                                                     encode_scope_definition(definition)));
    if (!payload.ok()) {
        return payload.status();
    }
    return decode_generation(payload.value());
}

Result<Generation> NodeClient::define_policy(const PolicyDef& definition) {
    auto payload = round_trip(*impl_, Op::DefinePolicy,
                              encode_session_request(impl_->session,
                                                     encode_policy_definition(definition)));
    if (!payload.ok()) {
        return payload.status();
    }
    return decode_generation(payload.value());
}

Result<Generation> NodeClient::define_subject(const SubjectDef& definition) {
    auto payload = round_trip(*impl_, Op::DefineSubject,
                              encode_session_request(impl_->session,
                                                     encode_subject_definition(definition)));
    if (!payload.ok()) {
        return payload.status();
    }
    return decode_generation(payload.value());
}

Result<Generation> NodeClient::assign(const PriorityAssignment& assignment) {
    auto payload = round_trip(
        *impl_, Op::Assign,
        encode_session_request(impl_->session, encode_assignment(assignment)));
    if (!payload.ok()) {
        return payload.status();
    }
    return decode_generation(payload.value());
}

Result<Generation> NodeClient::retire_assignment(const PriorityAssignmentId& id,
                                                std::string_view reason) {
    auto payload = round_trip(
        *impl_, Op::Retire,
        encode_session_request(impl_->session, encode_retire_request(id, reason)));
    if (!payload.ok()) {
        return payload.status();
    }
    return decode_generation(payload.value());
}

Result<FabricEpoch> NodeClient::advance_epoch(std::string_view reason) {
    auto payload = round_trip(
        *impl_, Op::AdvanceEpoch,
        encode_session_request(impl_->session, encode_reason(reason)));
    if (!payload.ok()) {
        return payload.status();
    }
    return decode_epoch(payload.value());
}

VoidResult NodeClient::fence(const PublisherId& publisher, const BootId& boot,
                             std::string_view reason) {
    auto payload = round_trip(
        *impl_, Op::Fence,
        encode_session_request(impl_->session,
                               encode_fence_request(publisher, boot, reason)));
    if (!payload.ok()) {
        return payload.status();
    }
    return VoidResult{};
}

Result<PriorityDecision> NodeClient::evaluate(const PriorityQuery& query) {
    auto payload = round_trip(
        *impl_, Op::Query,
        encode_session_request(impl_->session, encode_query(query)));
    if (!payload.ok()) {
        return payload.status();
    }
    return decode_decision(payload.value(), impl_->options.limits);
}

Result<Generation> NodeClient::checkpoint() {
    auto payload =
        round_trip(*impl_, Op::Checkpoint, encode_session_request(impl_->session, std::string()));
    if (!payload.ok()) {
        return payload.status();
    }
    return decode_generation(payload.value());
}

Result<std::pair<FabricStats, StateStats>> NodeClient::stats() {
    auto payload =
        round_trip(*impl_, Op::Stats, encode_session_request(impl_->session, std::string()));
    if (!payload.ok()) {
        return payload.status();
    }
    auto reply = decode_stats_reply(payload.value(), impl_->options.limits);
    if (!reply.ok()) {
        return reply.status();
    }
    return std::make_pair(reply.value().stats, reply.value().state);
}

Result<IntegrityReport> NodeClient::integrity() {
    auto payload =
        round_trip(*impl_, Op::Integrity, encode_session_request(impl_->session, std::string()));
    if (!payload.ok()) {
        return payload.status();
    }
    return decode_integrity_reply(payload.value(), impl_->options.limits);
}

VoidResult NodeClient::ping() {
    auto payload =
        round_trip(*impl_, Op::Ping, encode_session_request(impl_->session, std::string()));
    if (!payload.ok()) {
        return payload.status();
    }
    return VoidResult{};
}

VoidResult NodeClient::shutdown_node() {
    auto payload =
        round_trip(*impl_, Op::Shutdown, encode_session_request(impl_->session, std::string()));
    if (!payload.ok()) {
        return payload.status();
    }
    return VoidResult{};
}

}  // namespace pf
