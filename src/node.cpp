// Priority Fabric -- authoritative network priority classes.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "priority_fabric/node.hpp"

#include <algorithm>
#include <atomic>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "fsutil.hpp"
#include "net.hpp"
#include "priority_fabric/digest.hpp"
#include "priority_fabric/text.hpp"
#include "priority_fabric/wire.hpp"

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <unistd.h>
#endif

namespace pf {
namespace {

std::uint64_t current_process_id() {
#if defined(_WIN32)
    return static_cast<std::uint64_t>(::GetCurrentProcessId());
#else
    return static_cast<std::uint64_t>(::getpid());
#endif
}

/// Decodes a request that carries an authority block followed by an op payload.
struct SessionRequest {
    WireSession session;
    std::string inner;
};

Result<SessionRequest> decode_session_request(const std::string& payload, const Limits& limits) {
    Decoder decoder(payload.data(), payload.size(), limits);
    auto session_blob = decoder.str(limits.max_record_payload);
    if (!session_blob.ok()) {
        return session_blob.status();
    }
    Decoder session_decoder(session_blob.value().data(), session_blob.value().size(), limits);
    auto session = decode_session(session_decoder);
    if (!session.ok()) {
        return session.status();
    }
    auto session_end = session_decoder.finish();
    if (!session_end.ok()) {
        return session_end.status();
    }
    auto inner = decoder.raw(decoder.remaining());
    if (!inner.ok()) {
        return inner.status();
    }
    SessionRequest request;
    request.session = std::move(session.value());
    request.inner = std::move(inner.value());
    return request;
}

std::string encode_session_request(const Session& session, std::string_view inner) {
    Encoder encoder;
    const std::string session_blob = encode_session(WireSession::from_session(session));
    encoder.str(session_blob);
    encoder.raw(inner.data(), inner.size());
    return encoder.take();
}

}  // namespace

struct FabricNode::Impl {
    Options options;
    std::unique_ptr<FabricRuntime> runtime;
    net::Listener listener;
    PublisherId node_id;
    BootId node_boot;

    std::atomic<bool> stopping{false};
    std::atomic<bool> listening{false};
    std::atomic<std::uint64_t> connections_accepted{0};
    std::atomic<std::uint32_t> active_connections{0};

    /// Guards the worker and socket bookkeeping only. It is never held while joining a
    /// worker: stop() takes what it needs, releases the lock and joins outside it.
    mutable std::mutex bookkeeping;
    /// Serializes stop() so that a second caller waits for the first to finish draining
    /// instead of racing it into the runtime teardown.
    std::mutex stop_mutex;
    std::vector<std::thread> workers;
    std::vector<std::intptr_t> live_sockets;
    std::thread serve_thread;
    bool owns_serve_thread = false;
};

FabricNode::FabricNode() : impl_(std::make_unique<Impl>()) {}

FabricNode::~FabricNode() {
    if (impl_) {
        stop();
    }
}

FabricNode::FabricNode(FabricNode&&) noexcept = default;
FabricNode& FabricNode::operator=(FabricNode&&) noexcept = default;

VoidResult FabricNode::listen(const Options& options) {
    if (!impl_) {
        return make_error(StatusCode::NotReady, "the node was never constructed");
    }
    Impl& impl = *impl_;
    impl.options = options;

    auto boot = BootId::generate();
    if (!boot.ok()) {
        return boot.status();
    }
    impl.node_boot = boot.value();

    const std::uint64_t tag = fnv1a64(options.state_dir.string());
    const std::string node_id_text = "pf.node." + std::to_string(tag);
    auto node_id = PublisherId::parse(node_id_text, options.limits);
    if (!node_id.ok()) {
        return node_id.status();
    }
    impl.node_id = node_id.value();

    auto listener = net::listen_on(options.bind_address, options.port,
                                   options.max_connections == 0 ? 8 : options.max_connections,
                                   options.allow_non_loopback);
    if (!listener.ok()) {
        return listener.status();
    }
    impl.listener = std::move(listener.value());

    FabricRuntime::Options runtime_options;
    runtime_options.state_dir = options.state_dir;
    runtime_options.limits = options.limits;
    runtime_options.create_if_missing = options.create_if_missing;
    runtime_options.fsync_records = options.fsync_records;
    runtime_options.instance_boot_id = impl.node_boot;
    // A node is the authority for its state directory: taking it over is a new incarnation, so
    // the epoch moves and everything from before the restart stops being usable.
    runtime_options.advance_epoch_on_open = options.advance_epoch_on_open;
    auto runtime = FabricRuntime::open(runtime_options);
    if (!runtime.ok()) {
        impl.listener.close();
        return runtime.status();
    }
    impl.runtime = std::make_unique<FabricRuntime>(std::move(runtime.value()));
    impl.listening = true;

    if (!options.ready_file.empty()) {
        std::string contents;
        contents.append("port=").append(std::to_string(impl.listener.port())).append("\n");
        contents.append("address=").append(impl.listener.address()).append("\n");
        contents.append("node_id=").append(impl.node_id.str()).append("\n");
        contents.append("node_boot=").append(impl.node_boot.hex()).append("\n");
        contents.append("pid=").append(std::to_string(current_process_id())).append("\n");
        auto written = fsutil::write_atomic(options.ready_file, contents, true);
        if (!written.ok()) {
            return written.status();
        }
    }
    return VoidResult{};
}

VoidResult FabricNode::serve() {
    if (!impl_ || !impl_->listening) {
        return make_error(StatusCode::NotReady, "the node is not listening");
    }
    Impl& impl = *impl_;

    while (!impl.stopping.load()) {
        auto accepted = impl.listener.accept_one();
        if (!accepted.ok()) {
            if (impl.stopping.load()) {
                break;
            }
            return make_error(StatusCode::TransportError,
                              "the accept loop stopped: " + accepted.status().message());
        }
        if (impl.active_connections.load() >= impl.options.max_connections) {
            // Refuse politely over the wire rather than silently dropping the connection.
            net::Socket refused = std::move(accepted.value());
            const std::string payload =
                encode_error_reply(StatusCode::LimitExceeded,
                                   "the node is already serving its maximum of " +
                                       std::to_string(impl.options.max_connections) +
                                       " connections");
            const std::string frame =
                encode_frame(FrameHeader{PRIORITY_FABRIC_FORMAT_VERSION, Op::Error, 0, 0,
                                         static_cast<std::uint32_t>(payload.size())},
                             payload);
            (void)net::send_all(refused.handle(), frame.data(), frame.size());
            continue;
        }

        ++impl.connections_accepted;
        ++impl.active_connections;
        net::Socket socket = std::move(accepted.value());
        const std::intptr_t handle = socket.handle();

        std::thread worker([this, socket = std::move(socket), handle]() mutable {
            const std::intptr_t owned = socket.release();
            handle_connection(owned);
            Impl& state = *impl_;
            {
                std::lock_guard<std::mutex> guard(state.bookkeeping);
                const auto position =
                    std::find(state.live_sockets.begin(), state.live_sockets.end(), handle);
                if (position != state.live_sockets.end()) {
                    state.live_sockets.erase(position);
                }
            }
            --state.active_connections;
        });

        {
            std::lock_guard<std::mutex> guard(impl.bookkeeping);
            impl.live_sockets.push_back(handle);
            impl.workers.push_back(std::move(worker));
        }
    }
    return VoidResult{};
}

void FabricNode::handle_connection(std::intptr_t socket_handle) {
    net::Socket socket(socket_handle);
    Impl& impl = *impl_;
    if (impl.options.idle_timeout_ms > 0) {
        (void)net::set_io_deadline(socket.handle(), impl.options.idle_timeout_ms);
    }

    std::uint64_t served = 0;
    Session last_session;
    while (!impl.stopping.load()) {
        if (++served > impl.options.limits.max_requests_per_connection) {
            break;
        }
        std::string header_bytes(FrameHeader::kHeaderBytes, '\0');
        auto header_status =
            net::recv_exact(socket.handle(), header_bytes.data(), header_bytes.size());
        if (!header_status.ok()) {
            break;
        }
        const auto* header = reinterpret_cast<const std::uint8_t*>(header_bytes.data());
        auto read_le = [](const std::uint8_t* data, std::size_t width) {
            std::uint64_t value = 0;
            for (std::size_t i = 0; i < width; ++i) {
                value |= static_cast<std::uint64_t>(data[i]) << (8 * i);
            }
            return value;
        };
        if (read_le(header, 4) != FrameHeader::kMagic) {
            (void)send_error(socket.handle(), 0, StatusCode::ProtocolError,
                             "the frame does not start with the fabric magic value");
            break;
        }
        FrameHeader frame;
        frame.format = static_cast<std::uint16_t>(read_le(header + 4, 2));
        frame.op = static_cast<Op>(read_le(header + 6, 2));
        frame.flags = static_cast<std::uint32_t>(read_le(header + 8, 4));
        frame.request_id = read_le(header + 12, 8);
        frame.payload_length = static_cast<std::uint32_t>(read_le(header + 20, 4));

        auto header_ok = validate_frame_header(frame, impl.options.limits);
        if (!header_ok.ok()) {
            (void)send_error(socket.handle(), frame.request_id, header_ok.status().code(),
                             header_ok.status().message());
            break;
        }

        std::string body(static_cast<std::size_t>(frame.payload_length) +
                             FrameHeader::kTrailerBytes,
                         '\0');
        auto body_status = net::recv_exact(socket.handle(), body.data(), body.size());
        if (!body_status.ok()) {
            break;
        }
        std::string frame_buffer = header_bytes + body;
        auto checksum = verify_frame_checksum(frame_buffer, frame);
        if (!checksum.ok()) {
            (void)send_error(socket.handle(), frame.request_id, checksum.status().code(),
                             checksum.status().message());
            break;
        }
        const std::string payload =
            frame_buffer.substr(FrameHeader::kHeaderBytes, frame.payload_length);

        if (auto decoded = decode_session_request(payload, impl.options.limits);
            decoded.ok()) {
            last_session = decoded.value().session.to_session();
        }

        auto reply = dispatch(frame, payload);
        if (!reply.ok()) {
            (void)send_error(socket.handle(), frame.request_id, reply.status().code(),
                             reply.status().message());
            if (frame.op == Op::Hello) {
                break;  // a peer that cannot handshake gets no further service
            }
            continue;
        }
        const std::string response = reply.value();
        const std::string out = encode_frame(
            FrameHeader{PRIORITY_FABRIC_FORMAT_VERSION, Op::Response, 0, frame.request_id,
                        static_cast<std::uint32_t>(response.size())},
            response);
        auto sent = net::send_all(socket.handle(), out.data(), out.size());
        if (!sent.ok()) {
            break;
        }
    }
    socket.shutdown_both();

    // A publisher that lost its socket is treated as gone. Nothing is inferred about the
    // process itself: the fabric advances the epoch, which is a durable, explainable act.
    if (impl.options.fence_on_disconnect && last_session.valid() && !impl.stopping.load()) {
        (void)impl.runtime->advance_epoch(last_session, "publisher socket closed");
    }
}

Result<std::string> FabricNode::dispatch(const FrameHeader& frame, const std::string& payload) {
    Impl& impl = *impl_;
    const Limits& limits = impl.options.limits;

    if (frame.op == Op::Hello) {
        auto request = decode_hello(payload, limits);
        if (!request.ok()) {
            return request.status();
        }
        auto session = impl.runtime->grant_authority(request.value().publisher,
                                                     request.value().boot);
        if (!session.ok()) {
            return session.status();
        }
        HelloResponse response;
        response.node_id = impl.node_id;
        response.node_boot = impl.node_boot;
        response.epoch = session.value().epoch;
        response.token = session.value().token;
        response.state_generation = impl.runtime->state_generation();
        response.node_pid = current_process_id();
        return encode_hello_response(response);
    }

    auto request = decode_session_request(payload, limits);
    if (!request.ok()) {
        return request.status();
    }
    const Session session = request.value().session.to_session();
    const std::string& inner = request.value().inner;

    switch (frame.op) {
        case Op::DefineClass: {
            auto definition = decode_class_definition(inner, limits);
            if (!definition.ok()) {
                return definition.status();
            }
            auto generation = impl.runtime->define_class(session, definition.value());
            if (!generation.ok()) {
                return generation.status();
            }
            return encode_generation(generation.value());
        }
        case Op::DefineScope: {
            auto definition = decode_scope_definition(inner, limits);
            if (!definition.ok()) {
                return definition.status();
            }
            auto generation = impl.runtime->define_scope(session, definition.value());
            if (!generation.ok()) {
                return generation.status();
            }
            return encode_generation(generation.value());
        }
        case Op::DefinePolicy: {
            auto definition = decode_policy_definition(inner, limits);
            if (!definition.ok()) {
                return definition.status();
            }
            auto generation = impl.runtime->define_policy(session, definition.value());
            if (!generation.ok()) {
                return generation.status();
            }
            return encode_generation(generation.value());
        }
        case Op::DefineSubject: {
            auto definition = decode_subject_definition(inner, limits);
            if (!definition.ok()) {
                return definition.status();
            }
            auto generation = impl.runtime->define_subject(session, definition.value());
            if (!generation.ok()) {
                return generation.status();
            }
            return encode_generation(generation.value());
        }
        case Op::Assign: {
            auto assignment = decode_assignment(inner, limits);
            if (!assignment.ok()) {
                return assignment.status();
            }
            auto generation = impl.runtime->assign(session, assignment.value());
            if (!generation.ok()) {
                return generation.status();
            }
            return encode_generation(generation.value());
        }
        case Op::Retire: {
            auto decoded = decode_retire_request(inner, limits);
            if (!decoded.ok()) {
                return decoded.status();
            }
            auto generation = impl.runtime->retire_assignment(session, decoded.value().first,
                                                             decoded.value().second);
            if (!generation.ok()) {
                return generation.status();
            }
            return encode_generation(generation.value());
        }
        case Op::Query: {
            auto query = decode_query(inner, limits);
            if (!query.ok()) {
                return query.status();
            }
            const PriorityDecision decision = impl.runtime->evaluate(query.value());
            return encode_decision(decision);
        }
        case Op::AdvanceEpoch: {
            auto reason = decode_reason(inner, limits);
            if (!reason.ok()) {
                return reason.status();
            }
            auto epoch = impl.runtime->advance_epoch(session, reason.value());
            if (!epoch.ok()) {
                return epoch.status();
            }
            return encode_epoch(epoch.value());
        }
        case Op::Fence: {
            auto request_fence = decode_fence_request(inner, limits);
            if (!request_fence.ok()) {
                return request_fence.status();
            }
            auto fenced = impl.runtime->fence(session, request_fence.value().publisher,
                                              request_fence.value().boot,
                                              request_fence.value().reason);
            if (!fenced.ok()) {
                return fenced.status();
            }
            return std::string("");
        }
        case Op::Stats: {
            return encode_stats_reply(impl.runtime->stats(), impl.runtime->state_stats(),
                                      impl.node_boot, impl.node_id);
        }
        case Op::Checkpoint: {
            auto generation = impl.runtime->checkpoint();
            if (!generation.ok()) {
                return generation.status();
            }
            return encode_generation(generation.value());
        }
        case Op::Integrity: {
            return encode_integrity_reply(impl.runtime->integrity_report());
        }
        case Op::Audit: {
            auto entries = impl.runtime->audit(limits.max_audit_return);
            Encoder encoder;
            encoder.u32(static_cast<std::uint32_t>(entries.size()));
            for (const auto& entry : entries) {
                const std::string blob = encode_audit_entry(entry);
                encoder.str(blob);
            }
            return encoder.take();
        }
        case Op::Ping:
            return std::string("");
        case Op::Shutdown: {
            if (!impl.options.allow_remote_shutdown) {
                return make_error(StatusCode::Unauthorized,
                                  "this node does not accept remote shutdown requests");
            }
            (void)session;
            impl.stopping.store(true);
            impl.listener.close();
            return std::string("");
        }
        case Op::Hello:
        case Op::HelloAck:
        case Op::Response:
        case Op::Error:
            break;
    }
    return make_error(StatusCode::ProtocolError,
                      "operation '" + std::string(to_string(frame.op)) +
                          "' is not valid in this position");
}

VoidResult FabricNode::send_error(std::intptr_t socket_handle, std::uint64_t request_id,
                                 StatusCode code, std::string_view message) {
    const std::string payload = encode_error_reply(code, message);
    const std::string frame =
        encode_frame(FrameHeader{PRIORITY_FABRIC_FORMAT_VERSION, Op::Error, 0, request_id,
                                 static_cast<std::uint32_t>(payload.size())},
                     payload);
    return net::send_all(socket_handle, frame.data(), frame.size());
}

VoidResult FabricNode::start() {
    if (!impl_ || !impl_->listening) {
        return make_error(StatusCode::NotReady, "the node is not listening");
    }
    {
        std::lock_guard<std::mutex> guard(impl_->bookkeeping);
        if (impl_->owns_serve_thread) {
            return make_error(StatusCode::AlreadyExists, "the node is already serving");
        }
        impl_->owns_serve_thread = true;
    }
    impl_->serve_thread = std::thread([this]() { (void)serve(); });
    return VoidResult{};
}

void FabricNode::stop() {
    if (!impl_) {
        return;
    }
    Impl& impl = *impl_;
    // No node worker ever calls stop(), so waiting here cannot deadlock the work being
    // awaited; it only makes a concurrent second call wait its turn.
    std::lock_guard<std::mutex> stop_guard(impl.stop_mutex);
    const bool first = !impl.stopping.exchange(true);
    if (first) {
        // 1. stop accepting new work
        impl.listener.close();
    }

    // 2. wake every in-flight connection so it can observe the stop flag and leave
    std::vector<std::intptr_t> sockets;
    {
        std::lock_guard<std::mutex> guard(impl.bookkeeping);
        sockets = impl.live_sockets;
    }
    for (std::intptr_t handle : sockets) {
        net::Socket view(handle);
        view.shutdown_both();
        (void)view.release();
    }

    // 3. join outside the bookkeeping lock: a worker takes that lock on its way out, so
    //    holding it here would deadlock the very work being awaited.
    std::vector<std::thread> workers;
    {
        std::lock_guard<std::mutex> guard(impl.bookkeeping);
        workers = std::move(impl.workers);
        impl.workers.clear();
    }
    const auto self = std::this_thread::get_id();
    for (auto& worker : workers) {
        if (!worker.joinable()) {
            continue;
        }
        if (worker.get_id() == self) {
            // A worker asking for shutdown must not try to join itself.
            worker.detach();
            continue;
        }
        worker.join();
    }

    {
        std::lock_guard<std::mutex> guard(impl.bookkeeping);
        if (impl.owns_serve_thread && impl.serve_thread.joinable() &&
            impl.serve_thread.get_id() != self) {
            impl.serve_thread.join();
        } else if (impl.owns_serve_thread && impl.serve_thread.joinable()) {
            impl.serve_thread.detach();
        }
        impl.owns_serve_thread = false;
    }

    if (impl.runtime) {
        (void)impl.runtime->close();
    }
    impl.listening = false;
}

std::uint16_t FabricNode::port() const noexcept {
    return impl_ ? impl_->listener.port() : 0;
}

const std::string& FabricNode::bind_address() const noexcept {
    static const std::string empty;
    return impl_ ? impl_->listener.address() : empty;
}

const PublisherId& FabricNode::node_id() const noexcept {
    return impl_->node_id;
}

const BootId& FabricNode::node_boot() const noexcept {
    return impl_->node_boot;
}

FabricRuntime* FabricNode::runtime() noexcept {
    return impl_ ? impl_->runtime.get() : nullptr;
}

const FabricRuntime* FabricNode::runtime() const noexcept {
    return impl_ ? impl_->runtime.get() : nullptr;
}

std::uint64_t FabricNode::connections_accepted() const noexcept {
    return impl_ ? impl_->connections_accepted.load() : 0;
}

std::uint32_t FabricNode::active_connections() const noexcept {
    return impl_ ? impl_->active_connections.load() : 0;
}

}  // namespace pf
