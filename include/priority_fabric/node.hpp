// Priority Fabric -- authoritative network priority classes.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#ifndef PRIORITY_FABRIC_NODE_HPP
#define PRIORITY_FABRIC_NODE_HPP

#include <atomic>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include "priority_fabric/export.hpp"
#include "priority_fabric/limits.hpp"
#include "priority_fabric/runtime.hpp"
#include "priority_fabric/status.hpp"
#include "priority_fabric/wire.hpp"

namespace pf {

/// A fabric node: the process that owns a state directory and serves the framed protocol.
///
/// The node is the authority boundary. Clients never touch durable state; they hold an
/// epoch-scoped, boot-scoped grant and every request is re-validated against the live
/// authority table before it can mutate anything.
///
/// Security boundary: the transport is unauthenticated loopback TCP. Authority is bound by
/// (publisher, boot, epoch, fencing token), which prevents stale or duplicated writers from
/// corrupting state, but it does not authenticate a hostile local peer. The node refuses
/// non-loopback binds unless explicitly overridden, and that override is recorded in the
/// audit log.
class PF_API FabricNode {
public:
    struct Options {
        std::filesystem::path state_dir;
        std::string bind_address = "127.0.0.1";
        std::uint16_t port = 0;  ///< 0 = let the OS choose; query port() afterwards
        Limits limits{};
        bool create_if_missing = true;
        bool fsync_records = true;
        /// Path written with the resolved port and node identity once the listener is up.
        /// Written atomically after bind and before the accept loop starts.
        std::filesystem::path ready_file;
        /// Allow binds to addresses other than loopback. Recorded in the audit log.
        bool allow_non_loopback = false;
        /// When true, a publisher socket closing advances the epoch, so every piece of
        /// evidence that publisher published stops being usable immediately. This is the
        /// configuration for a deployment that treats a lost connection as a lost writer.
        bool fence_on_disconnect = false;
        /// When true, taking the store over advances the epoch as the node's first durable
        /// act. A node is the authority for its state directory, so a restart is a new
        /// incarnation of that authority.
        bool advance_epoch_on_open = true;
        /// Refuse the Shutdown operation from the wire. Off by default so that a harness can
        /// stop a node politely; a real deployment turns it off and stops the process instead.
        bool allow_remote_shutdown = true;
        std::uint32_t max_connections = 64;
        /// Bounded idle timeout in milliseconds for a connection with no request in flight.
        /// Zero disables the idle check entirely.
        std::uint32_t idle_timeout_ms = 0;
    };

    FabricNode();
    ~FabricNode();
    FabricNode(const FabricNode&) = delete;
    FabricNode& operator=(const FabricNode&) = delete;
    FabricNode(FabricNode&&) noexcept;
    FabricNode& operator=(FabricNode&&) noexcept;

    /// Opens the store, binds the listener and reports the resolved port. Does not start
    /// serving; call serve() (blocking) or start() (background thread).
    [[nodiscard]] VoidResult listen(const Options& options);

    /// Accept loop. Runs in the calling thread until stop() is called.
    [[nodiscard]] VoidResult serve();

    /// Runs serve() on a background thread.
    [[nodiscard]] VoidResult start();

    /// Stops accepting new work, wakes and drains in-flight connections, then joins every
    /// worker. Safe to call from any thread except a node worker thread. Idempotent.
    void stop();

    [[nodiscard]] std::uint16_t port() const noexcept;
    [[nodiscard]] const std::string& bind_address() const noexcept;
    [[nodiscard]] const PublisherId& node_id() const noexcept;
    [[nodiscard]] const BootId& node_boot() const noexcept;
    [[nodiscard]] FabricRuntime* runtime() noexcept;
    [[nodiscard]] const FabricRuntime* runtime() const noexcept;
    /// Number of connections accepted since listen().
    [[nodiscard]] std::uint64_t connections_accepted() const noexcept;
    /// Number of currently served connections.
    [[nodiscard]] std::uint32_t active_connections() const noexcept;

private:
    struct Impl;

    /// Serves one connection until the peer leaves, the node stops, or a bound trips. Takes
    /// the raw handle so that no internal socket type appears in this header.
    void handle_connection(std::intptr_t socket_handle);
    [[nodiscard]] VoidResult send_error(std::intptr_t socket_handle, std::uint64_t request_id,
                                        StatusCode code, std::string_view message);
    [[nodiscard]] Result<std::string> dispatch(const FrameHeader& frame,
                                               const std::string& payload);

    std::unique_ptr<Impl> impl_;
};

}  // namespace pf

#endif  // PRIORITY_FABRIC_NODE_HPP
