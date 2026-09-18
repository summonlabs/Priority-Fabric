// Priority Fabric -- authoritative network priority classes.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Internal: a thin, explicit socket layer. Every operation reports failure; nothing blocks
// without a deadline that turns into an error rather than a silent hang.

#ifndef PRIORITY_FABRIC_SRC_NET_HPP
#define PRIORITY_FABRIC_SRC_NET_HPP

#include <cstdint>
#include <string>
#include <string_view>

#include "priority_fabric/status.hpp"

namespace pf::net {

/// Owns a socket. Movable, never copyable, closes on destruction.
class Socket {
public:
    Socket() = default;
    explicit Socket(std::intptr_t handle) : handle_(handle) {}
    ~Socket();

    Socket(const Socket&) = delete;
    Socket& operator=(const Socket&) = delete;
    Socket(Socket&& other) noexcept;
    Socket& operator=(Socket&& other) noexcept;

    [[nodiscard]] bool valid() const noexcept;
    [[nodiscard]] std::intptr_t handle() const noexcept { return handle_; }

    /// Releases ownership without closing.
    std::intptr_t release() noexcept;

    void close() noexcept;
    /// Wakes a blocked recv or send without closing the handle.
    void shutdown_both() noexcept;

    /// Debug socket for this process. Used in diagnostics, never for authority.
    [[nodiscard]] static std::string describe_peer(std::intptr_t handle);

private:
    std::intptr_t handle_ = -1;
};

/// A bound, listening socket.
class Listener {
public:
    Listener() = default;
    explicit Listener(Socket socket);
    ~Listener() = default;
    Listener(const Listener&) = delete;
    Listener& operator=(const Listener&) = delete;
    Listener(Listener&&) noexcept = default;
    Listener& operator=(Listener&&) noexcept = default;

    [[nodiscard]] bool valid() const noexcept { return socket_.valid(); }
    [[nodiscard]] std::uint16_t port() const noexcept { return port_; }
    [[nodiscard]] const std::string& address() const noexcept { return address_; }
    [[nodiscard]] std::intptr_t handle() const noexcept { return socket_.handle(); }

    /// Blocks until a connection arrives. Returns TransportError when the listener was shut
    /// down, which is how stop() unblocks the accept loop.
    [[nodiscard]] Result<Socket> accept_one() const;

    void close() noexcept { socket_.close(); }

private:
    Socket socket_;
    std::uint16_t port_ = 0;
    std::string address_;
};

/// Binds and listens. \p port 0 asks the operating system to choose; the resolved port is
/// reported by Listener::port(). Refuses a non-loopback address unless \p allow_non_loopback.
[[nodiscard]] Result<Listener> listen_on(std::string_view address, std::uint16_t port,
                                         std::uint32_t backlog, bool allow_non_loopback);

/// Connects, retrying while a listener is starting up. \p attempts bounds the retry.
[[nodiscard]] Result<Socket> connect_to(std::string_view address, std::uint16_t port,
                                        std::uint32_t attempts, std::uint32_t retry_delay_ms);

/// Sets a receive and send deadline. A deadline expiring always produces an error; it is a
/// liveness guard against a dead peer, never a latency budget.
[[nodiscard]] VoidResult set_io_deadline(std::intptr_t handle, std::uint32_t milliseconds);

[[nodiscard]] VoidResult send_all(std::intptr_t handle, const void* data, std::size_t size);
/// Reads exactly \p size bytes or fails.
[[nodiscard]] VoidResult recv_exact(std::intptr_t handle, void* data, std::size_t size);

/// True when every byte is a loopback address.
[[nodiscard]] bool is_loopback_address(std::string_view address) noexcept;

[[nodiscard]] std::string last_socket_error_text();

}  // namespace pf::net

#endif  // PRIORITY_FABRIC_SRC_NET_HPP
