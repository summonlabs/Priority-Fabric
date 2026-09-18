// Priority Fabric -- authoritative network priority classes.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "net.hpp"

#include <chrono>
#include <cstring>
#include <mutex>
#include <thread>
#include <vector>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#endif

namespace pf::net {
namespace {

#if defined(_WIN32)
constexpr std::intptr_t kInvalidHandle = static_cast<std::intptr_t>(INVALID_SOCKET);

void ensure_winsock() {
    static std::once_flag once;
    std::call_once(once, []() {
        WSADATA data{};
        (void)::WSAStartup(MAKEWORD(2, 2), &data);
    });
}

std::string error_text(int code) {
    switch (code) {
        case WSAETIMEDOUT: return "the peer did not answer before the deadline";
        case WSAECONNRESET: return "the peer reset the connection";
        case WSAECONNREFUSED: return "the peer refused the connection";
        case WSAENOTCONN: return "the socket is not connected";
        case WSAESHUTDOWN: return "the socket was shut down";
        case WSAEINTR: return "the operation was interrupted";
        case WSAENOBUFS: return "the socket buffer is exhausted";
        case WSAEMFILE: return "the process is out of socket handles";
        default: return "socket error " + std::to_string(code);
    }
}
#else
constexpr std::intptr_t kInvalidHandle = -1;

void ensure_winsock() {}

std::string error_text(int code) {
    switch (code) {
        case ETIMEDOUT: return "the peer did not answer before the deadline";
        case ECONNRESET: return "the peer reset the connection";
        case ECONNREFUSED: return "the peer refused the connection";
        case ENOTCONN: return "the socket is not connected";
        case EINTR: return "the operation was interrupted";
        case ENOBUFS: return "the socket buffer is exhausted";
        case EMFILE: return "the process is out of socket handles";
        default: return std::string("socket error ") + std::strerror(code);
    }
}
#endif

}  // namespace

Socket::~Socket() {
    close();
}

Socket::Socket(Socket&& other) noexcept : handle_(other.handle_) {
    other.handle_ = kInvalidHandle;
}

Socket& Socket::operator=(Socket&& other) noexcept {
    if (this != &other) {
        close();
        handle_ = other.handle_;
        other.handle_ = kInvalidHandle;
    }
    return *this;
}

bool Socket::valid() const noexcept {
    return handle_ != kInvalidHandle && handle_ != 0;
}

std::intptr_t Socket::release() noexcept {
    const std::intptr_t handle = handle_;
    handle_ = kInvalidHandle;
    return handle;
}

void Socket::close() noexcept {
    if (!valid()) {
        return;
    }
    const std::intptr_t handle = handle_;
    handle_ = kInvalidHandle;
#if defined(_WIN32)
    (void)::closesocket(static_cast<SOCKET>(handle));
#else
    (void)::close(static_cast<int>(handle));
#endif
}

void Socket::shutdown_both() noexcept {
    if (!valid()) {
        return;
    }
#if defined(_WIN32)
    (void)::shutdown(static_cast<SOCKET>(handle_), SD_BOTH);
#else
    (void)::shutdown(static_cast<int>(handle_), SHUT_RDWR);
#endif
}

std::string Socket::describe_peer(std::intptr_t handle) {
    if (handle == kInvalidHandle) {
        return "<closed>";
    }
    sockaddr_storage storage{};
    socklen_t length = sizeof(storage);
#if defined(_WIN32)
    if (::getpeername(static_cast<SOCKET>(handle), reinterpret_cast<sockaddr*>(&storage),
                      &length) != 0) {
        return "<unknown>";
    }
#else
    if (::getpeername(static_cast<int>(handle), reinterpret_cast<sockaddr*>(&storage), &length) !=
        0) {
        return "<unknown>";
    }
#endif
    char text[INET6_ADDRSTRLEN] = {};
    if (storage.ss_family == AF_INET) {
        const auto* in4 = reinterpret_cast<const sockaddr_in*>(&storage);
        (void)::inet_ntop(AF_INET, &in4->sin_addr, text, sizeof(text));
        return std::string(text) + ":" + std::to_string(ntohs(in4->sin_port));
    }
    const auto* in6 = reinterpret_cast<const sockaddr_in6*>(&storage);
    (void)::inet_ntop(AF_INET6, &in6->sin6_addr, text, sizeof(text));
    return std::string("[") + text + "]:" + std::to_string(ntohs(in6->sin6_port));
}

Listener::Listener(Socket socket) : socket_(std::move(socket)) {
    if (!socket_.valid()) {
        return;
    }
    sockaddr_storage storage{};
    socklen_t length = sizeof(storage);
#if defined(_WIN32)
    if (::getsockname(static_cast<SOCKET>(socket_.handle()),
                      reinterpret_cast<sockaddr*>(&storage), &length) == 0) {
#else
    if (::getsockname(static_cast<int>(socket_.handle()),
                      reinterpret_cast<sockaddr*>(&storage), &length) == 0) {
#endif
        if (storage.ss_family == AF_INET) {
            const auto* in4 = reinterpret_cast<const sockaddr_in*>(&storage);
            char text[INET_ADDRSTRLEN] = {};
            (void)::inet_ntop(AF_INET, &in4->sin_addr, text, sizeof(text));
            address_ = text;
            port_ = ntohs(in4->sin_port);
        } else if (storage.ss_family == AF_INET6) {
            const auto* in6 = reinterpret_cast<const sockaddr_in6*>(&storage);
            char text[INET6_ADDRSTRLEN] = {};
            (void)::inet_ntop(AF_INET6, &in6->sin6_addr, text, sizeof(text));
            address_ = text;
            port_ = ntohs(in6->sin6_port);
        }
    }
}

Result<Socket> Listener::accept_one() const {
    if (!socket_.valid()) {
        return make_error(StatusCode::NotReady, "the listener is closed");
    }
    sockaddr_storage storage{};
    socklen_t length = sizeof(storage);
#if defined(_WIN32)
    const SOCKET accepted =
        ::accept(static_cast<SOCKET>(socket_.handle()), reinterpret_cast<sockaddr*>(&storage),
                 &length);
    if (accepted == INVALID_SOCKET) {
        const int code = ::WSAGetLastError();
        return make_error(StatusCode::TransportError, error_text(code));
    }
    return Socket(static_cast<std::intptr_t>(accepted));
#else
    const int accepted = ::accept(static_cast<int>(socket_.handle()),
                                  reinterpret_cast<sockaddr*>(&storage), &length);
    if (accepted < 0) {
        return make_error(StatusCode::TransportError, error_text(errno));
    }
    return Socket(static_cast<std::intptr_t>(accepted));
#endif
}

bool is_loopback_address(std::string_view address) noexcept {
    if (address == "127.0.0.1" || address == "::1" || address == "localhost") {
        return true;
    }
    // Any address inside 127.0.0.0/8 is loopback.
    if (address.size() >= 4 && address.substr(0, 4) == "127.") {
        return true;
    }
    return false;
}

Result<Listener> listen_on(std::string_view address, std::uint16_t port, std::uint32_t backlog,
                           bool allow_non_loopback) {
    ensure_winsock();
    if (!allow_non_loopback && !is_loopback_address(address)) {
        return make_error(StatusCode::Unauthorized,
                          "'" + std::string(address) +
                              "' is not a loopback address; binding a fabric node to a routable "
                              "interface requires the explicit override");
    }
    if (backlog == 0) {
        backlog = 8;
    }

    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE;
    addrinfo* resolved = nullptr;
    const std::string port_text = std::to_string(port);
    const std::string address_text(address);
    if (::getaddrinfo(address_text.c_str(), port_text.c_str(), &hints, &resolved) != 0 ||
        resolved == nullptr) {
        return make_error(StatusCode::InvalidArgument,
                          "cannot resolve '" + address_text + "'");
    }

    Socket listener;
    for (addrinfo* candidate = resolved; candidate != nullptr; candidate = candidate->ai_next) {
#if defined(_WIN32)
        const SOCKET handle =
            ::socket(candidate->ai_family, candidate->ai_socktype, candidate->ai_protocol);
        if (handle == INVALID_SOCKET) {
            continue;
        }
        const char enable = 1;
        (void)::setsockopt(handle, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, &enable, sizeof(enable));
        if (::bind(handle, candidate->ai_addr, static_cast<int>(candidate->ai_addrlen)) != 0) {
            (void)::closesocket(handle);
            continue;
        }
        if (::listen(handle, static_cast<int>(backlog)) != 0) {
            (void)::closesocket(handle);
            continue;
        }
        listener = Socket(static_cast<std::intptr_t>(handle));
        break;
#else
        const int handle =
            ::socket(candidate->ai_family, candidate->ai_socktype, candidate->ai_protocol);
        if (handle < 0) {
            continue;
        }
        const int enable = 1;
        (void)::setsockopt(handle, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable));
        if (::bind(handle, candidate->ai_addr, candidate->ai_addrlen) != 0) {
            (void)::close(handle);
            continue;
        }
        if (::listen(handle, static_cast<int>(backlog)) != 0) {
            (void)::close(handle);
            continue;
        }
        listener = Socket(static_cast<std::intptr_t>(handle));
        break;
#endif
    }
    ::freeaddrinfo(resolved);
    if (!listener.valid()) {
        return make_error(StatusCode::TransportError,
                          "could not bind '" + address_text + ":" + port_text +
                              "': " + last_socket_error_text());
    }
    return Listener(std::move(listener));
}

Result<Socket> connect_to(std::string_view address, std::uint16_t port, std::uint32_t attempts,
                          std::uint32_t retry_delay_ms) {
    ensure_winsock();
    if (attempts == 0) {
        return make_error(StatusCode::InvalidArgument, "connect attempts must be at least one");
    }
    const std::string address_text(address);
    const std::string port_text = std::to_string(port);
    std::string last_error = "no attempt was made";

    for (std::uint32_t attempt = 0; attempt < attempts; ++attempt) {
        addrinfo hints{};
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;
        addrinfo* resolved = nullptr;
        if (::getaddrinfo(address_text.c_str(), port_text.c_str(), &hints, &resolved) != 0 ||
            resolved == nullptr) {
            return make_error(StatusCode::InvalidArgument, "cannot resolve '" + address_text + "'");
        }
        bool connected = false;
        Socket socket;
        for (addrinfo* candidate = resolved; candidate != nullptr; candidate = candidate->ai_next) {
#if defined(_WIN32)
            const SOCKET handle =
                ::socket(candidate->ai_family, candidate->ai_socktype, candidate->ai_protocol);
            if (handle == INVALID_SOCKET) {
                last_error = error_text(::WSAGetLastError());
                continue;
            }
            if (::connect(handle, candidate->ai_addr, static_cast<int>(candidate->ai_addrlen)) !=
                0) {
                last_error = error_text(::WSAGetLastError());
                (void)::closesocket(handle);
                continue;
            }
            const char nodelay = 1;
            (void)::setsockopt(handle, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));
            socket = Socket(static_cast<std::intptr_t>(handle));
            connected = true;
            break;
#else
            const int handle =
                ::socket(candidate->ai_family, candidate->ai_socktype, candidate->ai_protocol);
            if (handle < 0) {
                last_error = error_text(errno);
                continue;
            }
            if (::connect(handle, candidate->ai_addr, candidate->ai_addrlen) != 0) {
                last_error = error_text(errno);
                (void)::close(handle);
                continue;
            }
            const int nodelay = 1;
            (void)::setsockopt(handle, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));
            socket = Socket(static_cast<std::intptr_t>(handle));
            connected = true;
            break;
#endif
        }
        ::freeaddrinfo(resolved);
        if (connected) {
            return socket;
        }
        if (attempt + 1 < attempts && retry_delay_ms > 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(retry_delay_ms));
        }
    }
    return make_error(StatusCode::TransportError,
                      "could not connect to '" + address_text + ":" + port_text +
                          "' after " + std::to_string(attempts) + " attempt(s): " + last_error);
}

VoidResult set_io_deadline(std::intptr_t handle, std::uint32_t milliseconds) {
    if (handle == kInvalidHandle) {
        return make_error(StatusCode::NotReady, "the socket is closed");
    }
#if defined(_WIN32)
    const DWORD value = milliseconds;
    if (::setsockopt(static_cast<SOCKET>(handle), SOL_SOCKET, SO_RCVTIMEO,
                     reinterpret_cast<const char*>(&value), sizeof(value)) != 0) {
        return make_error(StatusCode::TransportError,
                          "cannot set the receive deadline: " + last_socket_error_text());
    }
    if (::setsockopt(static_cast<SOCKET>(handle), SOL_SOCKET, SO_SNDTIMEO,
                     reinterpret_cast<const char*>(&value), sizeof(value)) != 0) {
        return make_error(StatusCode::TransportError,
                          "cannot set the send deadline: " + last_socket_error_text());
    }
#else
    timeval value{};
    value.tv_sec = static_cast<time_t>(milliseconds / 1000u);
    value.tv_usec = static_cast<suseconds_t>((milliseconds % 1000u) * 1000u);
    if (::setsockopt(static_cast<int>(handle), SOL_SOCKET, SO_RCVTIMEO, &value, sizeof(value)) !=
        0) {
        return make_error(StatusCode::TransportError,
                          "cannot set the receive deadline: " + last_socket_error_text());
    }
    if (::setsockopt(static_cast<int>(handle), SOL_SOCKET, SO_SNDTIMEO, &value, sizeof(value)) !=
        0) {
        return make_error(StatusCode::TransportError,
                          "cannot set the send deadline: " + last_socket_error_text());
    }
#endif
    return VoidResult{};
}

VoidResult send_all(std::intptr_t handle, const void* data, std::size_t size) {
    if (handle == kInvalidHandle) {
        return make_error(StatusCode::NotReady, "the socket is closed");
    }
    const auto* bytes = static_cast<const std::uint8_t*>(data);
    std::size_t sent = 0;
    while (sent < size) {
        const std::size_t chunk = size - sent;
#if defined(_WIN32)
        const int written = ::send(static_cast<SOCKET>(handle),
                                   reinterpret_cast<const char*>(bytes + sent),
                                   static_cast<int>(chunk), 0);
        if (written == SOCKET_ERROR) {
            return make_error(StatusCode::TransportError, error_text(::WSAGetLastError()));
        }
#else
        const ssize_t written =
            ::send(static_cast<int>(handle), bytes + sent, chunk, MSG_NOSIGNAL);
        if (written < 0) {
            return make_error(StatusCode::TransportError, error_text(errno));
        }
#endif
        if (written == 0) {
            return make_error(StatusCode::TransportError, "the connection stopped accepting data");
        }
        sent += static_cast<std::size_t>(written);
    }
    return VoidResult{};
}

VoidResult recv_exact(std::intptr_t handle, void* data, std::size_t size) {
    if (handle == kInvalidHandle) {
        return make_error(StatusCode::NotReady, "the socket is closed");
    }
    auto* bytes = static_cast<std::uint8_t*>(data);
    std::size_t received = 0;
    while (received < size) {
        const std::size_t chunk = size - received;
#if defined(_WIN32)
        const int read = ::recv(static_cast<SOCKET>(handle),
                                reinterpret_cast<char*>(bytes + received),
                                static_cast<int>(chunk), 0);
        if (read == SOCKET_ERROR) {
            return make_error(StatusCode::TransportError, error_text(::WSAGetLastError()));
        }
#else
        const ssize_t read = ::recv(static_cast<int>(handle), bytes + received, chunk, 0);
        if (read < 0) {
            return make_error(StatusCode::TransportError, error_text(errno));
        }
#endif
        if (read == 0) {
            return make_error(StatusCode::TransportError, "the peer closed the connection");
        }
        received += static_cast<std::size_t>(read);
    }
    return VoidResult{};
}

std::string last_socket_error_text() {
#if defined(_WIN32)
    return error_text(::WSAGetLastError());
#else
    return error_text(errno);
#endif
}

}  // namespace pf::net
