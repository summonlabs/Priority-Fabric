// Priority Fabric -- authoritative network priority classes.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#ifndef PRIORITY_FABRIC_CLIENT_HPP
#define PRIORITY_FABRIC_CLIENT_HPP

#include <cstdint>
#include <memory>
#include <string>

#include "priority_fabric/decision.hpp"
#include "priority_fabric/export.hpp"
#include "priority_fabric/limits.hpp"
#include "priority_fabric/model.hpp"
#include "priority_fabric/runtime.hpp"
#include "priority_fabric/status.hpp"
#include "priority_fabric/wire.hpp"

namespace pf {

/// Blocking client for the framed fabric protocol.
///
/// The client is deliberately dumb: it never caches authority, never retries a mutation on
/// its own and never reinterprets a status code. A caller that wants to re-establish
/// authority after a restart asks for it explicitly, which is what makes the fencing
/// evidence unambiguous.
class PF_API NodeClient {
public:
    struct Options {
        std::string host = "127.0.0.1";
        std::uint16_t port = 0;
        Limits limits{};
        /// Socket-level receive/send deadline in milliseconds. This is a failure detector,
        /// not a latency budget: a deadline expiring always produces an error and never a
        /// successful result. The value bounds the time a client can be blocked by a dead
        /// peer; it does not bound a test or a request's legitimate duration.
        std::uint32_t io_deadline_ms = 30000;
        /// Bounded retry while the listener is coming up.
        std::uint32_t connect_attempts = 100;
        std::uint32_t connect_retry_delay_ms = 20;
    };

    NodeClient();
    ~NodeClient();
    NodeClient(const NodeClient&) = delete;
    NodeClient& operator=(const NodeClient&) = delete;
    NodeClient(NodeClient&&) noexcept;
    NodeClient& operator=(NodeClient&&) noexcept;

    [[nodiscard]] VoidResult connect(const Options& options);
    [[nodiscard]] bool connected() const noexcept;
    void disconnect();

    /// Performs the handshake and stores the granted session.
    [[nodiscard]] Result<HelloResponse> hello(const PublisherId& publisher, const BootId& boot,
                                              std::string_view client_label = {});
    [[nodiscard]] const Session& session() const noexcept;
    void set_session(const Session& session);

    [[nodiscard]] Result<Generation> define_class(const PriorityClassDef& definition);
    [[nodiscard]] Result<Generation> define_scope(const PolicyScopeDef& definition);
    [[nodiscard]] Result<Generation> define_policy(const PolicyDef& definition);
    [[nodiscard]] Result<Generation> define_subject(const SubjectDef& definition);
    [[nodiscard]] Result<Generation> assign(const PriorityAssignment& assignment);
    [[nodiscard]] Result<Generation> retire_assignment(const PriorityAssignmentId& id,
                                                       std::string_view reason);
    [[nodiscard]] Result<FabricEpoch> advance_epoch(std::string_view reason);
    [[nodiscard]] VoidResult fence(const PublisherId& publisher, const BootId& boot,
                                   std::string_view reason);
    [[nodiscard]] Result<PriorityDecision> evaluate(const PriorityQuery& query);
    [[nodiscard]] Result<Generation> checkpoint();
    [[nodiscard]] Result<std::pair<FabricStats, StateStats>> stats();
    [[nodiscard]] Result<IntegrityReport> integrity();
    [[nodiscard]] VoidResult ping();
    [[nodiscard]] VoidResult shutdown_node();

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace pf

#endif  // PRIORITY_FABRIC_CLIENT_HPP
