// Priority Fabric -- authoritative network priority classes.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#ifndef PRIORITY_FABRIC_RUNTIME_HPP
#define PRIORITY_FABRIC_RUNTIME_HPP

#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "priority_fabric/decision.hpp"
#include "priority_fabric/export.hpp"
#include "priority_fabric/ident.hpp"
#include "priority_fabric/limits.hpp"
#include "priority_fabric/model.hpp"
#include "priority_fabric/status.hpp"

namespace pf {

/// Proof that a publisher incarnation holds authority in a specific epoch.
///
/// A session is accepted only together with the exact (publisher, boot, epoch, token)
/// tuple it was issued for. Carrying it across an epoch change, a publisher restart or a
/// fence produces FENCED, never a partial write.
struct PF_API Session {
    PublisherId publisher;
    BootId boot;
    FabricEpoch epoch;
    FencingToken token;

    [[nodiscard]] bool valid() const noexcept {
        return publisher.valid() && boot.valid() && epoch.is_established() && token.is_valid();
    }

    friend bool operator==(const Session&, const Session&) noexcept = default;
};

/// The authoritative priority fabric.
///
/// All methods are safe to call concurrently from multiple threads; internally the runtime
/// serializes mutation and takes a shared view for evaluation. Evaluation never blocks a
/// caller on a writer longer than the duration of one mutation application.
class PF_API FabricRuntime {
public:
    struct Options {
        /// Directory holding manifest.pfm, snapshot.pfs and journal*.pfj.
        std::filesystem::path state_dir;
        /// Bounds. Values above the compiled ceiling are rejected at open time.
        Limits limits{};
        /// When false the directory must already contain a valid store.
        bool create_if_missing = false;
        /// When true every durable step is flushed to the platform before the call
        /// returns. Turning this off trades crash-durability for latency and is reported
        /// by integrity_report() as a durability downgrade.
        bool fsync_records = true;
        /// Refuse to open when the initial scan finds a degraded store. Off by default:
        /// the runtime opens degraded so that an operator can inspect and repair it, and
        /// answers REJECTED in the meantime.
        bool fail_on_degraded = false;
        /// Deterministic boot id used when the caller wants reproducible allocations in
        /// tests. Absent = OS entropy.
        std::optional<BootId> instance_boot_id;
        /// When false, a publisher that has never been seen before is refused authority and
        /// the epoch is not advanced for it. A deployment that turns this off provisions its
        /// publishers through the command line tool first.
        bool allow_new_publishers = true;
        /// When true, opening an already-established store advances the fabric epoch as its
        /// first durable act. A node that takes ownership of a state directory is a new
        /// incarnation of the authority, so every grant and every piece of evidence from
        /// before the restart is fenced and must be re-established. Off by default for
        /// read-mostly tools, which must not move the epoch merely by looking at the state.
        bool advance_epoch_on_open = false;
        /// Take an exclusive lock on the state directory. Leave this on for anything that can
        /// write. A read-only inspection may turn it off: the durable records are
        /// self-describing and self-checked, so a reader that never mutates cannot be misled
        /// by a writer appending in parallel.
        bool exclusive_lock = true;
    };

    FabricRuntime();
    ~FabricRuntime();
    FabricRuntime(const FabricRuntime&) = delete;
    FabricRuntime& operator=(const FabricRuntime&) = delete;
    FabricRuntime(FabricRuntime&&) noexcept;
    FabricRuntime& operator=(FabricRuntime&&) noexcept;

    /// Opens (and, when requested, creates) a state directory, replays the durable state
    /// and mints this instance's boot id. Recovery is performed before any authority is
    /// handed out.
    [[nodiscard]] static Result<FabricRuntime> open(const Options& options);

    // ----- authority -----------------------------------------------------------------

    /// Grants authority to a publisher incarnation.
    ///
    /// * unknown publisher                     -> new publisher, epoch established if needed
    /// * known publisher, same boot id          -> the existing grant is returned unchanged
    /// * known publisher, different boot id     -> the fabric advances the epoch, marks every
    ///                                             other boot of that publisher Superseded,
    ///                                             and issues a fresh token
    ///
    /// The advancement is durable before the grant is returned.
    [[nodiscard]] Result<Session> grant_authority(const PublisherId& publisher,
                                                  const BootId& boot);

    /// Fences a specific publisher incarnation. Every later mutation that carries its
    /// session is rejected with Fenced. Fencing an already-fenced or unknown boot is an
    /// idempotent no-op that still records an audit entry.
    [[nodiscard]] VoidResult fence(const Session& actor, const PublisherId& publisher,
                                   const BootId& boot, std::string_view reason);

    /// Advances the fabric epoch. All authority granted under earlier epochs stops being
    /// usable; evidence published under them is reported as FENCED on evaluation.
    [[nodiscard]] Result<FabricEpoch> advance_epoch(const Session& actor, std::string_view reason);

    /// Current authority state of a publisher incarnation.
    [[nodiscard]] Result<AuthorityState> authority_state(const PublisherId& publisher,
                                                         const BootId& boot) const;

    // ----- definitions ---------------------------------------------------------------

    [[nodiscard]] Result<Generation> define_class(const Session& actor,
                                                  const PriorityClassDef& definition);
    [[nodiscard]] Result<Generation> define_scope(const Session& actor,
                                                  const PolicyScopeDef& definition);
    [[nodiscard]] Result<Generation> define_policy(const Session& actor,
                                                   const PolicyDef& definition);
    [[nodiscard]] Result<Generation> define_subject(const Session& actor,
                                                    const SubjectDef& definition);

    /// Publishes an assignment. The referenced subject, scope, class and (when present)
    /// policy must exist; their current generations are stamped into the assignment so
    /// that a later redefinition makes this assignment STALE rather than silently
    /// re-interpreted.
    [[nodiscard]] Result<Generation> assign(const Session& actor,
                                            const PriorityAssignment& assignment);

    /// Retires an assignment. Retirement is durable and audited; the assignment stops
    /// being evidence for any evaluation and is reported as REJECTED evidence with the
    /// retirement reason.
    [[nodiscard]] Result<Generation> retire_assignment(const Session& actor,
                                                       const PriorityAssignmentId& id,
                                                       std::string_view reason);

    // ----- evaluation ----------------------------------------------------------------

    /// Answers the core question. Never throws; a structurally invalid question is
    /// answered with Outcome::Rejected and a stable reason code.
    [[nodiscard]] PriorityDecision evaluate(const PriorityQuery& query);

    // ----- introspection -------------------------------------------------------------

    [[nodiscard]] const Limits& limits() const noexcept;
    [[nodiscard]] FabricEpoch epoch() const;
    [[nodiscard]] Generation state_generation() const;
    [[nodiscard]] Health health() const;
    [[nodiscard]] std::string health_detail() const;
    [[nodiscard]] StateStats state_stats() const;
    [[nodiscard]] FabricStats stats() const;
    [[nodiscard]] const BootId& instance_boot_id() const noexcept;
    [[nodiscard]] const std::filesystem::path& state_dir() const noexcept;

    [[nodiscard]] std::vector<AuditEntry> audit(std::uint32_t max_entries) const;
    [[nodiscard]] std::vector<PriorityClassDef> list_classes() const;
    [[nodiscard]] std::vector<PolicyScopeDef> list_scopes() const;
    [[nodiscard]] std::vector<PolicyDef> list_policies() const;
    [[nodiscard]] std::vector<SubjectDef> list_subjects() const;
    [[nodiscard]] std::vector<PriorityAssignment> list_assignments() const;

    [[nodiscard]] Result<PriorityClassDef> class_definition(const PriorityClassId& id) const;
    [[nodiscard]] Result<PolicyScopeDef> scope_definition(const PolicyScopeId& id) const;
    [[nodiscard]] Result<PolicyDef> policy_definition(const PolicyId& id) const;
    [[nodiscard]] Result<SubjectDef> subject_definition(const SubjectId& id) const;
    [[nodiscard]] Result<PriorityAssignment> assignment(const PriorityAssignmentId& id) const;

    /// Scans the durable state from scratch, replays it into a scratch image and compares
    /// the result with the live image. Never mutates live state.
    [[nodiscard]] IntegrityReport integrity_report() const;

    /// Forces a snapshot and compacts the journal. Returns the snapshot generation.
    [[nodiscard]] Result<Generation> checkpoint();

    /// Flushes and releases durable resources. Idempotent. After close() the runtime only
    /// answers introspection calls; mutations report NotReady and evaluation reports
    /// Rejected.
    [[nodiscard]] VoidResult close();
    [[nodiscard]] bool closed() const noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace pf

#endif  // PRIORITY_FABRIC_RUNTIME_HPP
