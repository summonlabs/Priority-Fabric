// Priority Fabric -- authoritative network priority classes.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "priority_fabric/runtime.hpp"

#include <algorithm>
#include <mutex>
#include <shared_mutex>
#include <utility>
#include <vector>

#include "evaluate.hpp"
#include "state.hpp"
#include "store.hpp"

namespace pf {

// Locking discipline (audited):
//   * exactly one authoritative-state lock per runtime, a shared_mutex;
//   * evaluation takes it shared, mutation takes it exclusive;
//   * a separate statistics mutex is only ever acquired *after* the state lock, never before,
//     so the two can never form a cycle;
//   * no callback, no I/O completion and no user code runs while the state lock is held;
//   * nothing in the runtime re-enters a public method from inside the lock, so there is no
//     read-to-write re-entry path.
struct FabricRuntime::Impl {
    mutable std::shared_mutex state_mutex;
    mutable std::mutex stats_mutex;
    detail::StateImage image;
    detail::DurableStore store;
    Limits limits{};
    BootId instance_boot;
    std::filesystem::path state_dir;
    bool closed = true;
    bool allow_new_publishers = true;
    FabricStats stats;
};

namespace {

struct CommitOutcome {
    Generation entity_generation;
    Generation state_generation;
    bool noop = false;
};

/// Journals and applies one mutation. Returns the generation the affected entity now holds.
[[nodiscard]] Result<CommitOutcome> commit_mutation(detail::DurableStore& store,
                                                    detail::StateImage& image,
                                                    const detail::Mutation& mutation) {
    CommitOutcome outcome;
    outcome.noop = detail::mutation_is_idempotent(image, mutation);
    outcome.entity_generation = detail::preview_entity_generation(image, mutation);
    auto status = store.commit(mutation, image);
    if (!status.ok()) {
        return status.status();
    }
    outcome.state_generation = image.generation;
    return outcome;
}

/// Records a refused attempt in the in-memory audit ring. Refusals are deliberately not
/// journaled: an attacker that can reach the runtime could otherwise grow the durable store
/// without bound. They are visible through audit() and stats() for the life of the process.
void record_rejection(detail::StateImage& image, const Limits& limits, std::string op,
                      const Status& status, const Session& actor) {
    AuditEntry entry;
    entry.sequence = image.next_audit_sequence++;
    entry.op = std::move(op);
    entry.result = status.code();
    entry.detail = status.message();
    entry.provenance.publisher = actor.publisher;
    entry.provenance.boot = actor.boot;
    entry.provenance.epoch = actor.epoch;
    entry.provenance.token = actor.token;
    entry.provenance.state_generation = image.generation;
    entry.provenance.audit_sequence = entry.sequence;
    entry.provenance.recorded_at_ms = wall_clock_ms();
    entry.provenance.op = entry.op;
    entry.state_generation = image.generation;
    detail::append_audit(image, std::move(entry), limits);
}

[[nodiscard]] detail::Mutation base_mutation(const Session& actor, detail::MutationOp op,
                                             std::string reason) {
    detail::Mutation mutation;
    mutation.op = op;
    mutation.epoch = actor.epoch;
    mutation.publisher = actor.publisher;
    mutation.boot = actor.boot;
    mutation.token = actor.token;
    mutation.recorded_at_ms = wall_clock_ms();
    mutation.reason = std::move(reason);
    return mutation;
}

[[nodiscard]] bool session_shape_valid(const Session& session) {
    return session.publisher.valid() && session.boot.valid() && session.epoch.is_established() &&
           session.token.is_valid();
}

}  // namespace

// ---------------------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------------------

FabricRuntime::FabricRuntime() : impl_(std::make_unique<Impl>()) {}

FabricRuntime::~FabricRuntime() = default;
FabricRuntime::FabricRuntime(FabricRuntime&&) noexcept = default;
FabricRuntime& FabricRuntime::operator=(FabricRuntime&&) noexcept = default;

Result<FabricRuntime> FabricRuntime::open(const Options& options) {
    if (!limits_within_compiled_ceiling(options.limits)) {
        return make_error(StatusCode::LimitExceeded,
                          "the requested limits exceed the compiled ceiling; the fabric refuses "
                          "to run with unbounded configuration");
    }
    if (options.state_dir.empty()) {
        return make_error(StatusCode::InvalidArgument, "no state directory was given");
    }

    FabricRuntime runtime;
    Impl& impl = *runtime.impl_;
    impl.limits = options.limits;
    impl.state_dir = options.state_dir;
    impl.allow_new_publishers = options.allow_new_publishers;

    if (options.instance_boot_id.has_value()) {
        if (!options.instance_boot_id->valid()) {
            return make_error(StatusCode::InvalidArgument,
                              "the supplied instance boot id is all zero");
        }
        impl.instance_boot = *options.instance_boot_id;
    } else {
        auto boot = BootId::generate();
        if (!boot.ok()) {
            return boot.status();
        }
        impl.instance_boot = boot.value();
    }

    detail::DurableStore::Options store_options;
    store_options.state_dir = options.state_dir;
    store_options.limits = options.limits;
    store_options.create_if_missing = options.create_if_missing;
    store_options.fsync = options.fsync_records;
    store_options.exclusive_lock = options.exclusive_lock;

    detail::StateImage image;
    IntegrityReport report;
    auto store = detail::DurableStore::open(store_options, image, report);
    if (!store.ok()) {
        return store.status();
    }
    if (options.fail_on_degraded && report.health != Health::Healthy) {
        return make_error(StatusCode::Degraded,
                          "the durable state is degraded and fail_on_degraded is set: " +
                              report.detail);
    }

    image.limits = options.limits;
    // Authority never survives a restart by itself. A grant that was live when the previous
    // process stopped is restored as Expired, so no publisher can act on yesterday's authority
    // without explicitly asking for it again. The incarnation itself is kept: it is a fact
    // about the past, not a licence for the present.
    for (auto& entry : image.authority) {
        if (entry.second.state == AuthorityState::Granted) {
            entry.second.state = AuthorityState::Expired;
        }
    }
    impl.image = std::move(image);
    impl.store = std::move(store.value());
    impl.closed = false;

    if (options.advance_epoch_on_open && impl.image.epoch.is_established() &&
        impl.image.health == Health::Healthy) {
        detail::Mutation epoch_mutation;
        epoch_mutation.op = detail::MutationOp::AdvanceEpoch;
        epoch_mutation.epoch = impl.image.epoch;
        epoch_mutation.recorded_at_ms = wall_clock_ms();
        epoch_mutation.reason = "state directory opened by a new authority incarnation";
        epoch_mutation.system = true;
        auto advanced = commit_mutation(impl.store, impl.image, epoch_mutation);
        if (!advanced.ok()) {
            return advanced.status();
        }
    }
    {
        std::lock_guard<std::mutex> guard(impl.stats_mutex);
        impl.stats.recoveries += 1;
    }
    return runtime;
}

VoidResult FabricRuntime::close() {
    if (!impl_) {
        return VoidResult{};
    }
    std::unique_lock<std::shared_mutex> lock(impl_->state_mutex);
    if (impl_->closed) {
        return VoidResult{};
    }
    impl_->closed = true;
    // Closing releases the journal handle through the store's destructor. There is no worker
    // thread, no queued work and no callback to drain, so nothing can be awaiting the lock
    // this call holds.
    impl_->store = detail::DurableStore{};
    return VoidResult{};
}

bool FabricRuntime::closed() const noexcept {
    if (!impl_) {
        return true;
    }
    std::shared_lock<std::shared_mutex> lock(impl_->state_mutex);
    return impl_->closed;
}

// ---------------------------------------------------------------------------------------
// Authority
// ---------------------------------------------------------------------------------------

Result<Session> FabricRuntime::grant_authority(const PublisherId& publisher, const BootId& boot) {
    if (!impl_) {
        return make_error(StatusCode::NotReady, "the runtime was never opened");
    }
    if (!publisher.valid()) {
        return make_error(StatusCode::MalformedId, "authority request carries no publisher id");
    }
    if (!boot.valid()) {
        return make_error(StatusCode::InvalidArgument,
                          "authority request carries an all-zero boot id");
    }
    std::unique_lock<std::shared_mutex> lock(impl_->state_mutex);
    Impl& impl = *impl_;
    if (impl.closed) {
        return make_error(StatusCode::NotReady, "the runtime is closed");
    }
    if (impl.image.health != Health::Healthy) {
        return make_error(StatusCode::Degraded, impl.image.health_detail);
    }

    const auto existing = impl.image.authority.find({publisher, boot});
    if (existing != impl.image.authority.end()) {
        if (existing->second.state == AuthorityState::Fenced) {
            // Fencing is final for an incarnation. The check happens before anything else so
            // that a refused registration cannot move the epoch as a side effect.
            return make_error(StatusCode::Fenced,
                              "publisher '" + publisher.str() + "' incarnation " + boot.hex() +
                                  " was fenced; it cannot be granted authority again");
        }
        if (existing->second.state == AuthorityState::Granted &&
            existing->second.epoch == impl.image.epoch) {
            return Session{publisher, boot, existing->second.epoch, existing->second.token};
        }
    }

    bool known_publisher = false;
    bool live_other_incarnation = false;
    for (const auto& entry : impl.image.authority) {
        if (entry.first.first == publisher) {
            known_publisher = true;
            if (entry.first.second != boot && entry.second.state == AuthorityState::Granted) {
                live_other_incarnation = true;
            }
        }
    }
    if (!known_publisher && !impl.allow_new_publishers) {
        return make_error(StatusCode::Unauthorized,
                          "publisher '" + publisher.str() +
                              "' is not registered and this fabric does not accept new publishers");
    }

    const Session bootstrap{publisher, boot, impl.image.epoch,
                            FencingToken{impl.image.next_fencing_token}};

    // Establish the epoch the first time, and advance it whenever a different incarnation of
    // the same publisher takes over. Both transitions are durable before the grant is
    // returned, so a crash can never leave authority that was not recorded.
    if (!impl.image.epoch.is_established() || live_other_incarnation) {
        detail::Mutation epoch_mutation =
            base_mutation(bootstrap, detail::MutationOp::AdvanceEpoch,
                          live_other_incarnation ? "publisher incarnation replaced"
                                                 : "fabric epoch established");
        epoch_mutation.system = true;
        auto advanced = commit_mutation(impl.store, impl.image, epoch_mutation);
        if (!advanced.ok()) {
            std::lock_guard<std::mutex> guard(impl.stats_mutex);
            impl.stats.mutations_rejected += 1;
            return advanced.status();
        }
        std::lock_guard<std::mutex> guard(impl.stats_mutex);
        impl.stats.epoch_advances += 1;
        impl.stats.mutations_accepted += 1;
        impl.stats.durable_commits += 1;
    }

    detail::Mutation grant =
        base_mutation(Session{publisher, boot, impl.image.epoch,
                              FencingToken{impl.image.next_fencing_token}},
                      detail::MutationOp::GrantAuthority, "authority granted");
    grant.system = true;
    auto outcome = commit_mutation(impl.store, impl.image, grant);
    if (!outcome.ok()) {
        std::lock_guard<std::mutex> guard(impl.stats_mutex);
        impl.stats.mutations_rejected += 1;
        return outcome.status();
    }
    const auto granted = impl.image.authority.find({publisher, boot});
    if (granted == impl.image.authority.end()) {
        return make_error(StatusCode::Internal, "the grant did not produce an authority record");
    }
    {
        std::lock_guard<std::mutex> guard(impl.stats_mutex);
        impl.stats.mutations_accepted += 1;
        impl.stats.durable_commits += 1;
        impl.stats.authorities_granted += 1;
    }
    return Session{publisher, boot, granted->second.epoch, granted->second.token};
}

Result<FabricEpoch> FabricRuntime::advance_epoch(const Session& actor, std::string_view reason) {
    if (!impl_) {
        return make_error(StatusCode::NotReady, "the runtime was never opened");
    }
    if (!session_shape_valid(actor)) {
        return make_error(StatusCode::Unauthorized, "the caller holds no usable session");
    }
    std::unique_lock<std::shared_mutex> lock(impl_->state_mutex);
    Impl& impl = *impl_;
    if (impl.closed) {
        return make_error(StatusCode::NotReady, "the runtime is closed");
    }
    auto mutation = base_mutation(actor, detail::MutationOp::AdvanceEpoch,
                                  std::string(reason.empty() ? "epoch advanced" : reason));
    auto outcome = commit_mutation(impl.store, impl.image, mutation);
    if (!outcome.ok()) {
        record_rejection(impl.image, impl.limits, "advance_epoch", outcome.status(), actor);
        std::lock_guard<std::mutex> guard(impl.stats_mutex);
        impl.stats.mutations_rejected += 1;
        return outcome.status();
    }
    std::lock_guard<std::mutex> guard(impl.stats_mutex);
    impl.stats.mutations_accepted += 1;
    impl.stats.durable_commits += 1;
    impl.stats.epoch_advances += 1;
    return impl.image.epoch;
}

VoidResult FabricRuntime::fence(const Session& actor, const PublisherId& publisher,
                                const BootId& boot, std::string_view reason) {
    if (!impl_) {
        return make_error(StatusCode::NotReady, "the runtime was never opened");
    }
    if (!session_shape_valid(actor)) {
        return make_error(StatusCode::Unauthorized, "the caller holds no usable session");
    }
    if (!publisher.valid() || !boot.valid()) {
        return make_error(StatusCode::InvalidArgument, "the fence request names no incarnation");
    }
    std::unique_lock<std::shared_mutex> lock(impl_->state_mutex);
    Impl& impl = *impl_;
    if (impl.closed) {
        return make_error(StatusCode::NotReady, "the runtime is closed");
    }
    const auto target = impl.image.authority.find({publisher, boot});
    const bool already_fenced =
        target != impl.image.authority.end() && target->second.state == AuthorityState::Fenced;
    auto mutation = base_mutation(actor, detail::MutationOp::FenceAuthority,
                                  std::string(reason.empty() ? "fenced" : reason));
    mutation.fence_publisher = publisher;
    mutation.fence_boot = boot;
    auto outcome = commit_mutation(impl.store, impl.image, mutation);
    if (!outcome.ok()) {
        record_rejection(impl.image, impl.limits, "fence", outcome.status(), actor);
        std::lock_guard<std::mutex> guard(impl.stats_mutex);
        impl.stats.mutations_rejected += 1;
        return outcome.status();
    }
    std::lock_guard<std::mutex> guard(impl.stats_mutex);
    impl.stats.mutations_accepted += 1;
    impl.stats.durable_commits += 1;
    if (!already_fenced) {
        impl.stats.fences_issued += 1;
    }
    return VoidResult{};
}

Result<AuthorityState> FabricRuntime::authority_state(const PublisherId& publisher,
                                                      const BootId& boot) const {
    if (!impl_) {
        return make_error(StatusCode::NotReady, "the runtime was never opened");
    }
    std::shared_lock<std::shared_mutex> lock(impl_->state_mutex);
    const auto entry = impl_->image.authority.find({publisher, boot});
    if (entry == impl_->image.authority.end()) {
        return make_error(StatusCode::NotFound, "no such publisher incarnation");
    }
    return entry->second.state;
}

// ---------------------------------------------------------------------------------------
// Definitions and assignments
// ---------------------------------------------------------------------------------------

Result<Generation> FabricRuntime::define_class(const Session& actor,
                                               const PriorityClassDef& definition) {
    if (!impl_) {
        return make_error(StatusCode::NotReady, "the runtime was never opened");
    }
    if (!session_shape_valid(actor)) {
        return make_error(StatusCode::Unauthorized, "the caller holds no usable session");
    }
    std::unique_lock<std::shared_mutex> lock(impl_->state_mutex);
    Impl& impl = *impl_;
    if (impl.closed) {
        return make_error(StatusCode::NotReady, "the runtime is closed");
    }
    auto mutation = base_mutation(actor, detail::MutationOp::DefineClass, "define class");
    mutation.cls = definition;
    mutation.cls.generation = Generation::unset();
    auto outcome = commit_mutation(impl.store, impl.image, mutation);
    if (!outcome.ok()) {
        record_rejection(impl.image, impl.limits, "define_class", outcome.status(), actor);
        std::lock_guard<std::mutex> guard(impl.stats_mutex);
        impl.stats.mutations_rejected += 1;
        return outcome.status();
    }
    std::lock_guard<std::mutex> guard(impl.stats_mutex);
    impl.stats.mutations_accepted += 1;
    impl.stats.durable_commits += 1;
    impl.stats.idempotent_noops += outcome.value().noop ? 1 : 0;
    return outcome.value().entity_generation;
}

Result<Generation> FabricRuntime::define_scope(const Session& actor,
                                               const PolicyScopeDef& definition) {
    if (!impl_) {
        return make_error(StatusCode::NotReady, "the runtime was never opened");
    }
    if (!session_shape_valid(actor)) {
        return make_error(StatusCode::Unauthorized, "the caller holds no usable session");
    }
    std::unique_lock<std::shared_mutex> lock(impl_->state_mutex);
    Impl& impl = *impl_;
    if (impl.closed) {
        return make_error(StatusCode::NotReady, "the runtime is closed");
    }
    auto mutation = base_mutation(actor, detail::MutationOp::DefineScope, "define scope");
    mutation.scope = definition;
    mutation.scope.generation = Generation::unset();
    auto outcome = commit_mutation(impl.store, impl.image, mutation);
    if (!outcome.ok()) {
        record_rejection(impl.image, impl.limits, "define_scope", outcome.status(), actor);
        std::lock_guard<std::mutex> guard(impl.stats_mutex);
        impl.stats.mutations_rejected += 1;
        return outcome.status();
    }
    std::lock_guard<std::mutex> guard(impl.stats_mutex);
    impl.stats.mutations_accepted += 1;
    impl.stats.durable_commits += 1;
    impl.stats.idempotent_noops += outcome.value().noop ? 1 : 0;
    return outcome.value().entity_generation;
}

Result<Generation> FabricRuntime::define_policy(const Session& actor,
                                                const PolicyDef& definition) {
    if (!impl_) {
        return make_error(StatusCode::NotReady, "the runtime was never opened");
    }
    if (!session_shape_valid(actor)) {
        return make_error(StatusCode::Unauthorized, "the caller holds no usable session");
    }
    std::unique_lock<std::shared_mutex> lock(impl_->state_mutex);
    Impl& impl = *impl_;
    if (impl.closed) {
        return make_error(StatusCode::NotReady, "the runtime is closed");
    }
    PolicyDef stamped = definition;
    stamped.generation = Generation::unset();
    const auto scope = impl.image.scopes.find(stamped.scope);
    if (scope == impl.image.scopes.end()) {
        const Status status = make_error(StatusCode::NotFound, "policy names scope '" +
                                                                   stamped.scope.str() +
                                                                   "' which is not defined");
        record_rejection(impl.image, impl.limits, "define_policy", status, actor);
        std::lock_guard<std::mutex> guard(impl.stats_mutex);
        impl.stats.mutations_rejected += 1;
        return status;
    }
    stamped.scope_generation = scope->second.definition.generation;

    auto mutation = base_mutation(actor, detail::MutationOp::DefinePolicy, "define policy");
    mutation.policy = std::move(stamped);
    auto outcome = commit_mutation(impl.store, impl.image, mutation);
    if (!outcome.ok()) {
        record_rejection(impl.image, impl.limits, "define_policy", outcome.status(), actor);
        std::lock_guard<std::mutex> guard(impl.stats_mutex);
        impl.stats.mutations_rejected += 1;
        return outcome.status();
    }
    std::lock_guard<std::mutex> guard(impl.stats_mutex);
    impl.stats.mutations_accepted += 1;
    impl.stats.durable_commits += 1;
    impl.stats.idempotent_noops += outcome.value().noop ? 1 : 0;
    return outcome.value().entity_generation;
}

Result<Generation> FabricRuntime::define_subject(const Session& actor,
                                                 const SubjectDef& definition) {
    if (!impl_) {
        return make_error(StatusCode::NotReady, "the runtime was never opened");
    }
    if (!session_shape_valid(actor)) {
        return make_error(StatusCode::Unauthorized, "the caller holds no usable session");
    }
    std::unique_lock<std::shared_mutex> lock(impl_->state_mutex);
    Impl& impl = *impl_;
    if (impl.closed) {
        return make_error(StatusCode::NotReady, "the runtime is closed");
    }
    auto mutation = base_mutation(actor, detail::MutationOp::DefineSubject, "define subject");
    mutation.subject = definition;
    mutation.subject.generation = Generation::unset();
    auto outcome = commit_mutation(impl.store, impl.image, mutation);
    if (!outcome.ok()) {
        record_rejection(impl.image, impl.limits, "define_subject", outcome.status(), actor);
        std::lock_guard<std::mutex> guard(impl.stats_mutex);
        impl.stats.mutations_rejected += 1;
        return outcome.status();
    }
    std::lock_guard<std::mutex> guard(impl.stats_mutex);
    impl.stats.mutations_accepted += 1;
    impl.stats.durable_commits += 1;
    impl.stats.idempotent_noops += outcome.value().noop ? 1 : 0;
    return outcome.value().entity_generation;
}

Result<Generation> FabricRuntime::assign(const Session& actor,
                                         const PriorityAssignment& assignment) {
    if (!impl_) {
        return make_error(StatusCode::NotReady, "the runtime was never opened");
    }
    if (!session_shape_valid(actor)) {
        return make_error(StatusCode::Unauthorized, "the caller holds no usable session");
    }
    std::unique_lock<std::shared_mutex> lock(impl_->state_mutex);
    Impl& impl = *impl_;
    if (impl.closed) {
        return make_error(StatusCode::NotReady, "the runtime is closed");
    }
    if (assignment.kind == AssignmentKind::Default) {
        return make_error(StatusCode::InvalidArgument,
                          "Default is produced by the fabric from a policy declaration and "
                          "cannot be published as an assignment");
    }

    PriorityAssignment stamped = assignment;
    stamped.generation = Generation::unset();
    const auto subject = impl.image.subjects.find(stamped.subject);
    if (subject == impl.image.subjects.end()) {
        const Status status = make_error(StatusCode::NotFound, "assignment names subject '" +
                                                                   stamped.subject.str() +
                                                                   "' which is not defined");
        record_rejection(impl.image, impl.limits, "assign", status, actor);
        std::lock_guard<std::mutex> guard(impl.stats_mutex);
        impl.stats.mutations_rejected += 1;
        return status;
    }
    const auto scope = impl.image.scopes.find(stamped.scope);
    if (scope == impl.image.scopes.end()) {
        const Status status = make_error(StatusCode::NotFound, "assignment names scope '" +
                                                                   stamped.scope.str() +
                                                                   "' which is not defined");
        record_rejection(impl.image, impl.limits, "assign", status, actor);
        std::lock_guard<std::mutex> guard(impl.stats_mutex);
        impl.stats.mutations_rejected += 1;
        return status;
    }
    const auto cls = impl.image.classes.find(stamped.cls);
    if (cls == impl.image.classes.end()) {
        const Status status = make_error(StatusCode::NotFound, "assignment names class '" +
                                                                   stamped.cls.str() +
                                                                   "' which is not defined");
        record_rejection(impl.image, impl.limits, "assign", status, actor);
        std::lock_guard<std::mutex> guard(impl.stats_mutex);
        impl.stats.mutations_rejected += 1;
        return status;
    }
    stamped.subject_generation = subject->second.definition.generation;
    stamped.scope_generation = scope->second.definition.generation;
    stamped.class_generation = cls->second.definition.generation;
    if (stamped.policy.has_value()) {
        const auto policy = impl.image.policies.find(*stamped.policy);
        if (policy == impl.image.policies.end()) {
            const Status status = make_error(StatusCode::NotFound,
                                             "assignment names policy '" +
                                                 stamped.policy->str() +
                                                 "' which is not defined");
            record_rejection(impl.image, impl.limits, "assign", status, actor);
            std::lock_guard<std::mutex> guard(impl.stats_mutex);
            impl.stats.mutations_rejected += 1;
            return status;
        }
        stamped.policy_generation = policy->second.definition.generation;
    } else {
        stamped.policy_generation = Generation::unset();
    }

    auto mutation = base_mutation(actor, detail::MutationOp::Assign, "assign");
    mutation.assignment = std::move(stamped);
    auto outcome = commit_mutation(impl.store, impl.image, mutation);
    if (!outcome.ok()) {
        record_rejection(impl.image, impl.limits, "assign", outcome.status(), actor);
        std::lock_guard<std::mutex> guard(impl.stats_mutex);
        impl.stats.mutations_rejected += 1;
        return outcome.status();
    }
    std::lock_guard<std::mutex> guard(impl.stats_mutex);
    impl.stats.mutations_accepted += 1;
    impl.stats.durable_commits += 1;
    impl.stats.idempotent_noops += outcome.value().noop ? 1 : 0;
    return outcome.value().entity_generation;
}

Result<Generation> FabricRuntime::retire_assignment(const Session& actor,
                                                    const PriorityAssignmentId& id,
                                                    std::string_view reason) {
    if (!impl_) {
        return make_error(StatusCode::NotReady, "the runtime was never opened");
    }
    if (!session_shape_valid(actor)) {
        return make_error(StatusCode::Unauthorized, "the caller holds no usable session");
    }
    std::unique_lock<std::shared_mutex> lock(impl_->state_mutex);
    Impl& impl = *impl_;
    if (impl.closed) {
        return make_error(StatusCode::NotReady, "the runtime is closed");
    }
    auto mutation = base_mutation(actor, detail::MutationOp::RetireAssignment,
                                  std::string(reason.empty() ? "retired" : reason));
    mutation.retire_target = id;
    auto outcome = commit_mutation(impl.store, impl.image, mutation);
    if (!outcome.ok()) {
        record_rejection(impl.image, impl.limits, "retire_assignment", outcome.status(), actor);
        std::lock_guard<std::mutex> guard(impl.stats_mutex);
        impl.stats.mutations_rejected += 1;
        return outcome.status();
    }
    std::lock_guard<std::mutex> guard(impl.stats_mutex);
    impl.stats.mutations_accepted += 1;
    impl.stats.durable_commits += 1;
    impl.stats.idempotent_noops += outcome.value().noop ? 1 : 0;
    return outcome.value().entity_generation;
}

// ---------------------------------------------------------------------------------------
// Evaluation
// ---------------------------------------------------------------------------------------

PriorityDecision FabricRuntime::evaluate(const PriorityQuery& query) {
    if (!impl_) {
        PriorityDecision decision;
        decision.outcome = Outcome::Rejected;
        decision.reason_code = "runtime_not_open";
        decision.reason = "the runtime was never opened";
        decision.resolution = "none";
        decision.digest = detail::compute_decision_digest(decision);
        return decision;
    }
    std::shared_lock<std::shared_mutex> lock(impl_->state_mutex);
    Impl& impl = *impl_;
    PriorityDecision decision;
    if (impl.closed) {
        decision.outcome = Outcome::Rejected;
        decision.reason_code = "runtime_closed";
        decision.reason = "the runtime is closed and no longer answers authoritatively";
        decision.resolution = "none";
        decision.epoch = impl.image.epoch;
        decision.state_generation = impl.image.generation;
        decision.digest = detail::compute_decision_digest(decision);
    } else {
        decision = detail::evaluate_query(impl.image, query);
    }
    {
        std::lock_guard<std::mutex> guard(impl.stats_mutex);
        impl.stats.evaluations += 1;
        switch (decision.outcome) {
            case Outcome::Assigned: impl.stats.evaluations_assigned += 1; break;
            case Outcome::Inherited: impl.stats.evaluations_inherited += 1; break;
            case Outcome::Overridden: impl.stats.evaluations_overridden += 1; break;
            case Outcome::Conflict: impl.stats.evaluations_conflict += 1; break;
            case Outcome::Unknown: impl.stats.evaluations_unknown += 1; break;
            case Outcome::Stale: impl.stats.evaluations_stale += 1; break;
            case Outcome::Fenced: impl.stats.evaluations_fenced += 1; break;
            case Outcome::Rejected: impl.stats.evaluations_rejected += 1; break;
        }
    }
    return decision;
}

// ---------------------------------------------------------------------------------------
// Introspection
// ---------------------------------------------------------------------------------------

const Limits& FabricRuntime::limits() const noexcept {
    return impl_->limits;
}

FabricEpoch FabricRuntime::epoch() const {
    std::shared_lock<std::shared_mutex> lock(impl_->state_mutex);
    return impl_->image.epoch;
}

Generation FabricRuntime::state_generation() const {
    std::shared_lock<std::shared_mutex> lock(impl_->state_mutex);
    return impl_->image.generation;
}

Health FabricRuntime::health() const {
    std::shared_lock<std::shared_mutex> lock(impl_->state_mutex);
    return impl_->image.health;
}

std::string FabricRuntime::health_detail() const {
    std::shared_lock<std::shared_mutex> lock(impl_->state_mutex);
    return impl_->image.health_detail;
}

StateStats FabricRuntime::state_stats() const {
    std::shared_lock<std::shared_mutex> lock(impl_->state_mutex);
    const detail::StateImage& image = impl_->image;
    StateStats stats;
    stats.classes = image.classes.size();
    stats.scopes = image.scopes.size();
    stats.policies = image.policies.size();
    stats.subjects = image.subjects.size();
    stats.assignments = image.assignments.size();
    for (const auto& entry : image.assignments) {
        if (!entry.second.active) {
            ++stats.retired_assignments;
        }
    }
    for (const auto& entry : image.authority) {
        ++stats.publishers;
        if (entry.second.state == AuthorityState::Fenced) {
            ++stats.fenced_boots;
        }
    }
    stats.audit_entries = image.audit.size();
    stats.durable_bytes = impl_->store.durable_bytes();
    stats.journal_records = impl_->store.journal_records();
    stats.state_generation = image.generation;
    stats.epoch = image.epoch;
    return stats;
}

FabricStats FabricRuntime::stats() const {
    std::lock_guard<std::mutex> guard(impl_->stats_mutex);
    return impl_->stats;
}

const BootId& FabricRuntime::instance_boot_id() const noexcept {
    return impl_->instance_boot;
}

const std::filesystem::path& FabricRuntime::state_dir() const noexcept {
    return impl_->state_dir;
}

std::vector<AuditEntry> FabricRuntime::audit(std::uint32_t max_entries) const {
    std::shared_lock<std::shared_mutex> lock(impl_->state_mutex);
    const auto& entries = impl_->image.audit;
    const std::uint32_t bound =
        std::min<std::uint32_t>(max_entries, impl_->limits.max_audit_return);
    std::vector<AuditEntry> out;
    const std::size_t take = std::min<std::size_t>(bound, entries.size());
    out.reserve(take);
    for (std::size_t i = entries.size() - take; i < entries.size(); ++i) {
        out.push_back(entries[i]);
    }
    return out;
}

std::vector<PriorityClassDef> FabricRuntime::list_classes() const {
    std::shared_lock<std::shared_mutex> lock(impl_->state_mutex);
    std::vector<PriorityClassDef> out;
    out.reserve(impl_->image.classes.size());
    for (const auto& entry : impl_->image.classes) {
        out.push_back(entry.second.definition);
    }
    return out;
}

std::vector<PolicyScopeDef> FabricRuntime::list_scopes() const {
    std::shared_lock<std::shared_mutex> lock(impl_->state_mutex);
    std::vector<PolicyScopeDef> out;
    out.reserve(impl_->image.scopes.size());
    for (const auto& entry : impl_->image.scopes) {
        out.push_back(entry.second.definition);
    }
    return out;
}

std::vector<PolicyDef> FabricRuntime::list_policies() const {
    std::shared_lock<std::shared_mutex> lock(impl_->state_mutex);
    std::vector<PolicyDef> out;
    out.reserve(impl_->image.policies.size());
    for (const auto& entry : impl_->image.policies) {
        out.push_back(entry.second.definition);
    }
    return out;
}

std::vector<SubjectDef> FabricRuntime::list_subjects() const {
    std::shared_lock<std::shared_mutex> lock(impl_->state_mutex);
    std::vector<SubjectDef> out;
    out.reserve(impl_->image.subjects.size());
    for (const auto& entry : impl_->image.subjects) {
        out.push_back(entry.second.definition);
    }
    return out;
}

std::vector<PriorityAssignment> FabricRuntime::list_assignments() const {
    std::shared_lock<std::shared_mutex> lock(impl_->state_mutex);
    std::vector<PriorityAssignment> out;
    out.reserve(impl_->image.assignments.size());
    for (const auto& entry : impl_->image.assignments) {
        out.push_back(entry.second.assignment);
    }
    return out;
}

Result<PriorityClassDef> FabricRuntime::class_definition(const PriorityClassId& id) const {
    std::shared_lock<std::shared_mutex> lock(impl_->state_mutex);
    const auto entry = impl_->image.classes.find(id);
    if (entry == impl_->image.classes.end()) {
        return make_error(StatusCode::NotFound, "class '" + id.str() + "' is not defined");
    }
    return entry->second.definition;
}

Result<PolicyScopeDef> FabricRuntime::scope_definition(const PolicyScopeId& id) const {
    std::shared_lock<std::shared_mutex> lock(impl_->state_mutex);
    const auto entry = impl_->image.scopes.find(id);
    if (entry == impl_->image.scopes.end()) {
        return make_error(StatusCode::NotFound, "scope '" + id.str() + "' is not defined");
    }
    return entry->second.definition;
}

Result<PolicyDef> FabricRuntime::policy_definition(const PolicyId& id) const {
    std::shared_lock<std::shared_mutex> lock(impl_->state_mutex);
    const auto entry = impl_->image.policies.find(id);
    if (entry == impl_->image.policies.end()) {
        return make_error(StatusCode::NotFound, "policy '" + id.str() + "' is not defined");
    }
    return entry->second.definition;
}

Result<SubjectDef> FabricRuntime::subject_definition(const SubjectId& id) const {
    std::shared_lock<std::shared_mutex> lock(impl_->state_mutex);
    const auto entry = impl_->image.subjects.find(id);
    if (entry == impl_->image.subjects.end()) {
        return make_error(StatusCode::NotFound, "subject '" + id.str() + "' is not defined");
    }
    return entry->second.definition;
}

Result<PriorityAssignment> FabricRuntime::assignment(const PriorityAssignmentId& id) const {
    std::shared_lock<std::shared_mutex> lock(impl_->state_mutex);
    const auto entry = impl_->image.assignments.find(id);
    if (entry == impl_->image.assignments.end()) {
        return make_error(StatusCode::NotFound, "assignment '" + id.str() + "' is not defined");
    }
    return entry->second.assignment;
}

IntegrityReport FabricRuntime::integrity_report() const {
    std::unique_lock<std::shared_mutex> lock(impl_->state_mutex);
    IntegrityReport report;
    if (impl_->closed) {
        report.ok = false;
        report.health = Health::Degraded;
        report.detail = "the runtime is closed";
        return report;
    }
    auto verified = impl_->store.verify(impl_->image);
    if (!verified.ok()) {
        report.ok = false;
        report.health = Health::Degraded;
        report.detail = verified.status().message();
        return report;
    }
    return verified.value();
}

Result<Generation> FabricRuntime::checkpoint() {
    if (!impl_) {
        return make_error(StatusCode::NotReady, "the runtime was never opened");
    }
    std::unique_lock<std::shared_mutex> lock(impl_->state_mutex);
    if (impl_->closed) {
        return make_error(StatusCode::NotReady, "the runtime is closed");
    }
    auto checkpointed = impl_->store.checkpoint(impl_->image);
    if (!checkpointed.ok()) {
        return checkpointed.status();
    }
    return checkpointed.value();
}

}  // namespace pf
