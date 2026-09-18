// Priority Fabric -- authoritative network priority classes.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Internal: the crash-safe durable store behind a fabric runtime.

#ifndef PRIORITY_FABRIC_SRC_STORE_HPP
#define PRIORITY_FABRIC_SRC_STORE_HPP

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

#include "fsutil.hpp"
#include "priority_fabric/decision.hpp"
#include "priority_fabric/limits.hpp"
#include "priority_fabric/status.hpp"
#include "state.hpp"

namespace pf::detail {

/// Durable store for one fabric state directory.
///
/// Commit protocol (never acknowledges before the state is durable):
///
///   validate  -> the mutation is checked against the live image and cannot fail later
///   bind      -> the mutation carries publisher, boot, epoch and fencing token
///   plan      -> the resulting generation is computed and recorded in the record
///   reserve   -> durable growth bounds are checked before anything is written
///   journal   -> a Pending record is appended and flushed to the platform
///   perform   -> the mutation is applied to the in-memory image
///   verify    -> the applied generation is compared with the planned generation
///   commit    -> a Commit record naming the pending sequence is appended and flushed
///   retire    -> a checkpoint folds the journal into a snapshot and drops old segments
///
/// Recovery distinguishes durable configuration, committed authoritative state, unfinished
/// attempts (a Pending record with no Commit) and evidence that failed verification.
class DurableStore {
public:
    struct Options {
        std::filesystem::path state_dir;
        Limits limits{};
        bool create_if_missing = false;
        bool fsync = true;
        /// Take an exclusive lock on the state directory. Two live writers on one store would
        /// each believe they own the journal; the lock makes that impossible instead of
        /// merely unlikely.
        bool exclusive_lock = true;
    };

    DurableStore() = default;
    ~DurableStore();
    DurableStore(const DurableStore&) = delete;
    DurableStore& operator=(const DurableStore&) = delete;
    DurableStore(DurableStore&&) noexcept;
    DurableStore& operator=(DurableStore&&) noexcept;

    /// Opens the directory, replays the durable state into \p image and reports what it
    /// found. Never returns a partially replayed image: on a structural failure the image is
    /// left empty and the failure is returned.
    [[nodiscard]] static Result<DurableStore> open(const Options& options, StateImage& image,
                                                  IntegrityReport& report);

    /// Journal and apply one mutation. See the protocol above.
    [[nodiscard]] VoidResult commit(const Mutation& mutation, StateImage& live);

    /// Folds the journal into a fresh snapshot and starts a new journal segment.
    [[nodiscard]] Result<Generation> checkpoint(const StateImage& image);

    /// Re-reads the whole store from disk, replays it into a scratch image and compares the
    /// result with \p live. Does not modify \p live or the files.
    [[nodiscard]] Result<IntegrityReport> verify(const StateImage& live) const;

    [[nodiscard]] std::uint64_t durable_bytes() const noexcept { return durable_bytes_; }
    [[nodiscard]] std::uint64_t journal_records() const noexcept { return journal_records_; }
    [[nodiscard]] bool fsync_enabled() const noexcept { return options_.fsync; }
    [[nodiscard]] const std::filesystem::path& directory() const noexcept {
        return options_.state_dir;
    }
    [[nodiscard]] std::uint32_t current_segment() const noexcept { return segment_index_; }

private:
    struct Manifest {
        FabricEpoch epoch;
        Generation state_generation;
        std::uint64_t last_sequence = 0;
        std::uint32_t first_segment = 0;
        bool snapshot_present = false;
        Digest snapshot_digest;
        std::uint64_t snapshot_bytes = 0;
    };

    [[nodiscard]] static Result<Manifest> read_manifest(const Options& options,
                                                        const std::string& key);
    [[nodiscard]] static VoidResult write_manifest(const Options& options, const std::string& key,
                                                   const Manifest& manifest);
    [[nodiscard]] VoidResult append_record(const std::string& record);
    [[nodiscard]] VoidResult write_snapshot(const StateImage& image);
    [[nodiscard]] static Result<StateImage> read_snapshot(const Options& options,
                                                          const std::string& key,
                                                          const Manifest& manifest);
    [[nodiscard]] static Result<IntegrityReport> replay(const Options& options,
                                                        const std::string& key,
                                                        StateImage& image);
    [[nodiscard]] VoidResult roll_segment_if_needed();
    void recompute_durable_bytes();

    Options options_{};
    std::string key_;
    std::uint32_t segment_index_ = 0;
    std::uint64_t segment_bytes_ = 0;
    std::uint64_t durable_bytes_ = 0;
    std::uint64_t journal_records_ = 0;
    std::uint64_t next_sequence_ = 1;
    int segment_fd_ = -1;
    bool open_ = false;
    fsutil::FileLock lock_;
};

}  // namespace pf::detail

#endif  // PRIORITY_FABRIC_SRC_STORE_HPP
