// Priority Fabric -- authoritative network priority classes.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "store.hpp"

#include <algorithm>
#include <cstring>
#include <limits>
#include <set>
#include <utility>

#if defined(_WIN32)
#include <io.h>
#else
#include <unistd.h>
#endif

#include "fsutil.hpp"
#include "priority_fabric/checked.hpp"
#include "priority_fabric/codec.hpp"
#include "priority_fabric/durability.hpp"
#include "priority_fabric/model_codec.hpp"
#include "priority_fabric/version.hpp"

namespace pf::detail {
namespace {

/// Journal segment rollover threshold. Bounds the size of any single durable file and of a
/// single recovery scan.
constexpr std::uint64_t kSegmentRollBytes = 64ull * 1024ull * 1024ull;

/// Fixed snapshot header: magic, format, payload length, payload digest.
constexpr std::size_t kSnapshotHeaderBytes = 4 + 2 + 4 + Digest::kSize;

void append_le(std::string& buffer, std::uint64_t value, std::size_t width) {
    for (std::size_t i = 0; i < width; ++i) {
        buffer.push_back(static_cast<char>((value >> (8 * i)) & 0xFFu));
    }
}

std::uint64_t read_le(const std::uint8_t* data, std::size_t width) noexcept {
    std::uint64_t value = 0;
    for (std::size_t i = 0; i < width; ++i) {
        value |= static_cast<std::uint64_t>(data[i]) << (8 * i);
    }
    return value;
}

std::string encode_commit_payload(std::uint64_t sequence, const Digest& digest) {
    std::string out;
    append_le(out, sequence, 8);
    out.append(reinterpret_cast<const char*>(digest.bytes.data()), digest.bytes.size());
    return out;
}

Result<std::pair<std::uint64_t, Digest>> decode_commit_payload(const std::string& payload) {
    if (payload.size() != 8 + Digest::kSize) {
        return make_error(StatusCode::Corrupt,
                          "commit record carries " + std::to_string(payload.size()) +
                              " bytes, expected " + std::to_string(8 + Digest::kSize));
    }
    const auto* bytes = reinterpret_cast<const std::uint8_t*>(payload.data());
    const std::uint64_t sequence = read_le(bytes, 8);
    Digest digest;
    for (std::size_t i = 0; i < Digest::kSize; ++i) {
        digest.bytes[i] = bytes[8 + i];
    }
    return std::make_pair(sequence, digest);
}

}  // namespace

DurableStore::~DurableStore() {
    if (segment_fd_ >= 0) {
#if defined(_WIN32)
        ::_close(segment_fd_);
#else
        ::close(segment_fd_);
#endif
        segment_fd_ = -1;
    }
}

DurableStore::DurableStore(DurableStore&& other) noexcept
    : options_(std::move(other.options_)),
      key_(std::move(other.key_)),
      segment_index_(other.segment_index_),
      segment_bytes_(other.segment_bytes_),
      durable_bytes_(other.durable_bytes_),
      journal_records_(other.journal_records_),
      next_sequence_(other.next_sequence_),
      segment_fd_(other.segment_fd_),
      open_(other.open_),
      lock_(std::move(other.lock_)) {
    other.segment_fd_ = -1;
    other.open_ = false;
}

DurableStore& DurableStore::operator=(DurableStore&& other) noexcept {
    if (this != &other) {
        if (segment_fd_ >= 0) {
#if defined(_WIN32)
            ::_close(segment_fd_);
#else
            ::close(segment_fd_);
#endif
        }
        options_ = std::move(other.options_);
        key_ = std::move(other.key_);
        segment_index_ = other.segment_index_;
        segment_bytes_ = other.segment_bytes_;
        durable_bytes_ = other.durable_bytes_;
        journal_records_ = other.journal_records_;
        next_sequence_ = other.next_sequence_;
        segment_fd_ = other.segment_fd_;
        open_ = other.open_;
        lock_ = std::move(other.lock_);
        other.segment_fd_ = -1;
        other.open_ = false;
    }
    return *this;
}

// ---------------------------------------------------------------------------------------
// Manifest
// ---------------------------------------------------------------------------------------

Result<DurableStore::Manifest> DurableStore::read_manifest(const Options& options,
                                                           const std::string& key) {
    const std::filesystem::path path = options.state_dir / DurableLayout::kManifestName;
    auto content = fsutil::read_all(path, 4096);
    if (!content.ok()) {
        return content.status();
    }
    const std::string& data = content.value();
    constexpr std::size_t kPayloadBytes = 4 + 2 + 8 + 8 + 8 + 4 + 1 + Digest::kSize + 8;
    const std::size_t expected = kPayloadBytes + 4 + DurableLayout::kRecordMacBytes;
    if (data.size() != expected) {
        return make_error(StatusCode::Corrupt, "manifest has " + std::to_string(data.size()) +
                                                   " bytes, expected " +
                                                   std::to_string(expected));
    }
    const auto* bytes = reinterpret_cast<const std::uint8_t*>(data.data());
    if (read_le(bytes, 4) != DurableLayout::kManifestMagic) {
        return make_error(StatusCode::Corrupt, "manifest has a wrong magic value");
    }
    if (read_le(bytes + 4, 2) != PRIORITY_FABRIC_FORMAT_VERSION) {
        return make_error(StatusCode::Unsupported,
                          "manifest was written by format version " +
                              std::to_string(read_le(bytes + 4, 2)));
    }
    const std::uint32_t declared_crc =
        static_cast<std::uint32_t>(read_le(bytes + kPayloadBytes, 4));
    if (declared_crc != crc32c(data.data(), kPayloadBytes)) {
        return make_error(StatusCode::IntegrityFailure, "manifest failed its checksum");
    }
    const std::string expected_mac =
        record_mac(key, std::string_view(data.data(), kPayloadBytes),
                   std::string_view(data.data() + kPayloadBytes, 4));
    if (!constant_time_equal(
            bytes + kPayloadBytes + 4,
            reinterpret_cast<const std::uint8_t*>(expected_mac.data()),
            DurableLayout::kRecordMacBytes)) {
        return make_error(StatusCode::IntegrityFailure,
                          "manifest failed authentication; it was altered or belongs to another "
                          "store");
    }

    Manifest manifest;
    manifest.epoch = FabricEpoch{read_le(bytes + 6, 8)};
    manifest.state_generation = Generation{read_le(bytes + 14, 8)};
    manifest.last_sequence = read_le(bytes + 22, 8);
    manifest.first_segment = static_cast<std::uint32_t>(read_le(bytes + 30, 4));
    const std::uint8_t snapshot_present = static_cast<std::uint8_t>(read_le(bytes + 34, 1));
    if (snapshot_present > 1) {
        return make_error(StatusCode::Corrupt, "manifest carries an invalid snapshot flag");
    }
    manifest.snapshot_present = snapshot_present == 1;
    for (std::size_t i = 0; i < Digest::kSize; ++i) {
        manifest.snapshot_digest.bytes[i] = bytes[35 + i];
    }
    manifest.snapshot_bytes = read_le(bytes + 35 + Digest::kSize, 8);
    return manifest;
}

VoidResult DurableStore::write_manifest(const Options& options, const std::string& key,
                                        const Manifest& manifest) {
    std::string payload;
    append_le(payload, DurableLayout::kManifestMagic, 4);
    append_le(payload, PRIORITY_FABRIC_FORMAT_VERSION, 2);
    append_le(payload, manifest.epoch.value, 8);
    append_le(payload, manifest.state_generation.value, 8);
    append_le(payload, manifest.last_sequence, 8);
    append_le(payload, manifest.first_segment, 4);
    append_le(payload, manifest.snapshot_present ? 1u : 0u, 1);
    payload.append(reinterpret_cast<const char*>(manifest.snapshot_digest.bytes.data()),
                   manifest.snapshot_digest.bytes.size());
    append_le(payload, manifest.snapshot_bytes, 8);

    std::string record = payload;
    append_le(record, crc32c(payload.data(), payload.size()), 4);
    record.append(record_mac(key, payload, std::string_view(record.data() + payload.size(), 4)));

    return fsutil::write_atomic(options.state_dir / DurableLayout::kManifestName, record,
                                options.fsync);
}

// ---------------------------------------------------------------------------------------
// Snapshot
// ---------------------------------------------------------------------------------------

VoidResult DurableStore::write_snapshot(const StateImage& image) {
    const std::string payload = encode_state(image);
    if (payload.size() > options_.limits.max_state_bytes) {
        return make_error(StatusCode::LimitExceeded,
                          "state image is " + std::to_string(payload.size()) +
                              " bytes, the durable growth bound is " +
                              std::to_string(options_.limits.max_state_bytes));
    }
    const Digest digest = Sha256::hash(payload);

    std::string file;
    file.reserve(kSnapshotHeaderBytes + payload.size() + 4 + DurableLayout::kRecordMacBytes);
    append_le(file, DurableLayout::kSnapshotMagic, 4);
    append_le(file, PRIORITY_FABRIC_FORMAT_VERSION, 2);
    append_le(file, payload.size(), 4);
    file.append(reinterpret_cast<const char*>(digest.bytes.data()), digest.bytes.size());
    file.append(payload);

    // The authentication tag covers the header and the payload together, so neither the
    // declared length nor the declared digest can be altered independently.
    const std::string header = file.substr(0, kSnapshotHeaderBytes);
    file.append(record_mac(key_, header, payload));

    return fsutil::write_atomic(options_.state_dir / DurableLayout::kSnapshotName, file,
                                options_.fsync);
}

Result<StateImage> DurableStore::read_snapshot(const Options& options, const std::string& key,
                                               const Manifest& manifest) {
    const std::filesystem::path path = options.state_dir / DurableLayout::kSnapshotName;
    auto content = fsutil::read_all(path, options.limits.max_state_bytes);
    if (!content.ok()) {
        return content.status();
    }
    const std::string& data = content.value();
    if (data.size() < kSnapshotHeaderBytes + DurableLayout::kRecordMacBytes) {
        return make_error(StatusCode::Truncated, "snapshot is shorter than its fixed header");
    }
    const auto* bytes = reinterpret_cast<const std::uint8_t*>(data.data());
    if (read_le(bytes, 4) != DurableLayout::kSnapshotMagic) {
        return make_error(StatusCode::Corrupt, "snapshot has a wrong magic value");
    }
    if (read_le(bytes + 4, 2) != PRIORITY_FABRIC_FORMAT_VERSION) {
        return make_error(StatusCode::Unsupported, "snapshot was written by format version " +
                                                       std::to_string(read_le(bytes + 4, 2)));
    }
    const std::uint64_t payload_length = read_le(bytes + 6, 4);
    const std::uint64_t expected = kSnapshotHeaderBytes + payload_length +
                                   DurableLayout::kRecordMacBytes;
    if (expected != data.size()) {
        return make_error(StatusCode::Truncated,
                          "snapshot declares " + std::to_string(payload_length) +
                              " payload bytes but the file holds " + std::to_string(data.size()));
    }
    if (payload_length > options.limits.max_state_bytes) {
        return make_error(StatusCode::LimitExceeded, "snapshot payload exceeds the growth bound");
    }
    Digest declared;
    for (std::size_t i = 0; i < Digest::kSize; ++i) {
        declared.bytes[i] = bytes[10 + i];
    }
    const std::string payload(data.data() + kSnapshotHeaderBytes,
                              static_cast<std::size_t>(payload_length));
    const Digest actual = Sha256::hash(payload);
    if (!(actual == declared)) {
        return make_error(StatusCode::IntegrityFailure,
                          "snapshot payload digest does not match the declared digest");
    }
    const std::string header(data.data(), kSnapshotHeaderBytes);
    const std::string expected_mac = record_mac(key, header, payload);
    if (!constant_time_equal(
            bytes + kSnapshotHeaderBytes + payload_length,
            reinterpret_cast<const std::uint8_t*>(expected_mac.data()),
            DurableLayout::kRecordMacBytes)) {
        return make_error(StatusCode::IntegrityFailure,
                          "snapshot failed authentication; it was altered or belongs to another "
                          "store");
    }
    if (manifest.snapshot_present && !(manifest.snapshot_digest == declared)) {
        return make_error(StatusCode::IntegrityFailure,
                          "snapshot does not match the digest recorded in the manifest");
    }
    return decode_state(payload, options.limits);
}

// ---------------------------------------------------------------------------------------
// Replay
// ---------------------------------------------------------------------------------------

Result<IntegrityReport> DurableStore::replay(const Options& options, const std::string& key,
                                             StateImage& image) {
    IntegrityReport report;
    image = StateImage{};
    image.limits = options.limits;

    Manifest manifest;
    const std::filesystem::path manifest_path =
        options.state_dir / DurableLayout::kManifestName;
    if (!fsutil::exists(manifest_path)) {
        report.ok = true;
        report.health = Health::Healthy;
        report.detail = "fresh state directory: no manifest, no journal, no snapshot";
        report.state_generation = image.generation;
        report.epoch = image.epoch;
        report.state_digest = state_digest(image);
        return report;
    }

    auto loaded_manifest = read_manifest(options, key);
    if (!loaded_manifest.ok()) {
        return loaded_manifest.status();
    }
    manifest = loaded_manifest.value();

    if (manifest.snapshot_present) {
        auto snapshot = read_snapshot(options, key, manifest);
        if (!snapshot.ok()) {
            return snapshot.status();
        }
        image = std::move(snapshot.value());
        report.records_applied = 1;
    }
    image.epoch = manifest.epoch;
    image.generation = manifest.state_generation;
    image.last_sequence = manifest.last_sequence;

    // Discover the segment files that belong to this store, in ascending order.
    std::vector<std::uint32_t> segments;
    std::error_code ec;
    std::filesystem::directory_iterator it(options.state_dir, ec);
    if (ec) {
        return make_error(StatusCode::IoError,
                          "cannot enumerate the state directory: " + ec.message());
    }
    for (const auto& entry : it) {
        if (!entry.is_regular_file(ec) || ec) {
            continue;
        }
        std::uint32_t index = 0;
        if (DurableLayout::parse_journal_segment_name(entry.path().filename().string(), index)) {
            if (index >= manifest.first_segment) {
                segments.push_back(index);
            }
        }
    }
    std::sort(segments.begin(), segments.end());
    if (segments.size() > options.limits.max_journal_segments) {
        return make_error(StatusCode::LimitExceeded,
                          "state directory holds " + std::to_string(segments.size()) +
                              " journal segments, limit is " +
                              std::to_string(options.limits.max_journal_segments));
    }

    std::uint64_t expected_sequence = manifest.last_sequence + 1;
    std::map<std::uint64_t, std::string> pending;

    for (std::size_t index = 0; index < segments.size(); ++index) {
        const bool is_last = index + 1 == segments.size();
        const std::filesystem::path path =
            options.state_dir / DurableLayout::journal_segment_name(segments[index]);
        auto scan = scan_journal_segment(path, key, options.limits);
        if (!scan.ok()) {
            return scan.status();
        }
        JournalScanResult& result = scan.value();
        report.records_scanned += result.records_read;

        if (result.integrity_failures > 0) {
            report.records_rejected += result.integrity_failures;
            report.health = Health::Degraded;
            report.detail = result.failure_detail;
        }

        for (const auto& record : result.records) {
            if (record.kind == RecordKind::Pending) {
                if (record.sequence < expected_sequence) {
                    report.records_rejected += 1;
                    report.health = Health::Degraded;
                    report.detail = "journal repeats sequence " +
                                    std::to_string(record.sequence) +
                                    ", which is already committed";
                    break;
                }
                if (pending.find(record.sequence) != pending.end()) {
                    report.records_rejected += 1;
                    report.health = Health::Degraded;
                    report.detail = "journal holds two pending records for sequence " +
                                    std::to_string(record.sequence);
                    break;
                }
                pending.emplace(record.sequence, record.payload);
                continue;
            }

            auto commit_payload = decode_commit_payload(record.payload);
            if (!commit_payload.ok()) {
                report.records_rejected += 1;
                report.health = Health::Degraded;
                report.detail = commit_payload.status().message();
                break;
            }
            const std::uint64_t sequence = commit_payload.value().first;
            if (sequence != record.sequence) {
                report.records_rejected += 1;
                report.health = Health::Degraded;
                report.detail = "commit record for sequence " +
                                std::to_string(record.sequence) + " names sequence " +
                                std::to_string(sequence);
                break;
            }
            const auto pending_it = pending.find(sequence);
            if (pending_it == pending.end()) {
                report.records_rejected += 1;
                report.health = Health::Degraded;
                report.detail = "commit record for sequence " + std::to_string(sequence) +
                                " has no matching pending record";
                break;
            }
            auto mutation = decode_mutation(pending_it->second, options.limits);
            if (!mutation.ok()) {
                report.records_rejected += 1;
                report.health = Health::Degraded;
                report.detail = mutation.status().message();
                break;
            }
            if (sequence != expected_sequence) {
                report.records_rejected += 1;
                report.health = Health::Degraded;
                report.detail = "journal jumps from sequence " +
                                std::to_string(expected_sequence - 1) + " to " +
                                std::to_string(sequence);
                break;
            }
            const std::string encoded = encode_mutation(mutation.value());
            const Digest encoded_digest = Sha256::hash(encoded);
            if (!(encoded_digest == commit_payload.value().second)) {
                report.records_rejected += 1;
                report.health = Health::Degraded;
                report.detail = "commit record digest does not match the pending payload for "
                                "sequence " +
                                std::to_string(sequence);
                break;
            }
            auto applied = apply_mutation(image, mutation.value(), true);
            if (!applied.ok()) {
                report.records_rejected += 1;
                report.health = Health::Degraded;
                report.detail = "replaying sequence " + std::to_string(sequence) +
                                " failed: " + applied.status().message();
                break;
            }
            image.last_sequence = sequence;
            expected_sequence = sequence + 1;
            pending.erase(pending_it);
            report.records_applied += 1;
        }

        if (report.health == Health::Degraded) {
            break;
        }

        if (result.trailing_bytes > 0) {
            if (is_last) {
                report.unfinished_attempts += result.trailing_bytes;
                report.trailing_bytes_discarded += result.trailing_bytes;
                // The tail is an unfinished append; drop it so that later appends do not
                // continue after unusable bytes.
                const std::uint64_t good = fsutil::file_size(path).value_or(0) - result.trailing_bytes;
                auto truncated = fsutil::truncate_file(path, good);
                if (!truncated.ok()) {
                    report.health = Health::Degraded;
                    report.detail = truncated.status().message();
                    break;
                }
            } else {
                report.health = Health::Degraded;
                report.detail = "journal segment " + std::to_string(segments[index]) +
                                " ends with " + std::to_string(result.trailing_bytes) +
                                " unusable bytes while a later segment exists";
                break;
            }
        }
    }

    if (report.health == Health::Healthy && !pending.empty()) {
        report.unfinished_attempts += pending.size();
    }

    report.ok = report.health == Health::Healthy;
    report.state_generation = image.generation;
    report.epoch = image.epoch;
    report.state_digest = state_digest(image);
    if (report.detail.empty()) {
        report.detail = report.ok ? "durable state verified" : "durable state is degraded";
    }
    if (!report.ok) {
        image.health = Health::Degraded;
        image.health_detail = report.detail;
    }
    return report;
}

// ---------------------------------------------------------------------------------------
// Open
// ---------------------------------------------------------------------------------------

Result<DurableStore> DurableStore::open(const Options& options, StateImage& image,
                                        IntegrityReport& report) {
    if (!limits_within_compiled_ceiling(options.limits)) {
        return make_error(StatusCode::LimitExceeded,
                          "the requested limits exceed the compiled ceiling");
    }
    if (options.state_dir.empty()) {
        return make_error(StatusCode::InvalidArgument, "no state directory was given");
    }
    DurableStore store;
    store.options_ = options;

    const bool exists = fsutil::exists(options.state_dir);
    if (!exists) {
        if (!options.create_if_missing) {
            return make_error(StatusCode::NotFound,
                              "state directory '" + options.state_dir.string() +
                                  "' does not exist and create_if_missing is false");
        }
        auto created = fsutil::ensure_directory(options.state_dir);
        if (!created.ok()) {
            return created.status();
        }
    } else {
        std::error_code ec;
        if (!std::filesystem::is_directory(options.state_dir, ec) || ec) {
            return make_error(StatusCode::InvalidArgument,
                              "'" + options.state_dir.string() + "' is not a directory");
        }
    }

    // The lock is taken before anything is read or written, so two live writers can never
    // interleave on one state directory.
    if (options.exclusive_lock) {
        auto lock = fsutil::FileLock::acquire(options.state_dir / "lock.pfk");
        if (!lock.ok()) {
            return lock.status();
        }
        store.lock_ = std::move(lock.value());
    }

    const std::filesystem::path manifest_path = options.state_dir / DurableLayout::kManifestName;
    const std::filesystem::path key_path = options.state_dir / DurableLayout::kKeyName;

    if (!fsutil::exists(manifest_path)) {
        if (!options.create_if_missing) {
            return make_error(StatusCode::NotFound,
                              "state directory '" + options.state_dir.string() +
                                  "' holds no fabric store and create_if_missing is false");
        }
        // The manifest is the only record of which journal segments belong to the store, so a
        // segment without a manifest is a damaged store rather than an empty one.
        std::error_code probe_ec;
        std::filesystem::directory_iterator probe(options.state_dir, probe_ec);
        if (probe_ec) {
            return make_error(StatusCode::IoError,
                              "cannot enumerate the state directory: " + probe_ec.message());
        }
        for (const auto& entry : probe) {
            std::uint32_t index = 0;
            std::error_code entry_ec;
            if (entry.is_regular_file(entry_ec) && !entry_ec &&
                DurableLayout::parse_journal_segment_name(entry.path().filename().string(),
                                                          index)) {
                return make_error(StatusCode::Corrupt,
                                  "state directory holds journal segment '" +
                                      entry.path().filename().string() +
                                      "' but no manifest; refusing to guess which records are "
                                      "authoritative");
            }
        }
        if (fsutil::exists(key_path)) {
            auto existing_key = read_store_key(options.state_dir);
            if (!existing_key.ok()) {
                return existing_key.status();
            }
            store.key_ = std::move(existing_key.value());
        } else {
            auto created_key = create_store_key(options.state_dir);
            if (!created_key.ok()) {
                return created_key.status();
            }
            store.key_ = std::move(created_key.value());
        }
        Manifest manifest;
        auto written = write_manifest(options, store.key_, manifest);
        if (!written.ok()) {
            return written.status();
        }
        image = StateImage{};
        image.limits = options.limits;
        report.ok = true;
        report.health = Health::Healthy;
        report.detail = "created a new fabric store";
        report.state_digest = state_digest(image);
        store.open_ = true;
        store.next_sequence_ = 1;
        store.recompute_durable_bytes();
        auto segment = fsutil::open_append(options.state_dir /
                                           DurableLayout::journal_segment_name(0));
        if (!segment.ok()) {
            return segment.status();
        }
        store.segment_fd_ = segment.value().release();
        store.segment_index_ = 0;
        store.segment_bytes_ = 0;
        return store;
    }

    auto key = read_store_key(options.state_dir);
    if (!key.ok()) {
        return key.status();
    }
    store.key_ = std::move(key.value());

    auto replayed = replay(options, store.key_, image);
    if (!replayed.ok()) {
        return replayed.status();
    }
    report = replayed.value();
    if (image.health == Health::Degraded) {
        report.health = Health::Degraded;
        report.ok = false;
    }

    // Resume appending after the highest segment that exists.
    std::uint32_t highest = 0;
    std::error_code ec;
    std::filesystem::directory_iterator it(options.state_dir, ec);
    if (ec) {
        return make_error(StatusCode::IoError, "cannot enumerate the state directory: " + ec.message());
    }
    bool found = false;
    for (const auto& entry : it) {
        std::uint32_t index = 0;
        if (entry.is_regular_file(ec) && !ec &&
            DurableLayout::parse_journal_segment_name(entry.path().filename().string(), index)) {
            if (!found || index > highest) {
                highest = index;
                found = true;
            }
        }
    }
    store.segment_index_ = found ? highest : 0;
    const std::filesystem::path segment_path =
        options.state_dir / DurableLayout::journal_segment_name(store.segment_index_);
    auto segment = fsutil::open_append(segment_path);
    if (!segment.ok()) {
        return segment.status();
    }
    store.segment_fd_ = segment.value().release();
    store.segment_bytes_ = fsutil::file_size(segment_path).value_or(0);
    store.next_sequence_ = image.last_sequence + 1;
    store.open_ = true;
    store.recompute_durable_bytes();
    return store;
}

void DurableStore::recompute_durable_bytes() {
    auto measured = fsutil::directory_bytes(options_.state_dir, 4096);
    durable_bytes_ = measured.ok() ? measured.value().first : 0;
}

VoidResult DurableStore::roll_segment_if_needed() {
    if (segment_bytes_ < kSegmentRollBytes) {
        return VoidResult{};
    }
    if (segment_index_ + 1 >= options_.limits.max_journal_segments) {
        return make_error(StatusCode::LimitExceeded,
                          "journal has reached " + std::to_string(segment_index_ + 1) +
                              " segments; run a checkpoint to compact the store");
    }
    if (segment_fd_ >= 0) {
#if defined(_WIN32)
        ::_close(segment_fd_);
#else
        ::close(segment_fd_);
#endif
        segment_fd_ = -1;
    }
    segment_index_ += 1;
    const std::filesystem::path path =
        options_.state_dir / DurableLayout::journal_segment_name(segment_index_);
    auto segment = fsutil::open_append(path);
    if (!segment.ok()) {
        return segment.status();
    }
    segment_fd_ = segment.value().release();
    segment_bytes_ = fsutil::file_size(path).value_or(0);
    return VoidResult{};
}

VoidResult DurableStore::append_record(const std::string& record) {
    if (segment_fd_ < 0) {
        return make_error(StatusCode::NotReady, "the journal segment is not open");
    }
    fsutil::File file(segment_fd_);
    auto written = fsutil::write_all(file, record.data(), record.size());
    (void)file.release();
    if (!written.ok()) {
        return written.status();
    }
    if (options_.fsync) {
        fsutil::File sync_file(segment_fd_);
        auto flushed = fsutil::flush_to_platform(sync_file);
        (void)sync_file.release();
        if (!flushed.ok()) {
            return flushed.status();
        }
    }
    segment_bytes_ += record.size();
    durable_bytes_ += record.size();
    return VoidResult{};
}

VoidResult DurableStore::commit(const Mutation& mutation, StateImage& live) {
    if (!open_) {
        return make_error(StatusCode::NotReady, "the store is not open");
    }
    if (live.health != Health::Healthy) {
        return make_error(StatusCode::Degraded,
                          "the store is degraded (" + live.health_detail +
                              "); refusing to extend it until the state is repaired");
    }

    // validate
    auto validated = validate_mutation(live, mutation, false);
    if (!validated.ok()) {
        return validated.status();
    }

    // plan
    Mutation planned = mutation;
    const bool idempotent = mutation_is_idempotent(live, mutation);
    planned.resulting_generation =
        idempotent ? live.generation : live.generation.next().value_or(Generation::unset());
    if (!planned.resulting_generation.is_set()) {
        return make_error(StatusCode::Overflow,
                          "the fabric state generation counter is exhausted");
    }

    const std::string payload = encode_mutation(planned);
    if (payload.size() > options_.limits.max_record_payload) {
        return make_error(StatusCode::LimitExceeded,
                          "mutation encodes to " + std::to_string(payload.size()) +
                              " bytes, the record limit is " +
                              std::to_string(options_.limits.max_record_payload));
    }

    // reserve
    const std::uint64_t record_bytes = journal_record_bytes(payload.size());
    const std::uint64_t commit_bytes = journal_record_bytes(8 + Digest::kSize);
    const std::uint64_t ceiling = std::numeric_limits<std::uint64_t>::max();
    const auto projected =
        checked_add(checked_add(durable_bytes_, record_bytes).value_or(ceiling), commit_bytes);
    if (!projected.has_value() || *projected > options_.limits.max_state_bytes) {
        return make_error(StatusCode::LimitExceeded,
                          "committing this mutation would grow the durable store beyond " +
                              std::to_string(options_.limits.max_state_bytes) +
                              " bytes; run a checkpoint");
    }
    auto rolled = roll_segment_if_needed();
    if (!rolled.ok()) {
        return rolled.status();
    }

    const std::uint64_t sequence = next_sequence_;
    // journal
    auto written = append_record(
        encode_journal_record(RecordKind::Pending, sequence, payload, key_));
    if (!written.ok()) {
        return written.status();
    }
    journal_records_ += 1;

    // perform
    const Generation before = live.generation;
    auto applied = apply_mutation(live, planned, false);
    if (!applied.ok()) {
        // The pending record is already durable and has no commit marker, so recovery rolls
        // it back. The in-memory image is untouched because application is all-or-nothing.
        return applied.status();
    }
    if (live.generation.value != planned.resulting_generation.value) {
        return make_error(StatusCode::Internal,
                          "the applier produced generation " +
                              std::to_string(live.generation.value) + " but the plan said " +
                              std::to_string(planned.resulting_generation.value));
    }
    (void)before;

    // verify + commit
    const Digest digest = Sha256::hash(payload);
    auto committed = append_record(encode_journal_record(
        RecordKind::Commit, sequence, encode_commit_payload(sequence, digest), key_));
    if (!committed.ok()) {
        return committed.status();
    }
    journal_records_ += 1;
    ++next_sequence_;
    live.last_sequence = sequence;
    return VoidResult{};
}

Result<Generation> DurableStore::checkpoint(const StateImage& image) {
    if (!open_) {
        return make_error(StatusCode::NotReady, "the store is not open");
    }
    if (image.health != Health::Healthy) {
        return make_error(StatusCode::Degraded,
                          "the store is degraded; refusing to snapshot degraded state");
    }
    auto written = write_snapshot(image);
    if (!written.ok()) {
        return written.status();
    }

    Manifest manifest;
    manifest.epoch = image.epoch;
    manifest.state_generation = image.generation;
    manifest.last_sequence = image.last_sequence;
    manifest.first_segment = segment_index_ + 1;
    manifest.snapshot_present = true;
    manifest.snapshot_digest =
        Sha256::hash(encode_state(image));
    manifest.snapshot_bytes = fsutil::file_size(options_.state_dir /
                                                DurableLayout::kSnapshotName)
                                  .value_or(0);
    auto manifest_written = write_manifest(options_, key_, manifest);
    if (!manifest_written.ok()) {
        return manifest_written.status();
    }

    const std::uint32_t old_index = segment_index_;
    if (segment_fd_ >= 0) {
#if defined(_WIN32)
        ::_close(segment_fd_);
#else
        ::close(segment_fd_);
#endif
        segment_fd_ = -1;
    }
    segment_index_ = manifest.first_segment;
    if (segment_index_ + 1 >= options_.limits.max_journal_segments) {
        return make_error(StatusCode::LimitExceeded, "journal segment counter is exhausted");
    }
    const std::filesystem::path path =
        options_.state_dir / DurableLayout::journal_segment_name(segment_index_);
    auto segment = fsutil::open_append(path);
    if (!segment.ok()) {
        return segment.status();
    }
    segment_fd_ = segment.value().release();
    segment_bytes_ = fsutil::file_size(path).value_or(0);

    // Retire the segments the new manifest no longer references. Best effort: a failure here
    // costs disk space, never correctness, because recovery only reads what the manifest
    // names.
    for (std::uint32_t index = 0; index <= old_index; ++index) {
        if (index >= manifest.first_segment) {
            break;
        }
        (void)fsutil::remove_file(options_.state_dir / DurableLayout::journal_segment_name(index));
    }
    recompute_durable_bytes();
    return image.generation;
}

Result<IntegrityReport> DurableStore::verify(const StateImage& live) const {
    StateImage scratch;
    auto replayed = replay(options_, key_, scratch);
    if (!replayed.ok()) {
        return replayed.status();
    }
    IntegrityReport report = replayed.value();

    // Recovery never restores publisher authority, so verification asks: "would recovering
    // from these bytes reproduce what I am serving, once both sides have been through the
    // same recovery normalization?" The durable history itself is compared unaltered by the
    // record checks above; only the digest comparison is normalized.
    if (report.health == Health::Healthy) {
        const auto normalize = [](StateImage& image) {
            for (auto& entry : image.authority) {
                if (entry.second.state == AuthorityState::Granted) {
                    entry.second.state = AuthorityState::Expired;
                }
            }
        };
        StateImage normalized_live = live;
        normalize(normalized_live);
        normalize(scratch);
        report.state_digest = state_digest(scratch);
        report.state_generation = scratch.generation;
        report.epoch = scratch.epoch;
        if (!(report.state_digest == state_digest(normalized_live))) {
            report.ok = false;
            report.health = Health::Degraded;
            report.detail = "the live image does not match a fresh replay of the durable store";
        } else if (report.state_generation != normalized_live.generation ||
                   !(report.epoch == normalized_live.epoch)) {
            report.ok = false;
            report.health = Health::Degraded;
            report.detail = "the live image generation or epoch does not match the durable store";
        } else {
            report.ok = true;
        }
    }
    return report;
}

}  // namespace pf::detail
