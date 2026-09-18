// Priority Fabric -- authoritative network priority classes.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#ifndef PRIORITY_FABRIC_DURABILITY_HPP
#define PRIORITY_FABRIC_DURABILITY_HPP

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

#include "priority_fabric/digest.hpp"
#include "priority_fabric/export.hpp"
#include "priority_fabric/limits.hpp"
#include "priority_fabric/status.hpp"

namespace pf {

/// On-disk layout of a fabric state directory.
///
///   manifest.pfm      atomically replaced pointer to the current snapshot and journal
///   snapshot.pfs      full canonical state image, self-describing and self-checked
///   journal.pfj       append-only record log (single segment, rolled when it grows)
///   journal.<n>.pfj   rolled segments, replayed in ascending order
///   key.pfk           per-store MAC key; journal records are tamper-evident with it
///
/// Everything is fixed little-endian and every file carries its own integrity envelope.
/// A store that fails verification is never silently trusted: the runtime degrades and
/// refuses to answer authoritatively until an operator resolves it.
struct PF_API DurableLayout {
    static constexpr std::uint32_t kJournalMagic = 0x314A4650u;   // "PFJ1"
    static constexpr std::uint32_t kSnapshotMagic = 0x31534650u;  // "PFS1"
    static constexpr std::uint32_t kManifestMagic = 0x314D4650u;  // "PFM1"
    static constexpr std::uint32_t kKeyMagic = 0x314B4650u;       // "PFK1"

    /// Bytes of a record header: magic, format, kind, sequence, length, payload CRC.
    static constexpr std::size_t kRecordHeaderBytes = 4 + 2 + 2 + 8 + 4 + 4;
    /// Bytes of the trailing authentication tag.
    static constexpr std::size_t kRecordMacBytes = 16;
    static constexpr std::size_t kRecordOverheadBytes = kRecordHeaderBytes + kRecordMacBytes;

    static constexpr const char* kManifestName = "manifest.pfm";
    static constexpr const char* kSnapshotName = "snapshot.pfs";
    static constexpr const char* kKeyName = "key.pfk";
    static constexpr const char* kJournalBaseName = "journal";
    static constexpr const char* kJournalExtension = ".pfj";

    /// Segment file name for index 0 is "journal.pfj"; later segments are
    /// "journal.<index>.pfj".
    [[nodiscard]] static std::string journal_segment_name(std::uint32_t index);

    /// Recognizes both segment spellings and returns the index. Returns false for any
    /// other name.
    [[nodiscard]] static bool parse_journal_segment_name(std::string_view name,
                                                         std::uint32_t& index) noexcept;
};

/// Lifecycle marker of a journal record. A mutation is durable only once its Commit record
/// has been written; a Pending record without a Commit is an unfinished attempt and is
/// rolled back during recovery, never replayed as authority.
enum class RecordKind : std::uint16_t {
    Pending = 1,  ///< a planned mutation; carries the encoded mutation payload
    Commit = 2,   ///< confirms the pending record with sequence S and its content digest
};

[[nodiscard]] PF_API const char* to_string(RecordKind kind) noexcept;

/// A framing-decoded journal record.
struct PF_API JournalRecord {
    RecordKind kind = RecordKind::Pending;
    std::uint64_t sequence = 0;
    std::string payload;
    std::uint32_t payload_crc = 0;
    bool mac_ok = false;
    std::uint64_t file_offset = 0;
};

/// Outcome of scanning one journal segment.
struct PF_API JournalScanResult {
    std::vector<JournalRecord> records;
    /// Bytes at the end of the segment that do not form a complete, verifiable record.
    /// A non-zero value on the *last* segment is an unfinished attempt (a crash during
    /// append); on any earlier segment it is corruption.
    std::uint64_t trailing_bytes = 0;
    /// Records whose framing checksum or authentication tag failed.
    std::uint64_t integrity_failures = 0;
    /// Records read successfully.
    std::uint64_t records_read = 0;
    /// Set when the segment could not be scanned further; the scan stops at the first
    /// unusable byte rather than skipping ahead.
    std::string failure_detail;
};

/// Scans one segment file. Structural failures stop the scan and are reported; the scan
/// never resynchronizes on a magic value found inside a corrupt region. \p key must be the
/// store key; a scan without the key is not verification and is refused.
[[nodiscard]] PF_API Result<JournalScanResult> scan_journal_segment(
    const std::filesystem::path& path, const std::string& key, const Limits& limits);

/// Builds a complete on-disk record: header, payload, authentication tag.
[[nodiscard]] PF_API std::string encode_journal_record(RecordKind kind, std::uint64_t sequence,
                                                       std::string_view payload,
                                                       const std::string& key);

/// Number of bytes a record with a payload of \p payload_size occupies on disk.
[[nodiscard]] PF_API std::uint64_t journal_record_bytes(std::uint64_t payload_size) noexcept;

/// Reads the per-store MAC key. Fails when the key file is missing, malformed or of the
/// wrong length; there is no default key.
[[nodiscard]] PF_API Result<std::string> read_store_key(const std::filesystem::path& state_dir);

/// Creates a fresh random MAC key. Refuses to overwrite an existing key.
[[nodiscard]] PF_API Result<std::string> create_store_key(const std::filesystem::path& state_dir);

/// Computes the authentication tag of a record: the first DurableLayout::kRecordMacBytes
/// bytes of HMAC-SHA256(key, header || payload).
[[nodiscard]] PF_API std::string record_mac(const std::string& key, std::string_view header,
                                            std::string_view payload);

}  // namespace pf

#endif  // PRIORITY_FABRIC_DURABILITY_HPP
