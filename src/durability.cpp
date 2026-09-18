// Priority Fabric -- authoritative network priority classes.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "priority_fabric/durability.hpp"

#include <cstring>

#include "fsutil.hpp"
#include "priority_fabric/checked.hpp"
#include "priority_fabric/codec.hpp"
#include "priority_fabric/version.hpp"

namespace pf {
namespace {

/// Hard ceiling on the number of records one segment scan will materialize. Chosen so that
/// a hostile 256 MiB segment of minimum-size records cannot exhaust memory.
constexpr std::uint64_t kMaxRecordsPerSegment = 4'000'000ull;

/// Fixed store key length in bytes.
constexpr std::size_t kStoreKeyBytes = 32;

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

int hex_value(char c) noexcept {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

std::string encode_key_file(const std::string& key) {
    std::string out;
    append_le(out, DurableLayout::kKeyMagic, 4);
    append_le(out, PRIORITY_FABRIC_FORMAT_VERSION, 2);
    append_le(out, static_cast<std::uint64_t>(key.size()), 4);
    out.append(key);
    const std::uint32_t crc = crc32c(out.data(), out.size());
    append_le(out, crc, 4);
    return out;
}

Result<std::string> decode_key_file(const std::string& content) {
    if (content.size() < 4 + 2 + 4 + 4) {
        return make_error(StatusCode::Corrupt, "store key file is shorter than its fixed header");
    }
    const auto* bytes = reinterpret_cast<const std::uint8_t*>(content.data());
    if (read_le(bytes, 4) != DurableLayout::kKeyMagic) {
        return make_error(StatusCode::Corrupt, "store key file has a wrong magic value");
    }
    if (read_le(bytes + 4, 2) != PRIORITY_FABRIC_FORMAT_VERSION) {
        return make_error(StatusCode::Unsupported,
                          "store key file was written by format version " +
                              std::to_string(read_le(bytes + 4, 2)) + ", this build implements " +
                              std::to_string(PRIORITY_FABRIC_FORMAT_VERSION));
    }
    const std::uint64_t length = read_le(bytes + 6, 4);
    const std::uint64_t expected = 4 + 2 + 4 + length + 4;
    if (expected != content.size()) {
        return make_error(StatusCode::Corrupt,
                          "store key file length field does not match the file size");
    }
    const std::uint32_t stored_crc =
        static_cast<std::uint32_t>(read_le(bytes + 4 + 2 + 4 + length, 4));
    const std::uint32_t actual_crc = crc32c(content.data(), content.size() - 4);
    if (stored_crc != actual_crc) {
        return make_error(StatusCode::IntegrityFailure,
                          "store key file failed its checksum; refusing to use a damaged key");
    }
    if (length != kStoreKeyBytes) {
        return make_error(StatusCode::Corrupt,
                          "store key is " + std::to_string(length) + " bytes, expected " +
                              std::to_string(kStoreKeyBytes));
    }
    return content.substr(4 + 2 + 4, static_cast<std::size_t>(length));
}

}  // namespace

const char* to_string(RecordKind kind) noexcept {
    switch (kind) {
        case RecordKind::Pending: return "pending";
        case RecordKind::Commit: return "commit";
    }
    return "unknown";
}

std::string DurableLayout::journal_segment_name(std::uint32_t index) {
    if (index == 0) {
        return std::string(kJournalBaseName) + kJournalExtension;
    }
    return std::string(kJournalBaseName) + "." + std::to_string(index) + kJournalExtension;
}

bool DurableLayout::parse_journal_segment_name(std::string_view name, std::uint32_t& index) noexcept {
    constexpr std::string_view kBase = "journal";
    constexpr std::string_view kExt = ".pfj";
    if (name.size() < kBase.size() + kExt.size()) {
        return false;
    }
    if (name.substr(0, kBase.size()) != kBase) {
        return false;
    }
    if (name.substr(name.size() - kExt.size()) != kExt) {
        return false;
    }
    const std::string_view middle =
        name.substr(kBase.size(), name.size() - kBase.size() - kExt.size());
    if (middle.empty()) {
        index = 0;
        return true;
    }
    if (middle.front() != '.') {
        return false;
    }
    const std::string_view digits = middle.substr(1);
    if (digits.empty() || digits.size() > 10) {
        return false;
    }
    std::uint64_t value = 0;
    for (char c : digits) {
        if (c < '0' || c > '9') {
            return false;
        }
        value = value * 10u + static_cast<std::uint64_t>(c - '0');
    }
    if (value == 0 || value > 0xFFFFFFFFull) {
        return false;
    }
    index = static_cast<std::uint32_t>(value);
    return true;
}

std::uint64_t journal_record_bytes(std::uint64_t payload_size) noexcept {
    const auto total = checked_add(payload_size, static_cast<std::uint64_t>(
                                                     DurableLayout::kRecordOverheadBytes));
    return total.has_value() ? *total : 0u;
}

std::string record_mac(const std::string& key, std::string_view header,
                       std::string_view payload) {
    const auto* key_bytes = reinterpret_cast<const std::uint8_t*>(key.data());
    std::string material;
    material.reserve(header.size() + payload.size());
    material.append(header);
    material.append(payload);
    const Digest mac = hmac_sha256(key_bytes, key.size(), material.data(), material.size());
    return std::string(reinterpret_cast<const char*>(mac.bytes.data()),
                       DurableLayout::kRecordMacBytes);
}

std::string encode_journal_record(RecordKind kind, std::uint64_t sequence,
                                  std::string_view payload, const std::string& key) {
    std::string header;
    header.reserve(DurableLayout::kRecordHeaderBytes);
    append_le(header, DurableLayout::kJournalMagic, 4);
    append_le(header, PRIORITY_FABRIC_FORMAT_VERSION, 2);
    append_le(header, static_cast<std::uint64_t>(kind), 2);
    append_le(header, sequence, 8);
    append_le(header, static_cast<std::uint64_t>(payload.size()), 4);
    append_le(header, static_cast<std::uint64_t>(crc32c(payload.data(), payload.size())), 4);

    std::string record;
    record.reserve(header.size() + payload.size() + DurableLayout::kRecordMacBytes);
    record.append(header);
    record.append(payload);
    record.append(record_mac(key, header, payload));
    return record;
}

Result<JournalScanResult> scan_journal_segment(const std::filesystem::path& path,
                                               const std::string& key, const Limits& limits) {
    if (key.empty()) {
        return make_error(StatusCode::InvalidArgument,
                          "a journal scan without the store key is not verification");
    }

    JournalScanResult result;
    auto content = fsutil::read_all(path, limits.max_state_bytes);
    if (!content.ok()) {
        return content.status();
    }
    const std::string& data = content.value();
    const auto* bytes = reinterpret_cast<const std::uint8_t*>(data.data());
    std::uint64_t offset = 0;

    while (offset < data.size()) {
        if (result.records.size() >= kMaxRecordsPerSegment) {
            result.failure_detail = "segment holds more than " +
                                    std::to_string(kMaxRecordsPerSegment) + " records";
            result.trailing_bytes = static_cast<std::uint64_t>(data.size()) - offset;
            return result;
        }
        const std::uint64_t remaining = static_cast<std::uint64_t>(data.size()) - offset;
        if (remaining < DurableLayout::kRecordHeaderBytes) {
            result.trailing_bytes = remaining;
            return result;
        }
        const std::uint8_t* header = bytes + offset;
        if (read_le(header, 4) != DurableLayout::kJournalMagic) {
            result.failure_detail =
                "journal record at offset " + std::to_string(offset) + " has a wrong magic value";
            result.trailing_bytes = remaining;
            return result;
        }
        const std::uint64_t format = read_le(header + 4, 2);
        if (format != PRIORITY_FABRIC_FORMAT_VERSION) {
            result.failure_detail = "journal record at offset " + std::to_string(offset) +
                                    " declares format version " + std::to_string(format) +
                                    "; this build implements " +
                                    std::to_string(PRIORITY_FABRIC_FORMAT_VERSION);
            result.trailing_bytes = remaining;
            return result;
        }
        const std::uint64_t kind_value = read_le(header + 6, 2);
        if (kind_value != static_cast<std::uint64_t>(RecordKind::Pending) &&
            kind_value != static_cast<std::uint64_t>(RecordKind::Commit)) {
            result.failure_detail = "journal record at offset " + std::to_string(offset) +
                                    " declares an unknown kind " + std::to_string(kind_value);
            result.trailing_bytes = remaining;
            return result;
        }
        const std::uint64_t sequence = read_le(header + 8, 8);
        const std::uint64_t payload_length = read_le(header + 16, 4);
        const std::uint32_t declared_crc = static_cast<std::uint32_t>(read_le(header + 20, 4));

        if (payload_length > limits.max_record_payload) {
            result.failure_detail = "journal record at offset " + std::to_string(offset) +
                                    " declares a payload of " + std::to_string(payload_length) +
                                    " bytes, limit is " +
                                    std::to_string(limits.max_record_payload);
            result.trailing_bytes = remaining;
            return result;
        }

        const std::uint64_t total = journal_record_bytes(payload_length);
        if (total == 0 || remaining < total) {
            // A short tail: either a torn write during append, or a truncated file.
            result.trailing_bytes = remaining;
            return result;
        }

        JournalRecord record;
        record.kind = static_cast<RecordKind>(kind_value);
        record.sequence = sequence;
        record.file_offset = offset;
        record.payload.assign(data.data() + offset + DurableLayout::kRecordHeaderBytes,
                              static_cast<std::size_t>(payload_length));
        record.payload_crc = declared_crc;

        const std::uint32_t actual_crc = crc32c(record.payload.data(), record.payload.size());
        if (actual_crc != declared_crc) {
            ++result.integrity_failures;
            result.failure_detail = "journal record at offset " + std::to_string(offset) +
                                    " failed its framing checksum";
            result.trailing_bytes = remaining;
            return result;
        }

        const std::string_view header_bytes(data.data() + offset,
                                              DurableLayout::kRecordHeaderBytes);
        const std::string expected_mac = record_mac(key, header_bytes, record.payload);
        const auto* stored_mac =
            bytes + offset + DurableLayout::kRecordHeaderBytes + payload_length;
        if (!constant_time_equal(
                stored_mac, reinterpret_cast<const std::uint8_t*>(expected_mac.data()),
                DurableLayout::kRecordMacBytes)) {
            record.mac_ok = false;
            ++result.integrity_failures;
            result.failure_detail = "journal record at offset " + std::to_string(offset) +
                                    " failed authentication; the record was altered or the key "
                                    "does not belong to this store";
            result.trailing_bytes = remaining;
            return result;
        }
        record.mac_ok = true;

        ++result.records_read;
        result.records.push_back(std::move(record));
        offset += total;
    }
    return result;
}

Result<std::string> read_store_key(const std::filesystem::path& state_dir) {
    const std::filesystem::path path = state_dir / DurableLayout::kKeyName;
    if (!fsutil::exists(path)) {
        return make_error(StatusCode::NotFound,
                          "state directory has no " + std::string(DurableLayout::kKeyName) +
                              "; refusing to open an unauthenticated store");
    }
    auto content = fsutil::read_all(path, 4096);
    if (!content.ok()) {
        return content.status();
    }
    return decode_key_file(content.value());
}

Result<std::string> create_store_key(const std::filesystem::path& state_dir) {
    const std::filesystem::path path = state_dir / DurableLayout::kKeyName;
    if (fsutil::exists(path)) {
        return make_error(StatusCode::AlreadyExists,
                          "state directory already holds a store key; refusing to replace it");
    }
    std::string key(kStoreKeyBytes, '\0');
    if (!secure_random_bytes(reinterpret_cast<std::uint8_t*>(key.data()), key.size())) {
        return make_error(StatusCode::Internal,
                          "the operating system entropy source is unavailable; refusing to "
                          "create a store with a predictable key");
    }
    auto written = fsutil::write_atomic(path, encode_key_file(key), true);
    if (!written.ok()) {
        return written.status();
    }
    auto restricted = fsutil::restrict_to_owner(path);
    if (!restricted.ok()) {
        return restricted.status();
    }
    return key;
}

}  // namespace pf
