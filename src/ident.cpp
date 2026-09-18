// Priority Fabric -- authoritative network priority classes.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "priority_fabric/ident.hpp"

#include <chrono>
#include <cstddef>

#include "priority_fabric/digest.hpp"
#include "priority_fabric/text.hpp"

namespace pf {
namespace {

constexpr bool is_ascii_space(char c) noexcept {
    return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f';
}

constexpr bool is_lower_alnum(char c) noexcept {
    return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9');
}

constexpr bool is_separator(char c) noexcept {
    return c == '.' || c == '_' || c == ':' || c == '-';
}

/// Upper bound on the raw text a caller may hand over before canonicalization refuses it.
/// Prevents an adversarial 100 MiB identifier from being copied before validation.
constexpr std::size_t kMaxRawIdBytes = 4096;

constexpr char kHexDigits[] = "0123456789abcdef";

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

}  // namespace

Result<CanonicalId> canonicalize_id(std::string_view raw, const Limits& limits) {
    if (raw.empty()) {
        return make_error(StatusCode::MalformedId, "identifier is empty");
    }
    if (raw.size() > kMaxRawIdBytes) {
        return make_error(StatusCode::LimitExceeded,
                          "identifier exceeds the maximum raw length of " +
                              std::to_string(kMaxRawIdBytes) + " bytes");
    }
    if (!is_printable_text(raw)) {
        return make_error(StatusCode::MalformedId,
                          "identifier contains control or non-UTF-8 bytes");
    }

    std::size_t begin = 0;
    std::size_t end = raw.size();
    while (begin < end && is_ascii_space(raw[begin])) {
        ++begin;
    }
    while (end > begin && is_ascii_space(raw[end - 1])) {
        --end;
    }
    if (begin == end) {
        return make_error(StatusCode::MalformedId, "identifier is empty after trimming");
    }

    std::string_view body = raw.substr(begin, end - begin);
    if (body.front() == '/') {
        body.remove_prefix(1);
    }
    if (body.empty()) {
        return make_error(StatusCode::MalformedId, "identifier is empty after removing '/'");
    }

    std::string canonical;
    canonical.reserve(body.size());
    for (char c : body) {
        if (c == '/') {
            canonical.push_back('.');
        } else if (c >= 'A' && c <= 'Z') {
            canonical.push_back(static_cast<char>(c - 'A' + 'a'));
        } else {
            canonical.push_back(c);
        }
    }

    if (canonical.size() > limits.max_id_length) {
        return make_error(StatusCode::LimitExceeded,
                          "canonical identifier is " + std::to_string(canonical.size()) +
                              " bytes, limit is " + std::to_string(limits.max_id_length));
    }

    if (!is_lower_alnum(canonical.front())) {
        return make_error(StatusCode::MalformedId,
                          "identifier must start with a lowercase letter or digit");
    }
    bool previous_separator = false;
    for (std::size_t i = 0; i < canonical.size(); ++i) {
        const char c = canonical[i];
        if (is_lower_alnum(c)) {
            previous_separator = false;
            continue;
        }
        if (!is_separator(c)) {
            return make_error(StatusCode::MalformedId,
                              "identifier contains an unsupported character at offset " +
                                  std::to_string(i));
        }
        if (previous_separator) {
            return make_error(StatusCode::MalformedId,
                              "identifier contains an empty segment at offset " +
                                  std::to_string(i));
        }
        previous_separator = true;
    }
    if (previous_separator) {
        return make_error(StatusCode::MalformedId, "identifier may not end with a separator");
    }

    CanonicalId out;
    out.value = std::move(canonical);
    return out;
}

// ---------------------------------------------------------------------------------------
// BootId
// ---------------------------------------------------------------------------------------

bool BootId::is_zero() const noexcept {
    for (std::uint8_t b : bytes) {
        if (b != 0) {
            return false;
        }
    }
    return true;
}

std::string BootId::hex() const {
    std::string out;
    out.resize(kSize * 2);
    for (std::size_t i = 0; i < kSize; ++i) {
        out[i * 2] = kHexDigits[(bytes[i] >> 4) & 0x0Fu];
        out[i * 2 + 1] = kHexDigits[bytes[i] & 0x0Fu];
    }
    return out;
}

Result<BootId> BootId::generate() {
    BootId id;
    if (!secure_random_bytes(id.bytes.data(), id.bytes.size())) {
        return make_error(StatusCode::Internal,
                          "the operating system entropy source is unavailable; refusing to mint "
                          "a predictable boot id");
    }
    if (id.is_zero()) {
        return make_error(StatusCode::Internal, "the entropy source returned all-zero bytes");
    }
    return id;
}

BootId BootId::from_seed(std::string_view seed) noexcept {
    const std::string material = std::string("priority-fabric/boot-id/v1:") + std::string(seed);
    const Digest digest = Sha256::hash(material);
    BootId id;
    for (std::size_t i = 0; i < kSize; ++i) {
        id.bytes[i] = digest.bytes[i];
    }
    return id;
}

Result<BootId> BootId::parse_hex(std::string_view hex) {
    if (hex.size() != kSize * 2) {
        return make_error(StatusCode::MalformedId,
                          "boot id must be exactly 32 hexadecimal characters, got " +
                              std::to_string(hex.size()));
    }
    BootId id;
    for (std::size_t i = 0; i < kSize; ++i) {
        const int hi = hex_value(hex[i * 2]);
        const int lo = hex_value(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) {
            return make_error(StatusCode::MalformedId,
                              "boot id contains a non-hexadecimal character at offset " +
                                  std::to_string(i * 2));
        }
        id.bytes[i] = static_cast<std::uint8_t>((hi << 4) | lo);
    }
    return id;
}

std::uint64_t wall_clock_ms() noexcept {
    const auto now = std::chrono::system_clock::now().time_since_epoch();
    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now).count();
    return ms < 0 ? 0u : static_cast<std::uint64_t>(ms);
}

}  // namespace pf
