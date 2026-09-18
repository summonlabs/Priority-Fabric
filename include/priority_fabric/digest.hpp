// Priority Fabric -- authoritative network priority classes.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#ifndef PRIORITY_FABRIC_DIGEST_HPP
#define PRIORITY_FABRIC_DIGEST_HPP

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

#include "priority_fabric/export.hpp"

namespace pf {

/// 256-bit digest produced by the fabric's content hash (SHA-256).
struct PF_API Digest {
    static constexpr std::size_t kSize = 32;
    std::array<std::uint8_t, kSize> bytes{};

    [[nodiscard]] static Digest zero() noexcept { return Digest{}; }
    [[nodiscard]] bool is_zero() const noexcept;

    /// Lowercase hex, 64 characters.
    [[nodiscard]] std::string hex() const;

    /// Lowercase hex truncated to p n characters (n <= 64). Used for compact audit lines;
    /// it is a display convenience only, never an identity comparison.
    [[nodiscard]] std::string short_hex(std::size_t n) const;

    friend bool operator==(const Digest&, const Digest&) noexcept = default;
    friend bool operator<(const Digest& a, const Digest& b) noexcept { return a.bytes < b.bytes; }
};

/// Streaming SHA-256. Deterministic, self-contained, no external dependency.
class PF_API Sha256 {
public:
    Sha256() noexcept;

    void update(const void* data, std::size_t size) noexcept;
    void update(std::string_view text) noexcept;

    /// Finalizes and returns the digest. The object must not be reused afterwards.
    [[nodiscard]] Digest finish() noexcept;

    /// Convenience one-shot helpers.
    [[nodiscard]] static Digest hash(std::string_view text) noexcept;
    [[nodiscard]] static Digest hash(const void* data, std::size_t size) noexcept;

private:
    void compress(const std::uint8_t block[64]) noexcept;

    std::array<std::uint32_t, 8> state_{};
    std::array<std::uint8_t, 64> buffer_{};
    std::uint64_t total_bytes_ = 0;
    std::size_t buffered_ = 0;
};

/// HMAC-SHA256. Used to make durable journal records tamper-evident: a record whose
/// contents were altered without knowledge of the store key fails verification even if
/// the attacker recomputes the framing checksum.
[[nodiscard]] PF_API Digest hmac_sha256(const std::uint8_t* key, std::size_t key_size,
                                        const void* data, std::size_t size) noexcept;

/// CRC-32C (Castagnoli), reflected, polynomial 0x1EDC6F41. Used as a fast framing
/// checksum on both the durable journal and the transport.
[[nodiscard]] PF_API std::uint32_t crc32c(const void* data, std::size_t size) noexcept;
[[nodiscard]] PF_API std::uint32_t crc32c(std::string_view text) noexcept;
/// Incremental CRC-32C so that a frame can be validated without re-reading it.
[[nodiscard]] PF_API std::uint32_t crc32c_extend(std::uint32_t seed, const void* data,
                                                 std::size_t size) noexcept;

/// FNV-1a 64-bit. Cheap, deterministic, used only for non-authoritative bucketing and
/// deterministic shuffling in randomized tests. Never used for integrity.
[[nodiscard]] PF_API std::uint64_t fnv1a64(const void* data, std::size_t size) noexcept;
[[nodiscard]] PF_API std::uint64_t fnv1a64(std::string_view text) noexcept;

/// Constant-time comparison for equal-length buffers (used for MAC comparison).
[[nodiscard]] PF_API bool constant_time_equal(const std::uint8_t* a, const std::uint8_t* b,
                                              std::size_t size) noexcept;

/// Cryptographically-seeded random bytes from the operating system entropy source.
/// Returns false when the platform source is unavailable; callers must treat that as a
/// hard failure rather than falling back to a predictable value.
[[nodiscard]] PF_API bool secure_random_bytes(std::uint8_t* out, std::size_t size) noexcept;

}  // namespace pf

#endif  // PRIORITY_FABRIC_DIGEST_HPP
