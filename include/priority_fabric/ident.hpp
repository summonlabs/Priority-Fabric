// Priority Fabric -- authoritative network priority classes.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#ifndef PRIORITY_FABRIC_IDENT_HPP
#define PRIORITY_FABRIC_IDENT_HPP

#include <array>
#include <cstdint>
#include <string>
#include <string_view>

#include "priority_fabric/checked.hpp"
#include "priority_fabric/export.hpp"
#include "priority_fabric/limits.hpp"
#include "priority_fabric/status.hpp"

namespace pf {

/// Canonicalization result: the fabric stores exactly one spelling of every identifier.
/// Two spellings that canonicalize to the same bytes are the same identifier; they can
/// never come to mean two different things.
struct CanonicalId {
    std::string value;
};

/// Canonicalizes a raw identifier:
///   * ASCII uppercase is folded to lowercase;
///   * a leading '/' is dropped and subsequent '/' separators become '.';
///   * surrounding ASCII whitespace is trimmed;
///   * the result must match [a-z0-9][a-z0-9._:-]* with no empty segment,
///     no trailing separator, and no two adjacent separators.
/// Anything else is rejected with MalformedId. There is no silent repair beyond the
/// steps above; in particular no Unicode folding is attempted.
[[nodiscard]] PF_API Result<CanonicalId> canonicalize_id(std::string_view raw,
                                                         const Limits& limits);

/// Strongly typed identifier. Distinct tags produce distinct, non-interchangeable types.
template <typename Tag>
class BasicId {
public:
    using IdTag = Tag;

    BasicId() = default;

    /// Parses and canonicalizes. Never accepts an already-invalid identifier.
    [[nodiscard]] static Result<BasicId> parse(std::string_view raw, const Limits& limits) {
        auto canon = canonicalize_id(raw, limits);
        if (!canon.ok()) {
            return canon.status();
        }
        return BasicId(std::move(canon.value().value));
    }

    /// Builds from an already-canonical string. Fails if it is not canonical, so that a
    /// caller cannot smuggle a non-canonical spelling into authoritative state.
    [[nodiscard]] static Result<BasicId> from_canonical(std::string_view canonical,
                                                        const Limits& limits) {
        auto reparsed = canonicalize_id(canonical, limits);
        if (!reparsed.ok()) {
            return reparsed.status();
        }
        if (reparsed.value().value != canonical) {
            return make_error(StatusCode::MalformedId,
                              "identifier is not in canonical form: '" + std::string(canonical) +
                                  "' (canonical spelling is '" + reparsed.value().value + "')");
        }
        return BasicId(std::string(canonical));
    }

    /// Used by the codec when a canonical identifier has already been validated.
    struct TrustedTag {};
    [[nodiscard]] static BasicId trusted(std::string canonical, TrustedTag) {
        return BasicId(std::move(canonical));
    }

    [[nodiscard]] bool valid() const noexcept { return !value_.empty(); }
    [[nodiscard]] const std::string& str() const noexcept { return value_; }
    [[nodiscard]] std::string_view view() const noexcept { return value_; }

    friend bool operator==(const BasicId&, const BasicId&) noexcept = default;
    friend bool operator<(const BasicId& a, const BasicId& b) noexcept { return a.value_ < b.value_; }
    friend bool operator>(const BasicId& a, const BasicId& b) noexcept { return b < a; }
    friend bool operator<=(const BasicId& a, const BasicId& b) noexcept { return !(b < a); }
    friend bool operator>=(const BasicId& a, const BasicId& b) noexcept { return !(a < b); }

private:
    explicit BasicId(std::string value) : value_(std::move(value)) {}
    std::string value_;
};

struct PriorityClassTag;
struct PriorityAssignmentTag;
struct SubjectTag;
struct PolicyScopeTag;
struct PolicyTag;
struct PublisherTag;

using PriorityClassId = BasicId<PriorityClassTag>;
using PriorityAssignmentId = BasicId<PriorityAssignmentTag>;
using SubjectId = BasicId<SubjectTag>;
using PolicyScopeId = BasicId<PolicyScopeTag>;
using PolicyId = BasicId<PolicyTag>;
using PublisherId = BasicId<PublisherTag>;

/// 128-bit process incarnation identifier. A boot id is minted fresh every time a
/// publisher process starts; durable state records it so that a restart is detectable and
/// the previous incarnation can be fenced rather than silently resumed.
struct PF_API BootId {
    static constexpr std::size_t kSize = 16;
    std::array<std::uint8_t, kSize> bytes{};

    [[nodiscard]] static BootId zero() noexcept { return BootId{}; }

    /// Mints a new boot id from OS entropy. Fails when no entropy source is available;
    /// there is no predictable fallback.
    [[nodiscard]] static Result<BootId> generate();

    /// Deterministic boot id for tests and reproducible harnesses. Derived from the seed
    /// with SHA-256 and tagged so that it cannot collide with a generated boot id.
    [[nodiscard]] static BootId from_seed(std::string_view seed) noexcept;

    [[nodiscard]] static Result<BootId> parse_hex(std::string_view hex);
    [[nodiscard]] std::string hex() const;
    [[nodiscard]] bool is_zero() const noexcept;
    [[nodiscard]] bool valid() const noexcept { return !is_zero(); }

    friend bool operator==(const BootId&, const BootId&) noexcept = default;
    friend bool operator<(const BootId& a, const BootId& b) noexcept { return a.bytes < b.bytes; }
};

/// Opaque fencing token issued with an authority grant. Any mutation that does not carry
/// the currently valid token for its (publisher, boot, epoch) triple is fenced.
struct PF_API FencingToken {
    std::uint64_t value = 0;

    [[nodiscard]] static constexpr FencingToken none() noexcept { return FencingToken{0}; }
    [[nodiscard]] constexpr bool is_valid() const noexcept { return value != 0; }

    friend constexpr bool operator==(FencingToken, FencingToken) noexcept = default;
    friend constexpr bool operator<(FencingToken a, FencingToken b) noexcept {
        return a.value < b.value;
    }
};

/// Wall-clock milliseconds since the Unix epoch. Recorded for audit only. It is never
/// used to decide authority, freshness or ordering: those are decided by generations,
/// epochs and fencing tokens.
[[nodiscard]] PF_API std::uint64_t wall_clock_ms() noexcept;

}  // namespace pf

#endif  // PRIORITY_FABRIC_IDENT_HPP
