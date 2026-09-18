// Priority Fabric -- authoritative network priority classes.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#ifndef PRIORITY_FABRIC_CHECKED_HPP
#define PRIORITY_FABRIC_CHECKED_HPP

#include <cstdint>
#include <limits>
#include <optional>
#include <type_traits>

#include "priority_fabric/export.hpp"

namespace pf {

/// Checked integer arithmetic. Every size, capacity, offset or growth computation that
/// is influenced by an external input goes through these helpers; a wrap is reported,
/// never silently absorbed.
template <typename T>
[[nodiscard]] constexpr std::optional<T> checked_add(T a, T b) noexcept {
    static_assert(std::is_unsigned_v<T>, "checked_add expects an unsigned type");
    if (a > static_cast<T>(std::numeric_limits<T>::max() - b)) {
        return std::nullopt;
    }
    return static_cast<T>(a + b);
}

template <typename T>
[[nodiscard]] constexpr std::optional<T> checked_mul(T a, T b) noexcept {
    static_assert(std::is_unsigned_v<T>, "checked_mul expects an unsigned type");
    if (a != 0 && b > static_cast<T>(std::numeric_limits<T>::max() / a)) {
        return std::nullopt;
    }
    return static_cast<T>(a * b);
}

template <typename T>
[[nodiscard]] constexpr std::optional<T> checked_sub(T a, T b) noexcept {
    static_assert(std::is_unsigned_v<T>, "checked_sub expects an unsigned type");
    if (b > a) {
        return std::nullopt;
    }
    return static_cast<T>(a - b);
}

/// Narrowing conversion that must not lose information.
template <typename Small, typename Large>
[[nodiscard]] constexpr std::optional<Small> checked_narrow(Large value) noexcept {
    static_assert(std::is_integral_v<Small> && std::is_integral_v<Large>,
                  "checked_narrow expects integral types");
    if (value < static_cast<Large>(std::numeric_limits<Small>::min()) ||
        value > static_cast<Large>(std::numeric_limits<Small>::max())) {
        return std::nullopt;
    }
    return static_cast<Small>(value);
}

/// Monotonic generation counter. Zero is the reserved "absent / unset" value; the first
/// real generation is 1. Increment past the maximum is a hard failure, not a wrap.
struct PF_API Generation {
    std::uint64_t value = 0;

    [[nodiscard]] static constexpr Generation unset() noexcept { return Generation{0}; }
    [[nodiscard]] static constexpr Generation first() noexcept { return Generation{1}; }

    [[nodiscard]] constexpr bool is_set() const noexcept { return value != 0; }

    /// Returns the successor generation, or nullopt on overflow.
    [[nodiscard]] constexpr std::optional<Generation> next() const noexcept {
        if (value == std::numeric_limits<std::uint64_t>::max()) {
            return std::nullopt;
        }
        return Generation{value + 1};
    }

    friend constexpr bool operator==(Generation, Generation) noexcept = default;
    friend constexpr bool operator<(Generation a, Generation b) noexcept {
        return a.value < b.value;
    }
    friend constexpr bool operator>(Generation a, Generation b) noexcept { return b < a; }
    friend constexpr bool operator<=(Generation a, Generation b) noexcept { return !(b < a); }
    friend constexpr bool operator>=(Generation a, Generation b) noexcept { return !(a < b); }
};

/// Fabric epoch. Node-scoped monotonic authority fence. Zero means "never established".
struct PF_API FabricEpoch {
    std::uint64_t value = 0;

    [[nodiscard]] static constexpr FabricEpoch unestablished() noexcept { return FabricEpoch{0}; }
    [[nodiscard]] constexpr bool is_established() const noexcept { return value != 0; }

    [[nodiscard]] constexpr std::optional<FabricEpoch> next() const noexcept {
        if (value == std::numeric_limits<std::uint64_t>::max()) {
            return std::nullopt;
        }
        return FabricEpoch{value + 1};
    }

    friend constexpr bool operator==(FabricEpoch, FabricEpoch) noexcept = default;
    friend constexpr bool operator<(FabricEpoch a, FabricEpoch b) noexcept {
        return a.value < b.value;
    }
    friend constexpr bool operator>(FabricEpoch a, FabricEpoch b) noexcept { return b < a; }
    friend constexpr bool operator<=(FabricEpoch a, FabricEpoch b) noexcept { return !(b < a); }
    friend constexpr bool operator>=(FabricEpoch a, FabricEpoch b) noexcept { return !(a < b); }
};

/// Explicit precedence rank. Higher rank means higher precedence; there is no implicit
/// default and no hidden ordering. Ranks are unique per active class in a fabric state.
struct PF_API PrecedenceRank {
    /// Ranks are drawn from [0, kMaxRank]. The ceiling exists so that arithmetic on ranks
    /// (used only for deterministic ordering, never for bandwidth or rates) cannot leave
    /// the representable range.
    static constexpr std::uint32_t kMaxRank = 1000000u;

    std::uint32_t value = 0;
    bool assigned = false;  ///< false = the rank was never explicitly declared

    [[nodiscard]] static constexpr PrecedenceRank make(std::uint32_t v) noexcept {
        return PrecedenceRank{v, true};
    }
    [[nodiscard]] static constexpr PrecedenceRank undeclared() noexcept {
        return PrecedenceRank{0, false};
    }
    [[nodiscard]] constexpr bool is_declared() const noexcept { return assigned; }

    friend constexpr bool operator==(PrecedenceRank a, PrecedenceRank b) noexcept {
        return a.assigned == b.assigned && (!a.assigned || a.value == b.value);
    }
    /// Total order over declared ranks. Only meaningful for two declared ranks.
    friend constexpr bool operator<(PrecedenceRank a, PrecedenceRank b) noexcept {
        return a.value < b.value;
    }
};

}  // namespace pf

#endif  // PRIORITY_FABRIC_CHECKED_HPP
