// Priority Fabric -- authoritative network priority classes.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#ifndef PRIORITY_FABRIC_VERSION_HPP
#define PRIORITY_FABRIC_VERSION_HPP

#include <cstdint>

#define PRIORITY_FABRIC_VERSION_MAJOR 1
#define PRIORITY_FABRIC_VERSION_MINOR 0
#define PRIORITY_FABRIC_VERSION_PATCH 0

// Wire/durable format version. Independent of the library version: durable files and
// frames carry this value so that a future format change is detected, never guessed.
#define PRIORITY_FABRIC_FORMAT_VERSION 1u

namespace pf {

/// Semantic version of the linked library.
struct Version {
    std::uint32_t major = PRIORITY_FABRIC_VERSION_MAJOR;
    std::uint32_t minor = PRIORITY_FABRIC_VERSION_MINOR;
    std::uint32_t patch = PRIORITY_FABRIC_VERSION_PATCH;

    friend bool operator==(const Version&, const Version&) = default;
};

/// Version of the library as a static string, e.g. "1.0.0".
[[nodiscard]] const char* version_string() noexcept;

/// Durable/wire format version implemented by this build.
[[nodiscard]] constexpr std::uint32_t format_version() noexcept {
    return PRIORITY_FABRIC_FORMAT_VERSION;
}

}  // namespace pf

#endif  // PRIORITY_FABRIC_VERSION_HPP
