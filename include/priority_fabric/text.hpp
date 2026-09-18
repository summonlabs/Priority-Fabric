// Priority Fabric -- authoritative network priority classes.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#ifndef PRIORITY_FABRIC_TEXT_HPP
#define PRIORITY_FABRIC_TEXT_HPP

#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

#include "priority_fabric/export.hpp"

namespace pf {

/// Truncates text to at most p limit bytes, appending "..." when truncation happened.
/// Truncation never splits a UTF-8 continuation byte. Every string the fabric stores or
/// returns from externally influenced input passes through this.
[[nodiscard]] PF_API std::string bound_text(std::string_view text, std::size_t limit);

/// ASCII-only lowercase. Non-ASCII bytes are left untouched; the fabric never guesses at
/// Unicode case folding.
[[nodiscard]] PF_API std::string ascii_lower(std::string_view text);

/// Splits on a single character. Empty segments are preserved so that callers can detect
/// them (identifier canonicalization relies on that).
[[nodiscard]] PF_API std::vector<std::string> split(std::string_view text, char separator);

/// Joins with a separator.
[[nodiscard]] PF_API std::string join(const std::vector<std::string>& parts,
                                      std::string_view separator);

/// True when every byte is printable ASCII or a UTF-8 continuation sequence that formed a
/// valid encoding of a printable code point. Control characters are rejected; the fabric
/// refuses to persist terminal escapes or NUL bytes in human-readable fields.
[[nodiscard]] PF_API bool is_printable_text(std::string_view text) noexcept;

}  // namespace pf

#endif  // PRIORITY_FABRIC_TEXT_HPP
