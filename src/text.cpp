// Priority Fabric -- authoritative network priority classes.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "priority_fabric/text.hpp"

#include <cstdint>

namespace pf {
namespace {

/// Length of a UTF-8 sequence starting with \p lead, or 0 when the lead byte is invalid.
std::size_t utf8_sequence_length(std::uint8_t lead) noexcept {
    if (lead < 0x80u) {
        return 1;
    }
    if (lead >= 0xC2u && lead <= 0xDFu) {
        return 2;
    }
    if (lead >= 0xE0u && lead <= 0xEFu) {
        return 3;
    }
    if (lead >= 0xF0u && lead <= 0xF4u) {
        return 4;
    }
    return 0;
}

}  // namespace

std::string bound_text(std::string_view text, std::size_t limit) {
    if (text.size() <= limit) {
        return std::string(text);
    }
    constexpr std::string_view kEllipsis = "...";
    if (limit <= kEllipsis.size()) {
        return std::string(kEllipsis.substr(0, limit));
    }
    std::size_t cut = limit - kEllipsis.size();
    // Never leave a dangling continuation byte.
    while (cut > 0 && (static_cast<std::uint8_t>(text[cut]) & 0xC0u) == 0x80u) {
        --cut;
    }
    std::string out(text.substr(0, cut));
    out.append(kEllipsis);
    return out;
}

std::string ascii_lower(std::string_view text) {
    std::string out;
    out.reserve(text.size());
    for (char c : text) {
        if (c >= 'A' && c <= 'Z') {
            out.push_back(static_cast<char>(c - 'A' + 'a'));
        } else {
            out.push_back(c);
        }
    }
    return out;
}

std::vector<std::string> split(std::string_view text, char separator) {
    std::vector<std::string> parts;
    std::size_t start = 0;
    for (std::size_t i = 0; i <= text.size(); ++i) {
        if (i == text.size() || text[i] == separator) {
            parts.emplace_back(text.substr(start, i - start));
            start = i + 1;
        }
    }
    return parts;
}

std::string join(const std::vector<std::string>& parts, std::string_view separator) {
    std::string out;
    for (std::size_t i = 0; i < parts.size(); ++i) {
        if (i != 0) {
            out.append(separator);
        }
        out.append(parts[i]);
    }
    return out;
}

bool is_printable_text(std::string_view text) noexcept {
    std::size_t i = 0;
    while (i < text.size()) {
        const auto lead = static_cast<std::uint8_t>(text[i]);
        if (lead < 0x80u) {
            if (lead < 0x20u || lead == 0x7Fu) {
                return false;
            }
            ++i;
            continue;
        }
        const std::size_t length = utf8_sequence_length(lead);
        if (length < 2 || i + length > text.size()) {
            return false;
        }
        for (std::size_t k = 1; k < length; ++k) {
            if ((static_cast<std::uint8_t>(text[i + k]) & 0xC0u) != 0x80u) {
                return false;
            }
        }
        i += length;
    }
    return true;
}

}  // namespace pf
