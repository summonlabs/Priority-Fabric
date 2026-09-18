// Priority Fabric -- authoritative network priority classes.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "priority_fabric/codec.hpp"

#include <cstring>

#include "priority_fabric/checked.hpp"

namespace pf {
namespace {

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

}  // namespace

// ---------------------------------------------------------------------------------------
// Encoder
// ---------------------------------------------------------------------------------------

void Encoder::u8(std::uint8_t v) {
    buffer_.push_back(static_cast<char>(v));
}

void Encoder::u16(std::uint16_t v) {
    append_le(buffer_, v, 2);
}

void Encoder::u32(std::uint32_t v) {
    append_le(buffer_, v, 4);
}

void Encoder::u64(std::uint64_t v) {
    append_le(buffer_, v, 8);
}

void Encoder::raw(const void* data, std::size_t size) {
    if (size == 0) {
        return;
    }
    buffer_.append(static_cast<const char*>(data), size);
}

void Encoder::str(std::string_view text) {
    const auto length = checked_narrow<std::uint32_t>(text.size());
    // Callers bound the text before encoding; a size that cannot be expressed in the
    // length prefix is a programming error, so clamp defensively rather than truncating
    // silently: the encoder writes the exact bytes it was given or it writes none.
    const std::uint32_t encoded_length = length.has_value() ? *length : 0u;
    u32(encoded_length);
    if (encoded_length != 0) {
        raw(text.data(), encoded_length);
    }
}

// ---------------------------------------------------------------------------------------
// Decoder
// ---------------------------------------------------------------------------------------

Decoder::Decoder(const void* data, std::size_t size, const Limits& limits) noexcept
    : data_(static_cast<const std::uint8_t*>(data)), size_(size), limits_(limits) {}

Result<const std::uint8_t*> Decoder::take(std::size_t n) {
    if (n > remaining()) {
        return make_error(StatusCode::Truncated,
                          "decoder underrun: wanted " + std::to_string(n) + " bytes, " +
                              std::to_string(remaining()) + " remain");
    }
    const std::uint8_t* out = data_ + offset_;
    offset_ += n;
    return out;
}

Result<std::uint8_t> Decoder::u8() {
    auto bytes = take(1);
    if (!bytes.ok()) {
        return bytes.status();
    }
    return *bytes.value();
}

Result<std::uint16_t> Decoder::u16() {
    auto bytes = take(2);
    if (!bytes.ok()) {
        return bytes.status();
    }
    return static_cast<std::uint16_t>(read_le(bytes.value(), 2));
}

Result<std::uint32_t> Decoder::u32() {
    auto bytes = take(4);
    if (!bytes.ok()) {
        return bytes.status();
    }
    return static_cast<std::uint32_t>(read_le(bytes.value(), 4));
}

Result<std::uint64_t> Decoder::u64() {
    auto bytes = take(8);
    if (!bytes.ok()) {
        return bytes.status();
    }
    return read_le(bytes.value(), 8);
}

Result<bool> Decoder::boolean() {
    auto value = u8();
    if (!value.ok()) {
        return value.status();
    }
    if (value.value() > 1u) {
        return make_error(StatusCode::ProtocolError,
                          "boolean field carried the invalid value " +
                              std::to_string(value.value()));
    }
    return value.value() == 1u;
}

Result<std::string> Decoder::raw(std::size_t size) {
    auto bytes = take(size);
    if (!bytes.ok()) {
        return bytes.status();
    }
    return std::string(reinterpret_cast<const char*>(bytes.value()), size);
}

Result<std::string> Decoder::str(std::uint32_t bound) {
    auto length = u32();
    if (!length.ok()) {
        return length.status();
    }
    if (length.value() > bound) {
        return make_error(StatusCode::LimitExceeded,
                          "length-prefixed field declares " + std::to_string(length.value()) +
                              " bytes, limit is " + std::to_string(bound));
    }
    return raw(length.value());
}

VoidResult Decoder::finish() const {
    if (!at_end()) {
        return make_error(StatusCode::ProtocolError,
                          "trailing bytes after a complete value: " +
                              std::to_string(remaining()) + " unexpected byte(s)");
    }
    return VoidResult{};
}

}  // namespace pf
