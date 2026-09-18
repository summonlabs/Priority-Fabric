// Priority Fabric -- authoritative network priority classes.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#ifndef PRIORITY_FABRIC_CODEC_HPP
#define PRIORITY_FABRIC_CODEC_HPP

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

#include "priority_fabric/export.hpp"
#include "priority_fabric/ident.hpp"
#include "priority_fabric/limits.hpp"
#include "priority_fabric/status.hpp"

namespace pf {

/// Canonical little-endian binary encoding shared by the durable journal and the wire
/// protocol. Exactly one byte sequence represents a given value: lengths are explicit,
/// padding does not exist, and a decoder that finds trailing bytes reports a protocol
/// error rather than ignoring them.
class PF_API Encoder {
public:
    Encoder() = default;

    void u8(std::uint8_t v);
    void u16(std::uint16_t v);
    void u32(std::uint32_t v);
    void u64(std::uint64_t v);
    void boolean(bool v) { u8(v ? 1u : 0u); }
    void raw(const void* data, std::size_t size);
    /// Length-prefixed (u32) byte string; the caller guarantees the bound was checked.
    void str(std::string_view text);

    [[nodiscard]] const std::string& buffer() const noexcept { return buffer_; }
    [[nodiscard]] std::string take() noexcept { return std::move(buffer_); }
    [[nodiscard]] std::size_t size() const noexcept { return buffer_.size(); }
    void clear() noexcept { buffer_.clear(); }

private:
    std::string buffer_;
};

/// Bounds-checked decoder. Every read either succeeds within the available bytes or
/// returns an error; there is no unchecked fast path and no way to read past the end.
class PF_API Decoder {
public:
    Decoder(const void* data, std::size_t size, const Limits& limits) noexcept;

    [[nodiscard]] Result<std::uint8_t> u8();
    [[nodiscard]] Result<std::uint16_t> u16();
    [[nodiscard]] Result<std::uint32_t> u32();
    [[nodiscard]] Result<std::uint64_t> u64();
    [[nodiscard]] Result<bool> boolean();
    /// Reads exactly p size bytes.
    [[nodiscard]] Result<std::string> raw(std::size_t size);
    /// Reads a length-prefixed byte string; the length is validated against
    /// Limits::max_record_payload before any allocation is attempted.
    [[nodiscard]] Result<std::string> str(std::uint32_t bound);
    /// Reads a length-prefixed identifier and canonicalizes it; a non-canonical identifier
    /// on the wire or on disk is a protocol error, not something to repair.
    template <typename Tag>
    [[nodiscard]] Result<BasicId<Tag>> id() {
        auto raw_value = str(limits_.max_id_length);
        if (!raw_value.ok()) {
            return raw_value.status();
        }
        return BasicId<Tag>::from_canonical(raw_value.value(), limits_);
    }

    [[nodiscard]] std::size_t remaining() const noexcept { return size_ - offset_; }
    [[nodiscard]] bool at_end() const noexcept { return offset_ == size_; }
    [[nodiscard]] std::size_t offset() const noexcept { return offset_; }

    /// Requires that every byte has been consumed.
    [[nodiscard]] VoidResult finish() const;

private:
    [[nodiscard]] Result<const std::uint8_t*> take(std::size_t n);

    const std::uint8_t* data_ = nullptr;
    std::size_t size_ = 0;
    std::size_t offset_ = 0;
    /// Owned, not borrowed. A decoder must not be able to outlive the limits it enforces, and
    /// a caller that passes a temporary must not be able to create a dangling reference.
    Limits limits_{};
};

}  // namespace pf

#endif  // PRIORITY_FABRIC_CODEC_HPP
