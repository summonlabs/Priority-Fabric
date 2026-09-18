// Priority Fabric -- authoritative network priority classes.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "priority_fabric/digest.hpp"

#include <cstring>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#else
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#endif

namespace pf {
namespace {

constexpr std::uint32_t kSha256K[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u,
    0xab1c5ed5u, 0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu,
    0x9bdc06a7u, 0xc19bf174u, 0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu,
    0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau, 0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu,
    0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u, 0xa2bfe8a1u, 0xa81a664bu,
    0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u, 0x19a4c116u,
    0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u,
    0xc67178f2u};

constexpr std::uint32_t rotr(std::uint32_t x, unsigned n) noexcept {
    return (x >> n) | (x << (32u - n));
}

constexpr std::uint32_t big_sigma0(std::uint32_t x) noexcept {
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
}
constexpr std::uint32_t big_sigma1(std::uint32_t x) noexcept {
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
}
constexpr std::uint32_t small_sigma0(std::uint32_t x) noexcept {
    return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
}
constexpr std::uint32_t small_sigma1(std::uint32_t x) noexcept {
    return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
}

struct Crc32cTable {
    std::uint32_t values[256];

    constexpr Crc32cTable() : values{} {
        constexpr std::uint32_t kPoly = 0x82F63B78u;  // reflected 0x1EDC6F41
        for (std::uint32_t i = 0; i < 256; ++i) {
            std::uint32_t crc = i;
            for (int bit = 0; bit < 8; ++bit) {
                crc = (crc & 1u) != 0u ? (crc >> 1) ^ kPoly : crc >> 1;
            }
            values[i] = crc;
        }
    }
};

constexpr Crc32cTable kCrc32cTable{};

constexpr char kHexDigits[] = "0123456789abcdef";

}  // namespace

// ---------------------------------------------------------------------------------------
// Digest
// ---------------------------------------------------------------------------------------

bool Digest::is_zero() const noexcept {
    for (std::uint8_t b : bytes) {
        if (b != 0) {
            return false;
        }
    }
    return true;
}

std::string Digest::hex() const {
    std::string out;
    out.resize(kSize * 2);
    for (std::size_t i = 0; i < kSize; ++i) {
        out[i * 2] = kHexDigits[(bytes[i] >> 4) & 0x0Fu];
        out[i * 2 + 1] = kHexDigits[bytes[i] & 0x0Fu];
    }
    return out;
}

std::string Digest::short_hex(std::size_t n) const {
    const std::string full = hex();
    if (n >= full.size()) {
        return full;
    }
    return full.substr(0, n);
}

// ---------------------------------------------------------------------------------------
// SHA-256
// ---------------------------------------------------------------------------------------

Sha256::Sha256() noexcept {
    state_ = {0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
              0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u};
}

void Sha256::compress(const std::uint8_t block[64]) noexcept {
    std::uint32_t w[64];
    for (std::size_t i = 0; i < 16; ++i) {
        w[i] = (static_cast<std::uint32_t>(block[i * 4]) << 24) |
               (static_cast<std::uint32_t>(block[i * 4 + 1]) << 16) |
               (static_cast<std::uint32_t>(block[i * 4 + 2]) << 8) |
               static_cast<std::uint32_t>(block[i * 4 + 3]);
    }
    for (std::size_t i = 16; i < 64; ++i) {
        w[i] = small_sigma1(w[i - 2]) + w[i - 7] + small_sigma0(w[i - 15]) + w[i - 16];
    }

    std::uint32_t a = state_[0];
    std::uint32_t b = state_[1];
    std::uint32_t c = state_[2];
    std::uint32_t d = state_[3];
    std::uint32_t e = state_[4];
    std::uint32_t f = state_[5];
    std::uint32_t g = state_[6];
    std::uint32_t h = state_[7];

    for (std::size_t i = 0; i < 64; ++i) {
        const std::uint32_t t1 = h + big_sigma1(e) + ((e & f) ^ (~e & g)) + kSha256K[i] + w[i];
        const std::uint32_t t2 = big_sigma0(a) + ((a & b) ^ (a & c) ^ (b & c));
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    state_[0] += a;
    state_[1] += b;
    state_[2] += c;
    state_[3] += d;
    state_[4] += e;
    state_[5] += f;
    state_[6] += g;
    state_[7] += h;
}

void Sha256::update(const void* data, std::size_t size) noexcept {
    const auto* bytes = static_cast<const std::uint8_t*>(data);
    total_bytes_ += static_cast<std::uint64_t>(size);

    if (buffered_ > 0) {
        const std::size_t need = 64 - buffered_;
        const std::size_t take = size < need ? size : need;
        std::memcpy(buffer_.data() + buffered_, bytes, take);
        buffered_ += take;
        bytes += take;
        size -= take;
        if (buffered_ == 64) {
            compress(buffer_.data());
            buffered_ = 0;
        }
    }

    while (size >= 64) {
        compress(bytes);
        bytes += 64;
        size -= 64;
    }

    if (size > 0) {
        std::memcpy(buffer_.data(), bytes, size);
        buffered_ = size;
    }
}

void Sha256::update(std::string_view text) noexcept {
    update(text.data(), text.size());
}

Digest Sha256::finish() noexcept {
    const std::uint64_t bit_length = total_bytes_ * 8u;

    const std::uint8_t pad = 0x80u;
    update(&pad, 1);

    const std::uint8_t zero = 0x00u;
    while (buffered_ != 56) {
        update(&zero, 1);
    }

    std::uint8_t length_bytes[8];
    for (std::size_t i = 0; i < 8; ++i) {
        length_bytes[i] = static_cast<std::uint8_t>((bit_length >> (56 - 8 * i)) & 0xFFu);
    }
    update(length_bytes, 8);

    Digest out;
    for (std::size_t i = 0; i < 8; ++i) {
        out.bytes[i * 4] = static_cast<std::uint8_t>((state_[i] >> 24) & 0xFFu);
        out.bytes[i * 4 + 1] = static_cast<std::uint8_t>((state_[i] >> 16) & 0xFFu);
        out.bytes[i * 4 + 2] = static_cast<std::uint8_t>((state_[i] >> 8) & 0xFFu);
        out.bytes[i * 4 + 3] = static_cast<std::uint8_t>(state_[i] & 0xFFu);
    }
    return out;
}

Digest Sha256::hash(std::string_view text) noexcept {
    Sha256 h;
    h.update(text);
    return h.finish();
}

Digest Sha256::hash(const void* data, std::size_t size) noexcept {
    Sha256 h;
    h.update(data, size);
    return h.finish();
}

// ---------------------------------------------------------------------------------------
// HMAC-SHA256
// ---------------------------------------------------------------------------------------

Digest hmac_sha256(const std::uint8_t* key, std::size_t key_size, const void* data,
                   std::size_t size) noexcept {
    constexpr std::size_t kBlock = 64;

    std::uint8_t normalized[64];
    std::memset(normalized, 0, sizeof(normalized));
    if (key_size > kBlock) {
        const Digest hashed = Sha256::hash(key, key_size);
        std::memcpy(normalized, hashed.bytes.data(), hashed.bytes.size());
    } else if (key_size > 0) {
        std::memcpy(normalized, key, key_size);
    }

    std::uint8_t ipad[64];
    std::uint8_t opad[64];
    for (std::size_t i = 0; i < kBlock; ++i) {
        ipad[i] = static_cast<std::uint8_t>(normalized[i] ^ 0x36u);
        opad[i] = static_cast<std::uint8_t>(normalized[i] ^ 0x5Cu);
    }

    Sha256 inner;
    inner.update(ipad, kBlock);
    inner.update(data, size);
    const Digest inner_digest = inner.finish();

    Sha256 outer;
    outer.update(opad, kBlock);
    outer.update(inner_digest.bytes.data(), inner_digest.bytes.size());
    return outer.finish();
}

// ---------------------------------------------------------------------------------------
// CRC-32C
// ---------------------------------------------------------------------------------------

std::uint32_t crc32c_extend(std::uint32_t seed, const void* data, std::size_t size) noexcept {
    const auto* bytes = static_cast<const std::uint8_t*>(data);
    std::uint32_t crc = ~seed;
    for (std::size_t i = 0; i < size; ++i) {
        crc = kCrc32cTable.values[(crc ^ bytes[i]) & 0xFFu] ^ (crc >> 8);
    }
    return ~crc;
}

std::uint32_t crc32c(const void* data, std::size_t size) noexcept {
    return crc32c_extend(0u, data, size);
}

std::uint32_t crc32c(std::string_view text) noexcept {
    return crc32c(text.data(), text.size());
}

// ---------------------------------------------------------------------------------------
// FNV-1a 64
// ---------------------------------------------------------------------------------------

std::uint64_t fnv1a64(const void* data, std::size_t size) noexcept {
    const auto* bytes = static_cast<const std::uint8_t*>(data);
    std::uint64_t hash = 14695981039346656037ull;
    for (std::size_t i = 0; i < size; ++i) {
        hash ^= bytes[i];
        hash *= 1099511628211ull;
    }
    return hash;
}

std::uint64_t fnv1a64(std::string_view text) noexcept {
    return fnv1a64(text.data(), text.size());
}

// ---------------------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------------------

bool constant_time_equal(const std::uint8_t* a, const std::uint8_t* b, std::size_t size) noexcept {
    std::uint8_t diff = 0;
    for (std::size_t i = 0; i < size; ++i) {
        diff = static_cast<std::uint8_t>(diff | (a[i] ^ b[i]));
    }
    return diff == 0;
}

bool secure_random_bytes(std::uint8_t* out, std::size_t size) noexcept {
    if (out == nullptr || size == 0) {
        return false;
    }
#if defined(_WIN32)
    const NTSTATUS status =
        ::BCryptGenRandom(nullptr, out, static_cast<ULONG>(size), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    return status == 0;
#else
    std::size_t filled = 0;
    const int fd = ::open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        return false;
    }
    while (filled < size) {
        const ssize_t n = ::read(fd, out + filled, size - filled);
        if (n <= 0) {
            if (n < 0 && errno == EINTR) {
                continue;
            }
            ::close(fd);
            return false;
        }
        filled += static_cast<std::size_t>(n);
    }
    ::close(fd);
    return true;
#endif
}

}  // namespace pf
