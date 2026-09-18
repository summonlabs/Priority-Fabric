// Priority Fabric -- authoritative network priority classes.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Internal: small, explicit file-system helpers. They exist so that the durability layer
// has exactly one implementation of "write every byte, then flush it to the platform" and
// exactly one implementation of "replace this file atomically".

#ifndef PRIORITY_FABRIC_SRC_FSUTIL_HPP
#define PRIORITY_FABRIC_SRC_FSUTIL_HPP

#include <cstdint>
#include <filesystem>
#include <string>

#include "priority_fabric/status.hpp"

namespace pf::fsutil {

/// Owns a platform file handle. Closes on destruction; never copies.
class File {
public:
    File() = default;
    explicit File(int descriptor) : fd_(descriptor) {}
    ~File();

    File(const File&) = delete;
    File& operator=(const File&) = delete;
    File(File&& other) noexcept;
    File& operator=(File&& other) noexcept;

    [[nodiscard]] bool valid() const noexcept { return fd_ >= 0; }
    [[nodiscard]] int descriptor() const noexcept { return fd_; }

    /// Closes and returns the resulting status. Idempotent.
    VoidResult close();
    int release() noexcept;

private:
    int fd_ = -1;
};

[[nodiscard]] Result<File> open_read(const std::filesystem::path& path);
/// Opens for appending, creating the file (and only the file) when missing.
[[nodiscard]] Result<File> open_append(const std::filesystem::path& path);
[[nodiscard]] Result<File> open_truncate(const std::filesystem::path& path);

[[nodiscard]] VoidResult write_all(File& file, const void* data, std::size_t size);
[[nodiscard]] VoidResult read_exact(File& file, void* data, std::size_t size);
[[nodiscard]] VoidResult flush_to_platform(File& file);
[[nodiscard]] Result<std::uint64_t> file_size(const std::filesystem::path& path);
[[nodiscard]] VoidResult truncate_file(const std::filesystem::path& path, std::uint64_t size);

/// Reads at most \p max_bytes. A file larger than the bound is refused rather than
/// partially read, so that an oversized durable artifact is a reported failure.
[[nodiscard]] Result<std::string> read_all(const std::filesystem::path& path,
                                           std::uint64_t max_bytes);

/// Atomically replaces \p destination with \p source. On Windows this uses
/// MoveFileEx with MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH; on POSIX, rename(2).
[[nodiscard]] VoidResult atomic_replace(const std::filesystem::path& source,
                                        const std::filesystem::path& destination);

[[nodiscard]] VoidResult remove_file(const std::filesystem::path& path);
[[nodiscard]] VoidResult ensure_directory(const std::filesystem::path& path);
[[nodiscard]] bool exists(const std::filesystem::path& path) noexcept;

/// Total size of the regular files directly inside \p directory. Bounded by
/// \p max_entries; exceeding the bound is reported, never truncated silently.
[[nodiscard]] Result<std::pair<std::uint64_t, std::uint64_t>> directory_bytes(
    const std::filesystem::path& directory, std::uint32_t max_entries);

/// Restricts a freshly created file to the owning user where the platform supports it.
[[nodiscard]] VoidResult restrict_to_owner(const std::filesystem::path& path);

/// An exclusive advisory lock on a file. The operating system releases it when the holding
/// process dies for any reason, so it can fence a second process out of a state directory
/// without leaving a stale lock file behind after a crash.
class FileLock {
public:
    FileLock() = default;
    ~FileLock();

    FileLock(const FileLock&) = delete;
    FileLock& operator=(const FileLock&) = delete;
    FileLock(FileLock&& other) noexcept;
    FileLock& operator=(FileLock&& other) noexcept;

    /// Takes the lock without blocking. Fails with AlreadyExists when another live process
    /// holds it.
    [[nodiscard]] static Result<FileLock> acquire(const std::filesystem::path& path);

    [[nodiscard]] bool held() const noexcept;
    void release() noexcept;

private:
#if defined(_WIN32)
    void* handle_ = nullptr;
#else
    int descriptor_ = -1;
#endif
};

/// Writes \p content to \p path by creating a sibling temporary file, flushing it, and
/// atomically replacing the destination. Used for the manifest and the snapshot.
[[nodiscard]] VoidResult write_atomic(const std::filesystem::path& path,
                                      const std::string& content, bool sync);

}  // namespace pf::fsutil

#endif  // PRIORITY_FABRIC_SRC_FSUTIL_HPP
