// Priority Fabric -- authoritative network priority classes.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "fsutil.hpp"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <system_error>
#include <vector>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <fcntl.h>
#include <io.h>
#include <share.h>
#include <sys/stat.h>
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#endif

namespace pf::fsutil {
namespace {

/// Numeric errno value formatted without the deprecated strerror().
std::string errno_text() {
#if defined(_WIN32)
    char buffer[256] = {};
    strerror_s(buffer, sizeof(buffer), errno);
    return std::string(buffer);
#else
    return std::string(std::strerror(errno));
#endif
}

Status io_error(std::string_view what, const std::filesystem::path& path) {
    return make_error(StatusCode::IoError,
                      std::string(what) + " '" + path.string() + "' failed: " + errno_text());
}

std::filesystem::path temporary_sibling(const std::filesystem::path& path,
                                        std::string_view suffix) {
    std::filesystem::path temp = path;
    temp += std::string(".pftmp-") + std::string(suffix);
    return temp;
}

}  // namespace

File::~File() {
    if (fd_ >= 0) {
#if defined(_WIN32)
        ::_close(fd_);
#else
        ::close(fd_);
#endif
    }
}

File::File(File&& other) noexcept : fd_(other.fd_) {
    other.fd_ = -1;
}

File& File::operator=(File&& other) noexcept {
    if (this != &other) {
        (void)close();
        fd_ = other.fd_;
        other.fd_ = -1;
    }
    return *this;
}

VoidResult File::close() {
    if (fd_ < 0) {
        return VoidResult{};
    }
    const int fd = fd_;
    fd_ = -1;
#if defined(_WIN32)
    if (::_close(fd) != 0) {
        return make_error(StatusCode::IoError, "closing a durable file failed");
    }
#else
    if (::close(fd) != 0) {
        return make_error(StatusCode::IoError, "closing a durable file failed");
    }
#endif
    return VoidResult{};
}

int File::release() noexcept {
    const int fd = fd_;
    fd_ = -1;
    return fd;
}

Result<File> open_read(const std::filesystem::path& path) {
#if defined(_WIN32)
    int fd = -1;
    if (::_wsopen_s(&fd, path.c_str(), _O_RDONLY | _O_BINARY | _O_NOINHERIT, _SH_DENYNO,
                    _S_IREAD) != 0) {
        return io_error("open for read", path);
    }
#else
    const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        return io_error("open for read", path);
    }
#endif
    return File(fd);
}

Result<File> open_append(const std::filesystem::path& path) {
#if defined(_WIN32)
    int fd = -1;
    if (::_wsopen_s(&fd, path.c_str(),
                    _O_RDWR | _O_BINARY | _O_CREAT | _O_APPEND | _O_NOINHERIT, _SH_DENYNO,
                    _S_IREAD | _S_IWRITE) != 0) {
        return io_error("open for append", path);
    }
#else
    const int fd = ::open(path.c_str(), O_RDWR | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
    if (fd < 0) {
        return io_error("open for append", path);
    }
#endif
    return File(fd);
}

Result<File> open_truncate(const std::filesystem::path& path) {
#if defined(_WIN32)
    int fd = -1;
    if (::_wsopen_s(&fd, path.c_str(),
                    _O_RDWR | _O_BINARY | _O_CREAT | _O_TRUNC | _O_NOINHERIT, _SH_DENYNO,
                    _S_IREAD | _S_IWRITE) != 0) {
        return io_error("open for write", path);
    }
#else
    const int fd = ::open(path.c_str(), O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0) {
        return io_error("open for write", path);
    }
#endif
    return File(fd);
}

VoidResult write_all(File& file, const void* data, std::size_t size) {
    if (!file.valid()) {
        return make_error(StatusCode::IoError, "write on a closed file handle");
    }
    const auto* bytes = static_cast<const std::uint8_t*>(data);
    std::size_t written = 0;
    while (written < size) {
        const std::size_t chunk = std::min<std::size_t>(size - written, 1u << 20);
#if defined(_WIN32)
        const int n = ::_write(file.descriptor(), bytes + written, static_cast<unsigned>(chunk));
#else
        const ssize_t n = ::write(file.descriptor(), bytes + written, chunk);
#endif
        if (n < 0) {
            return make_error(StatusCode::IoError,
                              "writing a durable file failed: " + errno_text());
        }
        if (n == 0) {
            return make_error(StatusCode::IoError, "writing a durable file made no progress");
        }
        written += static_cast<std::size_t>(n);
    }
    return VoidResult{};
}

VoidResult read_exact(File& file, void* data, std::size_t size) {
    if (!file.valid()) {
        return make_error(StatusCode::IoError, "read on a closed file handle");
    }
    auto* bytes = static_cast<std::uint8_t*>(data);
    std::size_t read_bytes = 0;
    while (read_bytes < size) {
#if defined(_WIN32)
        const int n = ::_read(file.descriptor(), bytes + read_bytes,
                              static_cast<unsigned>(size - read_bytes));
#else
        const ssize_t n = ::read(file.descriptor(), bytes + read_bytes, size - read_bytes);
#endif
        if (n < 0) {
            return make_error(StatusCode::IoError,
                              "reading a durable file failed: " + errno_text());
        }
        if (n == 0) {
            return make_error(StatusCode::Truncated, "unexpected end of file while reading");
        }
        read_bytes += static_cast<std::size_t>(n);
    }
    return VoidResult{};
}

VoidResult flush_to_platform(File& file) {
    if (!file.valid()) {
        return make_error(StatusCode::IoError, "flush on a closed file handle");
    }
#if defined(_WIN32)
    if (::_commit(file.descriptor()) != 0) {
        return make_error(StatusCode::IoError, "flushing a durable file failed");
    }
#else
    if (::fsync(file.descriptor()) != 0) {
        return make_error(StatusCode::IoError, "flushing a durable file failed");
    }
#endif
    return VoidResult{};
}

Result<std::uint64_t> file_size(const std::filesystem::path& path) {
    std::error_code ec;
    const auto size = std::filesystem::file_size(path, ec);
    if (ec) {
        return make_error(StatusCode::IoError,
                          "cannot determine the size of '" + path.string() + "': " + ec.message());
    }
    return static_cast<std::uint64_t>(size);
}

VoidResult truncate_file(const std::filesystem::path& path, std::uint64_t size) {
#if defined(_WIN32)
    int fd = -1;
    if (::_wsopen_s(&fd, path.c_str(), _O_RDWR | _O_BINARY | _O_NOINHERIT, _SH_DENYNO,
                    _S_IREAD | _S_IWRITE) != 0) {
        return io_error("open for truncation", path);
    }
    const int rc = ::_chsize_s(fd, static_cast<__int64>(size));
    (void)::_close(fd);
    if (rc != 0) {
        return io_error("truncate", path);
    }
#else
    if (::truncate(path.c_str(), static_cast<off_t>(size)) != 0) {
        return io_error("truncate", path);
    }
#endif
    return VoidResult{};
}

Result<std::string> read_all(const std::filesystem::path& path, std::uint64_t max_bytes) {
    // Qualified: an unqualified call would also find std::filesystem::file_size through
    // argument-dependent lookup on std::filesystem::path and be ambiguous.
    auto size = pf::fsutil::file_size(path);
    if (!size.ok()) {
        return size.status();
    }
    if (size.value() > max_bytes) {
        return make_error(StatusCode::LimitExceeded,
                          "durable artifact '" + path.string() + "' is " +
                              std::to_string(size.value()) + " bytes, limit is " +
                              std::to_string(max_bytes));
    }
    auto file = open_read(path);
    if (!file.ok()) {
        return file.status();
    }
    std::string content;
    content.resize(static_cast<std::size_t>(size.value()));
    if (!content.empty()) {
        auto read_status = read_exact(file.value(), content.data(), content.size());
        if (!read_status.ok()) {
            return read_status.status();
        }
    }
    return content;
}

VoidResult atomic_replace(const std::filesystem::path& source,
                          const std::filesystem::path& destination) {
#if defined(_WIN32)
    if (::MoveFileExW(source.c_str(), destination.c_str(),
                      MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) == 0) {
        return make_error(StatusCode::IoError,
                          "atomic replace of '" + destination.string() + "' failed with error " +
                              std::to_string(::GetLastError()));
    }
#else
    if (::rename(source.c_str(), destination.c_str()) != 0) {
        return io_error("atomic rename to", destination);
    }
#endif
    return VoidResult{};
}

VoidResult remove_file(const std::filesystem::path& path) {
    std::error_code ec;
    const bool removed = std::filesystem::remove(path, ec);
    if (ec) {
        return make_error(StatusCode::IoError,
                          "removing '" + path.string() + "' failed: " + ec.message());
    }
    (void)removed;
    return VoidResult{};
}

VoidResult ensure_directory(const std::filesystem::path& path) {
    std::error_code ec;
    if (std::filesystem::exists(path, ec)) {
        if (ec) {
            return make_error(StatusCode::IoError,
                              "probing '" + path.string() + "' failed: " + ec.message());
        }
        if (!std::filesystem::is_directory(path, ec) || ec) {
            return make_error(StatusCode::InvalidArgument,
                              "'" + path.string() + "' exists but is not a directory");
        }
        return VoidResult{};
    }
    std::filesystem::create_directories(path, ec);
    if (ec) {
        return make_error(StatusCode::IoError,
                          "creating '" + path.string() + "' failed: " + ec.message());
    }
    return VoidResult{};
}

bool exists(const std::filesystem::path& path) noexcept {
    std::error_code ec;
    return std::filesystem::exists(path, ec) && !ec;
}

Result<std::pair<std::uint64_t, std::uint64_t>> directory_bytes(
    const std::filesystem::path& directory, std::uint32_t max_entries) {
    std::uint64_t total = 0;
    std::uint64_t entries = 0;
    std::error_code ec;
    std::filesystem::directory_iterator it(directory, ec);
    if (ec) {
        return make_error(StatusCode::IoError,
                          "cannot enumerate '" + directory.string() + "': " + ec.message());
    }
    for (const auto& entry : it) {
        if (entries >= max_entries) {
            return make_error(StatusCode::LimitExceeded,
                              "state directory holds more than " + std::to_string(max_entries) +
                                  " entries");
        }
        ++entries;
        std::error_code entry_ec;
        if (entry.is_regular_file(entry_ec) && !entry_ec) {
            const auto size = entry.file_size(entry_ec);
            if (!entry_ec) {
                total += static_cast<std::uint64_t>(size);
            }
        }
    }
    return std::make_pair(total, entries);
}

VoidResult restrict_to_owner(const std::filesystem::path& path) {
#if defined(_WIN32)
    (void)path;  // The default DACL on a per-user profile directory already excludes others.
    return VoidResult{};
#else
    if (::chmod(path.c_str(), S_IRUSR | S_IWUSR) != 0) {
        return io_error("restrict permissions on", path);
    }
    return VoidResult{};
#endif
}

FileLock::~FileLock() {
    release();
}

FileLock::FileLock(FileLock&& other) noexcept {
#if defined(_WIN32)
    handle_ = other.handle_;
    other.handle_ = nullptr;
#else
    descriptor_ = other.descriptor_;
    other.descriptor_ = -1;
#endif
}

FileLock& FileLock::operator=(FileLock&& other) noexcept {
    if (this != &other) {
        release();
#if defined(_WIN32)
        handle_ = other.handle_;
        other.handle_ = nullptr;
#else
        descriptor_ = other.descriptor_;
        other.descriptor_ = -1;
#endif
    }
    return *this;
}

bool FileLock::held() const noexcept {
#if defined(_WIN32)
    return handle_ != nullptr;
#else
    return descriptor_ >= 0;
#endif
}

void FileLock::release() noexcept {
#if defined(_WIN32)
    if (handle_ != nullptr) {
        (void)::CloseHandle(static_cast<HANDLE>(handle_));
        handle_ = nullptr;
    }
#else
    if (descriptor_ >= 0) {
        (void)::flock(descriptor_, LOCK_UN);
        (void)::close(descriptor_);
        descriptor_ = -1;
    }
#endif
}

Result<FileLock> FileLock::acquire(const std::filesystem::path& path) {
    FileLock lock;
#if defined(_WIN32)
    // Sharing mode 0 means no other process may open the file at all while this handle lives,
    // and the operating system drops the handle when the process ends.
    HANDLE handle = ::CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                                  OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (handle == INVALID_HANDLE_VALUE) {
        const DWORD error = ::GetLastError();
        if (error == ERROR_SHARING_VIOLATION || error == ERROR_LOCK_VIOLATION) {
            return make_error(StatusCode::AlreadyExists,
                              "another live process already holds the fabric state directory '"
                                  + path.parent_path().string() + "'");
        }
        return make_error(StatusCode::IoError,
                          "cannot take the state directory lock '" + path.string() +
                              "' (error " + std::to_string(error) + ")");
    }
    lock.handle_ = handle;
#else
    const int descriptor = ::open(path.c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (descriptor < 0) {
        return io_error("open lock file", path);
    }
    if (::flock(descriptor, LOCK_EX | LOCK_NB) != 0) {
        (void)::close(descriptor);
        return make_error(StatusCode::AlreadyExists,
                          "another live process already holds the fabric state directory '" +
                              path.parent_path().string() + "'");
    }
    lock.descriptor_ = descriptor;
#endif
    return lock;
}

VoidResult write_atomic(const std::filesystem::path& path, const std::string& content,
                        bool sync) {
    const std::filesystem::path temp = temporary_sibling(path, "write");
    auto file = open_truncate(temp);
    if (!file.ok()) {
        return file.status();
    }
    if (!content.empty()) {
        auto written = write_all(file.value(), content.data(), content.size());
        if (!written.ok()) {
            (void)file.value().close();
            (void)remove_file(temp);
            return written.status();
        }
    }
    if (sync) {
        auto flushed = flush_to_platform(file.value());
        if (!flushed.ok()) {
            (void)file.value().close();
            (void)remove_file(temp);
            return flushed.status();
        }
    }
    auto closed = file.value().close();
    if (!closed.ok()) {
        (void)remove_file(temp);
        return closed.status();
    }
    auto replaced = atomic_replace(temp, path);
    if (!replaced.ok()) {
        (void)remove_file(temp);
        return replaced.status();
    }
    return VoidResult{};
}

}  // namespace pf::fsutil
