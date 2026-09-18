// Priority Fabric -- authoritative network priority classes.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Spawning real operating-system processes. Child output goes to a file rather than a pipe:
// a pipe would have to be drained by a thread and would deadlock the moment the child wrote
// more than the pipe buffer holds.

#ifndef PRIORITY_FABRIC_TESTS_MULTIPROCESS_PROCESS_HPP
#define PRIORITY_FABRIC_TESTS_MULTIPROCESS_PROCESS_HPP

#include <cstdint>
#include <filesystem>
#include <functional>
#include <string>
#include <vector>

#include "priority_fabric/status.hpp"

namespace pftest {

/// A running (or finished) child process.
class ChildProcess {
public:
    ChildProcess() = default;
    ~ChildProcess();
    ChildProcess(const ChildProcess&) = delete;
    ChildProcess& operator=(const ChildProcess&) = delete;
    ChildProcess(ChildProcess&& other) noexcept;
    ChildProcess& operator=(ChildProcess&& other) noexcept;

    /// Starts \p executable with \p arguments, sending both output streams to \p log.
    [[nodiscard]] static pf::Result<ChildProcess> spawn(const std::filesystem::path& executable,
                                                        const std::vector<std::string>& arguments,
                                                        const std::filesystem::path& log);

    [[nodiscard]] bool running() const noexcept;
    [[nodiscard]] std::uint64_t pid() const noexcept { return pid_; }

    /// Blocks until the child ends and returns its exit code.
    [[nodiscard]] int wait();

    /// Ends the child immediately, the way a crash or an operator's kill would.
    void kill();

    /// Everything the child wrote so far.
    [[nodiscard]] std::string output() const;

private:
    void reap();

#if defined(_WIN32)
    void* handle_ = nullptr;
    std::uint32_t os_pid_ = 0;
#else
    int os_pid_ = -1;
#endif
    std::uint64_t pid_ = 0;
    int exit_code_ = -1;
    bool reaped_ = false;
    std::filesystem::path log_;
};

/// Eventual consistency helper: waits until \p predicate holds. The bound exists to turn a
/// dead peer into a *failure*, never into a pass; it is not a test timeout.
[[nodiscard]] bool wait_until(const std::function<bool()>& predicate, std::uint32_t attempts,
                              std::uint32_t delay_ms);

/// True when a file exists and is non-empty.
[[nodiscard]] bool file_ready(const std::filesystem::path& path);

/// Reads "key=value" lines from a file into a map.
[[nodiscard]] std::vector<std::string> read_lines(const std::filesystem::path& path);

/// Finds the value of "key=..." in the probe or node output. Returns an empty string when the
/// key is absent.
[[nodiscard]] std::string find_value(const std::vector<std::string>& lines,
                                     const std::string& key);

}  // namespace pftest

#endif  // PRIORITY_FABRIC_TESTS_MULTIPROCESS_PROCESS_HPP
