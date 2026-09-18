// Priority Fabric -- authoritative network priority classes.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "process.hpp"

#include <chrono>
#include <fstream>
#include <functional>
#include <sstream>
#include <thread>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <csignal>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace pftest {

#if defined(_WIN32)
namespace {

/// Quotes one argument the way the C runtime's command line parser expects.
std::wstring quote_argument(const std::wstring& argument) {
    if (!argument.empty() &&
        argument.find_first_of(L" \t\n\v\"") == std::wstring::npos) {
        return argument;
    }
    std::wstring quoted;
    quoted.push_back(L'"');
    for (std::size_t i = 0; i < argument.size();) {
        std::size_t backslashes = 0;
        while (i < argument.size() && argument[i] == L'\\') {
            ++i;
            ++backslashes;
        }
        if (i == argument.size()) {
            quoted.append(backslashes * 2, L'\\');
            break;
        }
        if (argument[i] == L'"') {
            quoted.append(backslashes * 2 + 1, L'\\');
            quoted.push_back(L'"');
        } else {
            quoted.append(backslashes, L'\\');
            quoted.push_back(argument[i]);
        }
        ++i;
    }
    quoted.push_back(L'"');
    return quoted;
}

}  // namespace
#endif

ChildProcess::~ChildProcess() {
    if (!reaped_) {
        kill();
        (void)wait();
    }
}

ChildProcess::ChildProcess(ChildProcess&& other) noexcept
    : handle_(other.handle_),
      os_pid_(other.os_pid_),
      pid_(other.pid_),
      exit_code_(other.exit_code_),
      reaped_(other.reaped_),
      log_(std::move(other.log_)) {
#if defined(_WIN32)
    other.handle_ = nullptr;
    other.os_pid_ = 0;
#else
    other.os_pid_ = -1;
#endif
    other.reaped_ = true;
}

ChildProcess& ChildProcess::operator=(ChildProcess&& other) noexcept {
    if (this != &other) {
        if (!reaped_) {
            kill();
            (void)wait();
        }
#if defined(_WIN32)
        handle_ = other.handle_;
        os_pid_ = other.os_pid_;
        other.handle_ = nullptr;
        other.os_pid_ = 0;
#else
        os_pid_ = other.os_pid_;
        other.os_pid_ = -1;
#endif
        pid_ = other.pid_;
        exit_code_ = other.exit_code_;
        reaped_ = other.reaped_;
        log_ = std::move(other.log_);
        other.reaped_ = true;
    }
    return *this;
}

pf::Result<ChildProcess> ChildProcess::spawn(const std::filesystem::path& executable,
                                             const std::vector<std::string>& arguments,
                                             const std::filesystem::path& log) {
    if (!std::filesystem::exists(executable)) {
        return pf::make_error(pf::StatusCode::NotFound,
                              "the child executable '" + executable.string() + "' does not exist");
    }
    ChildProcess child;
    child.log_ = log;

#if defined(_WIN32)
    SECURITY_ATTRIBUTES attributes{};
    attributes.nLength = sizeof(attributes);
    attributes.bInheritHandle = TRUE;
    HANDLE log_handle = ::CreateFileW(log.c_str(), GENERIC_WRITE, FILE_SHARE_READ, &attributes,
                                      CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (log_handle == INVALID_HANDLE_VALUE) {
        return pf::make_error(pf::StatusCode::IoError,
                              "cannot open the child log '" + log.string() + "'");
    }

    std::wstring command = quote_argument(executable.wstring());
    for (const auto& argument : arguments) {
        command.push_back(L' ');
        command.append(quote_argument(std::wstring(argument.begin(), argument.end())));
    }

    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdOutput = log_handle;
    startup.hStdError = log_handle;
    startup.hStdInput = ::GetStdHandle(STD_INPUT_HANDLE);

    PROCESS_INFORMATION info{};
    std::wstring mutable_command = command;
    const BOOL created = ::CreateProcessW(nullptr, mutable_command.data(), nullptr, nullptr, TRUE,
                                          CREATE_NO_WINDOW, nullptr, nullptr, &startup, &info);
    (void)::CloseHandle(log_handle);
    if (created == 0) {
        return pf::make_error(pf::StatusCode::Internal,
                              "CreateProcess failed with error " +
                                  std::to_string(::GetLastError()) + " for '" +
                                  executable.string() + "'");
    }
    (void)::CloseHandle(info.hThread);
    child.handle_ = info.hProcess;
    child.os_pid_ = info.dwProcessId;
    child.pid_ = info.dwProcessId;
    return child;
#else
    const int log_descriptor =
        ::open(log.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (log_descriptor < 0) {
        return pf::make_error(pf::StatusCode::IoError, "cannot open the child log");
    }
    std::vector<std::string> storage;
    storage.push_back(executable.string());
    for (const auto& argument : arguments) {
        storage.push_back(argument);
    }
    std::vector<char*> argv;
    for (auto& item : storage) {
        argv.push_back(item.data());
    }
    argv.push_back(nullptr);

    const pid_t pid = ::fork();
    if (pid < 0) {
        ::close(log_descriptor);
        return pf::make_error(pf::StatusCode::Internal, "fork failed");
    }
    if (pid == 0) {
        (void)::dup2(log_descriptor, STDOUT_FILENO);
        (void)::dup2(log_descriptor, STDERR_FILENO);
        ::close(log_descriptor);
        ::execv(argv[0], argv.data());
        ::_exit(127);
    }
    ::close(log_descriptor);
    child.os_pid_ = pid;
    child.pid_ = static_cast<std::uint64_t>(pid);
    return child;
#endif
}

bool ChildProcess::running() const noexcept {
#if defined(_WIN32)
    if (handle_ == nullptr) {
        return false;
    }
    return ::WaitForSingleObject(static_cast<HANDLE>(handle_), 0) == WAIT_TIMEOUT;
#else
    if (os_pid_ <= 0) {
        return false;
    }
    int status = 0;
    const pid_t result = ::waitpid(os_pid_, &status, WNOHANG);
    return result == 0;
#endif
}

void ChildProcess::reap() {
    if (reaped_) {
        return;
    }
#if defined(_WIN32)
    if (handle_ != nullptr) {
        DWORD code = 0;
        (void)::GetExitCodeProcess(static_cast<HANDLE>(handle_), &code);
        exit_code_ = static_cast<int>(code);
        (void)::CloseHandle(static_cast<HANDLE>(handle_));
        handle_ = nullptr;
    }
#else
    if (os_pid_ > 0) {
        int status = 0;
        (void)::waitpid(os_pid_, &status, 0);
        if (WIFEXITED(status)) {
            exit_code_ = WEXITSTATUS(status);
        } else if (WIFSIGNALED(status)) {
            exit_code_ = 128 + WTERMSIG(status);
        } else {
            exit_code_ = -1;
        }
        os_pid_ = -1;
    }
#endif
    reaped_ = true;
}

int ChildProcess::wait() {
    if (reaped_) {
        return exit_code_;
    }
#if defined(_WIN32)
    if (handle_ != nullptr) {
        (void)::WaitForSingleObject(static_cast<HANDLE>(handle_), INFINITE);
    }
#endif
    reap();
    return exit_code_;
}

void ChildProcess::kill() {
    if (reaped_) {
        return;
    }
#if defined(_WIN32)
    if (handle_ != nullptr) {
        (void)::TerminateProcess(static_cast<HANDLE>(handle_), 0xDEADu);
        (void)::WaitForSingleObject(static_cast<HANDLE>(handle_), INFINITE);
    }
#else
    if (os_pid_ > 0) {
        (void)::kill(os_pid_, SIGKILL);
    }
#endif
    reap();
}

std::string ChildProcess::output() const {
    std::ifstream stream(log_, std::ios::binary);
    if (!stream) {
        return {};
    }
    std::ostringstream buffer;
    buffer << stream.rdbuf();
    return buffer.str();
}

bool wait_until(const std::function<bool()>& predicate, std::uint32_t attempts,
                std::uint32_t delay_ms) {
    for (std::uint32_t attempt = 0; attempt < attempts; ++attempt) {
        if (predicate()) {
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(delay_ms));
    }
    return predicate();
}

bool file_ready(const std::filesystem::path& path) {
    std::error_code ec;
    return std::filesystem::exists(path, ec) && !ec &&
           std::filesystem::file_size(path, ec) > 0 && !ec;
}

std::vector<std::string> read_lines(const std::filesystem::path& path) {
    std::vector<std::string> lines;
    std::ifstream stream(path, std::ios::binary);
    std::string line;
    while (std::getline(stream, line)) {
        while (!line.empty() && (line.back() == '\r' || line.back() == '\n')) {
            line.pop_back();
        }
        lines.push_back(line);
    }
    return lines;
}

std::string find_value(const std::vector<std::string>& lines, const std::string& key) {
    const std::string prefix = key + "=";
    for (const auto& line : lines) {
        std::size_t position = line.find(prefix);
        while (position != std::string::npos) {
            const bool at_boundary = position == 0 || line[position - 1] == ' ';
            if (at_boundary) {
                const std::size_t start = position + prefix.size();
                const std::size_t end = line.find(' ', start);
                return line.substr(start, end == std::string::npos ? std::string::npos
                                                                  : end - start);
            }
            position = line.find(prefix, position + 1);
        }
    }
    return {};
}

}  // namespace pftest
