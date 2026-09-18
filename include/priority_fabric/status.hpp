// Priority Fabric -- authoritative network priority classes.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#ifndef PRIORITY_FABRIC_STATUS_HPP
#define PRIORITY_FABRIC_STATUS_HPP

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

#include "priority_fabric/export.hpp"

namespace pf {

/// Machine-readable failure classification. Every rejection the fabric can produce maps
/// to exactly one of these; the human-readable text is supplementary.
enum class StatusCode : std::uint16_t {
    Ok = 0,
    InvalidArgument = 1,
    MalformedId = 2,
    NotFound = 3,
    AlreadyExists = 4,
    DuplicatePrecedence = 5,
    CycleDetected = 6,
    GenerationMismatch = 7,
    StaleGeneration = 8,
    StaleEpoch = 9,
    Fenced = 10,
    Unauthorized = 11,
    Conflict = 12,
    LimitExceeded = 13,
    Overflow = 14,
    Corrupt = 15,
    Truncated = 16,
    IntegrityFailure = 17,
    IoError = 18,
    Unsupported = 19,
    NotReady = 20,
    Degraded = 21,
    Cancelled = 22,
    Internal = 23,
    TransportError = 24,
    ProtocolError = 25,
    BoundaryViolation = 26,
};

/// Stable, lowercase, machine-stable name for a status code.
[[nodiscard]] PF_API const char* to_string(StatusCode code) noexcept;

/// A status is either Ok with no detail, or a failure with a code and bounded message.
class PF_API Status {
public:
    Status() = default;

    static Status success() { return Status{}; }

    static Status failure(StatusCode code, std::string_view message);

    [[nodiscard]] bool ok() const noexcept { return code_ == StatusCode::Ok; }
    [[nodiscard]] explicit operator bool() const noexcept { return ok(); }
    [[nodiscard]] StatusCode code() const noexcept { return code_; }
    [[nodiscard]] const std::string& message() const noexcept { return message_; }
    [[nodiscard]] std::string to_string() const;

private:
    StatusCode code_ = StatusCode::Ok;
    std::string message_;
};

/// Status-or-value. A failed Result never carries a value.
template <typename T>
class Result {
public:
    Result(T value) : value_(std::move(value)) {}          // NOLINT(google-explicit-constructor)
    Result(Status status) : status_(std::move(status)) {}  // NOLINT(google-explicit-constructor)

    [[nodiscard]] bool ok() const noexcept { return status_.ok(); }
    [[nodiscard]] explicit operator bool() const noexcept { return ok(); }

    [[nodiscard]] const Status& status() const noexcept { return status_; }

    [[nodiscard]] const T& value() const& { return value_.value(); }
    [[nodiscard]] T& value() & { return value_.value(); }
    [[nodiscard]] T&& value() && { return std::move(value_.value()); }

    [[nodiscard]] const T* operator->() const { return &value_.value(); }
    [[nodiscard]] T* operator->() { return &value_.value(); }
    [[nodiscard]] const T& operator*() const& { return value_.value(); }
    [[nodiscard]] T& operator*() & { return value_.value(); }

    /// The value when the call succeeded, \p fallback otherwise.
    template <typename U>
    [[nodiscard]] T value_or(U&& fallback) const& {
        return value_.has_value() ? *value_ : static_cast<T>(std::forward<U>(fallback));
    }

private:
    std::optional<T> value_;
    Status status_;
};

/// Status for operations with no value.
class PF_API VoidResult {
public:
    VoidResult() = default;
    VoidResult(Status status) : status_(std::move(status)) {}  // NOLINT(google-explicit-constructor)

    [[nodiscard]] bool ok() const noexcept { return status_.ok(); }
    [[nodiscard]] explicit operator bool() const noexcept { return ok(); }
    [[nodiscard]] const Status& status() const noexcept { return status_; }

private:
    Status status_;
};

// ---- convenience constructors -------------------------------------------------------

/// Builds a failure status. The message is bounded before it is stored.
[[nodiscard]] PF_API Status make_error(StatusCode code, std::string_view message);

}  // namespace pf

#endif  // PRIORITY_FABRIC_STATUS_HPP
