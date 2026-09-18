// Priority Fabric -- authoritative network priority classes.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// A deliberately small test harness. It registers named cases, runs the ones a suite asks
// for, prints a machine-readable summary line and returns a non-zero exit code on any
// failure. There are no timeouts anywhere: a test that hangs is a defect to diagnose, not
// something to be cut short.

#ifndef PRIORITY_FABRIC_TESTS_FRAMEWORK_HPP
#define PRIORITY_FABRIC_TESTS_FRAMEWORK_HPP

#include <cstdint>
#include <exception>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "priority_fabric/status.hpp"

namespace pftest {

using TestBody = void (*)();

struct TestCase {
    std::string suite;
    std::string name;
    TestBody body;
};

inline std::vector<TestCase>& registry() {
    static std::vector<TestCase> cases;
    return cases;
}

inline std::uint64_t& checks() {
    static std::uint64_t value = 0;
    return value;
}

inline std::uint64_t& failures() {
    static std::uint64_t value = 0;
    return value;
}

inline std::string& current_case() {
    static std::string value;
    return value;
}

struct Registrar {
    Registrar(const char* suite, const char* name, TestBody body) {
        registry().push_back(TestCase{suite, name, body});
    }
};

/// Failures printed for the current case. A property that breaks on every iteration would
/// otherwise bury the one line that matters.
constexpr std::uint64_t kMaxPrintedFailuresPerCase = 5;

inline std::uint64_t& printed_for_case() {
    static std::uint64_t value = 0;
    return value;
}

inline void report_failure(const char* file, int line, const std::string& message) {
    ++failures();
    if (printed_for_case() >= kMaxPrintedFailuresPerCase) {
        return;
    }
    if (printed_for_case() + 1 == kMaxPrintedFailuresPerCase) {
        std::cout << "  FAIL " << current_case() << "\n    (further failures in this case are "
                     "suppressed)\n";
    }
    ++printed_for_case();
    std::cout << "  FAIL " << current_case() << "\n    " << file << ":" << line << "\n    "
              << message << "\n";
}

inline void note(const std::string& message) {
    std::cout << "  note " << current_case() << ": " << message << "\n";
}

/// Runs every registered case whose suite matches \p suite, or every case when \p suite is
/// empty or "*". Returns the number of failures.
inline int run(const std::string& suite, const std::string& only_case) {
    int executed = 0;
    for (const auto& test : registry()) {
        if (!suite.empty() && suite != "*" && test.suite != suite) {
            continue;
        }
        if (!only_case.empty() && test.name != only_case) {
            continue;
        }
        current_case() = test.suite + "." + test.name;
        printed_for_case() = 0;
        ++executed;
        try {
            test.body();
        } catch (const std::exception& error) {
            report_failure(__FILE__, __LINE__,
                           std::string("uncaught exception: ") + error.what());
        } catch (...) {
            report_failure(__FILE__, __LINE__, "uncaught non-standard exception");
        }
    }
    std::cout << "SUMMARY suite=" << (suite.empty() ? "*" : suite) << " cases=" << executed
              << " checks=" << checks() << " failures=" << failures() << "\n";
    if (executed == 0) {
        std::cout << "  FAIL no test matched suite '" << suite << "'\n";
        return 1;
    }
    return static_cast<int>(failures());
}

inline std::string describe(const pf::Status& status) {
    return status.to_string();
}

}  // namespace pftest

#define PF_TEST(suite_name, case_name)                                                   \
    static void suite_name##_##case_name##_body();                                       \
    static const ::pftest::Registrar suite_name##_##case_name##_registrar(               \
        #suite_name, #case_name, &suite_name##_##case_name##_body);                      \
    static void suite_name##_##case_name##_body()

#define PF_CHECK(condition)                                                              \
    do {                                                                                 \
        ++::pftest::checks();                                                            \
        if (!(condition)) {                                                              \
            ::pftest::report_failure(__FILE__, __LINE__, "CHECK failed: " #condition);   \
        }                                                                                \
    } while (false)

#define PF_REQUIRE(condition)                                                            \
    do {                                                                                 \
        ++::pftest::checks();                                                            \
        if (!(condition)) {                                                              \
            ::pftest::report_failure(__FILE__, __LINE__, "REQUIRE failed: " #condition); \
            return;                                                                      \
        }                                                                                \
    } while (false)

#define PF_CHECK_EQ(actual, expected)                                                    \
    do {                                                                                 \
        ++::pftest::checks();                                                            \
        const auto& pf_actual = (actual);                                                \
        const auto& pf_expected = (expected);                                            \
        if (!(pf_actual == pf_expected)) {                                               \
            std::ostringstream pf_stream;                                                \
            pf_stream << "CHECK_EQ failed: " #actual " == " #expected;                   \
            ::pftest::report_failure(__FILE__, __LINE__, pf_stream.str());               \
        }                                                                                \
    } while (false)

#define PF_CHECK_NE(actual, unexpected)                                                  \
    do {                                                                                 \
        ++::pftest::checks();                                                            \
        const auto& pf_actual = (actual);                                                \
        const auto& pf_unexpected = (unexpected);                                        \
        if (pf_actual == pf_unexpected) {                                                \
            ::pftest::report_failure(__FILE__, __LINE__,                                 \
                                     "CHECK_NE failed: " #actual " != " #unexpected);    \
        }                                                                                \
    } while (false)

/// Requires that a Result succeeded, reporting its status otherwise.
#define PF_REQUIRE_OK(expr)                                                              \
    do {                                                                                 \
        ++::pftest::checks();                                                            \
        const auto& pf_result = (expr);                                                  \
        if (!pf_result.ok()) {                                                           \
            ::pftest::report_failure(__FILE__, __LINE__,                                 \
                                     "expected success from " #expr " but got: " +       \
                                         pf_result.status().to_string());                \
            return;                                                                      \
        }                                                                                \
    } while (false)

#define PF_REQUIRE_FAILS(expr, expected_code)                                            \
    do {                                                                                 \
        ++::pftest::checks();                                                            \
        const auto& pf_result = (expr);                                                  \
        if (pf_result.ok()) {                                                            \
            ::pftest::report_failure(__FILE__, __LINE__,                                 \
                                     "expected failure from " #expr " but it succeeded");\
            return;                                                                      \
        }                                                                                \
        if (pf_result.status().code() != (expected_code)) {                              \
            ::pftest::report_failure(                                                    \
                __FILE__, __LINE__,                                                      \
                "expected " #expr " to fail with " #expected_code " but it failed with " +\
                    std::string(pf::to_string(pf_result.status().code())) + " (" +       \
                    pf_result.status().message() + ")");                                 \
            return;                                                                      \
        }                                                                                \
    } while (false)

#endif  // PRIORITY_FABRIC_TESTS_FRAMEWORK_HPP
