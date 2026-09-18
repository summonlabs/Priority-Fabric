// Priority Fabric -- authoritative network priority classes.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include <cstring>
#include <iostream>
#include <string>

#include "framework.hpp"
#include "priority_fabric/version.hpp"

int main(int argc, char** argv) {
    std::string suite;
    std::string only_case;
    bool list = false;

    for (int i = 1; i < argc; ++i) {
        const std::string argument(argv[i]);
        if (argument == "--suite" && i + 1 < argc) {
            suite = argv[++i];
        } else if (argument == "--case" && i + 1 < argc) {
            only_case = argv[++i];
        } else if (argument == "--list") {
            list = true;
        } else if (argument == "--version") {
            std::cout << "priority fabric " << pf::version_string() << "\n";
            return 0;
        } else {
            std::cerr << "unknown argument: " << argument << "\n";
            return 2;
        }
    }

    if (list) {
        for (const auto& test : pftest::registry()) {
            std::cout << test.suite << "." << test.name << "\n";
        }
        return 0;
    }

    std::cout << "priority fabric " << pf::version_string() << " test runner\n";
    return pftest::run(suite, only_case);
}
