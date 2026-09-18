// Priority Fabric -- authoritative network priority classes.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include <iostream>
#include <string>

#include "../framework.hpp"
#include "priority_fabric/version.hpp"

int main(int argc, char** argv) {
    std::string only_case;
    for (int i = 1; i < argc; ++i) {
        const std::string argument(argv[i]);
        if (argument == "--case" && i + 1 < argc) {
            only_case = argv[++i];
        } else if (argument == "--list") {
            for (const auto& test : pftest::registry()) {
                std::cout << test.suite << "." << test.name << "\n";
            }
            return 0;
        }
    }
    std::cout << "priority fabric " << pf::version_string()
              << " multiprocess test runner\n";
    return pftest::run("multiprocess", only_case);
}
