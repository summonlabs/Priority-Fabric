// Priority Fabric -- authoritative network priority classes.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#ifndef PRIORITY_FABRIC_SRC_EVALUATE_HPP
#define PRIORITY_FABRIC_SRC_EVALUATE_HPP

#include "priority_fabric/decision.hpp"
#include "state.hpp"

namespace pf::detail {

/// Answers \p query from \p image. Pure: the image is never modified, so two calls with the
/// same inputs produce byte-identical decisions.
[[nodiscard]] PriorityDecision evaluate_query(const StateImage& image,
                                              const PriorityQuery& query);

}  // namespace pf::detail

#endif  // PRIORITY_FABRIC_SRC_EVALUATE_HPP
