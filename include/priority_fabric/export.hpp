// Priority Fabric -- authoritative network priority classes.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#ifndef PRIORITY_FABRIC_EXPORT_HPP
#define PRIORITY_FABRIC_EXPORT_HPP

// The library is usable as a static archive (default) or as a shared library.
// PRIORITY_FABRIC_SHARED is defined by the build system only when the shared
// flavour is selected.
#if defined(_WIN32) && defined(PRIORITY_FABRIC_SHARED)
#if defined(PRIORITY_FABRIC_BUILDING)
#define PF_API __declspec(dllexport)
#else
#define PF_API __declspec(dllimport)
#endif
#else
#define PF_API
#endif

#if defined(__GNUC__) || defined(__clang__)
#define PF_HIDDEN __attribute__((visibility("hidden")))
#else
#define PF_HIDDEN
#endif

// Marks internal linkage helpers that are intentionally part of the public translation
// unit set but not part of the documented API surface.
#define PF_INTERNAL

#endif  // PRIORITY_FABRIC_EXPORT_HPP
