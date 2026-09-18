// Priority Fabric -- authoritative network priority classes.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include <filesystem>
#include <fstream>
#include <string>

#include "framework.hpp"
#include "priority_fabric/durability.hpp"
#include "support.hpp"

using namespace pftest;

namespace {

std::filesystem::path journal_path(const Fabric& fabric) {
    return fabric.directory.path() / "state" / pf::DurableLayout::journal_segment_name(0);
}

std::uint64_t file_bytes(const std::filesystem::path& path) {
    std::error_code ec;
    const auto size = std::filesystem::file_size(path, ec);
    return ec ? 0u : static_cast<std::uint64_t>(size);
}

/// Named to avoid an argument-dependent-lookup clash with std::filesystem::resize_file.
void truncate_to(const std::filesystem::path& path, std::uint64_t size) {
    std::error_code ec;
    std::filesystem::resize_file(path, size, ec);
}

void flip_byte(const std::filesystem::path& path, std::uint64_t offset) {
    std::fstream stream(path, std::ios::in | std::ios::out | std::ios::binary);
    stream.seekg(static_cast<std::streamoff>(offset));
    char value = 0;
    stream.read(&value, 1);
    value = static_cast<char>(value ^ 0x5A);
    stream.seekp(static_cast<std::streamoff>(offset));
    stream.write(&value, 1);
}

/// Size on disk of one Commit record: header, fixed payload, authentication tag.
constexpr std::uint64_t kCommitRecordBytes =
    pf::DurableLayout::kRecordHeaderBytes + 8 + pf::Digest::kSize +
    pf::DurableLayout::kRecordMacBytes;

bool build_small_world(Fabric& fabric, std::string_view label) {
    if (!open_fabric(fabric, label)) {
        return false;
    }
    if (!fabric.runtime.define_class(fabric.session, make_class("net.gold", 900)).ok()) {
        return false;
    }
    if (!fabric.runtime.define_class(fabric.session, make_class("net.silver", 500)).ok()) {
        return false;
    }
    if (!fabric.runtime.define_scope(fabric.session, make_scope("root")).ok()) {
        return false;
    }
    if (!fabric.runtime
             .define_subject(fabric.session, pf::SubjectDef{subject_id("tenant.acme")})
             .ok()) {
        return false;
    }
    if (!fabric.runtime
             .assign(fabric.session, make_assignment("a.gold", "tenant.acme", "root", "net.gold"))
             .ok()) {
        return false;
    }
    return true;
}

pf::PriorityQuery acme_query() {
    pf::PriorityQuery query;
    query.subject = subject_id("tenant.acme");
    query.scope = scope_id("root");
    return query;
}

bool reopen(Fabric& fabric, std::string_view label, bool fail_on_degraded = false) {
    pf::FabricRuntime::Options options;
    options.state_dir = fabric.directory.path() / "state";
    options.create_if_missing = false;
    options.instance_boot_id = boot_for(std::string(label) + "/reopen");
    options.fail_on_degraded = fail_on_degraded;
    auto opened = pf::FabricRuntime::open(options);
    if (!opened.ok()) {
        ::pftest::note("reopen failed: " + opened.status().to_string());
        return false;
    }
    fabric.runtime = std::move(opened.value());
    auto session =
        fabric.runtime.grant_authority(publisher_id("test.publisher"), fabric.boot);
    if (!session.ok()) {
        ::pftest::note("re-grant failed: " + session.status().to_string());
        return false;
    }
    fabric.session = session.value();
    return true;
}

}  // namespace

PF_TEST(durability, the_journal_replays_without_a_snapshot) {
    Fabric fabric;
    PF_REQUIRE(build_small_world(fabric, "durability-replay"));
    const pf::StateStats before = fabric.runtime.state_stats();
    PF_CHECK_EQ(before.classes, std::uint64_t{2});
    PF_CHECK_EQ(before.assignments, std::uint64_t{1});
    PF_REQUIRE_OK(fabric.runtime.checkpoint());

    PF_REQUIRE_OK(fabric.runtime.close());
    PF_REQUIRE(reopen(fabric, "durability-replay"));
    const pf::StateStats after = fabric.runtime.state_stats();
    PF_CHECK_EQ(after.classes, before.classes);
    PF_CHECK_EQ(after.scopes, before.scopes);
    PF_CHECK_EQ(after.subjects, before.subjects);
    PF_CHECK_EQ(after.assignments, before.assignments);
    PF_CHECK(after.state_generation.value >= before.state_generation.value);
    PF_CHECK(fabric.runtime.evaluate(acme_query()).outcome == pf::Outcome::Assigned);
}

PF_TEST(durability, a_checkpoint_compacts_the_journal_and_keeps_the_state) {
    Fabric fabric;
    PF_REQUIRE(build_small_world(fabric, "durability-checkpoint"));
    const std::uint64_t journal_before = file_bytes(journal_path(fabric));
    PF_CHECK(journal_before > 0);
    PF_REQUIRE_OK(fabric.runtime.checkpoint());

    const auto segments = [&fabric]() {
        std::uint32_t highest = 0;
        bool found = false;
        for (const auto& entry :
             std::filesystem::directory_iterator(fabric.directory.path() / "state")) {
            std::uint32_t index = 0;
            if (entry.is_regular_file() &&
                pf::DurableLayout::parse_journal_segment_name(entry.path().filename().string(),
                                                              index)) {
                if (!found || index > highest) {
                    highest = index;
                    found = true;
                }
            }
        }
        return found ? highest : 0u;
    };
    PF_CHECK(segments() == 1u);
    PF_CHECK(std::filesystem::exists(fabric.directory.path() / "state" / "snapshot.pfs"));

    PF_REQUIRE_OK(fabric.runtime.close());
    PF_REQUIRE(reopen(fabric, "durability-checkpoint"));
    PF_CHECK(fabric.runtime.evaluate(acme_query()).outcome == pf::Outcome::Assigned);
    const auto report = fabric.runtime.integrity_report();
    if (!report.ok) {
        ::pftest::note("integrity: " + report.detail);
    }
    PF_CHECK(report.ok);
    PF_CHECK(report.health == pf::Health::Healthy);
}

PF_TEST(durability, an_uncommitted_pending_record_is_rolled_back) {
    Fabric fabric;
    PF_REQUIRE(build_small_world(fabric, "durability-pending"));
    PF_REQUIRE_OK(fabric.runtime.close());

    const std::filesystem::path journal = journal_path(fabric);
    const std::uint64_t size = file_bytes(journal);
    PF_CHECK(size > kCommitRecordBytes);
    // Drop exactly the last Commit record: its Pending record stays durable but unconfirmed,
    // which is precisely the state a crash between the two writes leaves behind.
    truncate_to(journal, size - kCommitRecordBytes);

    PF_REQUIRE(reopen(fabric, "durability-pending"));
    // The subject and both classes were committed earlier; the assignment was not.
    const pf::StateStats stats = fabric.runtime.state_stats();
    PF_CHECK_EQ(stats.classes, std::uint64_t{2});
    PF_CHECK_EQ(stats.assignments, std::uint64_t{0});
    PF_CHECK(fabric.runtime.evaluate(acme_query()).outcome == pf::Outcome::Unknown);
}

PF_TEST(durability, a_torn_tail_is_discarded_and_the_store_stays_healthy) {
    Fabric fabric;
    PF_REQUIRE(build_small_world(fabric, "durability-torn"));
    PF_REQUIRE_OK(fabric.runtime.close());

    const std::filesystem::path journal = journal_path(fabric);
    const std::uint64_t size = file_bytes(journal);
    truncate_to(journal, size - 7);  // a half-written record

    PF_REQUIRE(reopen(fabric, "durability-torn", /*fail_on_degraded=*/true));
    PF_CHECK(fabric.runtime.health() == pf::Health::Healthy);
    // The truncated commit is gone, so the assignment is not authoritative, but everything
    // that was committed before it is.
    const pf::StateStats stats = fabric.runtime.state_stats();
    PF_CHECK_EQ(stats.classes, std::uint64_t{2});
}

PF_TEST(durability, a_corrupt_payload_is_detected_and_degrades_the_store) {
    Fabric fabric;
    PF_REQUIRE(build_small_world(fabric, "durability-corrupt"));
    PF_REQUIRE_OK(fabric.runtime.close());

    // Flip a byte inside the first record's payload: the framing checksum must catch it.
    flip_byte(journal_path(fabric), pf::DurableLayout::kRecordHeaderBytes + 4);

    pf::FabricRuntime::Options options;
    options.state_dir = fabric.directory.path() / "state";
    options.instance_boot_id = boot_for("durability-corrupt/reopen");
    {
        auto opened = pf::FabricRuntime::open(options);
        PF_REQUIRE_OK(opened);
        pf::FabricRuntime& degraded = opened.value();
        PF_CHECK(degraded.health() == pf::Health::Degraded);

        const pf::PriorityDecision decision = degraded.evaluate(acme_query());
        PF_CHECK(decision.outcome == pf::Outcome::Rejected);
        PF_CHECK_EQ(decision.reason_code, std::string("state_degraded"));

        auto session = degraded.grant_authority(publisher_id("test.publisher"),
                                                boot_for("durability-corrupt"));
        PF_CHECK(!session.ok());
        PF_REQUIRE_OK(degraded.close());
    }

    // fail_on_degraded turns the same store into a refusal to open at all.
    pf::FabricRuntime::Options strict_options = options;
    strict_options.fail_on_degraded = true;
    auto strict = pf::FabricRuntime::open(strict_options);
    PF_REQUIRE_FAILS(strict, pf::StatusCode::Degraded);
}

PF_TEST(durability, authentication_catches_a_record_rewritten_with_a_valid_checksum) {
    Fabric fabric;
    PF_REQUIRE(build_small_world(fabric, "durability-tamper"));
    PF_REQUIRE_OK(fabric.runtime.close());

    const std::filesystem::path journal = journal_path(fabric);
    const std::uint64_t size = file_bytes(journal);
    // The authentication tag lives at the very end of the record and is not covered by the
    // framing checksum, so damaging it exercises the keyed check on its own.
    flip_byte(journal, size - 3);

    pf::FabricRuntime::Options options;
    options.state_dir = fabric.directory.path() / "state";
    options.instance_boot_id = boot_for("durability-tamper/reopen");
    auto opened = pf::FabricRuntime::open(options);
    PF_REQUIRE_OK(opened);
    fabric.runtime = std::move(opened.value());
    PF_CHECK(fabric.runtime.health() == pf::Health::Degraded);
    PF_CHECK(fabric.runtime.health_detail().find("authentication") != std::string::npos);
}

PF_TEST(durability, a_store_without_its_key_is_refused) {
    Fabric fabric;
    PF_REQUIRE(build_small_world(fabric, "durability-nokey"));
    PF_REQUIRE_OK(fabric.runtime.close());
    std::error_code ec;
    std::filesystem::remove(fabric.directory.path() / "state" / pf::DurableLayout::kKeyName, ec);
    PF_CHECK(!ec);

    pf::FabricRuntime::Options options;
    options.state_dir = fabric.directory.path() / "state";
    auto opened = pf::FabricRuntime::open(options);
    PF_REQUIRE_FAILS(opened, pf::StatusCode::NotFound);
}

PF_TEST(durability, a_damaged_manifest_is_refused) {
    Fabric fabric;
    PF_REQUIRE(build_small_world(fabric, "durability-manifest"));
    PF_REQUIRE_OK(fabric.runtime.close());
    flip_byte(fabric.directory.path() / "state" / pf::DurableLayout::kManifestName, 8);

    pf::FabricRuntime::Options options;
    options.state_dir = fabric.directory.path() / "state";
    auto opened = pf::FabricRuntime::open(options);
    PF_REQUIRE_FAILS(opened, pf::StatusCode::IntegrityFailure);
}

PF_TEST(durability, a_damaged_snapshot_is_refused) {
    Fabric fabric;
    PF_REQUIRE(build_small_world(fabric, "durability-snapshot"));
    PF_REQUIRE_OK(fabric.runtime.checkpoint());
    PF_REQUIRE_OK(fabric.runtime.close());
    flip_byte(fabric.directory.path() / "state" / pf::DurableLayout::kSnapshotName, 60);

    pf::FabricRuntime::Options options;
    options.state_dir = fabric.directory.path() / "state";
    auto opened = pf::FabricRuntime::open(options);
    PF_REQUIRE_FAILS(opened, pf::StatusCode::IntegrityFailure);
}

PF_TEST(durability, journal_records_that_appear_without_a_manifest_are_refused) {
    Fabric fabric;
    PF_REQUIRE(build_small_world(fabric, "durability-nomanifest"));
    PF_REQUIRE_OK(fabric.runtime.close());
    std::error_code ec;
    std::filesystem::remove(fabric.directory.path() / "state" / pf::DurableLayout::kManifestName,
                            ec);
    PF_CHECK(!ec);

    pf::FabricRuntime::Options options;
    options.state_dir = fabric.directory.path() / "state";
    options.create_if_missing = true;
    auto opened = pf::FabricRuntime::open(options);
    PF_REQUIRE_FAILS(opened, pf::StatusCode::Corrupt);
}

PF_TEST(durability, durable_growth_is_bounded) {
    pf::Limits limits;
    limits.max_state_bytes = 20000;
    Fabric fabric;
    PF_REQUIRE(open_fabric(fabric, "durability-growth", limits));
    bool refused = false;
    for (int i = 0; i < 400; ++i) {
        const std::string name = "net.class" + std::to_string(i);
        auto defined = fabric.runtime.define_class(
            fabric.session, make_class(name, 2000u + static_cast<std::uint32_t>(i)));
        if (!defined.ok()) {
            PF_CHECK_EQ(defined.status().code(), pf::StatusCode::LimitExceeded);
            refused = true;
            break;
        }
    }
    PF_CHECK(refused);
    PF_CHECK(fabric.runtime.health() == pf::Health::Healthy);
}

PF_TEST(durability, opening_a_directory_without_a_store_is_refused_unless_asked) {
    ScratchDirectory directory("durability-empty");
    pf::FabricRuntime::Options options;
    options.state_dir = directory.path() / "state";
    options.create_if_missing = false;
    auto opened = pf::FabricRuntime::open(options);
    PF_REQUIRE_FAILS(opened, pf::StatusCode::NotFound);

    options.create_if_missing = true;
    auto created = pf::FabricRuntime::open(options);
    PF_REQUIRE_OK(created);
    PF_CHECK(created.value().health() == pf::Health::Healthy);
}

PF_TEST(durability, integrity_report_matches_a_fresh_replay) {
    Fabric fabric;
    PF_REQUIRE(build_small_world(fabric, "durability-integrity"));
    const auto report = fabric.runtime.integrity_report();
    PF_CHECK(report.ok);
    PF_CHECK_EQ(report.state_generation.value, fabric.runtime.state_generation().value);
    PF_CHECK(report.records_applied > 0);
    PF_CHECK(report.records_rejected == 0);
    PF_CHECK(!report.state_digest.is_zero());
    PF_CHECK_EQ(report.epoch.value, fabric.runtime.epoch().value);
}

PF_TEST(durability, refusals_are_audited_in_memory_but_never_extend_the_journal) {
    Fabric fabric;
    PF_REQUIRE(build_small_world(fabric, "durability-audit"));
    const std::uint64_t before = file_bytes(journal_path(fabric));
    for (int i = 0; i < 50; ++i) {
        (void)fabric.runtime.assign(
            fabric.session,
            make_assignment("a.rejected." + std::to_string(i), "tenant.ghost", "root",
                            "net.gold"));
    }
    PF_CHECK_EQ(file_bytes(journal_path(fabric)), before);
    const auto audit = fabric.runtime.audit(200);
    PF_CHECK(!audit.empty());
    bool saw_rejection = false;
    for (const auto& entry : audit) {
        if (entry.result != pf::StatusCode::Ok) {
            saw_rejection = true;
        }
    }
    PF_CHECK(saw_rejection);
    std::uint64_t rejections = 0;
    for (const auto& entry : audit) {
        if (entry.result == pf::StatusCode::NotFound) {
            ++rejections;
        }
    }
    PF_CHECK_EQ(rejections, std::uint64_t{50});
}
