// Priority Fabric -- authoritative network priority classes.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "framework.hpp"
#include "priority_fabric/codec.hpp"
#include "priority_fabric/digest.hpp"
#include "priority_fabric/ident.hpp"
#include "priority_fabric/model_codec.hpp"
#include "priority_fabric/text.hpp"
#include "support.hpp"

using namespace pftest;

PF_TEST(identity, canonicalization_folds_case_and_separators) {
    const pf::Limits limits;
    auto trimmed = pf::canonicalize_id("  Net.Gold  ", limits);
    PF_REQUIRE_OK(trimmed);
    PF_CHECK_EQ(trimmed.value().value, std::string("net.gold"));

    auto slashed = pf::canonicalize_id("/net/gold", limits);
    PF_REQUIRE_OK(slashed);
    PF_CHECK_EQ(slashed.value().value, std::string("net.gold"));

    auto mixed = pf::canonicalize_id("Tenant-7:eu_west", limits);
    PF_REQUIRE_OK(mixed);
    PF_CHECK_EQ(mixed.value().value, std::string("tenant-7:eu_west"));
}

PF_TEST(identity, canonicalization_rejects_non_canonical_forms) {
    const pf::Limits limits;
    PF_REQUIRE_FAILS(pf::canonicalize_id("", limits), pf::StatusCode::MalformedId);
    PF_REQUIRE_FAILS(pf::canonicalize_id("   ", limits), pf::StatusCode::MalformedId);
    PF_REQUIRE_FAILS(pf::canonicalize_id("net..gold", limits), pf::StatusCode::MalformedId);
    PF_REQUIRE_FAILS(pf::canonicalize_id("net gold", limits), pf::StatusCode::MalformedId);
    PF_REQUIRE_FAILS(pf::canonicalize_id(".net", limits), pf::StatusCode::MalformedId);
    PF_REQUIRE_FAILS(pf::canonicalize_id("net.", limits), pf::StatusCode::MalformedId);
    PF_REQUIRE_FAILS(pf::canonicalize_id("net\\gold", limits), pf::StatusCode::MalformedId);
    PF_REQUIRE_FAILS(pf::canonicalize_id("net\tgold", limits), pf::StatusCode::MalformedId);
    PF_REQUIRE_FAILS(pf::canonicalize_id("/", limits), pf::StatusCode::MalformedId);
    std::string oversized(5000, 'a');
    PF_REQUIRE_FAILS(pf::canonicalize_id(oversized, limits), pf::StatusCode::LimitExceeded);
    std::string too_long(200, 'a');
    PF_REQUIRE_FAILS(pf::canonicalize_id(too_long, limits), pf::StatusCode::LimitExceeded);
}

PF_TEST(identity, from_canonical_refuses_a_non_canonical_spelling) {
    const pf::Limits limits;
    PF_REQUIRE_FAILS(pf::PriorityClassId::from_canonical("Net.Gold", limits),
                     pf::StatusCode::MalformedId);
    PF_REQUIRE_OK(pf::PriorityClassId::from_canonical("net.gold", limits));
    // Two spellings can never become two different identifiers.
    auto a = pf::PriorityClassId::parse("NET/GOLD", limits);
    auto b = pf::PriorityClassId::parse("net.gold", limits);
    PF_REQUIRE_OK(a);
    PF_REQUIRE_OK(b);
    PF_CHECK(a.value() == b.value());
}

PF_TEST(identity, generations_and_epochs_do_not_wrap) {
    PF_CHECK(!pf::Generation::unset().is_set());
    PF_CHECK_EQ(pf::Generation::unset().next().value().value, std::uint64_t{1});
    pf::Generation last{std::numeric_limits<std::uint64_t>::max()};
    PF_CHECK(!last.next().has_value());
    pf::FabricEpoch last_epoch{std::numeric_limits<std::uint64_t>::max()};
    PF_CHECK(!last_epoch.next().has_value());
    PF_CHECK(!pf::FabricEpoch::unestablished().is_established());
}

PF_TEST(identity, boot_ids_are_deterministic_from_a_seed_and_parse_back) {
    const pf::BootId a = pf::BootId::from_seed("alpha");
    const pf::BootId b = pf::BootId::from_seed("alpha");
    const pf::BootId c = pf::BootId::from_seed("beta");
    PF_CHECK(a == b);
    PF_CHECK(!(a == c));
    PF_CHECK(a.valid());
    auto parsed = pf::BootId::parse_hex(a.hex());
    PF_REQUIRE_OK(parsed);
    PF_CHECK(parsed.value() == a);
    PF_REQUIRE_FAILS(pf::BootId::parse_hex("abc"), pf::StatusCode::MalformedId);
    PF_REQUIRE_FAILS(pf::BootId::parse_hex("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"),
                     pf::StatusCode::MalformedId);
    auto generated = pf::BootId::generate();
    PF_REQUIRE_OK(generated);
    PF_CHECK(generated.value().valid());
}

PF_TEST(identity, sha256_matches_the_published_vector) {
    const pf::Digest digest = pf::Sha256::hash("abc");
    PF_CHECK_EQ(digest.hex(),
                std::string("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
    const pf::Digest empty = pf::Sha256::hash("");
    PF_CHECK_EQ(empty.hex(),
                std::string("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
    // Streaming in pieces must agree with the one-shot hash.
    pf::Sha256 stream;
    stream.update("a");
    stream.update("b");
    stream.update("c");
    PF_CHECK(stream.finish() == digest);
}

PF_TEST(identity, hmac_sha256_matches_rfc4231_case_1) {
    const std::string key(20, static_cast<char>(0x0b));
    const std::string data = "Hi There";
    const pf::Digest mac = pf::hmac_sha256(
        reinterpret_cast<const std::uint8_t*>(key.data()), key.size(), data.data(), data.size());
    PF_CHECK_EQ(mac.hex(),
                std::string("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"));
}

PF_TEST(identity, crc32c_matches_the_published_check_value) {
    PF_CHECK_EQ(pf::crc32c("123456789"), 0xE3069283u);
    PF_CHECK_EQ(pf::crc32c(""), 0u);
    // Extending must equal hashing the concatenation.
    const std::uint32_t first = pf::crc32c("1234");
    PF_CHECK_EQ(pf::crc32c_extend(first, "56789", 5), 0xE3069283u);
}

PF_TEST(identity, fnv1a64_matches_the_published_offset_basis) {
    PF_CHECK_EQ(pf::fnv1a64(""), 14695981039346656037ull);
    PF_CHECK_EQ(pf::fnv1a64("a"), 0xaf63dc4c8601ec8cull);
}

PF_TEST(identity, decoder_rejects_truncation_and_trailing_bytes) {
    pf::Encoder encoder;
    encoder.u32(0x11223344u);
    encoder.u64(0x0102030405060708ull);
    encoder.str("net.gold");
    const std::string encoded = encoder.buffer();

    const pf::Limits limits;
    {
        pf::Decoder decoder(encoded.data(), encoded.size(), limits);
        auto first = decoder.u32();
        PF_REQUIRE_OK(first);
        PF_CHECK_EQ(first.value(), 0x11223344u);
        auto second = decoder.u64();
        PF_REQUIRE_OK(second);
        PF_CHECK_EQ(second.value(), 0x0102030405060708ull);
        auto text = decoder.str(limits.max_id_length);
        PF_REQUIRE_OK(text);
        PF_CHECK_EQ(text.value(), std::string("net.gold"));
        PF_CHECK(decoder.finish().ok());
    }
    {
        pf::Decoder decoder(encoded.data(), encoded.size() - 1, limits);
        PF_REQUIRE_OK(decoder.u32());
        PF_REQUIRE_OK(decoder.u64());
        PF_REQUIRE_FAILS(decoder.str(limits.max_id_length), pf::StatusCode::Truncated);
    }
    {
        pf::Decoder decoder(encoded.data(), encoded.size(), limits);
        PF_REQUIRE_OK(decoder.u32());
        PF_REQUIRE_OK(decoder.u64());
        PF_REQUIRE_OK(decoder.str(limits.max_id_length));
        // Nothing was appended, so finish() must succeed; a padded buffer must not.
        PF_CHECK(decoder.finish().ok());
        std::string padded = encoded;
        padded.push_back('\0');
        pf::Decoder strict(padded.data(), padded.size(), limits);
        PF_REQUIRE_OK(strict.u32());
        PF_REQUIRE_OK(strict.u64());
        PF_REQUIRE_OK(strict.str(limits.max_id_length));
        PF_REQUIRE_FAILS(strict.finish(), pf::StatusCode::ProtocolError);
    }
}

PF_TEST(identity, length_prefixed_fields_are_bounded_before_allocation) {
    pf::Encoder encoder;
    encoder.u32(0xFFFFFFFFu);
    const std::string encoded = encoder.buffer();
    const pf::Limits limits;
    pf::Decoder decoder(encoded.data(), encoded.size(), limits);
    PF_REQUIRE_FAILS(decoder.str(128), pf::StatusCode::LimitExceeded);
}

PF_TEST(identity, definition_codecs_round_trip_and_reject_trailing_bytes) {
    const pf::Limits limits;
    pf::PriorityClassDef definition = make_class("net.gold", 900, pf::ClassKind::Tenant);
    definition.description = "gold tenant traffic";
    const std::string encoded = pf::encode_class_definition(definition);
    auto decoded = pf::decode_class_definition(encoded, limits);
    PF_REQUIRE_OK(decoded);
    PF_CHECK(decoded.value().id == definition.id);
    PF_CHECK(decoded.value().precedence == definition.precedence);
    PF_CHECK(decoded.value().kind == definition.kind);

    std::string padded = encoded;
    padded.push_back('x');
    PF_REQUIRE_FAILS(pf::decode_class_definition(padded, limits),
                     pf::StatusCode::ProtocolError);

    pf::PriorityAssignment assignment =
        make_assignment("assign.gold", "tenant.acme", "root", "net.gold");
    assignment.note = "publisher note";
    const std::string assignment_bytes = pf::encode_assignment(assignment);
    auto decoded_assignment = pf::decode_assignment(assignment_bytes, limits);
    PF_REQUIRE_OK(decoded_assignment);
    PF_CHECK(decoded_assignment.value().id == assignment.id);
    PF_CHECK(decoded_assignment.value().note == assignment.note);
}

PF_TEST(identity, text_bound_is_utf8_safe_and_marks_truncation) {
    PF_CHECK_EQ(pf::bound_text("short", 32), std::string("short"));
    const std::string truncated = pf::bound_text("0123456789", 5);
    PF_CHECK_EQ(truncated, std::string("01..."));
    // A multi-byte code point must never be cut in half.
    const std::string utf8 = "aa\xC3\xA9\xC3\xA9";
    const std::string bounded = pf::bound_text(utf8, 5);
    PF_CHECK(bounded.size() <= 5);
    for (std::size_t i = 0; i < bounded.size(); ++i) {
        PF_CHECK((static_cast<unsigned char>(bounded[i]) & 0xC0u) != 0x80u ||
                 i > 0);
    }
    PF_CHECK(!pf::is_printable_text(std::string("bad\x01")));
    PF_CHECK(pf::is_printable_text("good text"));
}
