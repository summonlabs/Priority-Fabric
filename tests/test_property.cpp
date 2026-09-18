// Priority Fabric -- authoritative network priority classes.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Seeded randomized exploration. Every generator is driven by a fixed seed so that a failure
// is reproducible from the seed printed in the failure message. Nothing here is wall-clock
// dependent.

#include <algorithm>
#include <map>
#include <random>
#include <set>
#include <string>
#include <vector>

#include "framework.hpp"
#include "support.hpp"

using namespace pftest;

namespace {

constexpr std::uint64_t kSeed = 0x5F3A2C19D4B7E801ull;

std::string class_name(int index) {
    return "rand.class." + std::to_string(index);
}

std::string scope_name(int index) {
    return "rand.scope." + std::to_string(index);
}

std::string subject_name(int index) {
    return "rand.subject." + std::to_string(index);
}

struct RandomWorld {
    int class_count = 0;
    int scope_count = 0;
    int subject_count = 0;
    std::vector<std::string> classes;
    std::vector<std::string> scopes;
    std::vector<std::string> subjects;
};

/// Builds a random but always valid world: strictly increasing precedence ranks, a scope tree
/// with a bounded depth and a subject tree with a bounded depth.
bool build_random_world(Fabric& fabric, std::uint64_t seed, RandomWorld& world,
                        std::string_view label) {
    std::mt19937_64 engine(seed);
    std::uniform_int_distribution<int> small(1, 4);
    std::uniform_int_distribution<int> medium(2, 8);

    if (!open_fabric(fabric, label)) {
        return false;
    }

    world.class_count = medium(engine);
    std::uint32_t rank = 100;
    for (int i = 0; i < world.class_count; ++i) {
        rank += 10u + static_cast<std::uint32_t>(small(engine) * 7);
        // A chain, so that every ordering pair of classes has a real ancestor relation and a
        // reversed edge is always a cycle rather than a legitimate new edge.
        std::vector<pf::PriorityClassId> parents;
        if (i > 0) {
            parents.push_back(class_id(class_name(i - 1)));
        }
        auto defined = fabric.runtime.define_class(
            fabric.session,
            make_class(class_name(i), rank, static_cast<pf::ClassKind>(i % 4), parents));
        if (!defined.ok()) {
            return false;
        }
        world.classes.push_back(class_name(i));
    }

    world.scope_count = medium(engine);
    for (int i = 0; i < world.scope_count; ++i) {
        std::optional<pf::PolicyScopeId> parent;
        if (i > 0) {
            std::uniform_int_distribution<int> pick(0, i - 1);
            parent = scope_id(scope_name(pick(engine)));
        }
        auto defined = fabric.runtime.define_scope(
            fabric.session, make_scope(scope_name(i), parent, pf::ConflictResolution::Deny));
        if (!defined.ok()) {
            return false;
        }
        world.scopes.push_back(scope_name(i));
    }

    world.subject_count = medium(engine);
    for (int i = 0; i < world.subject_count; ++i) {
        pf::SubjectDef subject;
        subject.id = subject_id(subject_name(i));
        if (i > 0) {
            std::uniform_int_distribution<int> pick(0, i - 1);
            subject.inherits_from.push_back(subject_id(subject_name(pick(engine))));
        }
        auto defined = fabric.runtime.define_subject(fabric.session, subject);
        if (!defined.ok()) {
            return false;
        }
        world.subjects.push_back(subject_name(i));
    }
    return true;
}

pf::PriorityQuery query_for(const RandomWorld& world, int subject, int scope) {
    pf::PriorityQuery query;
    query.subject = subject_id(world.subjects[static_cast<std::size_t>(subject)]);
    query.scope = scope_id(world.scopes[static_cast<std::size_t>(scope)]);
    query.max_explanation_steps = 24;
    return query;
}

}  // namespace

PF_TEST(property, precedence_is_a_strict_total_order) {
    std::mt19937_64 engine(kSeed);
    std::uniform_int_distribution<std::uint32_t> pick(0, pf::PrecedenceRank::kMaxRank);
    std::vector<pf::PrecedenceRank> ranks;
    for (int i = 0; i < 2000; ++i) {
        ranks.push_back(pf::PrecedenceRank::make(pick(engine)));
    }
    for (std::size_t i = 0; i < ranks.size(); ++i) {
        // Irreflexive.
        PF_CHECK(!(ranks[i] < ranks[i]));
        for (std::size_t j = i + 1; j < ranks.size(); j += 97) {
            // Exactly one of < , > or == holds.
            const int relations = (ranks[i] < ranks[j] ? 1 : 0) + (ranks[j] < ranks[i] ? 1 : 0) +
                                  (ranks[i] == ranks[j] ? 1 : 0);
            PF_CHECK_EQ(relations, 1);
            for (std::size_t k = j + 1; k < ranks.size(); k += 211) {
                if (ranks[i] < ranks[j] && ranks[j] < ranks[k]) {
                    PF_CHECK(ranks[i] < ranks[k]);  // transitive
                }
                if (ranks[i] == ranks[j]) {
                    PF_CHECK((ranks[i] < ranks[k]) == (ranks[j] < ranks[k]));
                }
            }
        }
    }
}

PF_TEST(property, ranking_is_identical_whichever_order_the_classes_arrive_in) {
    std::mt19937_64 engine(kSeed ^ 0x1234ull);
    for (int trial = 0; trial < 12; ++trial) {
        RandomWorld world;
        Fabric fabric;
        PF_REQUIRE(build_random_world(fabric, kSeed + static_cast<std::uint64_t>(trial), world,
                                      "property-order"));

        // The same logical assignment set, published in two different orders into two
        // otherwise identical fabrics. Generations necessarily differ; the authoritative
        // answer must not.
        struct Planned {
            std::string id;
            int subject;
            int scope;
            int cls;
        };
        std::vector<std::pair<int, int>> pairs;
        for (int s = 0; s < world.subject_count; ++s) {
            for (int c = 0; c < world.scope_count; ++c) {
                pairs.emplace_back(s, c);
            }
        }
        std::shuffle(pairs.begin(), pairs.end(), engine);

        std::vector<Planned> planned;
        int index = 0;
        for (const auto& pair : pairs) {
            planned.push_back(Planned{"rand.assign." + std::to_string(index), pair.first,
                                      pair.second, index % world.class_count});
            ++index;
        }

        const auto publish_all = [](Fabric& target, const RandomWorld& target_world,
                                    const std::vector<Planned>& plan,
                                    const std::vector<std::size_t>& order) {
            for (std::size_t position : order) {
                const Planned& item = plan[position];
                (void)target.runtime.assign(
                    target.session,
                    make_assignment(item.id,
                                    target_world.subjects[static_cast<std::size_t>(item.subject)],
                                    target_world.scopes[static_cast<std::size_t>(item.scope)],
                                    target_world.classes[static_cast<std::size_t>(item.cls)],
                                    pf::AssignmentKind::Explicit));
            }
        };

        std::vector<std::size_t> forward(planned.size());
        for (std::size_t i = 0; i < planned.size(); ++i) {
            forward[i] = i;
        }
        publish_all(fabric, world, planned, forward);

        std::map<std::string, std::string> answers;
        for (int s = 0; s < world.subject_count; ++s) {
            for (int c = 0; c < world.scope_count; ++c) {
                const pf::PriorityDecision decision = fabric.runtime.evaluate(query_for(world, s, c));
                answers[std::to_string(s) + "/" + std::to_string(c)] =
                    std::string(pf::to_string(decision.outcome)) + ":" + decision.cls.str();
            }
        }

        RandomWorld second_world;
        Fabric second;
        PF_REQUIRE(build_random_world(second, kSeed + static_cast<std::uint64_t>(trial),
                                      second_world, "property-order-b"));
        std::vector<std::size_t> reverse;
        reverse.reserve(planned.size());
        for (std::size_t i = planned.size(); i > 0; --i) {
            reverse.push_back(i - 1);
        }
        publish_all(second, second_world, planned, reverse);

        for (int s = 0; s < second_world.subject_count; ++s) {
            for (int c = 0; c < second_world.scope_count; ++c) {
                const pf::PriorityDecision decision =
                    second.runtime.evaluate(query_for(second_world, s, c));
                const std::string key = std::to_string(s) + "/" + std::to_string(c);
                const auto found = answers.find(key);
                if (found == answers.end()) {
                    continue;
                }
                PF_CHECK_EQ(found->second,
                            std::string(pf::to_string(decision.outcome)) + ":" +
                                decision.cls.str());
            }
        }
    }
}

PF_TEST(property, evaluation_is_deterministic_under_repetition) {
    RandomWorld world;
    Fabric fabric;
    PF_REQUIRE(build_random_world(fabric, kSeed ^ 0xABCDull, world, "property-determinism"));

    int published = 0;
    for (int s = 0; s < world.subject_count; ++s) {
        for (int c = 0; c < world.scope_count; ++c) {
            if (published % 3 == 0) {
                continue;  // leave gaps so that UNKNOWN and inheritance both occur
            }
            (void)fabric.runtime.assign(
                fabric.session,
                make_assignment("rand.assign." + std::to_string(published),
                                world.subjects[static_cast<std::size_t>(s)],
                                world.scopes[static_cast<std::size_t>(c)],
                                world.classes[static_cast<std::size_t>(published %
                                                                       world.class_count)]));
            ++published;
        }
    }

    std::map<std::string, pf::Digest> digests;
    for (int round = 0; round < 5; ++round) {
        for (int s = 0; s < world.subject_count; ++s) {
            for (int c = 0; c < world.scope_count; ++c) {
                const pf::PriorityDecision decision = fabric.runtime.evaluate(query_for(world, s, c));
                const std::string key = std::to_string(s) + "/" + std::to_string(c);
                const auto found = digests.find(key);
                if (found == digests.end()) {
                    digests.emplace(key, decision.digest);
                } else {
                    PF_CHECK(found->second == decision.digest);
                }
                if (decision.outcome == pf::Outcome::Unknown) {
                    PF_CHECK(!decision.authoritative);
                    PF_CHECK(!decision.cls.valid());
                    PF_CHECK(!decision.precedence.is_declared());
                }
                if (decision.authoritative) {
                    PF_CHECK(pf::outcome_carries_authority(decision.outcome));
                    PF_CHECK(decision.cls.valid());
                    PF_CHECK(decision.precedence.is_declared());
                }
            }
        }
    }
}

PF_TEST(property, injected_cycles_are_always_refused) {
    std::mt19937_64 engine(kSeed ^ 0x777ull);
    for (int trial = 0; trial < 30; ++trial) {
        RandomWorld world;
        Fabric fabric;
        PF_REQUIRE(build_random_world(fabric, kSeed + static_cast<std::uint64_t>(trial), world,
                                      "property-cycle"));
        if (world.class_count < 2) {
            continue;
        }
        std::uniform_int_distribution<int> pick(0, world.class_count - 1);
        int ancestor = pick(engine);
        int descendant = pick(engine);
        if (ancestor > descendant) {
            std::swap(ancestor, descendant);
        }
        if (ancestor == descendant) {
            continue;
        }
        // class[descendant] already inherits class[ancestor] transitively; reversing that
        // edge must always be refused.
        std::uint32_t rank = 10u;
        for (const auto& definition : fabric.runtime.list_classes()) {
            rank = std::max(rank, definition.precedence.value);
        }
        auto cyc = fabric.runtime.define_class(
            fabric.session,
            make_class(world.classes[static_cast<std::size_t>(ancestor)], rank + 1u,
                       pf::ClassKind::Standard,
                       {class_id(world.classes[static_cast<std::size_t>(descendant)])}));
        PF_CHECK(!cyc.ok());
        if (!cyc.ok()) {
            PF_CHECK_EQ(cyc.status().code(), pf::StatusCode::CycleDetected);
        }
    }
}

PF_TEST(property, a_superseded_definition_never_authorizes_again) {
    std::mt19937_64 engine(kSeed ^ 0x5150ull);
    RandomWorld world;
    Fabric fabric;
    PF_REQUIRE(build_random_world(fabric, kSeed ^ 0x9999ull, world, "property-supersede"));

    for (int s = 0; s < world.subject_count; ++s) {
        (void)fabric.runtime.assign(
            fabric.session,
            make_assignment("rand.assign." + std::to_string(s),
                            world.subjects[static_cast<std::size_t>(s)], world.scopes.front(),
                            world.classes[static_cast<std::size_t>(s % world.class_count)]));
    }

    for (int round = 0; round < 40; ++round) {
        std::uniform_int_distribution<int> pick_class(0, world.class_count - 1);
        const int target = pick_class(engine);
        std::uint32_t next_rank = 10u;
        for (const auto& definition : fabric.runtime.list_classes()) {
            next_rank = std::max(next_rank, definition.precedence.value);
        }
        auto redefined = fabric.runtime.define_class(
            fabric.session, make_class(world.classes[static_cast<std::size_t>(target)],
                                       next_rank + 1u));
        if (!redefined.ok()) {
            break;
        }

        for (int s = 0; s < world.subject_count; ++s) {
            const pf::PriorityDecision decision =
                fabric.runtime.evaluate(query_for(world, s, 0));
            if (!decision.authoritative) {
                continue;
            }
            // Whatever the fabric still authorized must be bound to the *current* definition
            // of the class it names.
            auto definition = fabric.runtime.class_definition(decision.cls);
            PF_REQUIRE_OK(definition);
            PF_CHECK_EQ(decision.class_generation.value, definition.value().generation.value);
            PF_CHECK_EQ(decision.precedence.value, definition.value().precedence.value);
        }
    }
}

PF_TEST(property, deep_inheritance_resolves_at_every_permitted_depth) {
    Fabric fabric;
    PF_REQUIRE(open_fabric(fabric, "property-depth"));
    PF_REQUIRE_OK(fabric.runtime.define_class(fabric.session, make_class("deep.root", 10)));
    PF_REQUIRE_OK(fabric.runtime.define_scope(fabric.session, make_scope("deep.root.scope")));
    PF_REQUIRE_OK(fabric.runtime.define_subject(
        fabric.session, pf::SubjectDef{subject_id("deep.subject.0")}));

    std::string previous_subject = "deep.subject.0";
    std::string previous_class = "deep.root";
    std::uint32_t rank = 10;
    for (int level = 1; level <= 20; ++level) {
        rank += 5;
        const std::string cls = "deep.class." + std::to_string(level);
        const std::string subject = "deep.subject." + std::to_string(level);
        auto defined_class = fabric.runtime.define_class(
            fabric.session,
            make_class(cls, rank, pf::ClassKind::Standard, {class_id(previous_class)}));
        PF_REQUIRE_OK(defined_class);
        auto defined_subject =
            fabric.runtime.define_subject(fabric.session,
                                          make_subject(subject, {previous_subject}));
        PF_REQUIRE_OK(defined_subject);
        previous_class = cls;
        previous_subject = subject;
    }

    // An inheritance-propagating assignment on the deepest ancestor must reach the leaf.
    PF_REQUIRE_OK(fabric.runtime.assign(
        fabric.session,
        make_assignment("deep.assign", "deep.subject.0", "deep.root.scope", "deep.root",
                        pf::AssignmentKind::Inherited)));
    const pf::PriorityDecision decision =
        fabric.runtime.evaluate([&]() {
            pf::PriorityQuery query;
            query.subject = subject_id("deep.subject.20");
            query.scope = scope_id("deep.root.scope");
            return query;
        }());
    PF_CHECK(decision.outcome == pf::Outcome::Inherited);
    PF_CHECK(decision.cls == class_id("deep.root"));
}

PF_TEST(property, fenced_incarnations_are_never_authoritative) {
    std::mt19937_64 engine(kSeed ^ 0xF00Dull);
    RandomWorld world;
    Fabric fabric;
    PF_REQUIRE(build_random_world(fabric, kSeed ^ 0x2468ull, world, "property-fence"));

    int published = 0;
    for (int s = 0; s < world.subject_count; ++s) {
        (void)fabric.runtime.assign(
            fabric.session,
            make_assignment("rand.assign." + std::to_string(published++),
                            world.subjects[static_cast<std::size_t>(s)], world.scopes.front(),
                            world.classes[static_cast<std::size_t>(s % world.class_count)]));
    }

    for (int round = 0; round < 6; ++round) {
        const pf::BootId next_boot =
            pf::BootId::from_seed("property-fence/" + std::to_string(round));
        auto session =
            fabric.runtime.grant_authority(publisher_id("test.publisher"), next_boot);
        PF_REQUIRE_OK(session);
        fabric.session = session.value();
        for (int s = 0; s < world.subject_count; ++s) {
            const pf::PriorityDecision decision =
                fabric.runtime.evaluate(query_for(world, s, 0));
            PF_CHECK(decision.outcome == pf::Outcome::Fenced);
            PF_CHECK(!decision.authoritative);
        }
        // The new incarnation can publish again and then be believed.
        PF_REQUIRE_OK(fabric.runtime.assign(
            fabric.session,
            make_assignment("rand.assign.fresh." + std::to_string(round),
                            world.subjects.front(), world.scopes.front(),
                            world.classes.front())));
        PF_CHECK(fabric.runtime.evaluate(query_for(world, 0, 0)).outcome == pf::Outcome::Assigned);
    }
}
