// Priority Fabric -- authoritative network priority classes.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// pfctl: the operator's command line over a fabric state directory. It speaks the public
// runtime API, never the durable format, so it cannot bypass a single validation.

#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

#include "priority_fabric/runtime.hpp"
#include "priority_fabric/text.hpp"
#include "priority_fabric/version.hpp"

namespace {

const char* kPublisherId = "pfctl.publisher";

void usage() {
    std::cout <<
        "usage: pfctl [--state DIR] [--shared] COMMAND [options]\n"
        "\n"
        "  --state DIR              state directory (default: ./pf-state)\n"
        "  --shared                 do not take the exclusive state directory lock; only use\n"
        "                           this for read-only commands against a live node\n"
        "\n"
        "commands:\n"
        "  init\n"
        "  class define --id ID --precedence N [--kind standard|tenant|system|emergency]\n"
        "               [--inherits A,B] [--description TEXT] [--privileged]\n"
        "  class list\n"
        "  scope define --id ID [--parent P] [--conflict deny|higher-precedence|assignment-id-order]\n"
        "               [--unknown-default CLASS] [--no-override] [--description TEXT]\n"
        "  scope list\n"
        "  policy define --id ID --scope S [--class C]... [--conflict MODE]\n"
        "                [--unknown-default CLASS] [--allow-unattributed] [--description TEXT]\n"
        "  policy list\n"
        "  subject define --id ID [--parent P]... [--description TEXT]\n"
        "  subject list\n"
        "  assign --id A --subject U --scope S --class C [--kind K] [--displaces CLASS]\n"
        "         [--policy P] [--note TEXT]\n"
        "  retire --id A [--reason TEXT]\n"
        "  query --subject U --scope S [--json] [--strict] [--as-of-epoch N] [--steps N]\n"
        "  verify\n"
        "  checkpoint\n"
        "  audit [--limit N]\n"
        "  stats\n"
        "  fence --publisher P --boot HEX [--reason TEXT]\n"
        "  advance-epoch [--reason TEXT]\n"
        "  version\n";
}

struct Options {
    std::vector<std::string> positional;
    std::vector<std::string> classes;
    std::vector<std::string> parents;
    std::string state = "pf-state";
    std::string id;
    std::string parent;
    std::string scope;
    std::string cls;
    std::string subject;
    std::string kind;
    std::string conflict;
    std::string unknown_default;
    std::string description;
    std::string note;
    std::string reason;
    std::string policy;
    std::string displaces;
    std::string publisher;
    std::string boot;
    std::string precedence;
    std::string limit;
    std::string as_of_epoch;
    std::string steps;
    std::vector<std::string> inherits;
    bool privileged = false;
    bool no_override = false;
    bool allow_unattributed = false;
    bool json = false;
    bool strict = false;
    bool shared = false;
};

bool parse(int argc, char** argv, Options& options) {
    for (int i = 1; i < argc; ++i) {
        const std::string flag(argv[i]);
        const auto value = [&](std::string& out) {
            if (i + 1 >= argc) {
                std::cerr << "pfctl: " << flag << " needs a value\n";
                return false;
            }
            out = argv[++i];
            return true;
        };
        const auto list = [&](std::vector<std::string>& out) {
            std::string raw;
            if (!value(raw)) {
                return false;
            }
            for (auto& part : pf::split(raw, ',')) {
                if (!part.empty()) {
                    out.push_back(part);
                }
            }
            return true;
        };
        if (flag == "--help" || flag == "-h") {
            usage();
            std::exit(0);
        } else if (flag == "--state") {
            if (!value(options.state)) return false;
        } else if (flag == "--shared") {
            options.shared = true;
        } else if (flag == "--json") {
            options.json = true;
        } else if (flag == "--strict") {
            options.strict = true;
        } else if (flag == "--privileged") {
            options.privileged = true;
        } else if (flag == "--no-override") {
            options.no_override = true;
        } else if (flag == "--allow-unattributed") {
            options.allow_unattributed = true;
        } else if (flag == "--id") {
            if (!value(options.id)) return false;
        } else if (flag == "--parent") {
            if (!value(options.parent)) return false;
        } else if (flag == "--inherits") {
            if (!list(options.inherits)) return false;
        } else if (flag == "--scope") {
            if (!value(options.scope)) return false;
        } else if (flag == "--class") {
            if (!value(options.cls)) return false;
            options.classes.push_back(options.cls);
        } else if (flag == "--subject") {
            if (!value(options.subject)) return false;
        } else if (flag == "--kind") {
            if (!value(options.kind)) return false;
        } else if (flag == "--conflict") {
            if (!value(options.conflict)) return false;
        } else if (flag == "--unknown-default") {
            if (!value(options.unknown_default)) return false;
        } else if (flag == "--description") {
            if (!value(options.description)) return false;
        } else if (flag == "--note") {
            if (!value(options.note)) return false;
        } else if (flag == "--reason") {
            if (!value(options.reason)) return false;
        } else if (flag == "--policy") {
            if (!value(options.policy)) return false;
        } else if (flag == "--displaces") {
            if (!value(options.displaces)) return false;
        } else if (flag == "--publisher") {
            if (!value(options.publisher)) return false;
        } else if (flag == "--boot") {
            if (!value(options.boot)) return false;
        } else if (flag == "--precedence") {
            if (!value(options.precedence)) return false;
        } else if (flag == "--limit") {
            if (!value(options.limit)) return false;
        } else if (flag == "--as-of-epoch") {
            if (!value(options.as_of_epoch)) return false;
        } else if (flag == "--steps") {
            if (!value(options.steps)) return false;
        } else if (!flag.empty() && flag[0] == '-') {
            std::cerr << "pfctl: unknown option " << flag << "\n";
            return false;
        } else {
            options.positional.push_back(flag);
        }
    }
    return true;
}

std::optional<std::uint64_t> to_number(const std::string& text) {
    if (text.empty()) {
        return std::nullopt;
    }
    for (char c : text) {
        if (c < '0' || c > '9') {
            return std::nullopt;
        }
    }
    return std::strtoull(text.c_str(), nullptr, 10);
}

int fail(const std::string& what) {
    std::cerr << "pfctl: " << what << "\n";
    return 1;
}

/// The command line tool is one logical publisher. Its boot id is derived from the state
/// directory so that consecutive invocations resume the same incarnation instead of fencing
/// everything the previous invocation published.
pf::BootId cli_boot(const std::filesystem::path& state) {
    std::error_code ec;
    const auto absolute = std::filesystem::absolute(state, ec);
    return pf::BootId::from_seed("pfctl/" + (ec ? state.string() : absolute.string()));
}

bool open_runtime(const Options& options, bool create, pf::FabricRuntime& runtime,
                  pf::Session& session) {
    pf::FabricRuntime::Options runtime_options;
    runtime_options.state_dir = options.state;
    runtime_options.create_if_missing = create;
    runtime_options.exclusive_lock = !options.shared;
    auto opened = pf::FabricRuntime::open(runtime_options);
    if (!opened.ok()) {
        return false;
    }
    runtime = std::move(opened.value());
    auto granted = runtime.grant_authority(
        pf::PublisherId::parse(kPublisherId, runtime.limits()).value(), cli_boot(options.state));
    if (!granted.ok()) {
        return false;
    }
    session = granted.value();
    return true;
}

void print_class(const pf::PriorityClassDef& definition) {
    std::cout << definition.id.str() << " precedence=" << definition.precedence.value
              << " kind=" << pf::to_string(definition.kind)
              << " generation=" << definition.generation.value;
    if (definition.privileged) {
        std::cout << " privileged";
    }
    if (!definition.inherits_from.empty()) {
        std::cout << " inherits=";
        for (std::size_t i = 0; i < definition.inherits_from.size(); ++i) {
            if (i != 0) {
                std::cout << ",";
            }
            std::cout << definition.inherits_from[i].str();
        }
    }
    if (!definition.description.empty()) {
        std::cout << " description=\"" << definition.description << "\"";
    }
    std::cout << "\n";
}

void print_scope(const pf::PolicyScopeDef& definition) {
    std::cout << definition.id.str() << " generation=" << definition.generation.value
              << " parent=" << (definition.parent.has_value() ? definition.parent->str() : "-")
              << " conflict=" << pf::to_string(definition.conflict_resolution)
              << " unknown-default="
              << (definition.unknown_default.has_value() ? definition.unknown_default->str() : "-")
              << " allow-override=" << (definition.allow_override ? "yes" : "no") << "\n";
}

void print_policy(const pf::PolicyDef& definition) {
    std::cout << definition.id.str() << " generation=" << definition.generation.value
              << " scope=" << definition.scope.str()
              << " scope-generation=" << definition.scope_generation.value
              << " require-policy=" << (definition.require_policy_for_assignment ? "yes" : "no")
              << " classes=";
    for (std::size_t i = 0; i < definition.visible_classes.size(); ++i) {
        if (i != 0) {
            std::cout << ",";
        }
        std::cout << definition.visible_classes[i].str();
    }
    if (definition.visible_classes.empty()) {
        std::cout << "-";
    }
    std::cout << "\n";
}

void print_subject(const pf::SubjectDef& definition) {
    std::cout << definition.id.str() << " generation=" << definition.generation.value
              << " inherits=";
    if (definition.inherits_from.empty()) {
        std::cout << "-";
    }
    for (std::size_t i = 0; i < definition.inherits_from.size(); ++i) {
        if (i != 0) {
            std::cout << ",";
        }
        std::cout << definition.inherits_from[i].str();
    }
    std::cout << "\n";
}

void print_assignment(const pf::PriorityAssignment& assignment) {
    std::cout << assignment.id.str() << " subject=" << assignment.subject.str()
              << " scope=" << assignment.scope.str() << " class=" << assignment.cls.str()
              << " kind=" << pf::to_string(assignment.kind)
              << " generation=" << assignment.generation.value
              << " subject-generation=" << assignment.subject_generation.value
              << " scope-generation=" << assignment.scope_generation.value
              << " class-generation=" << assignment.class_generation.value
              << " policy=" << (assignment.policy.has_value() ? assignment.policy->str() : "-")
              << "\n";
}

}  // namespace

int main(int argc, char** argv) {
    Options options;
    if (!parse(argc, argv, options)) {
        usage();
        return 2;
    }
    if (options.positional.empty()) {
        usage();
        return 2;
    }

    const std::string& group = options.positional[0];
    const std::string action = options.positional.size() > 1 ? options.positional[1] : std::string();

    if (group == "version") {
        std::cout << "pfctl " << pf::version_string() << " (format "
                  << pf::format_version() << ")\n";
        return 0;
    }

    const bool writes = !(group == "query" || group == "verify" || group == "audit" ||
                          group == "stats" || (group == "class" && action == "list") ||
                          (group == "scope" && action == "list") ||
                          (group == "policy" && action == "list") ||
                          (group == "subject" && action == "list"));

    pf::FabricRuntime runtime;
    pf::Session session;
    if (!open_runtime(options, true, runtime, session)) {
        return fail("cannot open the fabric state at '" + options.state + "'");
    }
    (void)writes;

    if (group == "init") {
        std::cout << "state=" << runtime.state_dir().string()
                  << " epoch=" << runtime.epoch().value
                  << " generation=" << runtime.state_generation().value
                  << " health=" << pf::to_string(runtime.health()) << "\n";
        return 0;
    }

    if (group == "class") {
        if (action == "list") {
            for (const auto& definition : runtime.list_classes()) {
                print_class(definition);
            }
            return 0;
        }
        if (action != "define") {
            return fail("unknown class subcommand '" + action + "'");
        }
        auto precedence = to_number(options.precedence);
        if (!precedence.has_value()) {
            return fail("--precedence must be a number in [0, " +
                        std::to_string(pf::PrecedenceRank::kMaxRank) + "]");
        }
        pf::PriorityClassDef definition;
        auto id = pf::PriorityClassId::parse(options.id, runtime.limits());
        if (!id.ok()) {
            return fail(id.status().to_string());
        }
        definition.id = id.value();
        definition.precedence = pf::PrecedenceRank::make(static_cast<std::uint32_t>(*precedence));
        if (!options.kind.empty() && !pf::parse_class_kind(options.kind, definition.kind)) {
            return fail("unknown class kind '" + options.kind + "'");
        }
        for (const auto& parent : options.inherits) {
            auto parsed = pf::PriorityClassId::parse(parent, runtime.limits());
            if (!parsed.ok()) {
                return fail(parsed.status().to_string());
            }
            definition.inherits_from.push_back(parsed.value());
        }
        definition.description = options.description;
        definition.privileged = options.privileged;
        auto result = runtime.define_class(session, definition);
        if (!result.ok()) {
            return fail(result.status().to_string());
        }
        std::cout << "class=" << definition.id.str() << " generation=" << result.value().value
                  << " state-generation=" << runtime.state_generation().value << "\n";
        return 0;
    }

    if (group == "scope") {
        if (action == "list") {
            for (const auto& definition : runtime.list_scopes()) {
                print_scope(definition);
            }
            return 0;
        }
        if (action != "define") {
            return fail("unknown scope subcommand '" + action + "'");
        }
        pf::PolicyScopeDef definition;
        auto id = pf::PolicyScopeId::parse(options.id, runtime.limits());
        if (!id.ok()) {
            return fail(id.status().to_string());
        }
        definition.id = id.value();
        if (!options.parent.empty()) {
            auto parsed = pf::PolicyScopeId::parse(options.parent, runtime.limits());
            if (!parsed.ok()) {
                return fail(parsed.status().to_string());
            }
            definition.parent = parsed.value();
        }
        if (!options.conflict.empty() &&
            !pf::parse_conflict_resolution(options.conflict, definition.conflict_resolution)) {
            return fail("unknown conflict mode '" + options.conflict + "'");
        }
        if (!options.unknown_default.empty()) {
            auto parsed = pf::PriorityClassId::parse(options.unknown_default, runtime.limits());
            if (!parsed.ok()) {
                return fail(parsed.status().to_string());
            }
            definition.unknown_default = parsed.value();
        }
        definition.allow_override = !options.no_override;
        definition.description = options.description;
        auto result = runtime.define_scope(session, definition);
        if (!result.ok()) {
            return fail(result.status().to_string());
        }
        std::cout << "scope=" << definition.id.str() << " generation=" << result.value().value
                  << " state-generation=" << runtime.state_generation().value << "\n";
        return 0;
    }

    if (group == "policy") {
        if (action == "list") {
            for (const auto& definition : runtime.list_policies()) {
                print_policy(definition);
            }
            return 0;
        }
        if (action != "define") {
            return fail("unknown policy subcommand '" + action + "'");
        }
        pf::PolicyDef definition;
        auto id = pf::PolicyId::parse(options.id, runtime.limits());
        if (!id.ok()) {
            return fail(id.status().to_string());
        }
        definition.id = id.value();
        auto scope = pf::PolicyScopeId::parse(options.scope, runtime.limits());
        if (!scope.ok()) {
            return fail(scope.status().to_string());
        }
        definition.scope = scope.value();
        for (const auto& cls : options.classes) {
            auto parsed = pf::PriorityClassId::parse(cls, runtime.limits());
            if (!parsed.ok()) {
                return fail(parsed.status().to_string());
            }
            definition.visible_classes.push_back(parsed.value());
        }
        if (!options.conflict.empty()) {
            pf::ConflictResolution mode = pf::ConflictResolution::Deny;
            if (!pf::parse_conflict_resolution(options.conflict, mode)) {
                return fail("unknown conflict mode '" + options.conflict + "'");
            }
            definition.conflict_resolution = mode;
        }
        if (!options.unknown_default.empty()) {
            auto parsed = pf::PriorityClassId::parse(options.unknown_default, runtime.limits());
            if (!parsed.ok()) {
                return fail(parsed.status().to_string());
            }
            definition.unknown_default = parsed.value();
        }
        definition.require_policy_for_assignment = !options.allow_unattributed;
        definition.description = options.description;
        auto result = runtime.define_policy(session, definition);
        if (!result.ok()) {
            return fail(result.status().to_string());
        }
        std::cout << "policy=" << definition.id.str() << " generation=" << result.value().value
                  << " state-generation=" << runtime.state_generation().value << "\n";
        return 0;
    }

    if (group == "subject") {
        if (action == "list") {
            for (const auto& definition : runtime.list_subjects()) {
                print_subject(definition);
            }
            return 0;
        }
        if (action != "define") {
            return fail("unknown subject subcommand '" + action + "'");
        }
        pf::SubjectDef definition;
        auto id = pf::SubjectId::parse(options.id, runtime.limits());
        if (!id.ok()) {
            return fail(id.status().to_string());
        }
        definition.id = id.value();
        if (!options.parent.empty()) {
            auto parsed = pf::SubjectId::parse(options.parent, runtime.limits());
            if (!parsed.ok()) {
                return fail(parsed.status().to_string());
            }
            definition.inherits_from.push_back(parsed.value());
        }
        for (const auto& parent : options.inherits) {
            auto parsed = pf::SubjectId::parse(parent, runtime.limits());
            if (!parsed.ok()) {
                return fail(parsed.status().to_string());
            }
            definition.inherits_from.push_back(parsed.value());
        }
        definition.description = options.description;
        auto result = runtime.define_subject(session, definition);
        if (!result.ok()) {
            return fail(result.status().to_string());
        }
        std::cout << "subject=" << definition.id.str() << " generation=" << result.value().value
                  << " state-generation=" << runtime.state_generation().value << "\n";
        return 0;
    }

    if (group == "assign") {
        pf::PriorityAssignment assignment;
        auto id = pf::PriorityAssignmentId::parse(options.id, runtime.limits());
        if (!id.ok()) {
            return fail(id.status().to_string());
        }
        assignment.id = id.value();
        auto subject = pf::SubjectId::parse(options.subject, runtime.limits());
        if (!subject.ok()) {
            return fail(subject.status().to_string());
        }
        assignment.subject = subject.value();
        auto scope = pf::PolicyScopeId::parse(options.scope, runtime.limits());
        if (!scope.ok()) {
            return fail(scope.status().to_string());
        }
        assignment.scope = scope.value();
        auto cls = pf::PriorityClassId::parse(options.cls, runtime.limits());
        if (!cls.ok()) {
            return fail(cls.status().to_string());
        }
        assignment.cls = cls.value();
        if (!options.kind.empty() && !pf::parse_assignment_kind(options.kind, assignment.kind)) {
            return fail("unknown assignment kind '" + options.kind + "'");
        }
        if (!options.displaces.empty()) {
            auto parsed = pf::PriorityClassId::parse(options.displaces, runtime.limits());
            if (!parsed.ok()) {
                return fail(parsed.status().to_string());
            }
            assignment.displaces = parsed.value();
        }
        if (!options.policy.empty()) {
            auto parsed = pf::PolicyId::parse(options.policy, runtime.limits());
            if (!parsed.ok()) {
                return fail(parsed.status().to_string());
            }
            assignment.policy = parsed.value();
        }
        assignment.note = options.note;
        auto result = runtime.assign(session, assignment);
        if (!result.ok()) {
            return fail(result.status().to_string());
        }
        std::cout << "assignment=" << assignment.id.str()
                  << " generation=" << result.value().value
                  << " state-generation=" << runtime.state_generation().value << "\n";
        return 0;
    }

    if (group == "retire") {
        auto id = pf::PriorityAssignmentId::parse(options.id, runtime.limits());
        if (!id.ok()) {
            return fail(id.status().to_string());
        }
        auto result = runtime.retire_assignment(session, id.value(), options.reason);
        if (!result.ok()) {
            return fail(result.status().to_string());
        }
        std::cout << "assignment=" << id.value().str() << " retired generation="
                  << result.value().value << "\n";
        return 0;
    }

    if (group == "query") {
        pf::PriorityQuery query;
        auto subject = pf::SubjectId::parse(options.subject, runtime.limits());
        if (!subject.ok()) {
            return fail(subject.status().to_string());
        }
        query.subject = subject.value();
        auto scope = pf::PolicyScopeId::parse(options.scope, runtime.limits());
        if (!scope.ok()) {
            return fail(scope.status().to_string());
        }
        query.scope = scope.value();
        query.strict_conflicts = options.strict;
        if (auto number = to_number(options.as_of_epoch); number.has_value()) {
            query.as_of_epoch = pf::FabricEpoch{*number};
        }
        if (auto number = to_number(options.steps); number.has_value()) {
            query.max_explanation_steps = static_cast<std::uint32_t>(*number);
        }
        const pf::PriorityDecision decision = runtime.evaluate(query);
        if (options.json) {
            std::cout << decision.to_json() << "\n";
        } else {
            std::cout << decision.to_text();
        }
        return decision.outcome == pf::Outcome::Rejected ? 3 : 0;
    }

    if (group == "verify") {
        const pf::IntegrityReport report = runtime.integrity_report();
        std::cout << "ok=" << (report.ok ? "true" : "false")
                  << " health=" << pf::to_string(report.health)
                  << " records_scanned=" << report.records_scanned
                  << " records_applied=" << report.records_applied
                  << " records_rejected=" << report.records_rejected
                  << " unfinished_attempts=" << report.unfinished_attempts
                  << " trailing_bytes_discarded=" << report.trailing_bytes_discarded
                  << " state-generation=" << report.state_generation.value
                  << " epoch=" << report.epoch.value << " digest=" << report.state_digest.hex()
                  << "\n";
        if (!report.detail.empty()) {
            std::cout << "detail=" << report.detail << "\n";
        }
        return report.ok ? 0 : 4;
    }

    if (group == "checkpoint") {
        auto result = runtime.checkpoint();
        if (!result.ok()) {
            return fail(result.status().to_string());
        }
        std::cout << "checkpoint generation=" << result.value().value
                  << " durable-bytes=" << runtime.state_stats().durable_bytes << "\n";
        return 0;
    }

    if (group == "audit") {
        std::uint32_t limit = 50;
        if (auto number = to_number(options.limit); number.has_value()) {
            limit = static_cast<std::uint32_t>(*number);
        }
        for (const auto& entry : runtime.audit(limit)) {
            std::cout << entry.sequence << " " << entry.op << " "
                      << pf::to_string(entry.result) << " publisher="
                      << entry.provenance.publisher.str()
                      << " boot=" << entry.provenance.boot.hex()
                      << " epoch=" << entry.provenance.epoch.value
                      << " generation=" << entry.state_generation.value;
            if (!entry.detail.empty()) {
                std::cout << " detail=\"" << entry.detail << "\"";
            }
            std::cout << "\n";
        }
        return 0;
    }

    if (group == "stats") {
        const pf::StateStats state = runtime.state_stats();
        const pf::FabricStats stats = runtime.stats();
        std::cout << "classes=" << state.classes << " scopes=" << state.scopes
                  << " policies=" << state.policies << " subjects=" << state.subjects
                  << " assignments=" << state.assignments
                  << " retired=" << state.retired_assignments
                  << " publishers=" << state.publishers
                  << " fenced-boots=" << state.fenced_boots
                  << " audit-entries=" << state.audit_entries
                  << " durable-bytes=" << state.durable_bytes
                  << " journal-records=" << state.journal_records
                  << " epoch=" << state.epoch.value
                  << " generation=" << state.state_generation.value << "\n";
        // The counters below count what *this process* did, not what the store contains.
        std::cout << "process.evaluations=" << stats.evaluations << " assigned="
                  << stats.evaluations_assigned << " inherited=" << stats.evaluations_inherited
                  << " overridden=" << stats.evaluations_overridden
                  << " conflict=" << stats.evaluations_conflict
                  << " unknown=" << stats.evaluations_unknown
                  << " stale=" << stats.evaluations_stale << " fenced=" << stats.evaluations_fenced
                  << " rejected=" << stats.evaluations_rejected
                  << " mutations-accepted=" << stats.mutations_accepted
                  << " mutations-rejected=" << stats.mutations_rejected
                  << " noops=" << stats.idempotent_noops
                  << " durable-commits=" << stats.durable_commits
                  << " recoveries=" << stats.recoveries
                  << " epoch-advances=" << stats.epoch_advances
                  << " fences=" << stats.fences_issued
                  << " grants=" << stats.authorities_granted << "\n";
        return 0;
    }

    if (group == "fence") {
        auto publisher = pf::PublisherId::parse(options.publisher, runtime.limits());
        if (!publisher.ok()) {
            return fail(publisher.status().to_string());
        }
        auto boot = pf::BootId::parse_hex(options.boot);
        if (!boot.ok()) {
            return fail(boot.status().to_string());
        }
        auto result = runtime.fence(session, publisher.value(), boot.value(), options.reason);
        if (!result.ok()) {
            return fail(result.status().to_string());
        }
        std::cout << "fenced publisher=" << publisher.value().str()
                  << " boot=" << boot.value().hex() << "\n";
        return 0;
    }

    if (group == "advance-epoch") {
        auto result = runtime.advance_epoch(session, options.reason);
        if (!result.ok()) {
            return fail(result.status().to_string());
        }
        std::cout << "epoch=" << result.value().value << "\n";
        return 0;
    }

    return fail("unknown command '" + group + "'");
}
