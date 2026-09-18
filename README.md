# Priority Fabric

An open-source, vendor-neutral C++20 runtime for authoritative network priority classes,
precedence, inheritance, conflict resolution, generations and policy-bound priority decisions.

Priority Fabric answers one question, and answers it with evidence:

> Given a traffic or workload identity, a policy scope, explicit priority declarations,
> inherited classes, exceptions, current generations and authority, **what priority class and
> precedence are authoritative now, why, and when must that priority be rejected, superseded,
> fenced, downgraded or revalidated?**

It owns priority *definition and evaluation*. It does not schedule flows, allocate bandwidth,
enforce rates, define end-to-end QoS obligations, admit traffic, place flows or control queues.
It tells those systems what is authoritative and why; it never makes them do anything.

## Status

Version 1.0.0. Everything described in this document is implemented, built and exercised by the
test suites in `tests/`. Nothing here is aspirational; where a capability is not implemented or
not validated on a given platform, the section says so explicitly.

## Build

```
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build --output-on-failure
```

Requirements: CMake 3.20 or newer, a C++20 compiler, and threads. The build has been validated
with MSVC 19.44 (Visual Studio 2022 17.14) on Windows x64. GCC and Clang are supported by the
build system and the source avoids MSVC-only constructs outside the platform layer, but this
release was not built or tested with them.

Options:

| Option | Default | Meaning |
| --- | --- | --- |
| `PRIORITY_FABRIC_BUILD_SHARED` | OFF | Build a shared library instead of a static archive |
| `PRIORITY_FABRIC_BUILD_TESTS` | ON (top level) | Build the test suites and register them with CTest |
| `PRIORITY_FABRIC_BUILD_TOOLS` | ON (top level) | Build `pfctl`, `pf_node` and `pf_probe` |
| `PRIORITY_FABRIC_BUILD_EXAMPLES` | ON (top level) | Build the examples |
| `PRIORITY_FABRIC_WARNINGS_AS_ERRORS` | ON | `/W4 /WX` on MSVC, `-Wall -Wextra ... -Werror` elsewhere |
| `PRIORITY_FABRIC_ENABLE_ASAN` | OFF | Build with AddressSanitizer |
| `PRIORITY_FABRIC_ENABLE_UBSAN` | OFF | Build with UndefinedBehaviorSanitizer (non-MSVC) |
| `PRIORITY_FABRIC_INSTALL` | ON | Generate install and CMake package rules |

## Use it

```cpp
#include "priority_fabric/runtime.hpp"

pf::FabricRuntime::Options options;
options.state_dir = "state";
options.create_if_missing = true;
auto opened = pf::FabricRuntime::open(options);
pf::FabricRuntime fabric = std::move(opened.value());

auto session = fabric.grant_authority(
    pf::PublisherId::parse("worker.publisher", fabric.limits()).value(),
    pf::BootId::from_seed("worker-1"));
// ... publish classes, scopes, policies and subjects with session.value() ...

pf::PriorityQuery query;
query.subject = pf::SubjectId::parse("tenant.acme.analytics", fabric.limits()).value();
query.scope = pf::PolicyScopeId::parse("dc.tenant-acme", fabric.limits()).value();

const pf::PriorityDecision decision = fabric.evaluate(query);
// decision.outcome, decision.cls, decision.precedence, decision.chain, decision.digest
```

Consume the installed package:

```cmake
find_package(PriorityFabric 1.0 REQUIRED)
target_link_libraries(your_target PRIVATE PriorityFabric::priorityfabric)
```

A complete independent consumer lives in `validation/consumer/`.

## Outcomes

Every evaluation returns exactly one of eight outcomes. Only the first three carry a class that
a consumer may act on.

| Outcome | Meaning | Authoritative |
| --- | --- | --- |
| `ASSIGNED` | Evidence names the class directly | yes |
| `INHERITED` | The class comes from a named ancestor subject | yes |
| `OVERRIDDEN` | A narrower, or non-overridable, scope displaced broader evidence | yes |
| `CONFLICT` | Contradictory evidence was found; authoritative only if a policy resolved it | conditional |
| `UNKNOWN` | No evidence at all | no |
| `STALE` | Evidence exists but is bound to superseded generations | no |
| `FENCED` | Evidence exists but its publisher incarnation lost authority | no |
| `REJECTED` | The question or the state is structurally invalid; no answer is given | no |

`CONFLICT` is reported whenever contradictory evidence exists at the deciding scope, even when a
policy resolves it deterministically. A resolved conflict is authoritative *and* still names the
contradiction, the rule that resolved it and the provenance of every losing candidate.

## Model

Strongly typed identities, each with its own generation where it can be redefined:

* `PriorityClassId` / generation — a canonical class and its explicit precedence rank
* `PriorityAssignmentId` / generation — a statement that a subject holds a class in a scope
* `SubjectId` / generation — a workload, tenant or endpoint identity
* `PolicyScopeId` / generation — a node of the policy scope tree
* `PolicyId` / generation — a policy document bound to a scope generation
* `PublisherId` + `BootId` — a publisher and one process incarnation of it
* `FabricEpoch` — the fabric's authority generation
* `Provenance` — publisher, boot, epoch, fencing token, state generation, audit sequence

There is no hidden numeric priority semantics: a class must declare its precedence rank, ranks
must be unique across the active registry, and the fabric never infers, defaults or gap-fills a
rank. Higher rank means higher precedence.

## Guarantees

* **Deterministic precedence.** The precedence relation is a strict total order over declared
  ranks; the inheritance and scope graphs are DAGs. Cycles, self-inheritance, duplicate parents
  and out-of-depth chains are refused with a specific status.
* **Duplicate class ids cannot mean different things.** An identifier maps to one definition in
  one state. Different content under the same identifier is a new *generation*, and every
  assignment records the generation it was bound to.
* **Conflicts are explicit.** Contradictory evidence is never silently resolved. The default is
  to deny; a policy may resolve it by declared rule, and the conflict is still reported.
* **Stale policy or scope cannot authorize priority.** An assignment bound to a superseded class,
  scope, subject or policy generation is reported as `STALE` evidence and never becomes an
  answer.
* **Authority is never restored by recovery.** A grant recorded as live when a process stopped is
  restored as expired. A publisher has to ask again. A node taking over a state directory also
  advances the epoch, fencing everything published before the restart.
* **`UNKNOWN` does not become low priority.** The only way an unassigned subject receives a class
  is a policy that declares that default explicitly; the fabric never substitutes a class of its
  own.
* **Consumers receive canonical ordering.** Ordering is by declared rank, never by identifier
  spelling, insertion order or iteration order. Identical questions against an unchanged state
  produce byte-identical decisions and identical SHA-256 decision digests.
* **Revoked evidence is reported, not hidden.** Retired assignments, fenced incarnations and
  stale generations appear in the decision as refused evidence with the reason they were refused.

## Durability

A state directory holds a versioned, integrity-checked, crash-safe store:

```
state/
  manifest.pfm     atomically replaced pointer to the current snapshot and journal segment
  snapshot.pfs     full canonical state image, self-describing and self-checked
  journal.pfj      append-only record log (rolled into journal.<n>.pfj as it grows)
  key.pfk          per-store key that makes every record tamper-evident
  lock.pfk         exclusive lock that prevents two live writers on one directory
```

Commit protocol — never acknowledged before the state is durable:

```
validate -> bind authority -> plan -> reserve -> journal pending -> perform
         -> verify -> commit -> retire/cleanup
```

* Every record carries a CRC-32C framing checksum **and** a truncated HMAC-SHA256 tag under a
  per-store key, so altering a record is detected even if the framing checksum is recomputed.
* A `Pending` record without its `Commit` is an unfinished attempt: recovery rolls it back and
  says so. A torn tail is discarded to the last good boundary; a damaged record anywhere else
  degrades the store, and a degraded store answers `REJECTED` instead of guessing.
* Recovery distinguishes durable configuration and history, committed authoritative state,
  unfinished attempts and evidence that failed verification.
* The manifest, snapshot and key are written through a temporary file and an atomic replace.

## Node and transport

`pf_node` owns a state directory and serves a framed protocol over TCP. `pf_probe` and `pfctl`
are clients. The frame carries a magic value, a format version, the operation, reserved flags
(a non-zero value is rejected, not ignored), a request id, an explicit payload length and a
CRC-32C over header and payload.

Authority is bound by `(publisher, boot, epoch, fencing token)`. A request that carries an epoch
the fabric has moved past, a fencing token that has been superseded or a boot that has been
fenced is refused before it can mutate anything. A publisher whose socket closes can be fenced
automatically by configuration, which advances the epoch so the next incarnation must
re-establish authority.

**Security boundary.** The transport is unauthenticated loopback TCP. The node refuses to bind a
non-loopback address unless explicitly overridden, and the override is audited. Authority binding
prevents a stale, duplicated or superseded writer from corrupting state; it does not authenticate
a hostile local peer. Do not expose a node to an untrusted network.

## Tools

```
pfctl init|class|scope|policy|subject|assign|retire|query|verify|checkpoint|audit|stats|fence|advance-epoch
pf_node --state DIR [--port N] [--ready-file PATH] [--run-for-ms N] ...
pf_probe --port N --mode publish|query|takeover|hold|garbage|stats|integrity
```

`pfctl` speaks only the public runtime API, so it cannot bypass a single validation. Use
`--shared` for read-only commands against a live node: the durable records are self-describing
and self-checked, so a reader that never mutates cannot be misled by a writer appending in
parallel.

## Validation

Nine in-process suites and one real multiprocess suite run under CTest:

`identity`, `precedence`, `evaluation`, `durability`, `property`, `adversarial`,
`concurrency`, `restart`, `transport`, `multiprocess`, plus a labelled benchmark.

The multiprocess suite starts `pf_node` and `pf_probe` as separate operating-system processes,
talks to them over real loopback TCP, kills them with the operating system's own termination and
restarts them on the same state directory.

`docs/VALIDATION.md` records exactly what was measured, which build configurations were used, and
which claims are `REAL`, which are `SYNTHETIC` and which are `UNSUPPORTED`.

## Repository layout

```
include/priority_fabric/   public headers
src/                       implementation, including the durable store and the socket layer
tools/                     pfctl, pf_node, pf_probe
tests/                     unit, property, adversarial, concurrency, restart, transport suites
tests/multiprocess/        the real multiprocess harness and suite
tests/bench/               the labelled benchmark
examples/                  runnable examples
validation/consumer/       an independent find_package consumer
docs/                      architecture, semantics, durability, protocol and validation notes
```

## License

Apache License 2.0. Copyright 2026 Summon Software Labs. No telemetry transmission.
