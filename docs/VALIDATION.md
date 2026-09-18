# Validation record

Everything below was produced by running the commands shown on the machine described. Figures
are copied from the command output, not estimated. Where a claim could not be validated, it is
labelled `UNSUPPORTED` and the reason is given.

## Environment

| | |
| --- | --- |
| Operating system | Windows 10.0.26200 (Windows 11 x64) |
| Compiler | MSVC 19.44.35209 (Visual Studio 2022 Community 17.14.25), toolset 14.44.35207 |
| Build system | CMake 4.3.2, Ninja 1.13.2 |
| Architecture | x86-64 for the Debug, Release and static-analysis builds; x86 for the sanitizer build |
| Compiler flags | `/W4 /permissive- /utf-8 /Zc:__cplusplus /Zc:preprocessor /EHsc /bigobj` and `/WX` |

## Test inventory

Ten suites, registered with CTest. Counts are from the Release build.

| Suite | Cases | Checks | What it covers |
| --- | --- | --- | --- |
| `identity` | 13 | 82 | Canonicalization, generations, epochs, boot ids, SHA-256/HMAC/CRC-32C/FNV-1a against published vectors, codec truncation and trailing bytes |
| `precedence` | 10 | 71 | Rank declaration and uniqueness, republication semantics, inheritance and scope cycles, depth bounds, generation stamping |
| `evaluation` | 27 | 1033 | All eight outcomes, override/exception semantics, non-overridable scopes, stale and fenced evidence, determinism, explanation bounds |
| `durability` | 14 | 82 | Journal replay, checkpointing, torn tails, uncommitted pending records, corruption, tamper detection, growth bounds, audit |
| `property` | 7 | 37992 | Seeded randomized worlds: total order, publication-order independence, determinism, injected cycles, supersession, deep inheritance, fencing |
| `adversarial` | 14 | 211 | Oversized and control-character text, population and edge limits, policy visibility, contradictory input, randomized journal corruption, forged sessions |
| `concurrency` | 5 | 149 | Readers against a writer, concurrent registrations, a fence racing an assignment, close during evaluation, parallel statistics |
| `restart` | 10 | 121 | Epoch and definition persistence, authority never restored by recovery, evidence re-establishment, fenced durability, checkpoints, audit recovery |
| `transport` | 9 | 85 | Full session over the wire, status propagation, epoch takeover, malformed and truncated frames, concurrent clients, bind policy, shutdown |
| `multiprocess` | 8 | 66 | Real `pf_node` and `pf_probe` processes over real loopback TCP, process kill, node restart, publisher death, malformed frames from a real peer, the state directory lock |
| **total** | **117** | **39892** | |

## Results

```
Debug   (MSVC, /W4 /WX)   100% tests passed, 0 tests failed out of 11
Release (MSVC, /W4 /WX)   100% tests passed, 0 tests failed out of 11
```

Both configurations compile with warnings as errors and emit no warnings. Nine of the eleven
CTest entries are the in-process suites; the other two are the multiprocess suite and the
labelled benchmark.

## Sanitizers

| Tool | Status | Evidence |
| --- | --- | --- |
| AddressSanitizer, x86-64 | `UNSUPPORTED` | This Visual Studio installation ships the ASan runtime for x86 only. `clang_rt.asan_dynamic_runtime_thunk-x86_64.lib` is absent, so the x64 build compiles and fails at link with `LNK1104`. No LLVM or clang-cl installation is present either. |
| AddressSanitizer, x86 | `REAL` | `cmake -B build-asan32 -DCMAKE_BUILD_TYPE=RelWithDebInfo -DPRIORITY_FABRIC_ENABLE_ASAN=ON` under `vcvars32`, then `ctest`. All 11 CTest tests pass with AddressSanitizer instrumentation and no report. |
| Runtime checks, x86-64 | `REAL` | The Debug configuration carries `/RTC1` (stack frame and uninitialized-local checks) and `_ITERATOR_DEBUG_LEVEL=2` (checked iterators) and passes every suite. |
| UndefinedBehaviorSanitizer | `UNSUPPORTED` | MSVC has no UBSan and no GCC or Clang toolchain is installed in this environment. |

AddressSanitizer earned its place. The x86 run found a genuine **stack-use-after-scope** in
`pf::Decoder::id`, where the decoder kept a pointer to the `Limits` it was constructed with and
one call site passed a temporary. The decoder now owns its limits. That defect was invisible to
every other check and is exactly the class of bug sanitizers exist to find.

## Test timing policy

No test has a timeout. Every suite runs plainly and is allowed to finish; a hanging test is a
defect to diagnose, not something to cut short.

Two bounded waits exist and both are *failure detectors*, never pass paths:

* `wait_until` in the multiprocess harness polls for a child's ready file. If the bound is
  reached the test **fails** with "the child never came up"; it can never turn a broken child
  into a passing test.
* `NodeClient::Options::io_deadline_ms` bounds how long a client can be blocked by a dead peer.
  A deadline expiring always produces an error and never a successful result.

The concurrency suite contains spin loops that wait for an invariant to become observable (for
example, every reader having seen a rejection after `close()`). They are join conditions, not
timeouts: the invariant is guaranteed once the runtime is closed, so a non-terminating spin would
itself be the defect.

## Static analysis

`cmake -B build-analyze -DCMAKE_BUILD_TYPE=Release -DCMAKE_CXX_FLAGS="/analyze"` followed by a
clean build of every target.

* **First-party findings: 0.**
* Six warnings in total, all from `Windows Kits\10\include\10.0.26100.0\um\ws2tcpip.h`
  (`C6101`, two distinct sites, repeated across translation units). They are in the platform
  header, not in this project.

## Benchmark

`pf_bench`, Release x86-64. **SYNTHETIC**: an in-process population over one local state
directory; no network interface, switch, NIC, DPU or queue is involved. The numbers describe how
fast the fabric answers, and every measurement counts *completed* work.

```
population classes=128 scopes=8 subjects=4096 assignments=65536
load.seconds=4.24661 load.ops_per_second=16429.1
evaluate.single_thread.completed=200000 seconds=13.0288 evaluations_per_second=15350.6 authoritative=200000
evaluate.parallel.completed=200000 threads=8 seconds=3.06031 evaluations_per_second=65352.9
durable.commits.completed=2000 seconds=3.54022 commits_per_second=564.937 bytes=507458
```

The durable figure is the honest one for a write path: it is measured with the platform flush
enabled on every commit, so each commit is on stable storage before it is acknowledged.

## Persistence and restart proof

| Claim | How it is proved | Label |
| --- | --- | --- |
| Committed state survives a process restart | `multiprocess.killing_the_node_and_restarting_it_advances_the_epoch` kills `pf_node` and starts a second process on the same directory | `REAL` |
| An unfinished attempt is rolled back | `durability.an_uncommitted_pending_record_is_rolled_back` removes exactly one Commit record from the journal | `REAL` |
| A torn tail is discarded and the store stays healthy | `durability.a_torn_tail_is_discarded_and_the_store_stays_healthy` truncates mid-record | `REAL` |
| Corruption is detected, not absorbed | `durability.a_corrupt_payload_is_detected_and_degrades_the_store` plus twelve randomized bit flips in `adversarial.a_randomly_corrupted_journal_never_yields_a_silent_wrong_answer` | `REAL` |
| Tampering survives a recomputed checksum | `durability.authentication_catches_a_record_rewritten_with_a_valid_checksum` damages the authentication tag only | `REAL` |
| Authority is not restored by recovery | `restart.authority_is_never_restored_by_reopening` and `restart.no_evidence_is_usable_until_its_publisher_re_establishes_authority` | `REAL` |
| A node restart advances the epoch | `multiprocess.killing_the_node_and_restarting_it_advances_the_epoch` | `REAL` |
| Two live processes cannot share a state directory | `multiprocess.a_second_node_refuses_to_share_a_live_state_directory`; the lock is the operating system's own and is released on process death | `REAL` |

## Distributed claims

| Claim | Label | Note |
| --- | --- | --- |
| Real operating-system processes | `REAL` | `CreateProcessW`; the child is a separate executable with its own address space and pid |
| Real framed transport | `REAL` | Blocking TCP sockets on loopback, with frame headers and checksums validated on both sides |
| Process kill and restart | `REAL` | `TerminateProcess`, then a fresh process on the same state directory |
| Fresh boot and incarnation fencing | `REAL` | A new boot id takes over; the previous incarnation's evidence is refused |
| Epoch advancement | `REAL` | Observed over the wire and durable before the grant is returned |
| Stale epoch, boot, generation and token rejection | `REAL` | Provoked both over the wire and in process |
| Multi-host, multi-switch, RDMA, NVLink, optical, NIC, DPU or physical-network behaviour | `UNSUPPORTED` | Not implemented and not claimed. The transport is loopback TCP between processes on one machine. |
| Transport authentication or encryption | `UNSUPPORTED` | Authority binding only; see the security boundary in `README.md`. |

## Install and consume

```
cmake --install build-release --prefix out/install
cmake -S validation/consumer -B out/consumer-build -G Ninja -DCMAKE_PREFIX_PATH=<prefix>
cmake --build out/consumer-build
out/consumer-build/pf_consumer.exe
```

The consumer configures against the installed package with `find_package(PriorityFabric 1.0
REQUIRED)`, links `PriorityFabric::priorityfabric`, compiles with `/W4 /WX` and prints:

```
linked priority fabric 1.0.0 (format 1)
outcome=ASSIGNED class=net.gold precedence=900 digest=dffcd51bacb15355
default_resolution=policy_default class=net.bulk
consumer: ok
```

It lives in `validation/consumer/`, outside the library, and uses only the installed headers and
the documented API. `REAL`.

## Operator tooling

`pfctl` was driven through a complete workflow over a scratch state directory: `init`, four class
definitions, two scopes, two subjects, three assignments, a denied conflict between two
assignments at the same scope level, `stats`, `verify`, `checkpoint`, `audit`, retirement of one
of the conflicting assignments, `advance-epoch`, and a final query showing the surviving evidence
refused as `FENCED` under the new epoch. Every command exited with the expected status, and the
`CONFLICT`, `ASSIGNED` and `FENCED` decisions each named the exact evidence and rule behind them.
`REAL`.

## Fresh clone

The committed tree is cloned into an empty directory from the local repository and configured,
built and tested there, without the working copy. `REAL`.
