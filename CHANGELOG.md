# Changelog

## 1.0.0 — 2026

First release.

**Runtime**

* `FabricRuntime` over a durable state directory: authority grants, class/scope/policy/subject
  definitions, assignments, retirement, evaluation, checkpointing and integrity reporting.
* Priority classes with explicit, unique precedence ranks and a cycle-checked inheritance DAG.
* Policy scope forest with per-scope conflict policy, override control and policy-declared
  defaults for unassigned subjects.
* Subject inheritance with deterministic ancestor order and bounded depth.
* Exceptions and overrides with named displacement targets.
* Eight outcomes — `ASSIGNED`, `INHERITED`, `OVERRIDDEN`, `CONFLICT`, `UNKNOWN`, `STALE`,
  `FENCED`, `REJECTED` — each with a reason code, a bounded explanation chain and provenance for
  every piece of evidence.
* SHA-256 decision digests so a consumer can detect that a decision is no longer current.

**Durability**

* Versioned, CRC-32C-checked and HMAC-SHA256-authenticated journal records under a per-store key.
* Two-phase commit: nothing is acknowledged before its pending record is durable.
* Snapshot and manifest written through temporary files and atomic replacement.
* Recovery that distinguishes committed state, unfinished attempts and evidence that failed
  verification, with trailing-byte discard and an explicit degraded mode.
* Exclusive state-directory lock so two live writers cannot share one store.
* Authority never survives a restart by itself.

**Transport**

* Framed protocol with magic, format version, reserved-flag rejection, explicit lengths and a
  checksum over header and payload.
* `FabricNode` with bounded connections and requests, graceful shutdown that drains in-flight
  work outside the bookkeeping lock, and optional epoch advancement when a publisher's socket
  closes.
* `NodeClient` that never caches authority and never reinterprets a status code.

**Tools**

* `pfctl` for operators, `pf_node` for the daemon, `pf_probe` for scripted clients.

**Validation**

* Nine in-process suites and one real multiprocess suite, registered with CTest.
* Seeded randomized property tests, adversarial input tests, concurrency and race tests,
  persistence and restart tests, and a labelled benchmark.
* Installable CMake package validated by an independent `find_package` consumer.
