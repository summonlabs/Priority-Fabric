# Semantics

This is the normative description of what an evaluation means. Every rule here is implemented in
`src/evaluate.cpp`, `src/state.cpp` and `src/runtime.cpp`, and every rule has at least one test in
`tests/`.

## Identifiers are canonical

An identifier is stored in exactly one spelling. Parsing folds ASCII case, trims surrounding
whitespace and turns a leading `/` and any `/` separators into `.`. It then requires
`[a-z0-9][a-z0-9._:-]*`, no empty segment, no trailing separator, at most 128 bytes. Anything
else is refused. Two spellings therefore cannot become two different identifiers, and a
non-canonical spelling is refused rather than repaired.

## Precedence is declared, never inferred

A class must declare a rank in `[0, 1000000]`. Ranks are unique across the active registry: a
second class claiming a rank that is already taken is refused with `duplicate_precedence`.
Higher rank means higher precedence. There is no default rank, no gap filling, no implicit
ordering by identifier and no implicit category ordering — the `ClassKind` (`standard`,
`tenant`, `system`, `emergency`) is descriptive and audited, and never changes ordering.

The precedence relation over declared ranks is a strict total order: irreflexive, antisymmetric,
transitive and total. The inheritance graph is a DAG, checked at definition time by reachability
from the proposed parent back to the class, with the cycle refused and reported.

## Inheritance

Two independent mechanisms, both explicit:

* **Class inheritance.** `PriorityClassDef::inherits_from` names direct ancestors. A class implies
  its ancestors transitively, which is how a policy's visible-class list can name an ancestor and
  still admit its descendants.
* **Subject inheritance.** `SubjectDef::inherits_from` names direct ancestors. An assignment
  declared with kind `Inherited` propagates to descendants; an assignment of any other kind
  applies only to the subject it names.

Lookup order for a subject `U`:

1. evidence on `U` itself, narrowest scope first;
2. otherwise the closest ancestor that offers any evidence, walking breadth-first by distance and
   ascending identifier within a distance;
3. otherwise the policy-declared default, if any;
4. otherwise `UNKNOWN`.

An explicit assignment on a descendant therefore always displaces what the descendant would
otherwise inherit.

## Scope tree

Scopes form a forest. `scope_chain` walks from the queried scope to its root; the chain is
bounded by `max_scope_depth` and a cycle is refused at definition time.

The **deciding level** is the narrowest scope on the chain with usable evidence, unless a broader
scope on the chain declares `allow_override = false` and has usable evidence — in which case the
narrowest such non-overridable scope decides. This is what makes a datacenter-wide declaration
immune to a tenant's attempt to displace it.

## Assignment kinds

| Kind | Meaning |
| --- | --- |
| `Explicit` | Declared for exactly this subject |
| `Inherited` | Declared for this subject and propagates to its descendants |
| `Override` | Declared to displace broader evidence |
| `Exception` | Declared to displace a specific class, named in `displaces` |
| `Default` | Produced by the fabric from a policy declaration; cannot be published |

An `Exception` without a `displaces` target is refused at evaluation with
`exception_without_target`. An `Exception` or `Override` whose target is not actually offered by a
strictly broader valid assignment is refused with `exception_target_mismatch` and does not apply.

## Conflicts

Contradictory evidence means two or more usable assignments at the *same* deciding level naming
different classes.

* The contradiction is **always** reported: it appears in `decision.conflicts`, and the outcome is
  `CONFLICT`.
* By default (`ConflictResolution::Deny`) no class is authoritative and `authoritative` is false.
* A scope or policy may declare `HigherPrecedence`, in which case the highest declared rank wins,
  or `AssignmentIdOrder`, in which case the lexicographically smallest assignment identifier
  wins. Both are deterministic because ranks are unique and identifiers are unique.
* A caller may set `strict_conflicts`, which denies regardless of policy.
* Losers are reported in `decision.superseded` with the rule that displaced them.

A resolved conflict still has outcome `CONFLICT`; `authoritative` says whether a consumer may act
on the class it names.

## Unknown

`UNKNOWN` means no evidence exists. It is never converted into a class unless a policy or scope
declares `unknown_default`. The nearest scope on the chain that declares a default supplies it —
a policy declaration at a level takes precedence over the scope declaration at the same level —
and the outcome becomes `ASSIGNED` with resolution `policy_default`.

If the declared default names a class that is not registered, or is not visible under the
effective policy, the fabric reports `UNKNOWN` with reason `default_class_unavailable`. It does
not substitute another class.

## Stale versus fenced

The distinction is deliberate and a consumer should treat the two differently.

**`STALE`** — the *content* the evidence was bound to has moved on:

| Reason code | Meaning |
| --- | --- |
| `subject_generation_stale` | The subject was redefined after the assignment bound it |
| `scope_generation_stale` | The scope was redefined |
| `class_generation_stale` | The class was redefined |
| `policy_generation_stale` | The policy was redefined |
| `assignment_retired` | The assignment was retired; the reason is reported |
| `class_not_registered` | The class is gone |
| `epoch_superseded` (decision-level) | The question itself was asked as of an old epoch |

**`FENCED`** — the *authority* behind the evidence is gone:

| Reason code | Meaning |
| --- | --- |
| `publisher_incarnation_fenced` | The publisher incarnation no longer holds authority |
| `epoch_superseded` (evidence-level) | The evidence was published under an old epoch |

A redefinition is only a redefinition when the content changes. Republishing identical content
refreshes the authority binding without moving the entity's generation, so it never invalidates
another publisher's evidence.

If usable evidence is empty and refused evidence is not, the outcome is `FENCED` when any
refusal was authority-related and `STALE` otherwise.

## Authority

`grant_authority(publisher, boot)`:

* a publisher that has never been seen gets a grant; the epoch is established on first use;
* the same boot asking again while its grant is live gets the same epoch and token back;
* a different boot of the same publisher takes over, which advances the epoch, marks the previous
  incarnation superseded and issues a fresh fencing token;
* a boot that was fenced is refused outright — fencing is final for an incarnation, and a process
  that was fenced must come back with a new boot id, which is what minting one per process start
  guarantees;
* if the fabric does not accept new publishers, an unknown publisher is refused and the epoch is
  **not** moved as a side effect.

`fence` marks a specific incarnation permanently unusable. `advance_epoch` moves the epoch and
expires every grant made under an earlier one.

**Recovery never restores authority.** A grant that was live when the process stopped is restored
as expired. A replaying process therefore holds no authority at all until a publisher asks again.
A node taking over a state directory also advances the epoch as its first durable act, so every
piece of evidence from before the restart is fenced.

## Limits

Every externally influenced size, count and depth is bounded by `Limits`: population sizes,
identifier and text lengths, scope and inheritance depth, parents per entity, classes per policy,
explanation steps per query, journal record and transport frame sizes, durable growth, connections
and requests per connection. Values above the compiled ceiling are refused when a runtime is
opened, and a caller may only lower them.

## Determinism

Evaluation reads ordered maps, walks chains in a fixed order, and breaks every tie by a declared
rule or by identifier order. Given the same image and the same query it produces the same
decision, and `PriorityDecision::digest` — a SHA-256 over the authoritative fields of the
decision — is byte-identical. That is the property the `property` suite hammers on: five
repetitions of every question in a randomized world, with and without supersession, always agree.
