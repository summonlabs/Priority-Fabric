# Architecture

Priority Fabric is one library, one state directory and one node process. Everything else is a
client of those three things.

## Boundary

The runtime owns **priority definition and evaluation**:

* what a priority class is and what it means,
* which classes exist, what their precedence is, and which classes are comparable,
* how a subject inherits a class from an ancestor,
* how the scope tree narrows or widens a decision,
* when conflicting declarations are contradictory,
* which generation of each definition an answer is bound to,
* which publisher incarnation was allowed to say so,
* and what the fabric must refuse.

It deliberately does **not** own scheduling, bandwidth allocation, rate enforcement, end-to-end
QoS obligations, admission control, flow placement or queue management. A decision carries a
class, a precedence, an explanation and a set of generations; acting on that is somebody else's
system.

Nothing in the fabric is on a packet path. It answers questions; it does not move bytes.

## Layers

```
  tools/                 pfctl, pf_node, pf_probe
        |
  FabricNode  <---->  framed transport (wire.hpp)  <---->  NodeClient
        |
  FabricRuntime           public API: authority, definitions, assignments, evaluation
        |
  +-----+-----------------------------+---------------------------+
  |                                   |                           |
  evaluation engine              authoritative image         durable store
  (evaluate.cpp)                 (state.hpp)                 (store.cpp)
  |                                   |                           |
  precedence, scope chain,       classes, scopes,            journal + snapshot
  inheritance, conflicts,        policies, subjects,         + manifest + key
  explanation chain              assignments, authority      + lock
  |                                   |                           |
  +-----------------------------------+---------------------------+
                                      |
                        identities, generations, epochs,
                        digests, codecs, checked arithmetic
```

## The authoritative image

`detail::StateImage` is the whole of the fabric's memory. It is a set of ordered maps keyed by
identifier, plus the current epoch, the state generation, the fencing-token counter, the audit
sequence and the authority table. Ordered maps are not an implementation detail: they are what
makes iteration order deterministic, and therefore what makes decisions reproducible.

Everything that changes the image is a `detail::Mutation` with a fixed set of fields. A mutation
is validated, journaled, applied and audited exactly once, and replaying the durable records
reproduces the same image byte for byte.

## Evaluation

`detail::evaluate_query` is pure: it takes an image and a query and returns a decision, without
touching anything. That is what makes "the same question against the same state gives the same
answer" a structural property rather than a hope.

The pipeline:

1. **Validate the question.** A malformed identifier, an unregistered subject, an unusable scope
   or an epoch from the future is `REJECTED`. Nothing is guessed.
2. **Check the epoch claim.** A question asked as of a superseded epoch is `STALE`.
3. **Check the required generations.** A caller that demands a generation the fabric has not
   reached is `STALE`.
4. **Collect evidence.** Direct assignments for the subject, then — if there are none — walk the
   subject's ancestors in deterministic order (breadth-first by distance, ascending identifier
   within a distance) and take the closest ancestor that offers anything.
5. **Bind each candidate.** An assignment is usable only when its publisher incarnation still
   holds live authority, its epoch is current, and its subject, scope, class and policy
   generations all match the live definitions. Everything else becomes *refused evidence* with
   the reason it was refused.
6. **Filter exceptions.** An assignment declared as an exception that names a class to displace
   only applies when a strictly broader scope actually offers that class.
7. **Choose the deciding level.** The narrowest scope with usable evidence, unless a broader
   scope declares itself non-overridable, in which case that scope decides.
8. **Resolve.** One class at the deciding level is the answer. Several different classes are a
   conflict: reported always, resolved only if a policy says how, denied otherwise.
9. **Explain and digest.** The chain, the displaced evidence, the refused evidence, the conflict
   statements and a SHA-256 digest over the whole decision.

See `docs/SEMANTICS.md` for the rules in full and `docs/DURABILITY.md` for how state survives a
crash.

## Locking

One `std::shared_mutex` per runtime guards the authoritative image. Evaluation takes it shared;
mutation takes it exclusive. A separate statistics mutex is only ever acquired *after* the state
lock, never before, so the two cannot form a cycle. No callback, no I/O completion and no user
code runs while the state lock is held, and nothing in the runtime re-enters a public method from
inside a lock.

The node adds a bookkeeping mutex for its worker list. `stop()` takes what it needs from that
mutex, releases it and joins workers outside it, because a worker takes the same mutex on its way
out and holding it would deadlock the very work being awaited. A worker that somehow asked for
shutdown detaches itself instead of trying to join itself.

## Shutdown

`FabricNode::stop()` stops accepting, closes the listener, shuts down every live socket so
blocked reads return, joins every worker, and only then closes the runtime. A second caller waits
for the first instead of racing it. Cancelled work cannot report success: a connection that
disappears mid-request has its reply dropped and its mutations either committed before the
authoritative boundary or not committed at all.

## Platform layer

`src/fsutil.hpp` and `src/net.hpp` are the only places that touch the operating system.
Everything above them is portable C++20. The Windows path uses `CreateFileW`/`_wsopen_s`,
`FlushFileBuffers` through `_commit`, `MoveFileExW` for atomic replacement and a zero-sharing
handle for the state directory lock. The POSIX path uses `open`/`fsync`/`rename`,
`flock(LOCK_EX|LOCK_NB)` and the usual socket calls.
