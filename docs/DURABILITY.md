# Durability

## On-disk layout

```
<state>/
  manifest.pfm     fixed-size, integrity-checked, atomically replaced
  snapshot.pfs     full canonical state image, self-describing and self-checked
  journal.pfj      the first journal segment (record log)
  journal.<n>.pfj  later segments, replayed in ascending order
  key.pfk          per-store MAC key; records are tamper-evident under it
  lock.pfk         exclusive lock held while a runtime has the directory open
```

A state directory is opened with an exclusive lock (`CreateFileW` with a zero sharing mode on
Windows, `flock(LOCK_EX|LOCK_NB)` elsewhere). The operating system releases it when the holding
process dies for any reason, so a crashed node never leaves a stale lock behind, and two live
writers on one store are impossible rather than merely unlikely.

## Record format

```
u32 magic 'PFJ1' | u16 format | u16 kind | u64 sequence | u32 payload length | u32 payload CRC
payload
16-byte authentication tag = HMAC-SHA256(store key, header || payload)[0..16)
```

The framing checksum catches a torn or damaged write. The authentication tag catches a record
that was altered by something that could recompute the framing checksum, because that something
does not have the store key. Both are checked on every read; a scan stops at the first byte it
cannot verify and never resynchronizes on a magic value found inside a corrupt region.

## Commit protocol

```
validate   the mutation is checked against the live image and cannot fail later
bind       the mutation carries publisher, boot, epoch and fencing token
plan       the resulting state generation is computed and recorded in the record
reserve    durable growth bounds are checked before anything is written
journal    a Pending record is appended and flushed to the platform
perform    the mutation is applied to the in-memory image
verify     the applied generation is compared with the planned generation
commit     a Commit record naming the pending sequence is appended and flushed
retire     a checkpoint folds the journal into a snapshot and drops old segments
```

Nothing is acknowledged before the `Pending` record is durable. The `Commit` record names the
pending sequence and the SHA-256 of its encoded payload, so a commit can never be attributed to
the wrong mutation.

## Recovery

```
manifest -> snapshot -> journal segments named by the manifest -> replay -> normalize
```

Replay distinguishes four things:

* **durable configuration and history** — classes, scopes, policies, subjects, audit entries;
* **committed authoritative state** — a `Pending` record with its `Commit`;
* **unfinished attempts** — a `Pending` record with no `Commit`. It is rolled back and counted in
  `IntegrityReport::unfinished_attempts`;
* **evidence that failed verification** — a bad checksum, a bad tag, a gap in the sequence, a
  commit without a pending record, a record that decodes to something structurally invalid.

A trailing partial record on the last segment is a crash during append: it is discarded and the
file is truncated to the last good boundary, so later appends do not continue after unusable
bytes. The same condition on an earlier segment is corruption, because later segments exist and
their content would be ambiguous.

Any structural failure degrades the store. A degraded store opens — so an operator can inspect
and repair it — but it refuses every mutation and answers `REJECTED` with reason
`state_degraded` rather than guessing. `fail_on_degraded` turns the same condition into a refusal
to open at all.

## Normalization

Recovery restores facts, never liveness. A grant recorded as live is restored as expired; the
incarnation itself is kept, because it is a fact about the past. That is why reopening a store
and asking a question yields `FENCED` until the publisher explicitly asks for authority again.

`integrity_report()` performs a fresh replay from the bytes on disk, replays it a second time for
the comparison, applies the same normalization to both sides and compares SHA-256 digests, the
state generation and the epoch. A mismatch means the state being served is not the state the
bytes describe.

## Checkpoints

A checkpoint writes the full image to `snapshot.pfs` through a temporary file and an atomic
replace, writes a manifest that names the snapshot, the next journal segment and the sequence the
snapshot covers, then opens that segment and deletes the segments the manifest no longer
references. A crash at any point leaves a store that recovers: the manifest is always replaced
atomically, and a segment the manifest does not name is never read.

## Tamper evidence and its limits

The store key makes records tamper-*evident*: altering a record without the key is detected even
if the framing checksum is recomputed. It is not tamper-*proof*, and it does not authenticate an
actor. Anyone who can read `key.pfk` and write to the directory can produce a store this runtime
will accept. The key is created with owner-only permissions where the platform supports it, and
is never transmitted.
