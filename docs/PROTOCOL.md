# Protocol

The framed protocol carries every client request to a node. It is little-endian, explicit about
lengths, and rejects anything it does not fully understand.

## Frame

```
u32 magic          0x50465731 ("PFW1")
u16 format         PRIORITY_FABRIC_FORMAT_VERSION (1)
u16 op             see below
u32 flags          reserved; a non-zero value is rejected, not ignored
u64 request id     echoed in the reply; a reply naming a different id is refused
u32 payload length
payload
u32 crc32c         over the 24 header bytes followed by the payload
```

The decoder refuses a wrong magic, a wrong format version, non-zero flags, a length above
`Limits::max_frame_payload`, a truncated body and a checksum mismatch **before** looking at the
payload. A connection that sends any of those is answered with an `Error` frame and then closed:
a peer that cannot frame correctly gets no further service.

## Operations

| Op | Value | Request payload | Reply payload |
| --- | --- | --- | --- |
| `Hello` | 1 | publisher id, boot id, client label, nonce | node id, node boot, epoch, token, state generation, pid |
| `DefineClass` | 10 | session, class definition | generation |
| `DefineScope` | 11 | session, scope definition | generation |
| `DefinePolicy` | 12 | session, policy definition | generation |
| `DefineSubject` | 13 | session, subject definition | generation |
| `Assign` | 14 | session, assignment | generation |
| `Retire` | 15 | session, assignment id, reason | generation |
| `Query` | 20 | session, query | full decision |
| `AdvanceEpoch` | 30 | session, reason | epoch |
| `Fence` | 31 | session, publisher id, boot id, reason | empty |
| `Stats` | 40 | session | fabric and state counters |
| `Checkpoint` | 41 | session | generation |
| `Audit` | 42 | session | audit entries |
| `Integrity` | 43 | session | integrity report |
| `Ping` | 50 | session | empty |
| `Shutdown` | 60 | session | empty |
| `Response` | 100 | — | the typed reply above |
| `Error` | 101 | — | status code and bounded message |

Every request other than `Hello` begins with a length-prefixed **session block**: publisher id,
boot id, epoch and fencing token. The node re-validates that block against the live authority
table on every request, so a cached session cannot outlive a fence, an epoch advance or a
takeover.

## Replies

A `Response` frame's payload is the canonical encoding of the operation's result. An `Error`
frame carries a 16-bit `StatusCode` and a bounded message; the client turns it back into a
`Status` so a caller sees the same code it would see in-process. A question the fabric can answer
with `REJECTED` is a *successful* reply carrying a decision, not an error: the client learns the
fabric's reasoning instead of a bare failure.

## Limits

`Limits::max_frame_payload` (4 MiB by default) bounds every payload,
`Limits::max_requests_per_connection` bounds how many requests one connection may send, and
`Limits::max_connections` bounds concurrency. A connection beyond the ceiling is refused over the
wire with `LimitExceeded` rather than dropped silently.

## Security boundary

The transport is unauthenticated loopback TCP. The node refuses to bind a non-loopback address
unless explicitly overridden on the command line, and the override is audited. Authority binding
prevents a stale, duplicated or superseded writer from corrupting state; it does not authenticate
a hostile local peer and does not encrypt anything. Do not expose a node to an untrusted network.
