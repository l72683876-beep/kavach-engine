# WAL snapshots and compaction

Kavach's durability story today is simple and correct: every write is appended to the
bookings and holds logs and fsynced (batched by group commit) BEFORE the caller gets its
ack. On restart, `replayLogs` replays both logs from line zero and rebuilds the inventory,
reservations, waitlist and idempotency state.

That is also the ceiling of the current design. The logs only ever grow. A service that
books 10,000 seats a day accumulates tens of megabytes of log per month, and recovery time
is linear in log size: a restart after a crash replays every line ever written, even though
99% of them describe holds that expired hours ago and bookings superseded long ago. At
flash-sale scale the log grows fastest exactly when recovery matters most.

This document specifies periodic snapshots plus log compaction, without giving up
persist-before-ack. **Status: SHIPPED** (2026-10-18), off by default; enable with
`-snapshot-every N` and/or `-snapshot-interval T`. Implementation lives in
`engine/snapshot.go`, chaos coverage in `sim/snapshot_test.py`.

## Design in one line

Every N writes (and every T seconds of inactivity), the engine dumps the complete live
state to a new snapshot file, fsyncs it, records the log offset it was taken at, then
rotates the WAL: new writes go to a fresh segment, and the old segments below the snapshot
point are deleted. Recovery becomes "load snapshot + replay only the tail".

## Snapshot contents

A snapshot must capture everything replayLogs reconstructs:

- **Inventory**: full seat map with per-seat owner/tenant state (sold, held, reserved).
- **Reservations**: every reservation with its id, tenant, user, seats and expiry.
- **Holds**: every live hold with its expiry (the hold-ttl sweeper regenerates expiry
  sweeps at startup, so only live holds matter).
- **Waitlist**: entries with their sequence numbers, so `waitlistSeq` is preserved exactly.
- **Idempotency store**: recent idempotency keys with their results. Older entries can be
  dropped; a client retrying with an entry older than the snapshot window is safe to
  re-execute (the original request was from before the last snapshot).
- **Counters**: booking-id and reservation-id sequences, waitlist sequence.

Format: one file, `snapshot-<seq>.bin`, little-endian: a 4-byte magic ("KVS1"), a version
word, an 8-byte payload length, the payload itself (JSON: seat map, reservations with
their idempotency alias index, waitlist with sequence, recent idempotency entries), and a
SHA-256 of the payload in the trailer. A snapshot that does not match its checksum is
never loaded, and the loader falls back to
full log replay (correct, just slower).

## Trigger policy

Three triggers, whichever comes first:

1. **Volume**: every N committed events (`-snapshot-every`, 0 = off).
2. **Time**: after T seconds with new events (`-snapshot-interval`, 0 = off), so recovery
   stays bounded even if a huge burst is split into many small writes.
3. Graceful-shutdown snapshotting is future work; a crash simply replays the short tail.

Snapshots run on a dedicated goroutine against a copy-on-write view: the engine already
serializes writes through its commit path, so the snapshotter takes the same lock once,
drains state into buffers, and releases before doing any I/O. No request ever waits on a
disk write it did not itself trigger.

## Crash safety, in the exact order that matters

The cycle (`Engine.runSnapshot`):

1. Freeze writers (the engine freeze lock), wait for group commit to fsync every
   submitted line, copy state and record each log's durable byte offset in memory.
2. Unfreeze: requests resume immediately; they append to the old segment beyond the
   recorded offset, so nothing is lost while the snapshot file is written.
3. Write `snapshot-<seq>.bin.tmp`, fsync, rename to `snapshot-<seq>.bin` (atomic on
   POSIX), fsync the directory. The offsets live inside the snapshot payload.
4. Rotate both WALs through the group committer (so rotation serializes behind pending
   writes): `bookings.jsonl` becomes `bookings.jsonl.snap-<seq>`, a fresh live log opens.
5. Prune snapshot files and segments below `seq-1` (two-deep retention).

If the process dies between any two steps, recovery resolves like this: if a complete
snapshot with a valid checksum and an offset file exists, load it and replay the tail of
the segment(s) after that offset; otherwise replay all segments from the start, exactly as
today. Every intermediate state lands in one of those two cases, never a third.

A subtle point: the snapshot records the offset AFTER the last event it included, and
events are only included if their group-commit fsync had already completed, so the
snapshot can never run ahead of the durable log.

## Compaction and retention

- Segments below the newest valid snapshot are deleted after one safety margin: a second
  completed snapshot must exist first. Deleting the only snapshot is never an option.
- Snapshots are kept 2-deep (current + previous). 20000 seats of state is roughly a few
  MB, so disk cost is negligible on any tier including Render's free plan.
- The idempotency store inside the snapshot keeps the last 10 minutes of keys (one hold
  window + slack), matching replay's existing TTL pruning.

## Recovery path

`recoverState` finds the newest `snapshot-<seq>.bin` with a valid trailer, applies it, then
replays only segments with sequence >= the snapshot's and only bytes after the recorded
offset. A corrupted newest snapshot falls back to replaying every segment from zero.
Snapshot numbering continues from disk across restarts, so a fresh run never overwrites a
snapshot file an older recovery path may still need. Log line format is unchanged, so a
deployment can roll back to an engine without snapshot support by deleting snapshot files;
the old replay path continues to work on any surviving logs.

## Metrics and verification

- `/metrics` carries: `snapshots_total`, `last_snapshot_age_seconds`,
  `recovery_replayed_lines` (the number that matters for restart time).
- `sim/snapshot_test.py`: 18 checks; books, snapshots mid-stream, kill -9 mid-flight,
  restarts, and asserts exact state equality, idempotency replay, waitlist survival and
  2-deep segment compaction. It runs in `scripts/test.sh --full`.

## Implemented and next

1. DONE: snapshot writer/loader, offset-based tail replay, volume + interval triggers,
   two-deep pruning, metrics, `sim/snapshot_test.py` (18/18), wired into
   `scripts/test.sh --full`.
2. Demo enablement: flip the flags in the Render service once a soak run confirms
   steady-state behavior (default stays off, so enabling is a one-flag change).
3. Cluster mode ties in later: snapshots become the seed for a follower catch-up, which
   is the next doc after this one.
