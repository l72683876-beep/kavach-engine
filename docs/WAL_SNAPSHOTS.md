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

This document is the design for fixing that with periodic snapshots plus log compaction,
without giving up persist-before-ack.

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

Format: one file, `snapshot-<seq>.bin`, little-endian, with a fixed magic + version header,
then length-prefixed sections. A SHA-256 of the section contents goes in the trailer; a
snapshot that does not match its checksum is never loaded, and the loader falls back to
full log replay (correct, just slower).

## Trigger policy

Three triggers, whichever comes first:

1. **Volume**: every 10,000 committed events (configurable `-snapshot-every`).
2. **Time**: at most one snapshot per 5 minutes while under load (configurable
   `-snapshot-interval`), so recovery stays bounded even if a huge burst is split
   into many small writes.
3. **Idle**: on graceful shutdown, always snapshot.

Snapshots run on a dedicated goroutine against a copy-on-write view: the engine already
serializes writes through its commit path, so the snapshotter takes the same lock once,
drains state into buffers, and releases before doing any I/O. No request ever waits on a
disk write it did not itself trigger.

## Crash safety, in the exact order that matters

1. Write `snapshot-<seq>.bin.tmp`, fsync the file.
2. Write `snapshot-<seq>.bin` (rename is atomic on POSIX), fsync the directory.
3. Write `snapshot-<seq>.offset` containing the byte offset in the CURRENT WAL segment
   the snapshot was taken at, fsync.
4. Rotate the WAL: subsequent writes append to `bookings-<seq+1>.log`.
5. Delete segments with a lower sequence than the snapshot's, only after 4's file exists
   and is fsynced.

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

`replayLogs` gains a preamble: find the newest `snapshot-<seq>.bin` with a valid trailer,
load it, then replay only segments with sequence >= the snapshot's segment and only bytes
after the recorded offset. Log line format is unchanged, so a deployment can roll back to
an engine without snapshot support by deleting snapshot files; the old replay path
continues to work on any surviving logs.

## Metrics and verification

- `/metrics` gains: `kavach_snapshots_total`, `kavach_last_snapshot_age_seconds`,
  `kavach_recovery_replayed_lines` (the number that matters for restart time).
- `sim/snapshot_test.py`: book N seats, snapshot mid-stream, kill -9 the engine mid-write,
  restart, and assert exact state equality against a reference engine that never
  crashed. This joins the nightly battery.

## Implementation plan

1. Snapshot writer/loader + offset-based tail replay, off by default
   (`-snapshot-every 0`), behind the same flag surface as the rest of the engine.
2. Enable by default in the demo (`-snapshot-every 10000 -snapshot-interval 5m`).
3. `sim/snapshot_test.py` chaos coverage + battery case.
4. Cluster mode ties in later: snapshots become the seed for a follower catch-up, which
   is the next doc after this one.

Estimate: writer + loader + replay wiring is the bulk of the work, roughly 300-400 lines
against the existing lock discipline; the chaos test is the part that must not be rushed.
