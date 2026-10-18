# Cluster mode: multi-shard, replication, failover

This is the first milestone of v2. Everything before it made one process as correct and
as fast as it can be; this document is about what happens when one process is no longer
the right size, or when it must survive its own death.

Kavach's core loop is single-threaded per inventory with an fsync-before-ack commit path.
That single-writer property is the source of its correctness (no double-sell is possible
because there is exactly one writer), and cluster mode is designed to PRESERVE it, not to
replace it with distributed consensus over every seat.

## Principle: shard by inventory, never by seat

The unit of sharding is an inventory (an event's seat map), chosen by a stable hash of the
inventory key. All operations on one inventory run on exactly one node. A booking across
two inventories is two single-writer operations coordinated above the engine, the same way
two banks coordinate a transfer; the engine's own guarantee stays "this inventory is never
double-sold by the node that owns it".

This keeps the hot path untouched: the 85ns limiter, the slice-offset seat scan, and
group-commit fsync all remain per-node code paths. Cross-shard reads (a global seat count
across a sharded event) are served by the router summing per-shard views and are explicitly
eventual; `/seats/state` on a sharded inventory returns per-shard breakdowns instead of
pretending to a global instant.

## Replication: the WAL is the replication stream

The existing bookings/holds log is already an ordered, fsynced, replayable event stream
with a deterministic replayer (`replayLogs`). Replication ships that stream instead of
inventing a second one.

- Followers tail the leader's segments over a plain TCP stream (`/internal/replicate`,
  authenticated with the same HMAC scheme as the client API, separate keys).
- Followers apply events through the same replay path, so a follower is byte-for-byte the
  state machine the leader is. No new apply logic, no drift.
- Default is asynchronous (a leader ack does not wait for followers). `-replicate-sync=1`
  waits for at least one follower to confirm the offset before acking: stronger guarantee,
  one extra network round trip on the commit path, off by default.

With WAL snapshots (see WAL_SNAPSHOTS.md), a new follower does not replay from the dawn of
time: it downloads the leader's latest snapshot plus the tail after its offset.

## Failover: epochs, leases, and what we refuse to promise

Leader identity is a lease, not a vote:

- Each leader holds a leased epoch number (a lease file + a small majority-heartbeat
  quorum of 3 nodes, one node is majority of itself in single-node clusters).
- Followers refuse writes from an epoch below the highest they have seen; a stale leader
  coming back cannot resurrect itself. This is the mechanism that makes split-brain
  refuse to serve, and it costs two lines in the write path.
- On leader loss, followers detect a lapsed heartbeat within the lease TTL (default 3s,
  `-lease-ttl`), the majority elects the follower with the highest applied offset, and it
  bumps the epoch.

What we state honestly in the README: with async replication, a crash may lose the last
few milliseconds of acked bookings on the old leader; those clients see a 409/unknown on
retry because the idempotency key did not survive, and the engine's answer is the same as
every serious system's: retry with the same idempotency key. With `-replicate-sync=1` the
RPO is zero at the cost of the round trip.

## Routing

A routing layer in front of shards (stateless, any node can serve it, SDK-implemented
first):

1. `/cluster/topology` returns the shard map with epochs (signed by the cluster's shared
   key). The Python and JS SDKs cache it with a TTL and retry once on a stale-shard 308.
2. Requests carry the inventory key in the path (`/book` gains an inventory scoping
   already present in the payload); the router hashes it, forwards to the shard owner.
3. A shard mid-failover answers 503 + `Retry-After` with its new owner's address.

## What is deliberately NOT in v2.0 of cluster mode

- No multi-shard transactions with 2PC. Cross-inventory booking is a documented
  application-level pattern (reserve on both, confirm or release), which the existing
  `/reserve` + TTL design already makes safe.
- No dynamic resharding in the first cut. Shard count is fixed at formation; rebalancing
  (moving an inventory between nodes with a lease handoff and log tail transfer) is
  phase 2.
- No Paxos/Raft library. The lease + epoch + highest-offset election is intentionally
  smaller and auditable, and is enough for the guarantee we sell.

## Chaos coverage

The chaos suite extends with: kill -9 leader mid-group-commit, network partition between
leader and follower for 10s then heal (assert zero double-sell on both sides after
reconciliation), stale-leader writes after failover (must 409), and follower apply-lag
under the k6 load test. Each case joins the nightly battery, and the pass condition is
always the same: after any sequence of failures, a seat is never sold twice.

## Phases

1. Segment streaming + follower apply (the WAL is reused; smallest step, biggest win).
2. Epoch/lease failover with the 3-node majority.
3. `/cluster/topology` + SDK routing.
4. Snapshot-based follower bootstrap (depends on WAL_SNAPSHOTS.md landing first).
5. Chaos suite extension + docs + a `docker-compose` 3-node demo for the README.

Rough shape: phases 1-2 are where the real hard lines live (replication protocol,
election, epoch checks in the write path, roughly 1.5-2k lines); 3-4 are thin; 5 is the
part reviewers will actually run.
