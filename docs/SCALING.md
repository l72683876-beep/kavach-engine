# Scaling Kavach: the five challenges after multi-shard, and their answers

Written Oct 19, 2026 after multi-shard (phase 2b) shipped. Each challenge is
either solved, an operator pattern that already works, or an honest roadmap
item. Nothing here changes default behavior: `-shards=1` and `-peers=""` are
byte-identical to the single-node engine.

## 1. Cross-shard totals (SOLVED)

One event lives on exactly one shard, so no single shard knows the global
picture. The aggregation is built in:

- `GET /metrics` on a multi-shard process sums every counter across shards
  and includes per-shard views under `shard_metrics`.
- In cluster mode, `GET /metrics` on the leader additionally sums across
  nodes (`cluster: true, total, sold, held, free, nodes`), so a global
  "total sold" is one request, no client-side math.

## 2. Hot-key skew (OPERATOR PATTERN)

A viral event lands its whole inventory on one shard while others idle.
Kavach already supports the fix without new code: split the hot event into
sub-inventories by suffix key. Event keys allow `[A-Za-z0-9._:-]`, so
`concert.n1`, `concert.n2`, ... each hash to a different shard and each is
its own inventory with its own writer, WAL and idempotency store. Ten
sub-shards multiply capacity tenfold. Total sold is the sum of the parts
(one `/metrics` call). The per-shard views in `/metrics` show the skew as it
happens, which tells the operator when a split is needed.

## 3. Rebalancing when the cluster changes (ROADMAP)

`-peers` seat slices are computed from the node list at startup: adding or
removing a node changes the mapping. The design that avoids rehash pain:

- Route by a FIXED logical shard space (for example 64 logical shards per
  node's share), never by node count, so events never remap when the
  cluster grows.
- Moving a shard then means moving a whole inventory once: snapshot the
  shard, transfer snapshot + WAL tail, flip routing. Planned endpoints:
  `/internal/export-shard` and `/internal/import-shard`.

Until that ships: fix the node count for the event window, and use the
sub-shard pattern above to grow capacity inside the existing nodes instead
of adding nodes mid-sale.

## 4. Multi-node cost (SOLVED LOCALLY, GUIDED REMOTELY)

`docker-compose.yaml` in the repo root boots a full 3-node cluster
(leader + 2 followers, replication, seat slices) on one machine for free:

    docker compose up --build

Guidance for hosting: Render's free tier runs ONE instance; a paid single
instance, or one small VPS, is where a real cluster belongs. The free
single node plus the watchdog stays the zero-cost setup.

## 5. Benchmark rerun (BASELINE RECORDED)

v2 rerun, Oct 19 2026, in-process Go benchmarks, 2 vCPU Xeon, `-shards=1`
baseline (multi-shard adds routing on top of these paths):

    BenchmarkLimiterAllow       9,517,434 ops   129.1 ns/op
    BenchmarkBookInProcess          595 ops   2,063,125 ns/op (~2.1 ms)
    BenchmarkSeatsReadInProcess  69,337 ops      15,434 ns/op (~15 us)

The 2.1 ms book path is dominated by persistence (fsync-style WAL write +
ack before confirm), which is the durability guarantee, not overhead to
remove. Reads are microseconds. Launch-day plan: k6 run (sim/k6_benchmark.js)
against a deployed multi-shard instance for end-user numbers.
