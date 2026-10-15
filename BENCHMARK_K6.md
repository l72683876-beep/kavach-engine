# Kavach k6 Benchmark (official)

Tool: Grafana k6 v0.54.0 (industry-standard open-source load tester).
Date: 15 October 2026. Script: `sim/k6_benchmark.js`.

Environment: one container, 2 CPU cores, 4 GB RAM. The k6 load generator and
the engine share the same 2 cores, so every number here is conservative: on
dedicated hardware the engine gets both cores to itself.

Scenario: 200 virtual users ramping over 10 s, then 30 s sustained. Every
iteration is a full cart flow: `POST /reserve` (1 seat) then `POST /confirm`.
Engine: 8 workers, local mode, rate limiters off (we are measuring the
engine, not the bot wall).

## Results

| Metric | v1.6 (fsync per write) | v1.7 (group commit) |
|---|---|---|
| HTTP requests | 9,462 | 91,354 |
| Throughput | 229.7 req/s | 2,276.6 req/s (9.9x) |
| Failures | 0 | 0 |
| Checks | 100% | 100% |
| Complete cart flows (reserve + confirm) | 4,731 | 45,677 |
| Duplicate seats | 0 | 0 (verify.py) |
| Latency p50 | 811 ms | 74 ms |
| Latency p95 | 1.2 s | 139 ms |
| Latency avg | 753 ms | 76 ms |

Same workload, same tool, same box; the only change between the two runs is
group commit. Every durability guarantee is unchanged: a response is only
sent after its record is fsynced to disk.

## The story

v1.6 paid one disk sync per write: every reserve and every confirm fsynced
the event log before its response, capping throughput near 230 req/s. v1.7
adds group commit: the writer goroutine takes the first pending write,
drains everything already queued behind it, writes the whole batch, syncs
ONCE, then releases every writer in the batch. Nothing is acknowledged
before it is on disk, but hundreds of bookings now share one disk sync.

## What still limits us

The 2-core container is the ceiling now: the k6 client and the engine share
both cores, and p95 (139 ms) reflects CPU contention, not the fsync path.
On dedicated hardware the same engine has headroom well beyond this box.
The next structural step is multi-node mode (Redis-backed), which scales
horizontally instead of vertically.
