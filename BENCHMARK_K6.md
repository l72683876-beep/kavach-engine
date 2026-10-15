Tool: Grafana k6 v0.54.0 (industry-standard open-source load tester).
Date: 15 October 2026. Script: `sim/k6_benchmark.js`.

Environment: one container, 2 CPU cores, 4 GB RAM. The k6 load generator and
the engine share the same 2 cores, so every number here is conservative: on
dedicated hardware the engine gets both cores to itself.

Scenario: 200 virtual users ramping over 10 s, then 30 s sustained. Every
iteration is a full cart flow: `POST /reserve` (1 seat) then `POST /confirm`.
Engine: 5,000 seats, 8 workers, local mode, rate limiters off (we are
measuring the engine, not the bot wall).

## Results

| Metric | Value |
|---|---|
| HTTP requests | 9,462 (229.7 req/s) |
| Failures | 0 |
| Checks | 100% (9,462 / 9,462) |
| Complete cart flows (reserve + confirm) | 4,731 |
| Seats sold | 4,731, duplicate seats 0 (verify.py) |
| Latency | p50 811 ms, p95 1.2 s, avg 753 ms |

## Finding: the fsync wall

The dominant cost is persist-before-ack: every reserve and every confirm
fsyncs the event log BEFORE its response is sent. On this container that is
one disk sync per write, which caps throughput near 230 req/s and puts p95 at
1.2 s. The durability guarantee is right; the implementation shape is not.

Production engines solve this with group commit: concurrent writes are
collected into a batch, one fsync covers the whole batch, then every response
in the batch is released. Nothing is acknowledged before it is on disk, so
the guarantee is unchanged, but hundreds of bookings share one disk sync
instead of paying for one each. Group commit is the next engine milestone;
until it lands, these numbers are the honest baseline.
