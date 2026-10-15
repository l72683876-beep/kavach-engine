# Demo videos

Real recordings of the engine under live HTTP load. Nothing here is a mock:
every frame comes from an actual run, and every number is read from the run's own logs.

## 1. kavach_demo.mp4 (~1 min) - the stampede and the crash

- **Scene 1:** 12,000 requests hit a 200-seat engine at once. 200/200 seats sell, each exactly once. Zero double-sell.
- **Scene 2:** Faults injected mid-run: contained worker panics and random stalls, the engine keeps answering. Then a SIGKILL in the middle of the rush: 297 connections refused while the node is down. On restart, the engine replays its event log and restores all 200 bookings. Traffic resumes, still zero double-sell.

## 2. kavach_big.mp4 (~1 min) - the million-request rounds

- **Round 1:** 1,000,000 requests over ~9 minutes against a 5,000-seat engine. Per-second peak 3,077 req/s, median ~2,300 req/s, 5,000/5,000 confirmed, 0 errors, median p95 ~330 ms.
- **Round 2:** 2,000,000 requests over ~18 minutes against one 20,000-seat engine, with no rate limiting. 20,000/20,000 confirmed, 0 errors, median p95 ~500 ms.
- **Combined:** 3,000,000 requests. Zero double-sell, zero oversell, zero hangs. Booking logs were re-read and seat totals re-checked after both rounds.

## Honest caveats

- Both rounds ran on a shared 2-core box while the load generator ran on the same box, so throughput is a floor, not a ceiling.
- Latency p95 grows under sustained full load (~500 ms) but the queue never hangs and never drops a confirmed booking.
- At IRCTC scale you run the v2 multi-node mode: seat-range sharding across nodes scales these numbers horizontally.

The benchmark methodology and raw numbers are in [BENCHMARK_K6.md](../BENCHMARK_K6.md).
