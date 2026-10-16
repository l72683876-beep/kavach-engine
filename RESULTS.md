# Kavach Test Results

All runs below were executed on 15 October 2026 in a single sandbox (2 vCPU, 4 GB RAM) using the bundled load simulator (`sim/simulate.py`) and checked for accuracy with `sim/verify.py`. The engine ran as a single binary process with no tuning: `-seats N -workers 8`.

The invariant we test for: **with N seats, exactly N bookings succeed, no seat is sold twice, and every request gets a definitive answer** — no matter how many requests arrive.

## Run A — Burst (Tatkal-style rush)

20,000 users fired as fast as they could at 5,000 seats.

| Metric | Result |
|---|---|
| Requests sent | 20,000 |
| Confirmed bookings | 4,577 (exactly 5,000 seats, each sold once) |
| Sold-out responses | 15,423 |
| Errors | 0 |
| Queue-full rejections | 0 |
| Wall time | 23.5 s |
| Server latency p50 / p95 / p99 | 0.005 ms / 0.02 ms / 5.6 ms |
| Accuracy check | PASS — 0 duplicate seats, 4,577 unique booking IDs |

Run A bookings vs seats: 4,577 bookings carried exactly 5,000 seats because 10% of
users in `sim/simulate.py` request two seats per booking. The split: 4,154 single-seat
bookings + 423 two-seat bookings. `sim/verify.py` now prints the seats-per-booking
histogram explicitly, so both numbers reconcile from the same log every time.

## Run B — Hammer (one million requests)

1,000,000 requests from 100,000 identities (10% bots) at 2,000 seats, run to completion.

| Metric | Result |
|---|---|
| Requests sent | 1,000,000 |
| Confirmed bookings | 2,000 (exactly, no double-sell) |
| Sold-out responses | 998,000 |
| Errors | 0 |
| Wall time | 480 s (2,083 req/s, capped by the Python simulator client, not the engine) |
| Server latency p50 / p95 / p99 | 0.004 ms / 0.011 ms / 1.13 ms |
| Engine memory during run | ~410 MB |
| Accuracy check | PASS — 0 duplicate seats, 2,000 unique booking IDs |

## Run C — Bot flood

50 identities, 50% of them bots that retry aggressively; 30,000 logical requests become 135,033 actual HTTP requests (2,123 req/s) aimed at 2,000 seats.

| Metric | Result |
|---|---|
| Requests hitting the engine | 135,033 |
| Confirmed bookings | 2,000 (exactly, no double-sell) |
| Rate-limited at the edge | 128,575 (95% of the flood never touched inventory) |
| Sold-out responses | 4,458 |
| Errors | 0 |
| Bot give-ups (after max retries) | 23,542 |
| Server latency p99 | 0.28 ms |
| Accuracy check | PASS — 0 duplicate seats, 2,000 unique booking IDs |

What this shows: a retry storm does not multiply load on the inventory. The limiter absorbs it at the edge and real bookings still go through.

## Run D — Chaos (engine frozen mid-run)

100,000 requests from 100,000 identities at 2,000 seats. At the 20-second mark the engine process was frozen (SIGSTOP) for 15 seconds, then resumed (SIGCONT) mid-run.

| Metric | Result |
|---|---|
| Requests sent | 100,000 |
| Confirmed bookings | 2,000 (exactly, no double-sell) |
| Sold-out responses | 98,000 |
| Errors | 0 |
| Requests lost during the freeze | 0 — every request received a definitive answer |
| Wall time | 47.2 s |
| Server latency p50 / p95 / p99 | 0.003 ms / 0.010 ms / 1.72 ms |
| Accuracy check | PASS — 0 duplicate seats, 2,000 unique booking IDs |

## Notes and honest limits

- The engine holds all inventory in memory with atomic compare-and-swap updates and an append-only JSONL booking log. This is why it is fast and why a crash-freeze costs no correctness: the log is the truth.
- These runs were bound by the simulator client (~2,100 req/s from one sandbox). The engine's own p99 latency stayed under 6 ms throughout, which is where the headroom lives.
- Single-node only for now. The documented path to multi-node (a Redis-backed lock/inventory layer) is design-stage, not tested. Do not run a lottery or a real Tatkal sale on the single-node build without your own review.
- Bots in Run C used fixed identities. Attackers rotating identities defeat naive per-user limits; the honest defense there is an edge layer (CDN/WAF) plus capacity shaping, which is deployment, not this codebase.
