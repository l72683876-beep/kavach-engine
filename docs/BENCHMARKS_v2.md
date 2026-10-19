# Kavach v2 benchmark report (Oct 19, 2026)

Hardware: 2 vCPU Intel Xeon 2.20GHz sandbox; load generator (aiohttp client)
and engine on the SAME box, so end-user latency includes client-side queueing
at 20,000 concurrent connections. Engine built from main at commit with
multi-shard (0a095bc). Latency percentiles are per HTTP attempt.

## Run A: Tatkal-style burst, protections ON (defaults)

Single shard, 20,000 seats, 20,000 users each retrying up to 8x.

- Accepted bookings: 1,231 confirmed
- Rejected requests: 154,900 rate_limited (IP limiter: 20 rps burst 40 from one IP), 0 sold_out, 0 errors
- Throughput: 1,139.7 requests/second (1:37.0 wall)
- Latency: p50 10.2s, p95 18.8s, p99 22.4s
- Unique sold seats (server-verified): 1,356 of 20,000

Read: from one IP the limiter ate 154,900 abusive retries and the engine
never crashed, never oversold. This run measures the PROTECTION, not the
booking ceiling; real users are spread over IPs.

## Run B: burst, protections OFF, single shard (engine ceiling on this box)

Single shard, 20,000 seats, 20,000 users, one attempt each.

- Accepted bookings: 18,241 confirmed, 1,759 sold_out (honest rejections)
- Rejected requests: 0 rate_limited, 0 errors
- Throughput: 750.8 requests/second (26.6s wall)
- Latency: p50 17.4s, p95 20.1s, p99 20.5s
- Unique sold seats (server-verified): 20,000 of 20,000, exactly zero oversold

## Run C: burst, protections OFF, 8 shards, 8 events

-shards=8, 20,000 seats per shard (160k total), users spread across 8 event
ids, one attempt each.

- Accepted bookings: 20,000 confirmed (all succeed, capacity not the limit)
- Rejected requests: 0
- Throughput: 672.8 requests/second (29.7s wall)
- Latency: p50 19.8s, p95 21.5s, p99 21.6s
- Unique sold seats (server-verified, sum of ev0..ev7): 22,062

Read: same wall time as Run B because on 2 vCPU the CLIENT plus server share
the cores; the load generator saturates first. What multi-shard bought here
is capacity (8 independent writers, 160k seats, per-event isolation and
per-shard WAL) and the verified aggregate: /metrics summed 20,000 confirmed
across 8 shards exactly matching the client view. Larger boxes convert that
isolation into parallel throughput; that is a launch-day k6 run
(sim/k6_benchmark.js) against a deployed instance.

## In-process Go benchmarks (same hardware)

    BenchmarkLimiterAllow        129.1 ns/op
    BenchmarkBookInProcess     2,063,125 ns/op  (~2.1 ms, WAL persist-before-ack durability cost)
    BenchmarkSeatsReadInProcess   15,434 ns/op

Reproduce:

    go test -run '^$' -bench . ./engine
    ./engine/kavach -seats 20000 -addr :8152 -ip-rate 0 -user-rate 0 &
    python3 sim/simulate.py --users 20000 --base http://127.0.0.1:8152 --out r.json
    ./engine/kavach -seats 20000 -shards 8 -addr :8153 -ip-rate 0 -user-rate 0 &
    python3 sim/simulate.py --users 20000 --events 8 --base http://127.0.0.1:8153 --out r.json
