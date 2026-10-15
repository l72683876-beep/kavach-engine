# Kavach

**Kavach** (Hindi for "armor") is an open-source booking engine built to survive a stampede:
millions of requests at once, no crashes, no hangs, and never a double-booked seat.
It is the kind of core machinery a system like IRCTC runs on, distilled into one small,
readable service that any app can put in front of its own logic.

Built to be learned from: every layer exists for a reason, and this README explains why.

## Why this exists

On a real Tatkal morning, thousands of people hit "book" in the same second.
Most systems die one of three ways: the database drowns, the process runs out of memory,
or the app hangs and users wait forever. Kavach is designed against those three failures:

1. **No request ever touches the database directly.** Requests flow through a pipeline;
   the database is written in batches behind it.
2. **The system accepts only what it can process.** A bounded queue sheds load with a clear
   "try again in N seconds" signal instead of collapsing. A rejection is recoverable; a crash is not.
3. **Correctness is a hard invariant.** A compare-and-swap on every seat means two workers
   can never hold the same seat, no matter how hard they race.

## The layers, in the order a request meets them

| Layer | What it does | Why |
|---|---|---|
| Edge | Validates, requires an idempotency key | Retries can never create two bookings |
| Rate limiter | Token bucket per user/key | Bots die here in microseconds, for free |
| Admission queue | Bounded, sheds when full | Backpressure instead of memory death |
| Worker pool | Fixed worker count pulls from the queue | Capacity is a setting, not a guess |
| Inventory cache | Seat map lives in memory, atomically updated | Reads never wait on the database |
| Seat lock | Atomic CAS per seat | Two people fight for seat 42: exactly one wins |
| Event log | Append-only JSONL of every booking | The durable record; the source of truth for audits |
| Metrics | Counters + latency percentiles at `/metrics` | You cannot fix what you cannot see |

## Quickstart (2 minutes)

```bash
# build and start the engine with 5,000 seats
cd engine
go build -o kavach .
./kavach -seats 5000 -workers 8

# book a seat (that's the whole API)
curl -X POST http://localhost:8080/book \
  -H 'Content-Type: application/json' \
  -d '{"user_id":"priya","idempotency_key":"priya-booking-1","seats":1}'
# {"status":"confirmed","seats":[2],"booking_id":"BK00000001"}

# see what's left, and how the engine is doing
curl http://localhost:8080/seats
curl http://localhost:8080/metrics
```

That is the "two lines" promise: point your app at `/book`, send a user id and an
idempotency key, and Kavach handles the stampede behind it.

## Run the stampede yourself

```bash
pip install aiohttp
# Tatkal burst: 20,000 users fire at once for 5,000 seats
python sim/simulate.py --users 20000 --concurrency 10000

# sustained hammer: 1,000,000 requests with 10% bots
python sim/simulate.py --total 1000000 --concurrency 3000 --users 100000 --bots 0.1

# prove no seat was ever double-sold
python sim/verify.py engine/bookings.jsonl 5000
```

## The report card (measured, not claimed)

Hardware: one small container, 2 CPU cores, 4 GB RAM. The test client (Python/asyncio)
was the bottleneck in every run; the engine's own latency percentiles are server-side.
Full numbers and honest limits in [RESULTS.md](RESULTS.md).

| Test | Load | Result |
|---|---|---|
| Tatkal burst | 20,000 users at once, 5,000 seats | Exactly 5,000 seats sold, 0 double-bookings, 0 errors, p50 0.005 ms, p99 5.6 ms |
| Sustained hammer | 1,000,000 requests, 100k users, 10% bots, 2,000 seats | Exactly 2,000 seats sold, 998,000 clean instant sold-outs, 0 errors, 0 crashes, p50 0.004 ms, p99 1.1 ms |
| Bot flood | 135,033 requests in 64 s, 50 fixed identities, half bots | 128,575 rate-limited at the edge (95%), exactly 2,000 seats sold, 0 errors, p99 0.28 ms |
| Chaos | Engine process frozen mid-rush, then resumed | Recovered and finished with perfect accuracy; no data loss |

## What v1 does not do yet (the honest list)

- Distributed mode: the v1 inventory is in one process (atomic CAS is the seat lock).
  The Redis-backed multi-node lock is the next milestone; the design is in the docs.
- The event log is a local file. The write-behind database layer is designed but not wired.
- Chaos v1 freezes the process; real chaos engineering kills stages independently.

## Roadmap

1. Redis-backed distributed seat lock + multi-node mode
2. Write-behind database layer (Postgres) replaying from the event log
3. Waitlist mode (queue positions instead of rejections)
4. Client SDKs (Python, JavaScript) so plugging in really is two lines
5. Chaos v2: kill workers mid-run, not the whole process

## License

MIT. Take it, use it, build your app on it.
