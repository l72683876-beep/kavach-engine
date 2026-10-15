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
| Reservation lifecycle | Hold with a TTL, confirm, release, expiry worker | A cart is not a sale: seats return if payment never lands |
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

## Security mode (v1.5)

Local mode (no keys) stays the two-minute default above. For anything exposed to a network:

```bash
./kavach -seats 5000 -workers 8 \
  -api-keys "sk_live_abc:tenant-a,sk_live_xyz:tenant-b" \
  -hmac-secret "$KAVACH_HMAC_SECRET" \
  -ip-rate 20 -user-rate 2
```

Every write must then carry: `Authorization: Bearer <key>`, `X-Kavach-Timestamp`
(unix seconds, ±5 min), `X-Kavach-Request-Id` (unique per request), and
`X-Kavach-Signature` = hex(HMAC-SHA256(secret, timestamp + "\n" + request_id + "\n" + raw_body)).
Replayed requests are rejected; a key reused with a different payload gets
`idempotency_conflict`; `GET /status?idempotency_key=...` resolves an ambiguous
timeout. A confirmed response means the booking is already fsynced to disk
(persist-before-ack). The full audit and the 14-test acceptance suite:
[docs/AUDIT.md](docs/AUDIT.md), `sim/security_test.py`.

## Hold, confirm, release (v1.6)

The direct `/book` path stays for speed. Real commerce needs a cart: reserve now,
pay later. Kavach's reservation lifecycle:

```bash
# 1. hold seats (they leave the free pool immediately, for a TTL)
curl -X POST http://localhost:8080/reserve \
  -H 'Content-Type: application/json' \
  -d '{"user_id":"priya","idempotency_key":"priya-cart-1","seats":2}'
# {"status":"held","reservation_id":"RSV00000001","seats":[2,3],"hold_expires_at":...}

# 2. after your payment provider confirms, turn the hold into a booking
curl -X POST http://localhost:8080/confirm \
  -H 'Content-Type: application/json' \
  -d '{"reservation_id":"RSV00000001","user_id":"priya"}'
# {"status":"confirmed","booking_id":"BK00000001","seats":[2,3]}

# 3. or give the seats back before the TTL (default 5 minutes, -hold-ttl)
curl -X POST http://localhost:8080/release \
  -H 'Content-Type: application/json' -d '{"reservation_id":"RSV00000001"}'

# resolve any ambiguity: what happened to that reservation?
curl 'http://localhost:8080/reservation?id=RSV00000001'
```

Why this is the hard part: an expiry worker returns abandoned holds to the free
pool every second, and every state change (`held → confirmed`, `held → expired`,
`held → released`) is a single-winner compare-and-swap. So a confirm racing the
expiry has exactly one winner: a seat can never be both expired and sold, a
confirmed seat never returns to the pool, and a re-confirm is idempotent (the
same booking comes back). Every lifecycle event is fsynced before its response,
same as bookings. 19-test acceptance suite: `sim/lifecycle_test.py`.

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
- Holds live in memory: a restart frees every hold (confirmed bookings are safe on disk;
  the event log records what was held). The database layer is the fix.

## Roadmap

1. Redis-backed distributed seat lock + multi-node mode
2. Write-behind database layer (Postgres) replaying from the event log
3. Waitlist mode (queue positions instead of rejections)
4. Client SDKs (Python, JavaScript) so plugging in really is two lines
5. Chaos v2: kill workers mid-run, not the whole process

## License

MIT. Take it, use it, build your app on it.
