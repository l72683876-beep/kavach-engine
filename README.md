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

## Waitlist (v1.8)

Joining is only for sold-out moments: with free seats on hand the engine
answers `409 {"status": "seats_available"}` and points the client at a
direct reservation.

Sold out should not mean lost. When the inventory is empty, users join a FIFO
waitlist instead of getting a dead end:

```bash
curl -X POST http://localhost:8080/waitlist \
  -H 'Content-Type: application/json' \
  -d '{"user_id":"priya","idempotency_key":"priya-line-1","seats":1}'
# {"status":"queued","waitlist_id":"WL00000001","position":1}

# your place in line
curl 'http://localhost:8080/waitlist?user_id=priya'

# leave the line
curl -X POST http://localhost:8080/waitlist/cancel \
  -H 'Content-Type: application/json' -d '{"waitlist_id":"WL00000001"}'
```

The fairness rule is strict: seats return on expiry or release and go to the
FRONT of the line first. A front entry that needs more seats than are free
blocks the entries behind it, so nobody can buy their way past the queue. The
fulfilled user gets a live reservation automatically, and if the engine was
started with `-webhook-url http://...`, a `waitlist_fulfilled` event is POSTed
there (fire-and-forget; deliveries never block the request path).
13-test acceptance suite: `sim/waitlist_test.py`.

## Restart recovery (v1.9)

The append-only logs are the source of truth. On boot the engine replays
`bookings.jsonl` and `holds.jsonl` in timestamp order and rebuilds: sold and
held seats, every reservation with its final state and its original expiry,
live waitlist entries in their exact FIFO order, idempotency keys (a retry
after a crash still returns the original booking), and the ID counters so new
IDs never collide with pre-crash ones. A `SIGKILL` mid-run loses nothing that
was acknowledged.

```
kavach recovery: 45 bookings, 46 reservations, 1 waitlist entries restored
```

Logs written before v1.9 carry no expiry timestamps; those holds get a fresh
TTL on recovery.

## Chaos, built in (v1.9)

Real systems fail in the middle, not at the edges. Kavach can inject its own
failures so you can watch it survive them:

```bash
./kavach -seats 2000 -chaos-prob 0.05 -chaos-stall-ms 700 -chaos-panic 0.04
```

- `-chaos-prob` + `-chaos-stall-ms`: a random slice of requests hits a stall
  (a slow downstream dependency). Latency degrades; correctness does not.
- `-chaos-panic`: workers panic at random. One `recover()` per job contains
  it: the request gets a clean 500, the engine never dies from a single
  panicking worker.

`sim/chaos_test.py` runs a rush under both and proves the invariant holds:
exactly the right seats sold, zero double-sells, process alive. Counters
`chaos_stalls` and `chaos_panics` show on `/metrics`.

## Client SDKs: the real two lines

```python
# sdk/python/kavach.py - standard library only, no dependencies
from kavach import Kavach
k = Kavach("http://localhost:8080")
print(k.book("priya", "priya-booking-1", seats=1))
```

```js
// sdk/javascript/kavach.mjs - Node 18+ or any modern browser
import { Kavach } from "./kavach.mjs";
const k = new Kavach("http://localhost:8080");
console.log(await k.book("priya", "priya-booking-1", 1));
```

Pass `api_key` and `hmac_secret` and both SDKs speak the production auth
handshake (bearer key, timestamp, request id, HMAC signature) with zero extra
code. Both are covered by their own acceptance tests (11 and 9 checks,
`sdk/test_sdks.py`, `sdk/test_sdk.mjs`).

A hands-on walkthrough of everything above, written for a browser tab:
[TEST_GUIDE.md](TEST_GUIDE.md).

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
| k6 cart flow, fsync per write (v1.6) | 200 users, reserve+confirm per iteration, k6 v0.54 | 229.7 req/s, p95 1.2 s, 0 failures, 0 duplicate seats |
| k6 cart flow, group commit (v1.7) | Same workload, same box, only group commit changed | 2,276.6 req/s (9.9x), p95 139 ms, 0 failures, 0 duplicate seats |

## What v1 does not do yet (the honest list)

- Distributed mode: the v1 inventory is in one process (atomic CAS is the seat lock).
  The Redis-backed multi-node lock is the next milestone; the design is in the docs.
- The event log is a local file. The write-behind database layer is designed but not wired.
- Chaos v1 froze the whole process; v1.9 adds contained worker panics and random stalls.
- A restart replays the append-only event log, so sold seats, live holds (with their
  original expiry), waitlist positions and idempotency keys all come back exactly as
  they were. Reservation objects still live in memory between restarts; the
  write-behind database layer is the next step.

## Roadmap

1. Redis-backed distributed seat lock + multi-node mode
2. Write-behind database layer (Postgres) replaying from the event log
3. ~~Waitlist mode~~ shipped in v1.8
4. ~~Client SDKs (Python, JavaScript)~~ shipped in v1.8
5. ~~Chaos v2~~ shipped in v1.9 (contained worker panics, random stalls)

## License

MIT. Take it, use it, build your app on it.
