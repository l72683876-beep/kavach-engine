# Kavach

[![CI](https://github.com/l72683876-beep/kavach-engine/actions/workflows/test.yml/badge.svg)](https://github.com/l72683876-beep/kavach-engine/actions/workflows/test.yml)

**Kavach** (Hindi for "armor") is an open-source inventory-reservation and booking engine
for ANY flash sale: e-commerce drop sales, event and hotel bookings, ticket queues,
waitlists, or anything limited that lakhs of people want at the same second. Millions of
requests at once, no crashes, no hangs, and never a double-sold item. It is one small,
readable Go service that any app can put in front of its own logic.

IRCTC's Tatkal rush (lakhs of people hitting the same train seats at 10:00 AM) is the
stress test we benchmark against, because it is the hardest version of this problem.
The engine itself knows nothing about trains.

## What Kavach is, and is not

Kavach is a small, embeddable core: inventory, holds, confirm/release, rate limiting,
crash recovery, sharding. It is deliberately NOT a full e-commerce platform. Pricing,
coupons, taxes (GST), user verification and payment flows stay in YOUR application
layer, where they belong. That is a design choice, not a missing feature: keeping heavy
business logic out of the hot path is exactly why the core stays fast, and mature
commerce systems separate these layers the same way.

A full worked example of this split, a checkout that reserves, prices, taxes,
verifies and pays, and why the heavy logic does not slow the stampede path:
[docs/INTEGRATION.md](docs/INTEGRATION.md).

About RAM: a response is only sent after its event is fsynced to an append-only log
(persist-before-ack). On restart the logs are replayed and every acknowledged booking,
hold and waitlist entry is rebuilt; a SIGKILL mid-rush loses nothing that was
acknowledged. Live data sits in memory for speed; durability lives in the log.

Full benchmark methodology and numbers: [BENCHMARK_K6.md](BENCHMARK_K6.md) and
[RESULTS.md](RESULTS.md). All k6 scripts ship in the repo, so every claim on this page
is reproducible on your own machine.

Built to be learned from: every layer exists for a reason, and this README explains why.

**Run it in one click:** press Code, then Codespaces, then Create codespace on this
repo, and a 100-seat demo runs itself: build, live bookings, an idempotency proof,
a 2,000-user mini stampede, and an independent log verification.

**Test it in one command:** `make test` (or `bash scripts/test.sh`) builds, vets,
runs the race detector, fires a live burst and verifies its log independently, then
runs every acceptance suite, and ends with one PASS/FAIL report. `--full` adds the
chaos, recovery and cluster suites. CI runs the same script on every push.

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
| Rate limiter | Token bucket per user/key | Bots die here: an in-memory token-bucket check rejects abuse in nanoseconds of CPU, before inventory is touched |
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
`X-Kavach-Signature` = hex(HMAC-SHA256(secret, timestamp + "\n" + request_id + "\n" + method + "\n" + request_uri + "\n" + raw_body)): the signature is bound to exactly one request, so a captured one cannot be replayed against another path.
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

## Multi-node (v2.0)

One process has one CPU budget. When a single node saturates, run a cluster: pass
`-peers` with EVERY node's address, this one included.

```bash
# terminal 1, 2, 3: three nodes, each owning a disjoint slice of the inventory
./kavach -seats 100 -workers 4 -peers 127.0.0.1:8081,127.0.0.1:8082,127.0.0.1:8083 -addr :8081
./kavach -seats 100 -workers 4 -peers 127.0.0.1:8081,127.0.0.1:8082,127.0.0.1:8083 -addr :8082
./kavach -seats 100 -workers 4 -peers 127.0.0.1:8081,127.0.0.1:8082,127.0.0.1:8083 -addr :8083
```

How it works, and why there is still no double-sell:

- **Seat-range sharding.** Node 0 owns seats 0-99, node 1 owns 100-199, and so on
  (`-seats` is the per-node slice; the cluster total is nodes x seats). Every write is
  a CAS on the node's own slice, so there is no shared lock to argue over, and the
  never-double-sell guarantee is the same atomic CAS as single-node, just partitioned.
  No Redis, no consensus, no extra dependency.
- **Ring forwarding.** A node whose slice is sold out forwards the request (original
  bytes plus auth headers, with an `X-Kavach-Forwarded-By` marker) to the next peers in
  the ring until one confirms. Every node can serve every request; any node is a valid
  entry point.
- **Disjoint ID ranges.** Node k issues IDs starting at k x 10,000,000, so BK/RSV/WL
  ids from different nodes never collide and logs stay mergeable.
- **Forwarded retries are safe.** The owning node's idempotency store answers a
  forwarded retry with the stored result, so a lost response can never become a second
  booking. Reads (`/reservation`, `/status`, `/confirm`, `/release`) forward on
  not-found, so any node can resolve any object.
- **Per-node durability.** Each node keeps its own append-only logs and replays them on
  restart, exactly like single-node. Kill a node mid-rush, restart it, its slice is back.
- **`/seats` becomes the cluster view**: the same total/sold/held/free shape, summed
  across nodes, plus a per-node breakdown (`/seats?local=1` stays local).

Known limits, on the record: waitlist and per-user rate limits are per-node (a global
waitlist needs the shared-state milestone); `/metrics` is local; a forwarded request
skips the peer's IP limiter (it was already limited at the entry node) while still
passing full auth verification, so keep `-peers` on a private network.

## Postgres write-behind (v2.1)

The local append-only logs stay the source of truth. A booking is acknowledged
after the LOCAL log is durable, exactly as before. With a Postgres sink enabled,
a background tailer ships every committed line to Postgres, where SQL, dashboards
and retention policies can work with it. Postgres never sits in the request path:
if it is slow or down, the engine keeps serving and catches up when it returns.

```bash
cd engine && go build -tags postgres -o kavach_pg . && \
./kavach_pg -pg-dsn "postgres://user@host:5432/db?sslmode=disable" -node-id n1
```

The default build (`go build -o kavach .`) stays dependency-free; only the
`postgres` tag pulls in pgx v5 (pure Go, no cgo). The schema is created
automatically:

- `kavach_events(node_id, source, line_off, logged_at, data jsonb)`: one row per
  committed log line, `data` being the event as JSON.
- `kavach_ship_state(node_id, source, byte_offset)`: the resume cursor. A crash
  between an insert and its cursor update re-inserts the same lines, and the
  primary key turns that into a no-op: at-least-once shipping, exactly-once landing.

Restart resumes from the stored cursor; the first boot against a fresh database
ships the full history. `-node-id` names this node (matters in multi-node mode).
Inspect the data without a psql install:

```bash
go run ./pgq "SELECT data->>'user_id', data->>'seats' FROM kavach_events WHERE source='bookings.jsonl' LIMIT 5"
```

Acceptance tests: `python3 sim/pg_test.py` (needs a live Postgres and `./kavach_pg`).

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

## Run it as a real app (three-tier demo)

Standalone benchmarks are one thing; the same rush through a real web
application is another. [examples/demo-app](examples/demo-app) is a
complete concert-ticketing site (static UI + Flask backend + the Python
SDK) that holds seats while a simulated payment runs, confirms on
success, releases on failure, and waitlists the latecomers. Its load
test drives 2,000 buyers through the app and fails hard unless the
engine's final sold count matches the app's confirmed seats exactly.

```bash
cd examples/demo-app && python3 loadtest_app.py 9000 2000 100
```

Measured on a 2-core box: 200/200 seats sold through the app, zero
double-sells, p95 667 ms end to end. Full numbers in
[examples/demo-app/README.md](examples/demo-app/README.md).

## Watch it run (video evidence)

Real recordings of live runs, not mockups: [demo/kavach_demo.mp4](demo/kavach_demo.mp4)
shows a 12,000-request stampede on a 200-seat engine plus a mid-rush SIGKILL crash and
log-replay recovery (zero double-sell throughout). [demo/kavach_big.mp4](demo/kavach_big.mp4)
shows two sustained rounds, 1,000,000 and 2,000,000 requests (~18 minutes of continuous
pressure, peak 3,077 req/s on a 2-core box, 0 errors, 0 double-sell). Details and honest
caveats in [demo/README.md](demo/README.md).

## Reproducible benchmark run (Oct 15, 2026)

This run used this repository's engine with `sim/simulate.py` and `sim/verify.py` on a
4-core GitHub Codespace, and the report below was written from the raw result logs.
The scripts ship in this repo, so nobody has to take these numbers on faith: run the
commands under "Reproduce" and compare against this table yourself.

| Suite | Users / Seats | Requests | Peak RPS | P50 / P95 / P99 (ms) | Duplicate seats | Server errors |
|---|---|---|---|---|---|---|
| 1 | 100,000 / 5,000 | 784,187 | 3,852.4 | 2.08 / 3.67 / 6.73 | 0 | 0 |
| 2 | 200,000 / 20,000 | 1,567,432 | 3,660.2 | 2.45 / 4.98 / 9.33 | 0 | 0 |

Totals: 2,351,619 requests, zero duplicate seats, zero crashes, zero HTTP 500s. In Suite 2,
1,558,881 of 1,567,432 requests were rejected by IP rate limiting, which is the overload
protection working as designed. Because rejections are cheap, the sub-5 ms P95 above mostly
reflects the fast reject path, not end-to-end booking confirmations; the k6 table below shows
P95 for accepted bookings under heavy contention. The request counts are totals, not
simultaneous connections.

Reproduce:

```bash
cd engine && go build -o kavach . && ./kavach -seats 5000 -ip-rate 0
# separate terminal
python3 sim/simulate.py --users 100000 --seats 5000
python3 sim/verify.py engine/bookings.jsonl 5000
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
| k6 cart flow, v2.1 (single node) | Same workload, same box; a live Postgres shared the container during the run | 1,966.6 req/s, p95 157 ms, 0 failures, 0 duplicate seats |

## What v1 does not do yet (the honest list)

- Shared-state mode: multi-node is seat-range sharding (each node owns a disjoint
  slice, shipped in v2.0). A Redis-backed shared store for global rate limiting and a
  cluster-wide waitlist is the next milestone; the design is in the docs.
- The event log is a local file by design. Postgres write-behind (v2.1) mirrors it for SQL and analytics; the file remains the source of truth.
- Chaos v1 froze the whole process; v1.9 adds contained worker panics and random stalls.
- A restart replays the append-only event log, so sold seats, live holds (with their
  original expiry), waitlist positions and idempotency keys all come back exactly as
  they were. Reservation objects still live in memory between restarts; the
  write-behind database layer shipped in v2.1.

## Roadmap

1. Redis-backed distributed seat lock + multi-node mode
2. ~~Write-behind database layer (Postgres) replaying from the event log~~ shipped in v2.1
3. ~~Waitlist mode~~ shipped in v1.8
4. ~~Client SDKs (Python, JavaScript)~~ shipped in v1.8
5. ~~Chaos v2~~ shipped in v1.9 (contained worker panics, random stalls)
6. ~~Multi-node~~ shipped in v2.0 (seat-range sharding, ring forwarding, disjoint ID ranges)

## License

MIT. Take it, use it, build your app on it.
